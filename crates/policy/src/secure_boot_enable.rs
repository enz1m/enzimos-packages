// SPDX-License-Identifier: MIT
//! Prepare verified owner boot images, then publish entries, catalog and policy.
//! An interrupted attempt remains a review boundary, never a rollback/replay job.
use super::{Wrapped, wrap_inner};
use crate::{
    boot_entries,
    boot_volume::{Artifact, ReplacedArtifact, Volume},
    catalog, operation,
    recovery_build_source::Source,
    secure_artifacts::{self, Signed},
    secure_boot, secure_loader_refresh,
    secure_owner_source::Owner,
    transition_idle,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, publication, require};
use serde_json::{Value, json as value};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const ATTEMPT: &str = "enable-attempt.json";
/// Terminal record of the last abandoned enablement (kept for review).
const ABANDONED: &str = "enable-abandoned.json";
const MASK: &str = "systemd-boot-update.service";

fn owned_unlink(mut before: files::FileIdentity, mut after: files::FileIdentity) -> bool {
    if before.10 != 1 || after.10 != 0 {
        return false;
    }
    before.5 = 0;
    before.6 = 0;
    before.10 = 0;
    after.5 = 0;
    after.6 = 0;
    before == after
}
fn record(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema phase filesystem_uuid certificate_sha256 entries_sha256",
    )?;
    require(
        v["schema"] == 1 && matches!(v["phase"].as_str(), Some("prepared" | "complete")),
        "owner enable attempt schema/phase",
    )?;
    crate::identity::uuid(crate::recovery_records::text(v, "filesystem_uuid")?)?;
    for name in ["certificate_sha256", "entries_sha256"] {
        crate::identity::sha(crate::recovery_records::text(v, name)?)?;
    }
    Ok(())
}
/// The owner policy directory, when it exists.
fn owner_directory() -> Result<Option<File>> {
    let root = files::directory(Path::new("/"), Some(0))?;
    let Some(var) = files::optional_directory_relative(&root, Path::new("var"), Some(0))? else {
        return Ok(None);
    };
    let Some(lib) = files::optional_directory_relative(&var, Path::new("lib"), Some(0))? else {
        return Ok(None);
    };
    let Some(control) =
        files::optional_directory_relative(&lib, Path::new("enzimos-control"), Some(0))?
    else {
        return Ok(None);
    };
    files::optional_directory_relative(&control, Path::new("secure-boot"), Some(0))
}
/// Called only after acquiring the actual operation lock. A read record can
/// refuse work, but cannot authorize continuing an interrupted enablement.
pub(crate) fn pending_entry() -> Result<()> {
    let Some(owner) = owner_directory()? else {
        return Ok(());
    };
    let Some(attempt) = files::optional_relative(&owner, Path::new(ATTEMPT))? else {
        return Ok(());
    };
    let value = json::decode(&files::read_file(&attempt, 4096, Some(0), true)?, 4096)?;
    record(&value)?;
    if value["phase"] == "prepared" {
        // The enabling process is gone (it holds this lock for its whole run).
        // A preparation left for a week that never rewrote a boot entry is
        // abandoned instead of refusing every operation forever; its staged
        // images stay until an explicit `secure-boot abandon` or a new enable.
        let age = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| {
                now.as_secs() as i64 - attempt.metadata().map_or(i64::MAX, |m| m.mtime())
            });
        let abandoned = stale(age)
            && (|| {
                let volume = Volume::observe()?;
                before_no_return(&value, secure_boot::configured()?, &entry_texts(&volume)?)?;
                secure_boot::abandon_record(
                    &owner,
                    &attempt,
                    ATTEMPT,
                    ABANDONED,
                    &value,
                    "stale-preparation",
                    &mut || Ok(()),
                )
            })()
            .is_ok();
        require(
            abandoned,
            "interrupted owner boot enablement requires review or `secure-boot abandon`; no replay",
        )?;
        return Ok(());
    }
    require(
        secure_boot::configured()?,
        "completed enablement policy missing",
    )?;
    let certificate = files::open_relative(&owner, Path::new("owner.crt"))?;
    require(
        json::sha256(&files::read_file(&certificate, 16384, Some(0), false)?)
            == value["certificate_sha256"],
        "completed enablement owner certificate changed",
    )
}
/// A prepared enablement older than this (seconds) is abandoned automatically
/// when it is still before its point of no return.
const STALE: i64 = 7 * 86400;
fn stale(age: i64) -> bool {
    age >= STALE
}
/// The `.conf` boot entries exactly as enablement fingerprints them.
fn entry_texts(volume: &Volume) -> Result<BTreeMap<String, String>> {
    let directory = volume.directory(Path::new("loader/entries"))?;
    let mut texts = BTreeMap::new();
    for name in files::directory_names(&directory, 128)? {
        let name = name
            .to_str()
            .ok_or_else(|| Error("boot entry encoding".into()))?;
        if !name.ends_with(".conf") {
            continue;
        }
        let original = volume.artifact(&Path::new("loader/entries").join(name), 65536)?;
        let text = String::from_utf8(files::read_file(&original.file, 65536, Some(0), false)?)
            .map_err(|_| Error("boot entry encoding".into()))?;
        texts.insert(name.to_owned(), text);
    }
    Ok(texts)
}
/// The point of no return of an enablement is its first boot entry rewrite:
/// from then on entries (and then the catalog and policy) name signed UKIs.
/// Before it, every entry still hashes to the attempt's `entries_sha256`, none
/// names a UKI and no policy exists, so the system boots exactly as before;
/// the built UKIs are referenced by nothing, and the re-signed loaders and the
/// updater mask belong to the owner key, which stays.
fn before_no_return(
    attempt: &Value,
    configured: bool,
    texts: &BTreeMap<String, String>,
) -> Result<()> {
    require(
        attempt["phase"] == "prepared",
        "owner boot enablement is not unfinished; nothing to abandon",
    )?;
    require(
        !configured,
        "owner UKI policy already published; past the point of no return",
    )?;
    for text in texts.values() {
        require(
            !boot_entries::fields(text, false)?.contains_key("uki"),
            "a boot entry already names an owner UKI; past the point of no return",
        )?;
    }
    require(
        json::fingerprint(&value!(texts))? == attempt["entries_sha256"],
        "boot entries changed since enablement started; review required",
    )
}
/// Staged owner UKI images (`<sha256>.efi`) and interrupted publications of
/// them (`.new`); any other member is left alone.
fn staged_image(name: &str) -> bool {
    let digest = name
        .strip_suffix(".efi.new")
        .or_else(|| name.strip_suffix(".efi"));
    digest.is_some_and(|d| crate::identity::sha(d).is_ok())
}
/// Explicitly abandon an unfinished owner boot enablement before its point of
/// no return (see [`before_no_return`]): remove its unreferenced staged UKIs
/// through the boot artifact retirement path, then publish the terminal
/// `enable-abandoned.json` and remove the attempt, which frees every operation
/// it blocked. An unfinished enrollment is abandoned too when the firmware db
/// is provably unchanged. The caller holds the operation lock taken without
/// the enablement refusal.
pub fn abandon_locked(lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    let enrollment = crate::secure_owner_source::enrollment::abandon_unchanged(&mut || {
        operation::root_only()?;
        lock.recheck()
    })?;
    let mut result = value!({"status":"nothing-to-abandon","enrollment":enrollment,"removed_images":[],
        "kept_members":[],"firmware_changed":false,"owner_key_kept":true});
    let Some(owner) = owner_directory()? else {
        return Ok(result);
    };
    let Some(attempt) = files::optional_relative(&owner, Path::new(ATTEMPT))? else {
        return Ok(result);
    };
    let value = json::decode(&files::read_file(&attempt, 4096, Some(0), true)?, 4096)?;
    record(&value)?;
    let volume = Volume::observe()?;
    volume.writable()?;
    let check = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        volume.writable()?;
        before_no_return(&value, secure_boot::configured()?, &entry_texts(&volume)?)
    };
    check()?;
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    let relative = Path::new("enzimos/secure-boot");
    if !matches!(std::fs::symlink_metadata(volume.path(relative)?), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        let parent = volume.directory(relative)?;
        for name in files::directory_names(&parent, 256)? {
            let name = name
                .into_string()
                .map_err(|_| Error("owner UKI member encoding".into()))?;
            if !staged_image(&name) {
                kept.push(name);
                continue;
            }
            check()?;
            volume
                .artifact(&relative.join(&name), 256 * 1024 * 1024)?
                .quarantine_original(&parent, 256 * 1024 * 1024, &mut || check())?
                .unlink(&mut || check())?;
            removed.push(name);
        }
    }
    // The attempt goes last, so an interrupted abandonment still blocks and
    // is completed by running it again.
    check()?;
    secure_boot::abandon_record(
        &owner,
        &attempt,
        ATTEMPT,
        ABANDONED,
        &value,
        "explicit",
        &mut || {
            operation::root_only()?;
            lock.recheck()
        },
    )?;
    result["status"] = value!("owner-boot-enablement-abandoned");
    result["removed_images"] = value!(removed);
    result["kept_members"] = value!(kept);
    Ok(result)
}

struct Entry {
    original: Option<Artifact>,
    replaced: Option<ReplacedArtifact>,
    text: String,
    wrapped: Option<Wrapped>,
}
impl Entry {
    fn recheck(&self, permission: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if let Some(original) = &self.original {
            original.recheck()?;
        }
        if let Some(replaced) = &self.replaced {
            replaced.recheck()?;
        }
        if let Some(wrapped) = &self.wrapped {
            wrapped.recheck(permission)?;
        }
        require(
            self.original.is_some() != self.replaced.is_some(),
            "entry publication authority incomplete",
        )
    }
}
struct Loader {
    source: Source,
    before: Artifact,
    epoch: files::FileIdentity,
    signed: Option<Signed>,
}
impl Loader {
    fn recheck(&self, permission: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.source.recheck()?;
        match &self.signed {
            Some(signed) => {
                signed.require_replaced_input(&self.before.file, self.epoch, permission)
            }
            None => self.before.recheck(),
        }
    }
}

// Fixed updater mask. Retain its original directory and, if present, the exact
// ordinary unit description across one owned unlink and exclusive symlink.
struct Mask {
    parent: File,
    mount: u64,
    shape: (u64, u64, u32),
    original: Option<File>,
    epoch: Option<files::FileIdentity>,
    ready: bool,
    link: Option<(File, files::FileIdentity, i32)>,
}
impl Mask {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
    fn observe() -> Result<Self> {
        let parent = files::directory(Path::new("/etc/systemd/system"), Some(0))?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let m = parent.metadata()?;
        let shape = (m.dev(), m.ino(), m.mode());
        let leaf =
            CString::new(MASK).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `leaf` is a NUL-terminated CString, `status` is a writable `libc::stat`, and
        // `parent` stays open.
        let found = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        let ready = found == 0 && status.st_mode & libc::S_IFMT == libc::S_IFLNK;
        if found != 0 {
            require(
                std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound,
                "updater mask observation refused",
            )?;
        }
        let original = if found == 0 && !ready {
            Some(files::open_relative(&parent, Path::new(MASK))?)
        } else {
            None
        };
        let epoch = original
            .as_ref()
            .map(|f| f.metadata().map(|m| files::identity(&m)))
            .transpose()?;
        if let Some(original) = &original {
            let m = original.metadata()?;
            require(
                m.is_file()
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o022 == 0
                    && m.nlink() == 1
                    && mount_identity::id(original.as_fd(), true)? == mount,
                "original updater unit protection differs",
            )?;
        }
        let mut this = Self {
            parent,
            mount,
            shape,
            original,
            epoch,
            ready,
            link: None,
        };
        if ready {
            this.retain_link()?;
        }
        this.recheck()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn retain_link(&mut self) -> Result<()> {
        let leaf =
            CString::new(MASK).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        // SAFETY: `leaf` is a NUL-terminated C string and `self.parent` keeps the descriptor open.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "original updater mask handle unavailable")?;
        // SAFETY: `fd` was just returned by openat and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata()?;
        require(
            m.file_type().is_symlink()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "original updater mask ownership/mount",
        )?;
        let flags = enzimos_platform::files::status_flags(&file);
        require(flags >= 0, "mask description status unavailable")?;
        self.link = Some((file, files::identity(&m), flags));
        Ok(())
    }
    fn parent(&self) -> Result<()> {
        let named = files::directory(Path::new("/etc/systemd/system"), Some(0))?;
        for parent in [&self.parent, &named] {
            let m = parent.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode()) == self.shape
                    && mount_identity::id(parent.as_fd(), true)? == self.mount,
                "updater mask directory replaced/covered",
            )?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatat, readlinkat).")]
    fn recheck(&self) -> Result<()> {
        self.parent()?;
        if self.ready {
            let (held, epoch, flags) = self
                .link
                .as_ref()
                .ok_or_else(|| Error("owned mask handle absent".into()))?;
            let leaf = CString::new(MASK)
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
            // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
            let mut status: libc::stat = unsafe { std::mem::zeroed() };
            require(
                // SAFETY: `leaf` is a NUL-terminated CString, the stat buffer is writable, and
                // `self.parent` stays open.
                unsafe {
                    libc::fstatat(
                        self.parent.as_raw_fd(),
                        leaf.as_ptr(),
                        &mut status,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0
                    && (status.st_dev, status.st_ino) == (epoch.0, epoch.1)
                    && files::identity(&held.metadata()?) == *epoch
                    && enzimos_platform::files::status_flags(&held) == *flags
                    && mount_identity::id(held.as_fd(), true)? == self.mount,
                "original updater mask replaced/changed",
            )?;
            let leaf = CString::new(MASK)
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
            let mut target = [0u8; 32];
            // SAFETY: `leaf` is NUL-terminated, the buffer pointer and length describe `target`,
            // and `self.parent` stays open.
            let count = unsafe {
                libc::readlinkat(
                    self.parent.as_raw_fd(),
                    leaf.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            require(
                count == 9 && &target[..9] == b"/dev/null",
                "original updater mask changed",
            )?;
            if let Some(old) = &self.original {
                require(
                    owned_unlink(self.epoch.unwrap(), files::identity(&old.metadata()?)),
                    "owned updater unit changed outside known unlink",
                )?;
            }
        } else if let Some(original) = &self.original {
            require(
                Some(files::identity(&original.metadata()?)) == self.epoch
                    && Some(files::identity(
                        &files::open_relative(&self.parent, Path::new(MASK))?.metadata()?,
                    )) == self.epoch,
                "original updater unit replaced/changed",
            )?;
        } else {
            require(
                files::optional_relative(&self.parent, Path::new(MASK))?.is_none(),
                "updater mask appeared",
            )?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (symlinkat, unlinkat).")]
    fn publish(&mut self, permission: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        permission()?;
        self.recheck()?;
        if self.ready {
            return Ok(());
        }
        let leaf =
            CString::new(MASK).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        if self.original.is_some() {
            require(
                // SAFETY: `leaf` is a NUL-terminated C string and `self.parent` keeps the
                // descriptor open.
                unsafe { libc::unlinkat(self.parent.as_raw_fd(), leaf.as_ptr(), 0) } == 0,
                "owned updater unit unlink uncertain; no replay",
            )?;
            require(
                self.original
                    .as_ref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                    .metadata()?
                    .nlink()
                    == 0,
                "owned updater unit unlink not observed",
            )?;
        }
        self.parent()?;
        require(
            // SAFETY: Both paths are NUL-terminated and `self.parent` keeps the descriptor open.
            unsafe {
                libc::symlinkat(
                    c"/dev/null".as_ptr(),
                    self.parent.as_raw_fd(),
                    leaf.as_ptr(),
                )
            } == 0,
            "exclusive updater mask publication uncertain; no replay",
        )?;
        self.parent.sync_all()?;
        self.ready = true;
        self.retain_link()?;
        self.recheck()?;
        permission()
    }
}

pub fn enable_locked(lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    require(secure_boot::firmware()?["uefi"] == true, "UEFI required")?;
    let idle = transition_idle::Snapshot::online()?;
    let volume = Volume::observe()?;
    volume.writable()?;
    let owner = RefCell::new(Owner::credentials()?);
    require(
        !secure_boot::configured()?,
        "owner UKI policy already enabled",
    )?;
    let mut registry = catalog::Transaction::begin()?;
    registry.recheck()?;
    let directory = volume.directory(Path::new("loader/entries"))?;
    let names = files::directory_names(&directory, 128)?;
    let entries = RefCell::new(BTreeMap::<String, Entry>::new());
    let mut other_entries = Vec::new();
    for name in &names {
        let name = name
            .to_str()
            .ok_or_else(|| Error("boot entry encoding".into()))?;
        require(
            name.len() <= 200 && !name.chars().any(char::is_control),
            "boot entry basename bound",
        )?;
        if !name.ends_with(".conf") {
            other_entries.push(volume.artifact(&Path::new("loader/entries").join(name), 65536)?);
            continue;
        }
        let original = volume.artifact(&Path::new("loader/entries").join(name), 65536)?;
        let body = files::read_file(&original.file, 65536, Some(0), false)?;
        let text = String::from_utf8(body).map_err(|_| Error("boot entry encoding".into()))?;
        let fields = boot_entries::fields(&text, false)?;
        require(
            !fields.contains_key("uki"),
            "preexisting owner UKI without active policy requires review",
        )?;
        original.recheck()?;
        entries.borrow_mut().insert(
            name.into(),
            Entry {
                original: Some(original),
                replaced: None,
                text,
                wrapped: None,
            },
        );
    }
    require(
        !entries.borrow().is_empty() && entries.borrow().len() <= 126,
        "boot entry bounds",
    )?;
    let bios = volume.artifact(Path::new("limine/limine.conf"), 1024 * 1024)?;
    let bios_text = String::from_utf8(files::read_file(&bios.file, 1024 * 1024, Some(0), false)?)
        .map_err(|_| Error("BIOS menu encoding".into()))?;
    let before_texts = entries
        .borrow()
        .iter()
        .map(|(n, e)| (n.clone(), e.text.clone()))
        .collect::<BTreeMap<_, _>>();
    for generation in registry.data["generations"]
        .as_object()
        .ok_or_else(|| Error("generation catalog object".into()))?
        .values()
    {
        require(
            generation["state"] == "ready"
                && boot_entries::fingerprint_entries(generation, &before_texts, &bios_text)?
                    == generation["entry_fingerprints"],
            "existing generation boot binding changed",
        )?;
    }
    let mut mask = Mask::observe()?;
    let loaders = RefCell::new(BTreeMap::<String, Loader>::new());
    let root = files::directory(Path::new("/"), Some(0))?;
    let root_mount = mount_identity::id(root.as_fd(), true)?;
    for (relative, path) in secure_loader_refresh::LOADERS {
        // Installed native boot contract supplies all four loaders. Fail before
        // mutation if this installation is incomplete rather than skip signing.
        let source = Source::observe(Path::new(path), 16 * 1024 * 1024)?;
        require(
            mount_identity::id(source.file.as_fd(), true)? == root_mount,
            "installed loader source crosses another mount",
        )?;
        let before = volume.artifact(Path::new(relative), 16 * 1024 * 1024)?;
        let epoch = files::identity(&before.file.metadata()?);
        loaders.borrow_mut().insert(
            relative.into(),
            Loader {
                source,
                before,
                epoch,
                signed: None,
            },
        );
    }
    let base = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        idle.recheck()?;
        volume.writable()?;
        bios.recheck()?;
        for original in &other_entries {
            original.recheck()?;
        }
        owner.borrow().recheck()
    };
    base()?;
    registry.recheck()?;
    let mut attempt = value!({"schema":1,"phase":"prepared","filesystem_uuid":registry.config["filesystem_uuid"],
        "certificate_sha256":owner.borrow().certificate_hash(),"entries_sha256":json::fingerprint(&value!(before_texts))?});
    record(&attempt)?;
    let path = Path::new(secure_boot::DIRECTORY).join(ATTEMPT);
    let prepared = publication::Prepared::write_authorized(
        &path,
        &json::canonical(&attempt)?,
        0,
        &mut || base(),
    )?;
    let mut receipt =
        publication::Chain::new(prepared.commit_retained_authorized(false, &mut || base())?)?;
    let keys = entries.borrow().keys().cloned().collect::<Vec<_>>();
    // Build and verify every UKI while all selected entries still retain their
    // original bytes. The explicit preparation mode cannot be selected by CLI.
    for name in &keys {
        let text = entries.borrow()[name].text.clone();
        let permission = || {
            base()?;
            receipt.recheck()?;
            registry.recheck()?;
            mask.recheck()?;
            for entry in entries.borrow().values() {
                entry.recheck(&mut || base())?;
            }
            for loader in loaders.borrow().values() {
                loader.recheck(&mut || base())?;
            }
            Ok(())
        };
        let wrapped = wrap_inner(&text, lock, &mut || permission(), true)?;
        wrapped.require_original_entry(&text, &mut || permission())?;
        let rewritten = wrapped.text(&mut || permission())?.to_owned();
        let mut rows = entries.borrow_mut();
        let entry = rows
            .get_mut(name)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        entry.text = rewritten;
        entry.wrapped = Some(wrapped);
    }
    require(
        files::directory_names(&directory, 128)? == names,
        "boot entry namespace changed during preparation",
    )?;
    mask.publish(&mut || base())?;
    // The four retained sources and their exact predecessors remain live through
    // the signing producer's owned replacements and terminal policy publication.
    let loader_keys = loaders.borrow().keys().cloned().collect::<Vec<_>>();
    for name in &loader_keys {
        let source_path = secure_loader_refresh::LOADERS
            .iter()
            .find(|(n, _)| *n == name)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .1;
        let permission = || {
            base()?;
            receipt.recheck()?;
            mask.recheck()?;
            registry.recheck()?;
            for entry in entries.borrow().values() {
                entry.recheck(&mut || base())?;
            }
            for (key, loader) in loaders.borrow().iter() {
                if key != name {
                    loader.recheck(&mut || base())?;
                } else {
                    loader.source.recheck()?;
                }
            }
            Ok(())
        };
        loaders.borrow()[name].before.recheck()?;
        let signed = secure_artifacts::sign_retained_authorized(
            Path::new(source_path),
            Some(&volume.path(Path::new(name))?),
            lock,
            &mut || permission(),
        )?;
        {
            let rows = loaders.borrow();
            let original = &rows[name];
            signed.require_replaced_input(&original.before.file, original.epoch, &mut || {
                permission()
            })?;
        }
        loaders
            .borrow_mut()
            .get_mut(name)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .signed = Some(signed);
    }
    for name in &keys {
        let target = Path::new("/boot/loader/entries").join(name);
        let text = entries.borrow()[name].text.clone();
        let permission = || {
            base()?;
            receipt.recheck()?;
            mask.recheck()?;
            registry.recheck()?;
            for (key, entry) in entries.borrow().iter() {
                if key != name {
                    entry.recheck(&mut || base())?;
                }
            }
            for loader in loaders.borrow().values() {
                loader.recheck(&mut || base())?;
            }
            Ok(())
        };
        let prepared =
            publication::Prepared::write_authorized(&target, text.as_bytes(), 0, &mut || {
                permission()
            })?;
        entries.borrow()[name]
            .original
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .require_original_publication(&prepared)?;
        let committed = prepared.commit_checked(
            true,
            &mut || {
                permission()?;
                entries.borrow()[name]
                    .original
                    .as_ref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                    .recheck()
            },
            &mut |actual| {
                permission()?;
                entries.borrow()[name]
                    .original
                    .as_ref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                    .require_owned_replacement(actual)
            },
        )?;
        let mut rows = entries.borrow_mut();
        let entry = rows
            .get_mut(name)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        entry.replaced = Some(
            entry
                .original
                .take()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                .into_replaced(committed)?,
        );
    }
    require(
        files::directory_names(&directory, 128)? == names,
        "boot entry namespace changed during publication",
    )?;
    let after_texts = entries
        .borrow()
        .iter()
        .map(|(n, e)| (n.clone(), e.text.clone()))
        .collect::<BTreeMap<_, _>>();
    for generation in
        enzimos_platform::json::object_mut(&mut registry.data["generations"])?.values_mut()
    {
        generation["entry_fingerprints"] =
            boot_entries::fingerprint_entries(generation, &after_texts, &bios_text)?;
    }
    let permission = || {
        base()?;
        receipt.recheck()?;
        mask.recheck()?;
        for entry in entries.borrow().values() {
            entry.recheck(&mut || base())?;
        }
        for loader in loaders.borrow().values() {
            loader.recheck(&mut || base())?;
        }
        Ok(())
    };
    if !enzimos_platform::json::object(&registry.data["generations"])?.is_empty() {
        registry.commit_idle_authorized(&idle, &mut || {
            operation::root_only()?;
            crate::namespaces::initial()?;
            lock.recheck()?;
            volume.writable()?;
            bios.recheck()?;
            for original in &other_entries {
                original.recheck()?;
            }
            owner.borrow().recheck()?;
            receipt.recheck()?;
            mask.recheck()?;
            for entry in entries.borrow().values() {
                entry.recheck(&mut || lock.recheck())?;
            }
            for loader in loaders.borrow().values() {
                loader.recheck(&mut || lock.recheck())?;
            }
            Ok(())
        })?;
    }
    // Policy is the last publication. Its actual new file permits only the
    // known false->true transition of independently held owner descriptions.
    registry.recheck()?;
    permission()?;
    let config = Path::new(secure_boot::DIRECTORY).join("config.json");
    let prepared = publication::Prepared::write_authorized(
        &config,
        &json::canonical(&value!({"schema":1,"mode":"owner-uki"}))?,
        0,
        &mut || permission(),
    )?;
    let configured = prepared.commit_checked(
        false,
        &mut || {
            permission()?;
            registry.recheck()
        },
        &mut |actual| {
            owner.borrow_mut().accept_configuration(actual)?;
            for entry in entries.borrow_mut().values_mut() {
                if let Some(binding) = entry.wrapped.as_mut().and_then(|w| w.binding.as_mut()) {
                    binding.owner.accept_configuration(actual)?;
                }
            }
            base()?;
            registry.recheck()?;
            mask.recheck()?;
            Ok(())
        },
    )?;
    configured.recheck()?;
    require(
        files::directory_names(&directory, 128)? == names,
        "entry namespace changed before completed policy receipt",
    )?;
    permission()?;
    registry.recheck()?;
    attempt["phase"] = value!("complete");
    receipt.replace(&json::canonical(&attempt)?, &mut || {
        base()?;
        registry.recheck()?;
        configured.recheck()?;
        mask.recheck()?;
        for entry in entries.borrow().values() {
            entry.recheck(&mut || base())?;
        }
        for loader in loaders.borrow().values() {
            loader.recheck(&mut || base())?;
        }
        require(
            files::directory_names(&directory, 128)? == names,
            "entry namespace changed during completion",
        )
    })?;
    receipt.recheck()?;
    configured.recheck()?;
    require(
        files::directory_names(&directory, 128)? == names,
        "entry namespace changed before completed policy receipt",
    )?;
    base()?;
    mask.recheck()?;
    for entry in entries.borrow().values() {
        entry.recheck(&mut || base())?;
    }
    for loader in loaders.borrow().values() {
        loader.recheck(&mut || base())?;
    }
    registry.recheck()?;
    Ok(
        value!({"status":"signed-owner-boot-prepared","firmware_changed":false,"certificate":format!("{}/owner.cer",secure_boot::DIRECTORY)}),
    )
}
