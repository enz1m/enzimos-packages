// SPDX-License-Identifier: MIT
//! Original fixed loader/default files for one native Root staging publication.
//! No decoded state creates this observer or grants a filesystem mutation.
use crate::{
    boot_volume::{Artifact, Volume},
    root_retirement_online_journal::Published as Receipt,
    root_retirement_online_stage_targets::Protected,
    root_retirement_signed_namespace::{Published as Signer, State as SignState},
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn flags(file: &File) -> Result<i32> {
    let value = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original Root loader read-only description required",
    )?;
    Ok(value)
}
fn names(folder: &File) -> Result<BTreeSet<String>> {
    files::directory_names(folder, 126)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| enzimos_platform::Error("Root loader member encoding".into()))?;
            crate::identity::safe_id(&name)?;
            Ok(name)
        })
        .collect()
}
struct DefaultDirectory {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    members: BTreeSet<String>,
}
impl DefaultDirectory {
    fn recheck(&self, volume: &Volume, path: &str) -> Result<()> {
        let named = volume.directory(Path::new(path))?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.file)? == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == volume.unique
                && mount_identity::id(named.as_fd(), true)? == volume.unique
                && names(&self.file)? == self.members,
            "original Root default directory changed/replaced/covered",
        )
    }
}
pub struct Original<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    receipt: &'a Receipt<'a>,
    signer: &'a Signer<'a>,
    protected: &'a Protected<'a>,
    volume: Volume,
    directory: File,
    epoch: files::FileIdentity,
    directory_flags: i32,
    members: BTreeSet<String>,
    defaults: BTreeMap<String, (Artifact, i32, String)>,
    default_directories: BTreeMap<String, DefaultDirectory>,
    entry: String,
    next_bios: String,
    next_defaults: String,
}
impl<'a> Original<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        receipt: &'a Receipt<'a>,
        signer: &'a Signer<'a>,
        protected: &'a Protected<'a>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        receipt.require_source(guard, lock)?;
        protected.recheck_signing(receipt, &SignState::Published(signer), authorize)?;
        let record = receipt.record()?;
        require(
            record["schema"] == 2
                && record["phase"] == "prepared"
                && record["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "original staged Root receipt/source differs",
        )?;
        let coordinator = &record["coordinator"];
        let options = crate::recovery_records::text(coordinator, "options")?;
        let parameters = crate::root_retirement_parameters::Parameters::parse(options)?;
        parameters.matches_record(record)?;
        let volume = Volume::observe()?;
        volume.writable()?;
        require(
            parameters.esp == volume.uuid
                && parameters.control
                    == crate::recovery_records::text(&guard.configuration, "control_subvol")?,
            "staged coordinator belongs to another actual ESP/control",
        )?;
        let entries = crate::root_retirement_boot_contract::entries(
            options,
            crate::recovery_records::text(coordinator, "image")?,
        )?;
        signer.require_original_entry(&entries.uefi, authorize)?;
        let entry = crate::recovery_records::text(coordinator, "uefi_entry")?.to_owned();
        let directory = volume.directory(Path::new("loader/entries"))?;
        let epoch = files::identity(&directory.metadata()?);
        let directory_flags = flags(&directory)?;
        require(
            directory.metadata()?.gid() == 0 && directory.metadata()?.mode() & 0o022 == 0,
            "original Root loader directory protection",
        )?;
        let members = names(&directory)?;
        require(
            members.len() < 126 && !members.contains(&entry),
            "Root loader publication cannot adopt existing or overfull entry",
        )?;
        let mut default_directories = BTreeMap::new();
        for path in ["loader", "limine"] {
            let file = volume.directory(Path::new(path))?;
            require(
                file.metadata()?.gid() == 0 && file.metadata()?.mode() & 0o022 == 0,
                "original Root default directory protection",
            )?;
            let members = names(&file)?;
            require(
                members.len() < 126,
                "Root default directory has no publication headroom",
            )?;
            default_directories.insert(
                path.into(),
                DefaultDirectory {
                    epoch: files::identity(&file.metadata()?),
                    flags: flags(&file)?,
                    file,
                    members,
                },
            );
        }
        let mut defaults = BTreeMap::new();
        for name in ["loader/loader.conf", "limine/limine.conf"] {
            let artifact =
                volume.artifact(Path::new(name), crate::boot_entries::MAX_TEXT as u64)?;
            let bytes =
                files::read_file(&artifact.file, crate::boot_entries::MAX_TEXT, Some(0), true)?;
            let text = String::from_utf8(bytes)
                .map_err(|_| enzimos_platform::Error("Root default file encoding".into()))?;
            let original_flags = flags(&artifact.file)?;
            defaults.insert(name.into(), (artifact, original_flags, text));
        }
        let loader = &defaults["loader/loader.conf"].2;
        require(
            crate::boot_entries::fields(loader, false)?.get("default")
                == Some(&parameters.uefi_previous),
            "Root loader previous default changed before publication",
        )?;
        let bios = &defaults["limine/limine.conf"].2;
        let menu = crate::boot_entries::menu(bios)?;
        require(
            menu.selected == parameters.bios_previous
                && menu.entries.len() + 1 == parameters.bios_own
                && menu
                    .entries
                    .iter()
                    .all(|item| item.title != coordinator["bios_title"]),
            "Root BIOS previous default/entry inventory changed before publication",
        )?;
        let next_bios = crate::recovery_boot::replace_default(
            &format!("{}\n{}", bios.trim_end(), entries.bios),
            "default_entry: ",
            &parameters.bios_own.to_string(),
        )?;
        let next_defaults = if coordinator["uefi_mode"] == "default" {
            crate::recovery_boot::replace_default(loader, "default ", &entry)?
        } else {
            loader.clone()
        };
        let restored = crate::root_retirement_boot_contract::restore(
            record,
            &next_defaults,
            &next_bios,
            signer.entry(authorize)?,
        )?;
        require(
            restored.defaults == *loader
                && crate::boot_entries::menu(&restored.bios)?.selected == menu.selected,
            "actual signed Root entry cannot restore original defaults",
        )?;
        let this = Self {
            guard,
            lock,
            receipt,
            signer,
            protected,
            volume,
            directory,
            epoch,
            directory_flags,
            members,
            defaults,
            default_directories,
            entry,
            next_bios,
            next_defaults,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_default_directories()?;
        self.receipt.require_source(self.guard, self.lock)?;
        self.protected.recheck_signing(
            self.receipt,
            &SignState::Published(self.signer),
            authorize,
        )?;
        self.volume.writable()?;
        let named = self.volume.directory(Path::new("loader/entries"))?;
        require(
            files::identity(&self.directory.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.directory)? == self.directory_flags
                && mount_identity::id(self.directory.as_fd(), true)? == self.volume.unique
                && mount_identity::id(named.as_fd(), true)? == self.volume.unique
                && names(&self.directory)? == self.members
                && files::optional_relative(&self.directory, Path::new(&self.entry))?.is_none(),
            "original Root loader directory changed/replaced/covered",
        )?;
        for (artifact, original_flags, text) in self.defaults.values() {
            require(
                flags(&artifact.file)? == *original_flags,
                "original Root default description flags changed",
            )?;
            artifact.recheck()?;
            require(
                files::read_file(&artifact.file, crate::boot_entries::MAX_TEXT, Some(0), true)?
                    == text.as_bytes(),
                "original Root default bytes changed",
            )?;
            authorize()?;
        }
        self.protected.recheck_signing(
            self.receipt,
            &SignState::Published(self.signer),
            authorize,
        )?;
        self.receipt.recheck()
    }
    /// Consume one original observation into exactly one pending entry write.
    /// The durable staged receipt already exists. Errors preserve pending bytes
    /// and have no retry, adoption, unlink or rollback.
    pub fn prepare_entry(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PendingEntry<'a>> {
        self.recheck(authorize)?;
        let body = self.signer.entry(authorize)?.as_bytes().to_vec();
        require(
            body.len() <= crate::boot_entries::MAX_TEXT,
            "Root coordinator entry byte bound",
        )?;
        let path = self
            .volume
            .path(Path::new(&format!("loader/entries/{}", self.entry)))?;
        let prepared = enzimos_platform::publication::Prepared::write_authorized(
            &path,
            &body,
            0,
            &mut || self.source_barrier(authorize),
        )?;
        prepared.require_new_destination(&self.directory, Path::new(&self.entry))?;
        let epoch = files::identity(&self.directory.metadata()?);
        require(
            same_directory(self.epoch, epoch),
            "owned pending entry changed original directory identity/protection",
        )?;
        let result = PendingEntry {
            original: self,
            prepared,
            epoch,
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    fn recheck_default_directories(&self) -> Result<()> {
        for (path, directory) in &self.default_directories {
            directory.recheck(&self.volume, path)?;
        }
        Ok(())
    }
    fn source_barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.source_barrier_with(None, None, authorize)
    }
    fn source_barrier_with(
        &self,
        bios: Option<&enzimos_platform::publication::Committed>,
        loader: Option<&enzimos_platform::publication::Committed>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.receipt.require_source(self.guard, self.lock)?;
        self.signer.recheck(authorize)?;
        self.volume.writable()?;
        for (name, (artifact, original_flags, _)) in &self.defaults {
            require(
                flags(&artifact.file)? == *original_flags,
                "original Root default description changed",
            )?;
            if name == "limine/limine.conf"
                && let Some(bios) = bios
            {
                artifact.require_owned_replacement(bios)?;
                continue;
            }
            if name == "loader/loader.conf"
                && let Some(loader) = loader
            {
                artifact.require_owned_replacement(loader)?;
                continue;
            }
            artifact.recheck()?;
        }
        authorize()
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.entry,"directory_epoch":self.epoch,"directory_flags":self.directory_flags,
            "members":self.members,"next_bios_sha256":enzimos_platform::json::sha256(self.next_bios.as_bytes()),
            "next_defaults_sha256":enzimos_platform::json::sha256(self.next_defaults.as_bytes()),
            "defaults":self.defaults.iter().map(|(name,(a,f,_))| (name.clone(),json!({"sha256":a.sha,"bytes":a.bytes,"flags":f}))).collect::<BTreeMap<_,_>>(),
            "execution_authorized":false}),
        )
    }
}

fn same_directory(before: files::FileIdentity, after: files::FileIdentity) -> bool {
    (before.0, before.1, before.7, before.8, before.9, before.10)
        == (after.0, after.1, after.7, after.8, after.9, after.10)
}
/// Actual pending entry bytes; no decoded or named file constructs this actor.
pub struct PendingEntry<'a> {
    original: Original<'a>,
    prepared: enzimos_platform::publication::Prepared,
    epoch: files::FileIdentity,
}
impl<'a> PendingEntry<'a> {
    pub(crate) fn require_frame(
        &self,
        receipt: &Receipt<'_>,
        signer: &Signer<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.original.receipt, receipt)
                && std::ptr::eq(self.original.signer, signer),
            "pending Root entry belongs to another actual receipt/signer producer",
        )?;
        self.recheck(authorize)
    }
    pub(crate) fn require_original_directory(
        &self,
        parent: &File,
        original: (files::FileIdentity, i32),
        members: &BTreeSet<String>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            (self.original.epoch, self.original.directory_flags) == original
                && &self.original.members == members
                && files::identity(&parent.metadata()?) == self.epoch
                && flags(parent)? == original.1
                && mount_identity::id(parent.as_fd(), true)? == self.original.volume.unique,
            "pending Root entry differs from independently original loader directory",
        )?;
        self.recheck(authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.original.recheck_default_directories()?;
        self.original.source_barrier(authorize)?;
        self.prepared
            .require_new_destination(&self.original.directory, Path::new(&self.original.entry))?;
        let named = self
            .original
            .volume
            .directory(Path::new("loader/entries"))?;
        let mut expected = self.original.members.clone();
        expected.insert(format!("{}.new", self.original.entry));
        require(
            files::identity(&self.original.directory.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.original.directory)? == self.original.directory_flags
                && mount_identity::id(named.as_fd(), true)? == self.original.volume.unique
                && mount_identity::id(self.original.directory.as_fd(), true)?
                    == self.original.volume.unique
                && names(&self.original.directory)? == expected,
            "actual pending Root entry directory changed/replaced/covered",
        )?;
        self.prepared.recheck()?;
        self.original.source_barrier(authorize)
    }
    /// One retained no-replace commit. The full independent boot/target
    /// protection is checked before this consuming attempt; uncertain errors
    /// preserve the staged receipt and pending evidence without replay.
    pub fn commit(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<CommittedEntry<'a>>
    where
        Self: Sized,
    {
        self.recheck(authorize)?;
        self.original.protected.recheck_pending_entry(
            self.original.receipt,
            self.original.signer,
            &self,
            authorize,
        )?;
        let original = self.original;
        let committed = self
            .prepared
            .commit_retained_authorized(false, &mut || original.source_barrier(authorize))?;
        committed.require_destination(&original.directory, Path::new(&original.entry))?;
        let epoch = files::identity(&original.directory.metadata()?);
        require(
            same_directory(original.epoch, epoch),
            "owned entry commit changed original directory identity/protection",
        )?;
        let result = CommittedEntry {
            original,
            committed,
            epoch,
        };
        result.recheck(authorize)?;
        result.original.protected.recheck_committed_entry(
            result.original.receipt,
            result.original.signer,
            &result,
            authorize,
        )?;
        Ok(result)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.original.entry,"original_directory_epoch":self.original.epoch,
            "pending_directory_epoch":self.epoch,"original_members":self.original.members,
            "execution_authorized":false,"entry_committed":false}),
        )
    }
}

/// Actual committed UEFI entry retains its original observation and publication.
/// No existing path or decoded completion constructs this actor.
pub struct CommittedEntry<'a> {
    original: Original<'a>,
    committed: enzimos_platform::publication::Committed,
    epoch: files::FileIdentity,
}
impl<'a> CommittedEntry<'a> {
    fn require_frame(
        &self,
        receipt: &Receipt<'_>,
        signer: &Signer<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.original.receipt, receipt)
                && std::ptr::eq(self.original.signer, signer),
            "committed Root entry belongs to another actual receipt/signer producer",
        )?;
        self.recheck(authorize)
    }
    fn require_original_directory(
        &self,
        parent: &File,
        original: (files::FileIdentity, i32),
        members: &BTreeSet<String>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            (self.original.epoch, self.original.directory_flags) == original
                && &self.original.members == members
                && files::identity(&parent.metadata()?) == self.epoch
                && flags(parent)? == original.1
                && mount_identity::id(parent.as_fd(), true)? == self.original.volume.unique,
            "committed Root entry differs from independently original directory",
        )?;
        self.recheck(authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.original.recheck_default_directories()?;
        self.recheck_body(authorize)
    }
    fn recheck_body(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_body_with(None, None, authorize)
    }
    fn recheck_body_with(
        &self,
        bios: Option<&enzimos_platform::publication::Committed>,
        loader: Option<&enzimos_platform::publication::Committed>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.source_barrier_with(bios, loader, authorize)?;
        self.committed
            .require_destination(&self.original.directory, Path::new(&self.original.entry))?;
        let named = self
            .original
            .volume
            .directory(Path::new("loader/entries"))?;
        let mut expected = self.original.members.clone();
        expected.insert(self.original.entry.clone());
        require(
            files::identity(&self.original.directory.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.original.directory)? == self.original.directory_flags
                && mount_identity::id(named.as_fd(), true)? == self.original.volume.unique
                && mount_identity::id(self.original.directory.as_fd(), true)?
                    == self.original.volume.unique
                && names(&self.original.directory)? == expected,
            "actual committed Root entry directory changed/replaced/covered",
        )?;
        require(
            files::read_file(
                self.committed.file()?,
                crate::boot_entries::MAX_TEXT,
                Some(0),
                true,
            )? == self.original.signer.entry(authorize)?.as_bytes(),
            "actual committed Root entry differs from retained original signer",
        )?;
        self.committed.recheck()?;
        self.original.source_barrier_with(bios, loader, authorize)
    }
    /// Create exactly one pending BIOS selection from the retained original file.
    /// No retry/adoption or rollback is available after this consuming attempt.
    pub fn prepare_bios(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PendingBios<'a>> {
        self.recheck(authorize)?;
        self.original.protected.recheck_committed_entry(
            self.original.receipt,
            self.original.signer,
            &self,
            authorize,
        )?;
        let path = self.original.volume.path(Path::new("limine/limine.conf"))?;
        let prepared = enzimos_platform::publication::Prepared::write_authorized(
            &path,
            self.original.next_bios.as_bytes(),
            0,
            &mut || self.recheck_body(authorize),
        )?;
        self.original.defaults["limine/limine.conf"].0.recheck()?;
        self.original.defaults["limine/limine.conf"]
            .0
            .require_original_publication(&prepared)?;
        let directory = &self.original.default_directories["limine"];
        let epoch = files::identity(&directory.file.metadata()?);
        require(
            same_directory(directory.epoch, epoch),
            "owned pending BIOS changed original directory identity/protection",
        )?;
        let result = PendingBios {
            entry: self,
            prepared,
            epoch,
        };
        result.recheck(authorize)?;
        result.entry.original.protected.recheck_pending_bios(
            result.entry.original.receipt,
            result.entry.original.signer,
            &result,
            authorize,
        )?;
        Ok(result)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.original.entry,"original_directory_epoch":self.original.epoch,
            "committed_directory_epoch":self.epoch,"original_members":self.original.members,
            "entry_sha256":enzimos_platform::json::sha256(&files::read_file(self.committed.file()?,
                crate::boot_entries::MAX_TEXT, Some(0), true)?),"execution_authorized":false}),
        )
    }
}

/// Retained actual pending BIOS write, tied to the consumed committed entry.
pub struct PendingBios<'a> {
    entry: CommittedEntry<'a>,
    prepared: enzimos_platform::publication::Prepared,
    epoch: files::FileIdentity,
}

/// Actual BIOS replacement and independently original entry/default inventory.
pub struct CommittedBios<'a> {
    entry: CommittedEntry<'a>,
    committed: enzimos_platform::publication::Committed,
    epoch: files::FileIdentity,
}

/// Actual pending UEFI default, retaining the original BIOS/entry producers.
pub struct PendingDefaults<'a> {
    bios: CommittedBios<'a>,
    prepared: enzimos_platform::publication::Prepared,
    epoch: files::FileIdentity,
}
impl<'a> PendingDefaults<'a> {
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.bios.recheck_body(None, authorize)?;
        let original = &self.bios.entry.original;
        let directory = &original.default_directories["loader"];
        let named = original.volume.directory(Path::new("loader"))?;
        let mut expected = directory.members.clone();
        expected.insert("loader.conf.new".into());
        require(
            files::identity(&directory.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&directory.file)? == directory.flags
                && mount_identity::id(directory.file.as_fd(), true)? == original.volume.unique
                && mount_identity::id(named.as_fd(), true)? == original.volume.unique
                && names(&directory.file)? == expected,
            "actual pending UEFI default directory changed/replaced/covered",
        )?;
        original.defaults["loader/loader.conf"]
            .0
            .require_original_publication(&self.prepared)?;
        self.bios.recheck_body(None, authorize)
    }
    pub fn commit(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<CommittedDefaults<'a>> {
        self.recheck(authorize)?;
        let original = &self.bios.entry.original;
        original.protected.recheck_pending_defaults(
            original.receipt,
            original.signer,
            &self,
            authorize,
        )?;
        let bios = self.bios;
        let authorization = std::cell::RefCell::new(authorize);
        let committed = self.prepared.commit_checked(
            true,
            &mut || bios.recheck_body(None, &mut **authorization.borrow_mut()),
            &mut |actual| bios.recheck_body(Some(actual), &mut **authorization.borrow_mut()),
        )?;
        let directory = &bios.entry.original.default_directories["loader"];
        let epoch = files::identity(&directory.file.metadata()?);
        require(
            same_directory(directory.epoch, epoch),
            "owned UEFI default commit changed original directory identity/protection",
        )?;
        let result = CommittedDefaults {
            bios,
            committed,
            epoch,
        };
        result.recheck(&mut **authorization.borrow_mut())?;
        let original = &result.bios.entry.original;
        original.protected.recheck_committed_defaults(
            original.receipt,
            original.signer,
            &result,
            &mut **authorization.borrow_mut(),
        )?;
        Ok(result)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.bios.entry.original.entry,"loader_directory_epoch":self.epoch,
            "defaults_committed":false,"execution_authorized":false}),
        )
    }
}
/// Actual UEFI selection replacement; no decoded record constructs it.
pub struct CommittedDefaults<'a> {
    bios: CommittedBios<'a>,
    committed: enzimos_platform::publication::Committed,
    epoch: files::FileIdentity,
}
impl CommittedDefaults<'_> {
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.bios.recheck_body(Some(&self.committed), authorize)?;
        let original = &self.bios.entry.original;
        let directory = &original.default_directories["loader"];
        let named = original.volume.directory(Path::new("loader"))?;
        require(
            files::identity(&directory.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&directory.file)? == directory.flags
                && mount_identity::id(directory.file.as_fd(), true)? == original.volume.unique
                && mount_identity::id(named.as_fd(), true)? == original.volume.unique
                && names(&directory.file)? == directory.members,
            "actual committed UEFI default directory changed/replaced/covered",
        )?;
        self.committed
            .require_destination(&directory.file, Path::new("loader.conf"))?;
        require(
            files::read_file(
                self.committed.file()?,
                crate::boot_entries::MAX_TEXT,
                Some(0),
                true,
            )? == original.next_defaults.as_bytes(),
            "UEFI default bytes differ from original derived selection",
        )?;
        self.bios.recheck_body(Some(&self.committed), authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.bios.entry.original.entry,"loader_directory_epoch":self.epoch,
            "defaults_committed":true,"execution_authorized":false}),
        )
    }
}

/// Closed states of actual one-attempt loader publication, never decoded markers.
pub enum State<'b, 'a> {
    Pending(&'b PendingEntry<'a>),
    Committed(&'b CommittedEntry<'a>),
    BiosPending(&'b PendingBios<'a>),
    BiosCommitted(&'b CommittedBios<'a>),
    DefaultsPending(&'b PendingDefaults<'a>),
    DefaultsCommitted(&'b CommittedDefaults<'a>),
    OneShot(&'b crate::root_retirement_firmware_publication::Published<'a>),
}
impl State<'_, '_> {
    fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        match self {
            Self::Pending(actor) => actor.recheck(authorize),
            Self::Committed(actor) => actor.recheck(authorize),
            Self::BiosPending(actor) => actor.recheck(authorize),
            Self::BiosCommitted(actor) => actor.recheck(authorize),
            Self::DefaultsPending(actor) => actor.recheck(authorize),
            Self::DefaultsCommitted(actor) => actor.recheck(authorize),
            Self::OneShot(actor) => actor.recheck(authorize),
        }
    }
    pub(crate) fn require_original_artifact(
        &self,
        name: &str,
        artifact: &Artifact,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool> {
        let replacement = match self {
            Self::BiosCommitted(actor) if name == "limine/limine.conf" => Some(&actor.committed),
            Self::DefaultsPending(actor) if name == "limine/limine.conf" => {
                Some(&actor.bios.committed)
            }
            Self::DefaultsCommitted(actor) if name == "limine/limine.conf" => {
                Some(&actor.bios.committed)
            }
            Self::DefaultsCommitted(actor) if name == "loader/loader.conf" => {
                Some(&actor.committed)
            }
            Self::OneShot(actor) if name == "limine/limine.conf" => {
                Some(&actor.bios(authorize)?.committed)
            }
            _ => None,
        };
        if let Some(replacement) = replacement {
            self.recheck(authorize)?;
            artifact.require_owned_replacement(replacement)?;
            self.recheck(authorize)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn require_original_firmware(
        &self,
        original: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool> {
        if let Self::OneShot(actor) = self {
            actor.require_original(original, authorize)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(crate) fn require_frame(
        &self,
        receipt: &Receipt<'_>,
        signer: &Signer<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Pending(actor) => actor.require_frame(receipt, signer, authorize),
            Self::Committed(actor) => actor.require_frame(receipt, signer, authorize),
            Self::BiosPending(actor) => {
                require(
                    std::ptr::eq(actor.entry.original.receipt, receipt)
                        && std::ptr::eq(actor.entry.original.signer, signer),
                    "pending BIOS belongs to another actual receipt/signer",
                )?;
                actor.recheck(authorize)
            }
            Self::BiosCommitted(actor) => {
                require(
                    std::ptr::eq(actor.entry.original.receipt, receipt)
                        && std::ptr::eq(actor.entry.original.signer, signer),
                    "pending BIOS belongs to another actual receipt/signer",
                )?;
                actor.recheck(authorize)
            }
            Self::OneShot(actor) => {
                require(
                    std::ptr::eq(actor.bios(authorize)?.entry.original.receipt, receipt)
                        && std::ptr::eq(actor.bios(authorize)?.entry.original.signer, signer),
                    "pending BIOS belongs to another actual receipt/signer",
                )?;
                actor.recheck(authorize)
            }
            Self::DefaultsPending(actor) => {
                require(
                    std::ptr::eq(actor.bios.entry.original.receipt, receipt)
                        && std::ptr::eq(actor.bios.entry.original.signer, signer),
                    "pending BIOS belongs to another actual receipt/signer",
                )?;
                actor.recheck(authorize)
            }
            Self::DefaultsCommitted(actor) => {
                require(
                    std::ptr::eq(actor.bios.entry.original.receipt, receipt)
                        && std::ptr::eq(actor.bios.entry.original.signer, signer),
                    "pending BIOS belongs to another actual receipt/signer",
                )?;
                actor.recheck(authorize)
            }
        }
    }
    pub(crate) fn require_original_directory(
        &self,
        parent: &File,
        original: (files::FileIdentity, i32),
        members: &BTreeSet<String>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Pending(actor) => {
                actor.require_original_directory(parent, original, members, authorize)
            }
            Self::Committed(actor) => {
                actor.require_original_directory(parent, original, members, authorize)
            }
            Self::BiosPending(actor) => {
                actor.recheck(authorize)?;
                let entry = &actor.entry;
                require(
                    (entry.original.epoch, entry.original.directory_flags) == original
                        && &entry.original.members == members
                        && files::identity(&parent.metadata()?) == entry.epoch
                        && flags(parent)? == original.1
                        && mount_identity::id(parent.as_fd(), true)?
                            == entry.original.volume.unique,
                    "pending BIOS differs from independent original loader directory",
                )?;
                actor.recheck(authorize)
            }
            Self::BiosCommitted(actor) => {
                actor.recheck(authorize)?;
                let entry = &actor.entry;
                require(
                    (entry.original.epoch, entry.original.directory_flags) == original
                        && &entry.original.members == members
                        && files::identity(&parent.metadata()?) == entry.epoch
                        && flags(parent)? == original.1
                        && mount_identity::id(parent.as_fd(), true)?
                            == entry.original.volume.unique,
                    "pending BIOS differs from independent original loader directory",
                )?;
                actor.recheck(authorize)
            }
            Self::OneShot(actor) => {
                actor.recheck(authorize)?;
                let entry = &actor.bios(authorize)?.entry;
                require(
                    (entry.original.epoch, entry.original.directory_flags) == original
                        && &entry.original.members == members
                        && files::identity(&parent.metadata()?) == entry.epoch
                        && flags(parent)? == original.1
                        && mount_identity::id(parent.as_fd(), true)?
                            == entry.original.volume.unique,
                    "pending BIOS differs from independent original loader directory",
                )?;
                actor.recheck(authorize)
            }
            Self::DefaultsPending(actor) => {
                actor.recheck(authorize)?;
                let entry = &actor.bios.entry;
                require(
                    (entry.original.epoch, entry.original.directory_flags) == original
                        && &entry.original.members == members
                        && files::identity(&parent.metadata()?) == entry.epoch
                        && flags(parent)? == original.1
                        && mount_identity::id(parent.as_fd(), true)?
                            == entry.original.volume.unique,
                    "pending BIOS differs from independent original loader directory",
                )?;
                actor.recheck(authorize)
            }
            Self::DefaultsCommitted(actor) => {
                actor.recheck(authorize)?;
                let entry = &actor.bios.entry;
                require(
                    (entry.original.epoch, entry.original.directory_flags) == original
                        && &entry.original.members == members
                        && files::identity(&parent.metadata()?) == entry.epoch
                        && flags(parent)? == original.1
                        && mount_identity::id(parent.as_fd(), true)?
                            == entry.original.volume.unique,
                    "pending BIOS differs from independent original loader directory",
                )?;
                actor.recheck(authorize)
            }
        }
    }
}

mod bios;
