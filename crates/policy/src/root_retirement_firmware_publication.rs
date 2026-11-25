// SPDX-License-Identifier: MIT
//! Original EFI variables and one actual exclusive Rust kernel publication.
//! Only kernel descriptors retained before mutation can supply this observer.
use crate::storage_runtime::Guard;
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
#[path = "root_retirement_finish_firmware.rs"]
pub mod finish;
const EFI: &str = crate::recovery_activation_runtime::EFI;
const GUID: &str = crate::recovery_activation_runtime::GUID;
// Linux UAPI linux/magic.h EFIVARFS_MAGIC, observed in the installed header.
const EFIVARFS: i64 = 0xde5e81e4;
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original firmware read-only description required",
    )?;
    Ok(flags)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs, fstatvfs).")]
fn filesystem(file: &File) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } == 0,
        "original firmware filesystem unavailable",
    )?;
    let stat = unsafe { stat.assume_init() };
    require(stat.f_type == EFIVARFS, "actual efivarfs required")?;
    let mut options = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(
        unsafe { libc::fstatvfs(file.as_raw_fd(), options.as_mut_ptr()) } == 0,
        "original firmware mount options unavailable",
    )?;
    let options = unsafe { options.assume_init() };
    require(
        options.f_flag & libc::ST_RDONLY == 0,
        "actual writable efivarfs required",
    )
}
fn names(file: &File) -> Result<BTreeSet<String>> {
    files::directory_names(file, 4096)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| enzimos_platform::Error("firmware variable name encoding".into()))?;
            require(
                !name.is_empty()
                    && name.len() <= 255
                    && name != "."
                    && name != ".."
                    && !name.contains(['/', '\\', '\0'])
                    && !name.chars().any(char::is_control),
                "firmware variable basename",
            )?;
            Ok(name)
        })
        .collect()
}
fn loader_namespace(members: &BTreeSet<String>, one_shot: bool) -> Result<()> {
    let suffix = format!("-{GUID}");
    let mut count = 0;
    for name in members
        .iter()
        .filter(|name| name.starts_with("LoaderEntry") && name.ends_with(&suffix))
    {
        count += 1;
        let key = name.strip_suffix(&suffix).unwrap();
        require(
            count <= 64
                && (matches!(key, "LoaderEntrySelected" | "LoaderEntryLastBooted")
                    || one_shot && key == "LoaderEntryOneShot"),
            "unknown or preexisting EFI selection override requires review",
        )?;
    }
    Ok(())
}
struct Variable {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    bytes: Vec<u8>,
}
impl Variable {
    fn observe(parent: &File, leaf: &str, mount: u64) -> Result<Self> {
        let file = files::open_relative(parent, Path::new(leaf))?;
        require(
            file.metadata()?.gid() == 0 && mount_identity::id(file.as_fd(), true)? == mount,
            "original kernel firmware variable mount/owner",
        )?;
        let epoch = files::identity(&file.metadata()?);
        let flags = flags(&file)?;
        let bytes = files::read_file(&file, 8192, Some(0), true)?;
        crate::boot_entries::efi_string(&bytes)?;
        let result = Self {
            file,
            epoch,
            flags,
            bytes,
        };
        result.recheck(parent, leaf, mount)?;
        Ok(result)
    }
    fn recheck(&self, parent: &File, leaf: &str, mount: u64) -> Result<()> {
        let named = files::open_relative(parent, Path::new(leaf))?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.file)? == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == mount
                && mount_identity::id(named.as_fd(), true)? == mount
                && files::read_file(&self.file, 8192, Some(0), true)? == self.bytes,
            "original firmware variable changed/replaced/covered",
        )
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn metadata_member(parent: &File, leaf: &str) -> Result<File> {
    let name = std::ffi::CString::new(leaf)
        .map_err(|_| enzimos_platform::Error("firmware member basename encoding".into()))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, "original firmware metadata member unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
struct Member {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
}
impl Member {
    fn observe(parent: &File, leaf: &str, mount: u64) -> Result<Self> {
        let file = metadata_member(parent, leaf)?;
        let metadata = file.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.nlink() == 1
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original firmware member protection/mount",
        )?;
        let result = Self {
            epoch: files::identity(&metadata),
            flags: flags(&file)?,
            file,
        };
        result.recheck(parent, leaf, mount)?;
        Ok(result)
    }
    fn recheck(&self, parent: &File, leaf: &str, mount: u64) -> Result<()> {
        let named = metadata_member(parent, leaf)?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.file)? == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == mount
                && mount_identity::id(named.as_fd(), true)? == mount,
            "unrelated original firmware member changed/replaced/covered",
        )
    }
}
pub struct Original<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    directory: File,
    epoch: files::FileIdentity,
    directory_flags: i32,
    mount: u64,
    members: BTreeSet<String>,
    variables: BTreeMap<String, Variable>,
    other_members: BTreeMap<String, Member>,
    state: Value,
}
impl<'a> Original<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        require(
            crate::recovery_activation_runtime::efi_guard()?,
            "actual EFI firmware required for one-shot mode",
        )?;
        let directory = files::directory(Path::new(EFI), Some(0))?;
        require(
            directory.metadata()?.gid() == 0,
            "original firmware directory group",
        )?;
        filesystem(&directory)?;
        let epoch = files::identity(&directory.metadata()?);
        let directory_flags = flags(&directory)?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let members = names(&directory)?;
        require(
            members.len() < 4096,
            "firmware namespace has no selection headroom",
        )?;
        loader_namespace(&members, false)?;
        let mut variables = BTreeMap::new();
        let mut values = json!({});
        for key in ["LoaderEntrySelected", "LoaderEntryLastBooted"] {
            let leaf = format!("{key}-{GUID}");
            if members.contains(&leaf) {
                let variable = Variable::observe(&directory, &leaf, mount)?;
                values[key] = json!(crate::boot_entries::efi_string(&variable.bytes)?);
                variables.insert(leaf, variable);
            }
        }
        let mut other_members = BTreeMap::new();
        for leaf in members.iter().filter(|leaf| !variables.contains_key(*leaf)) {
            other_members.insert(leaf.clone(), Member::observe(&directory, leaf, mount)?);
            authorize()?;
        }
        let result = Self {
            guard,
            lock,
            directory,
            epoch,
            directory_flags,
            mount,
            members,
            variables,
            other_members,
            state: json!({"observable":true,"variables":values}),
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    fn source_barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        let named = files::directory(Path::new(EFI), Some(0))?;
        let a = self.directory.metadata()?;
        let b = named.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode(), a.uid(), a.gid(), a.nlink())
                == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid(), b.nlink())
                && (a.dev(), a.ino(), a.mode(), a.uid(), a.gid(), a.nlink())
                    == (
                        self.epoch.0,
                        self.epoch.1,
                        self.epoch.7,
                        self.epoch.8,
                        self.epoch.9,
                        self.epoch.10,
                    )
                && flags(&self.directory)? == self.directory_flags
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original firmware directory changed/replaced/covered",
        )?;
        filesystem(&self.directory)?;
        for (leaf, member) in &self.other_members {
            member.recheck(&self.directory, leaf, self.mount)?;
            authorize()?;
        }
        for (leaf, variable) in &self.variables {
            variable.recheck(&self.directory, leaf, self.mount)?;
            authorize()?;
        }
        authorize()
    }
    pub(crate) fn require_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "firmware observer belongs to another actual original source",
        )?;
        self.recheck(authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.source_barrier(authorize)?;
        let named = files::directory(Path::new(EFI), Some(0))?;
        require(
            files::identity(&self.directory.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && names(&self.directory)? == self.members,
            "original firmware namespace epoch/membership changed",
        )?;
        loader_namespace(&self.members, false)?;
        self.source_barrier(authorize)
    }
    /// One exclusive kernel write from this original namespace and actual BIOS
    /// producer. Uncertain errors leave firmware state and receipt untouched.
    pub fn select(
        self,
        bios: crate::root_retirement_loader_publication::CommittedBios<'a>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>> {
        self.recheck(authorize)?;
        let entry = bios
            .require_firmware_source(self.guard, self.lock, authorize)?
            .to_owned();
        let expected = one_shot_bytes(&entry)?;
        let leaf = format!("LoaderEntryOneShot-{GUID}");
        // This actual exclusive descriptor precedes the sole kernel write.
        let created = Created::new(&self.directory, &leaf)?;
        self.source_barrier(authorize)?;
        let mut expected_members = self.members.clone();
        expected_members.insert(leaf.clone());
        require(
            names(&self.directory)? == expected_members,
            "firmware namespace differs after actual exclusive creation",
        )?;
        bios.recheck(authorize)?;
        created.recheck()?;
        self.source_barrier(authorize)?;
        let written = created.write(&expected)?;
        self.source_barrier(authorize)?;
        let variable = Variable {
            file: written.created.reader.try_clone()?,
            epoch: written.epoch,
            flags: written.created.reader_flags,
            bytes: expected,
        };
        variable.recheck(&self.directory, &leaf, self.mount)?;
        let epoch = files::identity(&self.directory.metadata()?);
        let published = Published {
            original: self,
            bios,
            variable,
            written,
            epoch,
            leaf,
            entry,
        };
        published.recheck(authorize)?;
        published
            .bios
            .recheck_firmware_publication(&published, authorize)?;
        Ok(published)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"firmware":self.state,"directory_epoch":self.epoch,"directory_flags":self.directory_flags,
            "mount":self.mount,"members":self.members,"unrelated_retained_members":self.other_members.len(),"execution_authorized":false}),
        )
    }
}
fn status(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(value >= 0, "firmware writer description unavailable")?;
    Ok(value)
}
fn same_file(before: files::FileIdentity, after: files::FileIdentity) -> bool {
    (before.0, before.1, before.7, before.8, before.9, before.10)
        == (after.0, after.1, after.7, after.8, after.9, after.10)
}
/// Private exclusive creator, retaining reader and writer before mutation.
/// Kernel empty-node cleanup on last close is a kernel outcome, never replay or
/// an application unlink/rollback. The durable Root coordinator receipt remains.
struct Created {
    parent: File,
    parent_epoch: files::FileIdentity,
    parent_flags: i32,
    leaf: String,
    writer: File,
    writer_flags: i32,
    reader: File,
    reader_flags: i32,
    before: files::FileIdentity,
    mount: u64,
    owner: u32,
}
impl Created {
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn new(parent: &File, leaf: &str) -> Result<Self> {
        require(
            leaf == format!("LoaderEntryOneShot-{GUID}"),
            "fixed firmware selection leaf required",
        )?;
        let metadata = parent.metadata()?;
        let owner = metadata.uid();
        require(
            metadata.is_dir()
                && metadata.mode() & 0o022 == 0
                && enzimos_platform::process_identity::effective_uid() == owner,
            "firmware creation parent owner/mode",
        )?;
        let parent = parent.try_clone()?;
        let parent_flags = flags(&parent)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let name = std::ffi::CString::new(leaf).unwrap();
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(
            fd >= 0,
            "firmware exclusive creation refused; no adoption or replay",
        )?;
        let writer = unsafe { File::from_raw_fd(fd) };
        let writer_flags = status(&writer)?;
        let before = files::identity(&writer.metadata()?);
        let reader = files::open_relative(&parent, Path::new(leaf))?;
        let reader_flags = flags(&reader)?;
        let parent_epoch = files::identity(&parent.metadata()?);
        require(
            same_file(files::identity(&metadata), parent_epoch),
            "firmware exclusive creation changed parent identity/protection",
        )?;
        let result = Self {
            parent,
            parent_epoch,
            parent_flags,
            leaf: leaf.into(),
            writer,
            writer_flags,
            reader,
            reader_flags,
            before,
            mount,
            owner,
        };
        result.recheck()?;
        Ok(result)
    }
    fn parent(&self) -> Result<()> {
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch
                && flags(&self.parent)? == self.parent_flags
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && enzimos_platform::process_identity::effective_uid() == self.owner,
            "actual exclusive firmware parent changed/covered",
        )
    }
    fn recheck(&self) -> Result<()> {
        self.parent()?;
        let named = files::open_relative(&self.parent, Path::new(&self.leaf))?;
        let m = self.writer.metadata()?;
        require(
            files::identity(&m) == self.before
                && m.is_file()
                && m.len() == 0
                && m.uid() == self.owner
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && files::identity(&self.reader.metadata()?) == self.before
                && files::identity(&named.metadata()?) == self.before
                && status(&self.writer)? == self.writer_flags
                && self.writer_flags & libc::O_ACCMODE == libc::O_WRONLY
                && flags(&self.reader)? == self.reader_flags
                && mount_identity::id(self.writer.as_fd(), true)? == self.mount
                && mount_identity::id(self.reader.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "actual exclusive empty firmware descriptors changed/replaced/covered",
        )?;
        self.parent()
    }
    /// Exactly one syscall; partial errors/EINTR cannot retry or construct output.
    #[allow(unsafe_code, reason = "Linux syscall ABI (write).")]
    fn write(self, bytes: &[u8]) -> Result<Written> {
        require(
            bytes.len() > 4 && bytes.len() <= 8192,
            "single firmware write bound",
        )?;
        self.recheck()?;
        let count =
            unsafe { libc::write(self.writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        require(
            count == bytes.len() as isize,
            "single firmware write failed or uncertain; no replay",
        )?;
        let epoch = files::identity(&self.writer.metadata()?);
        require(
            same_file(self.before, epoch) && epoch.2 == bytes.len() as u64,
            "single owned firmware write changed identity/protection or size",
        )?;
        let result = Written {
            created: self,
            epoch,
        };
        result.recheck(bytes)?;
        Ok(result)
    }
}
struct Written {
    created: Created,
    epoch: files::FileIdentity,
}
impl Written {
    fn recheck(&self, bytes: &[u8]) -> Result<()> {
        let c = &self.created;
        c.parent()?;
        let named = files::open_relative(&c.parent, Path::new(&c.leaf))?;
        require(
            files::identity(&c.writer.metadata()?) == self.epoch
                && files::identity(&c.reader.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && status(&c.writer)? == c.writer_flags
                && flags(&c.reader)? == c.reader_flags
                && mount_identity::id(c.writer.as_fd(), true)? == c.mount
                && mount_identity::id(c.reader.as_fd(), true)? == c.mount
                && mount_identity::id(named.as_fd(), true)? == c.mount
                && files::read_file(&c.reader, 8192, Some(c.owner), true)? == bytes,
            "actual firmware writer/readback changed/replaced/covered",
        )?;
        c.parent()
    }
}

fn one_shot_bytes(entry: &str) -> Result<Vec<u8>> {
    crate::recovery_records::literal_entry(entry)?;
    // systemd basic/efivars.c: NV|BOOTSERVICE_ACCESS|RUNTIME_ACCESS.
    let mut bytes = 7u32.to_le_bytes().to_vec();
    for word in entry.encode_utf16().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    require(bytes.len() <= 8192, "firmware selection byte bound")?;
    Ok(bytes)
}
/// Actual completed one-shot write retains all original firmware descriptions.
/// Existing variables and decoded status cannot construct this actor.
pub struct Published<'a> {
    original: Original<'a>,
    bios: crate::root_retirement_loader_publication::CommittedBios<'a>,
    variable: Variable,
    written: Written,
    epoch: files::FileIdentity,
    leaf: String,
    entry: String,
}
impl Published<'_> {
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.written.recheck(&self.variable.bytes)?;
        self.original.source_barrier(authorize)?;
        self.bios.recheck(authorize)?;
        let named = files::directory(Path::new(EFI), Some(0))?;
        let mut expected = self.original.members.clone();
        expected.insert(self.leaf.clone());
        require(
            files::identity(&self.original.directory.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && names(&self.original.directory)? == expected,
            "actual one-shot firmware namespace changed/replaced/covered",
        )?;
        loader_namespace(&expected, true)?;
        self.variable
            .recheck(&self.original.directory, &self.leaf, self.original.mount)?;
        require(
            self.variable.bytes == one_shot_bytes(&self.entry)?,
            "actual one-shot firmware attributes/value changed",
        )?;
        self.original.source_barrier(authorize)
    }
    pub(crate) fn bios(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&crate::root_retirement_loader_publication::CommittedBios<'_>> {
        self.recheck(authorize)?;
        Ok(&self.bios)
    }
    pub(crate) fn require_original(
        &self,
        state: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            self.original.state == *state,
            "one-shot producer differs from independently original boot firmware",
        )?;
        self.recheck(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.entry,"original_firmware":self.original.state,
            "directory_epoch":self.epoch,"variable_epoch":self.variable.epoch,
            "variable_flags":self.variable.flags,"attributes":7,"one_shot_selected":true,
            "execution_authorized":false}),
        )
    }
}
