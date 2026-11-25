// SPDX-License-Identifier: MIT
//! A native libalpm transaction barrier never prepares or commits package changes.
use crate::{backup_attempt::Attempt, namespaces, operation};
use enzimos_platform::{
    Error, Result, directory_entry::Entry, files, json, mount_identity, require, stream_copy,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "original package capture directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
fn soname(name: &Path) -> Result<String> {
    let s = name
        .to_str()
        .ok_or_else(|| Error("ALPM image name encoding".into()))?;
    let version = s
        .strip_prefix("libalpm.so.")
        .ok_or_else(|| Error("fixed ALPM ABI image required".into()))?;
    let parts = version.split('.').collect::<Vec<_>>();
    require(
        parts.len() == 3
            && parts[0] == "16"
            && version.len() <= 24
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit())
                    && p.parse::<u32>().is_ok_and(|n| n.to_string() == *p)
            }),
        "qualified ALPM16 canonical image required",
    )?;
    Ok(version.into())
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (__errno_location, close, closedir, fcntl and others)."
)]
pub(crate) fn descriptors(directory: &File) -> Result<BTreeSet<i32>> {
    // procfs fd-directory size changes as descriptors open. Keep its stable
    // inode/owner/mode/mount, with a fresh cursor; ordinary directory scans keep
    // their stricter full metadata guarantee.
    let metadata = directory.metadata()?;
    let owner = enzimos_platform::process_identity::effective_uid();
    require(
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "original own-process descriptor directory required",
    )?;
    let shape_proc = |f: &File| -> Result<Shape> {
        let m = f.metadata()?;
        Ok((
            m.dev(),
            m.ino(),
            m.uid(),
            m.gid(),
            m.mode(),
            mount_identity::id(f.as_fd(), true)?,
        ))
    };
    let expected = shape_proc(directory)?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x9fa0,
        "actual procfs descriptor inventory required",
    )?;
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let cursor = unsafe { File::from_raw_fd(raw) };
    require(
        shape_proc(&cursor)? == expected,
        "procfs descriptor inventory changed",
    )?;
    let raw = cursor.into_raw_fd();
    let pointer = unsafe { libc::fdopendir(raw) };
    if pointer.is_null() {
        unsafe { libc::close(raw) };
        return Err(std::io::Error::last_os_error().into());
    }
    struct Cursor(*mut libc::DIR);
    impl Drop for Cursor {
        #[allow(unsafe_code, reason = "Linux syscall ABI (closedir).")]
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let cursor = Cursor(pointer);
    let mut names = Vec::new();
    let mut complete = false;
    for _ in 0..4099 {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(cursor.0) };
        if entry.is_null() {
            require(
                unsafe { *libc::__errno_location() } == 0,
                "procfs descriptor enumeration failed",
            )?;
            complete = true;
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        require(names.len() < 4096, "procfs descriptor inventory bound")?;
        let text = std::str::from_utf8(name)
            .map_err(|_| Error("package descriptor inventory encoding".into()))?;
        let fd = text
            .parse::<i32>()
            .map_err(|_| Error("package descriptor inventory number".into()))?;
        require(
            (0..1_048_576).contains(&fd) && fd.to_string() == text,
            "canonical package descriptor inventory required",
        )?;
        names.push(fd);
    }
    require(
        complete && shape_proc(directory)? == expected,
        "procfs descriptor inventory incomplete or changed",
    )?;
    drop(cursor);
    Ok(names
        .into_iter()
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFL) } >= 0)
        .collect())
}
/// Before-call regular-file identities, rather than reusable descriptor numbers.
pub(crate) struct DescriptorSnapshot(BTreeMap<i32, (i32, files::FileIdentity)>);
impl DescriptorSnapshot {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub(crate) fn capture(directory: &File) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for fd in descriptors(directory)? {
            let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
            if raw < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                return Err(error.into());
            }
            let held = unsafe { File::from_raw_fd(raw) };
            let metadata = held.metadata()?;
            let flags = enzimos_platform::files::status_flags(&held);
            require(flags >= 0, "original descriptor flags unavailable")?;
            if metadata.is_file() {
                entries.insert(fd, (flags & libc::O_ACCMODE, files::identity(&metadata)));
            }
        }
        Ok(Self(entries))
    }
    pub(crate) fn existed(&self, fd: i32, file: &File, access: i32) -> Result<bool> {
        let epoch = files::identity(&file.metadata()?);
        // Conservatively exclude an earlier alias of the same inode even if
        // its mutable timestamps changed. An unrelated reused number is new.
        Ok(self
            .0
            .get(&fd)
            .is_some_and(|(flags, old)| *flags == access && old.0 == epoch.0 && old.1 == epoch.1))
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn original_lock(
    directory: &File,
    process_fds: &File,
    before: &DescriptorSnapshot,
) -> Result<File> {
    let named = files::open_relative(directory, Path::new("db.lck"))?;
    let epoch = files::identity(&named.metadata()?);
    require(epoch.2 == 0, "native ALPM lock must be empty")?;
    let mut found = None;
    for fd in descriptors(process_fds)? {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_WRONLY {
            continue;
        }
        let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error.into());
        }
        let original = unsafe { File::from_raw_fd(raw) };
        if !before.existed(fd, &original, libc::O_WRONLY)?
            && enzimos_platform::files::status_flags(&original) & libc::O_ACCMODE == libc::O_WRONLY
            && files::identity(&original.metadata()?) == epoch
        {
            require(
                found.is_none(),
                "native ALPM created ambiguous lock descriptors",
            )?;
            found = Some(original);
        }
    }
    let original = found.ok_or_else(|| {
        Error("actual newly created ALPM lock descriptor unavailable; no path adoption".into())
    })?;
    require(
        files::identity(&original.metadata()?) == files::identity(&named.metadata()?),
        "original ALPM lock changed during retention",
    )?;
    Ok(original)
}
type Handle = *mut libc::c_void;
type Initialize =
    unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, *mut libc::c_int) -> Handle;
type Action = unsafe extern "C" fn(Handle) -> libc::c_int;
type Begin = unsafe extern "C" fn(Handle, libc::c_int) -> libc::c_int;
type Getter = unsafe extern "C" fn(Handle) -> *const libc::c_char;
type List = unsafe extern "C" fn(Handle) -> Handle;
struct Library {
    handle: Handle,
    parent: File,
    parent_shape: Shape,
    entry: Entry,
    name: PathBuf,
    file: File,
    epoch: files::FileIdentity,
    mount: u64,
    version: String,
    sha: String,
    alias: CString,
}
impl Library {
    #[allow(unsafe_code, reason = "Linux syscall ABI (dlmopen).")]
    fn open() -> Result<Self> {
        require(
            ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"]
                .iter()
                .all(|n| std::env::var_os(n).is_none()),
            "package capture loader environment refused",
        )?;
        let parent = files::directory(Path::new("/usr/lib"), Some(0))?;
        let parent_shape = shape(&parent)?;
        let entry = Entry::observe(&parent, Path::new("libalpm.so.16"))?;
        let m = entry.metadata()?;
        require(
            m.uid() == 0 && m.gid() == 0 && m.file_type().is_symlink(),
            "original ALPM16 public link required",
        )?;
        let name = entry.read_link(64)?;
        let version = soname(&name)?;
        let file = files::open_relative(&parent, &name)?;
        let m = file.metadata()?;
        require(
            m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0,
            "protected original ALPM ELF required",
        )?;
        let head = files::read_file(&file, 32 * 1024 * 1024, Some(0), true)?;
        require(
            head.len() >= 64
                && head.starts_with(b"\x7fELF\x02\x01\x01")
                && u16::from_le_bytes(head[18..20].try_into().unwrap()) == 62,
            "native x86-64 ALPM image required",
        )?;
        let (_, sha) = stream_copy::hash_borrowed(&file, 32 * 1024 * 1024, Some(0))?;
        let alias = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let handle = unsafe {
            libc::dlmopen(
                libc::LM_ID_NEWLM,
                alias.as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        };
        require(
            !handle.is_null(),
            "isolated original ALPM library unavailable",
        )?;
        let mount = mount_identity::id(file.as_fd(), true)?;
        let this = Self {
            handle,
            parent,
            parent_shape,
            entry,
            name,
            file,
            epoch: files::identity(&m),
            mount,
            version,
            sha,
            alias,
        };
        this.recheck()?;
        let version_fn: unsafe extern "C" fn() -> *const libc::c_char =
            unsafe { this.symbol(c"alpm_version")? };
        let actual = unsafe { version_fn() };
        require(
            !actual.is_null()
                && unsafe { CStr::from_ptr(actual) }.to_bytes() == this.version.as_bytes(),
            "ALPM loaded version differs from original image",
        )?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Native dynamic-loader ABI.")]
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> Result<T> {
        let pointer = unsafe { libc::dlsym(self.handle, name.as_ptr()) };
        require(
            !pointer.is_null() && std::mem::size_of::<T>() == std::mem::size_of::<Handle>(),
            "fixed ALPM API unavailable",
        )?;
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::dladdr(pointer, &mut info) } != 0
                && !info.dli_fname.is_null()
                && unsafe { CStr::from_ptr(info.dli_fname) } == self.alias.as_c_str(),
            "ALPM symbol does not belong to original isolated image",
        )?;
        Ok(unsafe { std::mem::transmute_copy(&pointer) })
    }
    fn recheck(&self) -> Result<()> {
        self.entry.recheck()?;
        let parent = files::directory(Path::new("/usr/lib"), Some(0))?;
        let named = files::open_relative(&self.parent, &self.name)?;
        require(
            shape(&self.parent)? == self.parent_shape
                && shape(&parent)? == self.parent_shape
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original ALPM image replaced or covered",
        )
    }
}
impl Drop for Library {
    #[allow(unsafe_code, reason = "Native dynamic-loader ABI.")]
    fn drop(&mut self) {
        unsafe { libc::dlclose(self.handle) };
    }
}
#[repr(C)]
struct PackageNode {
    data: Handle,
    previous: *const PackageNode,
    next: *const PackageNode,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (strnlen).")]
fn native_text(pointer: *const libc::c_char, maximum: usize) -> Result<String> {
    require(!pointer.is_null(), "native package text unavailable")?;
    let length = unsafe { libc::strnlen(pointer, maximum + 1) };
    require(length > 0 && length <= maximum, "native package text bound")?;
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    String::from_utf8(bytes.to_vec()).map_err(|_| Error("native package text encoding".into()))
}
fn package_row(name: &str, version: &str) -> Result<()> {
    require(
        !name.is_empty()
            && name.len() <= 128
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
            && !version.is_empty()
            && version.len() <= 256
            && version.bytes().all(|b| b.is_ascii_graphic()),
        "installed package name or version cannot form an inventory line",
    )
}
struct Api {
    release: Action,
    begin: Begin,
    end: Action,
    root: Getter,
    db: Getter,
    lock: Getter,
    added: List,
    removed: List,
    flags: Action,
    local_database: List,
    package_cache: List,
    package_name: Getter,
    package_version: Getter,
    errno: Action,
}
impl Api {
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    unsafe fn load(l: &Library) -> Result<(Initialize, Self)> {
        unsafe {
            Ok((
                l.symbol(c"alpm_initialize")?,
                Self {
                    release: l.symbol(c"alpm_release")?,
                    begin: l.symbol(c"alpm_trans_init")?,
                    end: l.symbol(c"alpm_trans_release")?,
                    root: l.symbol(c"alpm_option_get_root")?,
                    db: l.symbol(c"alpm_option_get_dbpath")?,
                    lock: l.symbol(c"alpm_option_get_lockfile")?,
                    added: l.symbol(c"alpm_trans_get_add")?,
                    removed: l.symbol(c"alpm_trans_get_remove")?,
                    flags: l.symbol(c"alpm_trans_get_flags")?,
                    local_database: l.symbol(c"alpm_get_localdb")?,
                    package_cache: l.symbol(c"alpm_db_get_pkgcache")?,
                    package_name: l.symbol(c"alpm_pkg_get_name")?,
                    package_version: l.symbol(c"alpm_pkg_get_version")?,
                    errno: l.symbol(c"alpm_errno")?,
                },
            ))
        }
    }
}
/// Explicit close is mandatory. On uncertain ownership, Drop leaves the ALPM
/// context and lock untouched until process death; it never unlinks a named file.
pub struct Capture<'a, 'g> {
    attempt: &'a Attempt<'g>,
    operation: &'a files::Lock,
    library: Option<Library>,
    api: Api,
    handle: Handle,
    directory: File,
    directory_shape: Shape,
    lock: File,
    lock_epoch: files::FileIdentity,
    lock_bytes: Vec<u8>,
    closed: bool,
}
impl<'a, 'g> Capture<'a, 'g> {
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    pub fn acquire(
        attempt: &'a Attempt<'g>,
        operation_lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        namespaces::initial()?;
        authorize()?;
        attempt.evidence()?;
        attempt.require_lock(operation_lock)?;
        operation_lock.recheck()?;
        let directory = files::directory(Path::new("/var/lib/pacman"), Some(0))?;
        let directory_shape = shape(&directory)?;
        require(
            files::optional_relative(&directory, Path::new("db.lck"))?.is_none(),
            "package transaction busy; no stale lock removal",
        )?;
        let library = Library::open()?;
        let (initialize, api) = unsafe { Api::load(&library)? };
        authorize()?;
        attempt.evidence()?;
        operation_lock.recheck()?;
        library.recheck()?;
        let named = files::directory(Path::new("/var/lib/pacman"), Some(0))?;
        require(
            shape(&named)? == directory_shape && shape(&directory)? == directory_shape,
            "package database changed before native transaction entry",
        )?;
        let mut error = 0;
        let handle = unsafe { initialize(c"/".as_ptr(), c"/var/lib/pacman".as_ptr(), &mut error) };
        require(!handle.is_null(), "ALPM capture handle unavailable")?;
        // A failed entry is not adopted or retried. No transaction preparation,
        // commit, package addition, removal or stale-lock recovery API is loaded.
        let library = std::mem::ManuallyDrop::new(library);
        let process_fds = files::directory(
            &PathBuf::from(format!("/proc/{}/fd", std::process::id())),
            Some(0),
        )?;
        let before = DescriptorSnapshot::capture(&process_fds)?;
        require(
            unsafe { (api.begin)(handle, 0) } == 0,
            "native package transaction capture entry failed or busy; no replay",
        )?;
        let lock = original_lock(&directory, &process_fds, &before)?;
        let m = lock.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0
                && m.len() == 0
                && mount_identity::id(lock.as_fd(), true)? == directory_shape.5,
            "original native package lock protection refused",
        )?;
        // ALPM16 creates an empty mode000 lock and retains its original writable
        // descriptor. PID text belonged to an older protocol and is not authority.
        let lock_bytes = Vec::new();
        let library = std::mem::ManuallyDrop::into_inner(library);
        let this = Self {
            attempt,
            operation: operation_lock,
            library: Some(library),
            api,
            handle,
            directory,
            directory_shape,
            lock,
            lock_epoch: files::identity(&m),
            lock_bytes,
            closed: false,
        };
        this.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn require_original(&self, attempt: &Attempt<'_>, lock: &files::Lock) -> Result<()> {
        require(
            self.attempt.same_actor(attempt) && std::ptr::eq(self.operation, lock),
            "package barrier requires original running attempt and operation lock",
        )?;
        self.recheck()
    }
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    pub fn recheck(&self) -> Result<()> {
        require(!self.closed, "package capture already closed")?;
        namespaces::initial()?;
        self.attempt.evidence()?;
        self.operation.recheck()?;
        self.library.as_ref().unwrap().recheck()?;
        let named = files::directory(Path::new("/var/lib/pacman"), Some(0))?;
        let lock = files::open_relative(&self.directory, Path::new("db.lck"))?;
        require(
            shape(&named)? == self.directory_shape
                && shape(&self.directory)? == self.directory_shape
                && files::identity(&self.lock.metadata()?) == self.lock_epoch
                && files::identity(&lock.metadata()?) == self.lock_epoch
                && mount_identity::id(lock.as_fd(), true)? == self.directory_shape.5
                && self.lock.metadata()?.len() == 0
                && files::identity(&self.lock.metadata()?) == self.lock_epoch,
            "original package capture database or lock changed",
        )?;
        for (getter, expected) in [
            (self.api.root, c"/"),
            (self.api.db, c"/var/lib/pacman/"),
            (self.api.lock, c"/var/lib/pacman/db.lck"),
        ] {
            let pointer = unsafe { getter(self.handle) };
            require(
                !pointer.is_null() && unsafe { CStr::from_ptr(pointer) } == expected,
                "native ALPM handle paths changed",
            )?;
        }
        require(
            unsafe { (self.api.flags)(self.handle) } == 0
                && unsafe { (self.api.added)(self.handle) }.is_null()
                && unsafe { (self.api.removed)(self.handle) }.is_null(),
            "capture must contain no package transaction work",
        )
    }
    /// Copy the actual local database while this original empty transaction
    /// still owns its native lock. Native pointers never leave the call.
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    pub fn installed_packages(&self) -> Result<BTreeMap<String, String>> {
        self.recheck()?;
        let database = unsafe { (self.api.local_database)(self.handle) };
        require(
            !database.is_null(),
            "native local package database unavailable",
        )?;
        let mut node = unsafe { (self.api.package_cache)(database) } as *const PackageNode;
        require(
            unsafe { (self.api.errno)(self.handle) } == 0,
            "native installed package cache failed",
        )?;
        let mut visited = BTreeSet::new();
        let mut packages = BTreeMap::new();
        let mut bytes = 0;
        while !node.is_null() {
            require(
                packages.len() < 16384 && visited.insert(node as usize),
                "native installed package list bound or cycle",
            )?;
            // alpm_list_t layout is pinned to the reviewed public ALPM16 ABI.
            let row = unsafe { &*node };
            require(!row.data.is_null(), "native installed package missing")?;
            let name = native_text(unsafe { (self.api.package_name)(row.data) }, 128)?;
            let version = native_text(unsafe { (self.api.package_version)(row.data) }, 256)?;
            package_row(&name, &version)?;
            bytes += name.len() + version.len() + 2;
            require(
                bytes <= 256 * 1024 && packages.insert(name, version).is_none(),
                "installed package inventory bound or duplicate",
            )?;
            node = row.next;
        }
        require(!packages.is_empty(), "installed package inventory empty")?;
        self.recheck()?;
        Ok(packages)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let l = self.library.as_ref().unwrap();
        Ok(
            value!({"kind":"libalpm-empty-native-transaction","abi":l.version,"image":l.epoch,"image_sha256":l.sha,"database":self.directory_shape,"lock":self.lock_epoch,"lock_bytes_sha256":json::sha256(&self.lock_bytes),"package_changes":false}),
        )
    }
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    pub fn close(mut self) -> Result<()> {
        self.recheck()?;
        require(
            unsafe { (self.api.end)(self.handle) } == 0,
            "native package capture release failed; explicit review required",
        )?;
        require(
            unsafe { (self.api.release)(self.handle) } == 0,
            "native package handle release failed",
        )?;
        self.closed = true;
        let named = files::directory(Path::new("/var/lib/pacman"), Some(0))?;
        require(
            shape(&named)? == self.directory_shape
                && shape(&self.directory)? == self.directory_shape
                && files::optional_relative(&self.directory, Path::new("db.lck"))?.is_none()
                && self.lock.metadata()?.nlink() == 0,
            "native package lock was not normally released",
        )?;
        self.library.as_ref().unwrap().recheck()?;
        self.attempt.evidence()?;
        self.operation.recheck()
    }
}
impl Drop for Capture<'_, '_> {
    fn drop(&mut self) {
        if !self.closed
            && let Some(l) = self.library.take()
        {
            std::mem::forget(l);
        }
    }
}
