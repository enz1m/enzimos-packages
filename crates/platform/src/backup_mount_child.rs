// SPDX-License-Identifier: MIT
//! Precomputed child-only readonly source attachment. Preparation never mounts.
use crate::{Error, Result, files, mount_identity, require};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const ROOT: &str = "/backup-source";
fn relative(target: &str) -> Result<&str> {
    let relative = target
        .strip_prefix("/backup-source/")
        .ok_or_else(|| Error("closed backup source target".into()))?;
    if matches!(relative, "system" | "home" | "boot" | "inventory") {
        return Ok(relative);
    }
    let name = relative
        .strip_prefix("additional/")
        .ok_or_else(|| Error("closed additional backup source target".into()))?;
    require(
        !name.is_empty()
            && name.len() <= 32
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "closed additional source component",
    )?;
    Ok(relative)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, fstatvfs).")]
fn protections(file: &File) -> Result<()> {
    let m = file.metadata()?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7022 == 0
            && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_RDONLY
            && unsafe { libc::fstatvfs(file.as_raw_fd(), &mut status) } == 0
            && status.f_flag & required == required,
        "actual readonly backup source protection",
    )
}
struct Tree {
    name: CString,
    file: File,
    epoch: files::FileIdentity,
    mount: u64,
}
pub struct Prepared {
    creator: u32,
    creator_pidfd: File,
    namespace: File,
    anchor: File,
    anchor_epoch: files::FileIdentity,
    anchor_mount: u64,
    trees: Vec<Tree>,
    additional: bool,
    arguments: Vec<String>,
}
impl Prepared {
    /// The caller separately retains its actual admitted source/worker actors.
    /// This constructor only duplicates actual readonly descriptions; it accepts
    /// neither inode metadata nor a caller-selected attachment root.
    pub fn prepare(sources: BTreeMap<&str, &File>) -> Result<Self> {
        let arguments =
            crate::backup_command::arguments(&sources.keys().map(|s| (*s).to_owned()).collect())?;
        Self::prepare_reviewed(sources, &arguments)
    }
    /// Preserve the original reviewed dataset order and paired exclusions.
    /// Actual descriptors and Root parent checks remain mandatory.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (getegid, geteuid, getgid, getuid and others)."
    )]
    pub fn prepare_reviewed(sources: BTreeMap<&str, &File>, arguments: &[String]) -> Result<Self> {
        crate::backup_command::validate(
            arguments,
            &sources.keys().map(|s| (*s).to_owned()).collect(),
        )?;
        require(
            unsafe { libc::getuid() } == 0
                && unsafe { libc::geteuid() } == 0
                && unsafe { libc::getgid() } == 0
                && unsafe { libc::getegid() } == 0,
            "Root backup child preparation",
        )?;
        require(
            (4..=34).contains(&sources.len())
                && ["system", "home", "boot", "inventory"]
                    .iter()
                    .all(|slot| sources.contains_key(format!("{ROOT}/{slot}").as_str())),
            "complete bounded backup child source set",
        )?;
        let anchor = files::directory(Path::new(ROOT), Some(0))?;
        let m = anchor.metadata()?;
        require(
            m.gid() == 0
                && m.mode() & 0o7777 == 0o700
                && mount_identity::id(anchor.as_fd(), true)?
                    == mount_identity::id(
                        files::directory(Path::new("/"), Some(0))?.as_fd(),
                        true,
                    )?,
            "original protected backup attachment placeholder",
        )?;
        let creator = std::process::id();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, creator, 0) };
        require(raw >= 0, "original backup creator pidfd")?;
        use std::os::fd::FromRawFd;
        let creator_pidfd = unsafe { File::from_raw_fd(raw as i32) };
        let namespace = File::open("/proc/self/ns/mnt")?;
        let mut trees = Vec::new();
        let mut mounts = std::collections::BTreeSet::new();
        let mut additional = false;
        for (target, source) in sources {
            let name = relative(target)?;
            protections(source)?;
            let mount = mount_identity::id(source.as_fd(), true)?;
            require(
                mounts.insert(mount),
                "distinct original source mount descriptions",
            )?;
            additional |= name.starts_with("additional/");
            trees.push(Tree {
                name: CString::new(name).map_err(|_| Error("source component encoding".into()))?,
                file: source.try_clone()?,
                epoch: files::identity(&source.metadata()?),
                mount,
            });
        }
        let this = Self {
            creator,
            creator_pidfd,
            namespace,
            anchor_epoch: files::identity(&m),
            anchor_mount: mount_identity::id(anchor.as_fd(), true)?,
            anchor,
            trees,
            additional,
            arguments: arguments.to_vec(),
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }
    pub fn recheck(&self) -> Result<()> {
        require(
            self.creator == std::process::id(),
            "backup preparation belongs to original parent",
        )?;
        require(
            crate::process_identity::pidfd_target(self.creator_pidfd.as_fd())? == self.creator,
            "original backup creator changed",
        )?;
        let current = File::open("/proc/self/ns/mnt")?;
        let a = self.namespace.metadata()?;
        let b = current.metadata()?;
        let named = files::directory(Path::new(ROOT), Some(0))?;
        require(
            (a.dev(), a.ino()) == (b.dev(), b.ino())
                && files::identity(&self.anchor.metadata()?) == self.anchor_epoch
                && files::identity(&named.metadata()?) == self.anchor_epoch
                && mount_identity::id(self.anchor.as_fd(), true)? == self.anchor_mount
                && mount_identity::id(named.as_fd(), true)? == self.anchor_mount,
            "original backup parent namespace or placeholder changed",
        )?;
        for tree in &self.trees {
            protections(&tree.file)?;
            require(
                files::identity(&tree.file.metadata()?) == tree.epoch
                    && mount_identity::id(tree.file.as_fd(), true)? == tree.mount,
                "original prepared backup source changed",
            )?;
        }
        Ok(())
    }
    /// Attach sources only in a direct owned fork child before exec/capability
    /// removal. A failed step leaves that child private and must abort execution.
    ///
    /// # Safety
    /// Call only from the owned child's pre_exec hook. No allocation or lock is
    /// performed. The caller must close inherited source/outside directory FDs,
    /// isolate networking, drop mount/ptrace/handle-access capabilities and enter
    /// the required backup AppArmor profile before running the fixed consumer.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (close, fstat, fstatfs, geteuid and others)."
    )]
    pub unsafe fn enter_child(&self) -> std::io::Result<()> {
        let denied = || std::io::Error::from_raw_os_error(libc::EPERM);
        if unsafe { libc::getpid() } == self.creator as i32
            || unsafe { libc::getppid() } != self.creator as i32
            || unsafe { libc::geteuid() } != 0
        {
            return Err(denied());
        }
        let mut poll = libc::pollfd {
            fd: self.creator_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
            return Err(denied());
        }
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
            || unsafe { libc::getppid() } != self.creator as i32
        {
            return Err(denied());
        }
        let old = unsafe {
            libc::open(
                c"/proc/self/ns/mnt".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if old < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let same = unsafe { same_inode(old, self.namespace.as_raw_fd()) };
        unsafe { libc::close(old) };
        if !same {
            return Err(denied());
        }
        for tree in &self.trees {
            if !unsafe { exact(tree.file.as_raw_fd(), tree.epoch, Some(tree.mount)) }
                || !unsafe { readonly(tree.file.as_raw_fd()) }
            {
                return Err(denied());
            }
        }
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let anchor = unsafe {
            libc::open(
                c"/backup-source".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if anchor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let valid = unsafe { exact(anchor, self.anchor_epoch, None) };
        unsafe { libc::close(anchor) };
        if !valid {
            return Err(denied());
        }
        if unsafe {
            libc::mount(
                c"enzimos-backup-source".as_ptr(),
                c"/backup-source".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"mode=0700,size=1M".as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let root = unsafe {
            libc::open(
                c"/backup-source".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if root < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        let valid = unsafe { libc::fstatfs(root, &mut filesystem) } == 0
            && filesystem.f_type == libc::TMPFS_MAGIC
            && unsafe { libc::fstat(root, &mut metadata) } == 0
            && metadata.st_uid == 0
            && metadata.st_gid == 0
            && metadata.st_mode & 0o7777 == 0o700;
        if !valid {
            unsafe { libc::close(root) };
            return Err(denied());
        }
        let result = unsafe { self.attach(root) };
        unsafe { libc::close(root) };
        result
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (close, mkdirat, openat, syscall)."
    )]
    unsafe fn attach(&self, root: i32) -> std::io::Result<()> {
        if self.additional && unsafe { libc::mkdirat(root, c"additional".as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for tree in &self.trees {
            if unsafe { libc::mkdirat(root, tree.name.as_ptr(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let target = unsafe {
                libc::openat(
                    root,
                    tree.name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if target < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let moved = unsafe {
                libc::syscall(
                    libc::SYS_move_mount,
                    tree.file.as_raw_fd(),
                    c"".as_ptr(),
                    target,
                    c"".as_ptr(),
                    4u32 | 0x40,
                )
            };
            unsafe { libc::close(target) };
            if moved != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let actual = unsafe {
                libc::openat(
                    root,
                    tree.name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if actual < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let valid = unsafe { exact(actual, tree.epoch, Some(tree.mount)) && readonly(actual) };
            unsafe { libc::close(actual) };
            if !valid {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
        }
        Ok(())
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstat).")]
pub(crate) unsafe fn same_inode(a: i32, b: i32) -> bool {
    let mut left: libc::stat = unsafe { std::mem::zeroed() };
    let mut right: libc::stat = unsafe { std::mem::zeroed() };
    unsafe {
        libc::fstat(a, &mut left) == 0
            && libc::fstat(b, &mut right) == 0
            && (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstat, statx).")]
pub(crate) unsafe fn exact(fd: i32, epoch: files::FileIdentity, mount: Option<u64>) -> bool {
    let mut m: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut m) } != 0 {
        return false;
    }
    if (
        m.st_dev,
        m.st_ino,
        m.st_size as u64,
        m.st_mtime,
        m.st_mtime_nsec,
        m.st_ctime,
        m.st_ctime_nsec,
        m.st_mode,
        m.st_uid,
        m.st_gid,
        m.st_nlink,
    ) != epoch
    {
        return false;
    }
    if let Some(expected) = mount {
        let mut status: libc::statx = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                0x4000,
                &mut status,
            )
        } != 0
            || status.stx_mask & 0x4000 == 0
            || status.stx_mnt_id != expected
        {
            return false;
        }
    }
    true
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
unsafe fn readonly(fd: i32) -> bool {
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    unsafe { libc::fstatvfs(fd, &mut status) == 0 && status.f_flag & required == required }
}
