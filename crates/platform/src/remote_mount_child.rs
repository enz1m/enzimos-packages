// SPDX-License-Identifier: MIT
//! The NAS share for one remote Restic child. The Root parent resolves the
//! server, checks that it answers and reads the share password; only an owned
//! fork child mounts the share, with kernel CIFS in its own private mount
//! namespace, so the mount ends with that child.
use crate::remote_restic::{Endpoint, MOUNT};
use crate::{Error, Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
/// A NAS that is off or unreachable is reported before any Restic child starts.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A server that accepts TCP but never finishes the SMB session cannot hold a
/// child in the mount call longer than this: the child is killed instead.
const MOUNT_SECONDS: u32 = 90;
/// `s_magic` of an SMB2/SMB3 kernel CIFS mount.
const SMB2_SUPER_MAGIC: i64 = 0xFE53_4D42;
const FSOPEN_CLOEXEC: u32 = 1;
const FSCONFIG_SET_FLAG: u32 = 0;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_CMD_CREATE: u32 = 6;
const FSMOUNT_CLOEXEC: u32 = 1;
const MOUNT_ATTR_NOSUID: u32 = 0x2;
const MOUNT_ATTR_NODEV: u32 = 0x4;
const MOUNT_ATTR_NOEXEC: u32 = 0x8;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;
/// SMB 3.0 or later only, signed, its own TCP session, a soft mount that
/// fails I/O on a dead server, and fixed Root ownership of every file.
const FLAGS: [&std::ffi::CStr; 5] = [c"soft", c"sign", c"nosharesock", c"forceuid", c"forcegid"];
/// The share password, wiped when dropped; it is never printed.
struct Password(Vec<u8>);
impl Drop for Password {
    #[allow(
        unsafe_code,
        reason = "Volatile writes keep the wipe from being elided."
    )]
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: `byte` is a valid, exclusive reference into this vector.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}
/// The password file holds the password on its first line; a final line
/// break is not part of it.
fn password(file: &File) -> Result<Password> {
    let mut bytes = Password(files::read_file(file, 4096, Some(0), true)?);
    if bytes.0.ends_with(b"\n") {
        bytes.0.pop();
        if bytes.0.ends_with(b"\r") {
            bytes.0.pop();
        }
    }
    require(
        (1..=512).contains(&bytes.0.len())
            && !bytes.0.iter().any(|b| matches!(b, 0 | b'\n' | b'\r')),
        "remote-share-secret-refused: the share password must be one line of 1 to 512 bytes",
    )?;
    bytes.0.push(0);
    Ok(bytes)
}
/// One IPv4 address for the server; the kernel client never resolves names.
fn address(endpoint: &Endpoint) -> Result<Ipv4Addr> {
    let found = (endpoint.server(), 445)
        .to_socket_addrs()
        .map_err(|_| {
            Error(format!(
                "remote-share-unreachable: the NAS {} could not be found",
                endpoint.server()
            ))
        })?
        .find_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            Error(format!(
                "remote-share-unreachable: the NAS {} has no IPv4 address",
                endpoint.server()
            ))
        })?;
    require(
        !found.is_unspecified() && !found.is_multicast() && found != Ipv4Addr::BROADCAST,
        "remote-share-unreachable: the NAS address is not a single host",
    )?;
    Ok(found)
}
/// The server's address once it answers on the SMB port.
fn answering(endpoint: &Endpoint) -> Result<Ipv4Addr> {
    let ip = address(endpoint)?;
    TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), 445), CONNECT_TIMEOUT).map_err(
        |e| {
            Error(format!(
                "remote-share-unreachable: the NAS {} did not answer on the SMB port: {e}",
                endpoint.server()
            ))
        },
    )?;
    Ok(ip)
}
/// Whether the NAS can be found and answers on the SMB port within the
/// connect timeout. Nothing is mounted and no password is read.
///
/// # Errors
/// `remote-share-unreachable` with the reason.
pub fn reachable(endpoint: &Endpoint) -> Result<()> {
    answering(endpoint).map(|_| ())
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
/// One workflow's share attachment: resolved address, mount options and the
/// share password, ready for each owned Restic child to mount privately.
pub struct Prepared {
    creator: u32,
    creator_pidfd: File,
    namespace: File,
    anchor: File,
    anchor_epoch: files::FileIdentity,
    anchor_mount: u64,
    credential: File,
    credential_epoch: files::FileIdentity,
    credential_parent: Shape,
    strings: Vec<(&'static std::ffi::CStr, CString)>,
    password: Password,
}
impl Prepared {
    /// Resolve the server once (every child of this workflow uses the same
    /// address), check that it answers on the SMB port and read the share
    /// password from its Root-only file. Nothing is mounted here.
    ///
    /// # Errors
    /// Non-Root callers, a changed namespace or mount point, an unprotected or
    /// malformed password file, an unknown server or one that does not answer.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (fcntl, getegid, geteuid, getgid and others)."
    )]
    pub fn prepare(endpoint: &Endpoint, credential: &File) -> Result<Self> {
        require(
            crate::process_identity::real_uid() == 0
                && crate::process_identity::effective_uid() == 0
                && crate::process_identity::real_gid() == 0
                && crate::process_identity::effective_gid() == 0,
            "Root SMB attachment preparation",
        )?;
        let namespace = File::open("/proc/self/ns/mnt")?;
        let initial = File::open("/proc/1/ns/mnt")?;
        require(
            // SAFETY: Both descriptors are owned by live Files for the duration of the call.
            unsafe {
                crate::backup_mount_child::same_inode(namespace.as_raw_fd(), initial.as_raw_fd())
            },
            "initial SMB preparation mount namespace",
        )?;
        let anchor = files::directory(Path::new(MOUNT), Some(0))?;
        let m = anchor.metadata()?;
        let anchor_mount = mount_identity::id(anchor.as_fd(), true)?;
        require(
            m.gid() == 0
                && m.mode() & 0o7777 == 0o700
                && anchor_mount
                    == mount_identity::id(
                        files::directory(Path::new("/"), Some(0))?.as_fd(),
                        true,
                    )?,
            "protected empty /backup-remote mount point on the root file system",
        )?;
        let c = credential.metadata()?;
        let flags = crate::files::status_flags(&credential);
        require(
            c.is_file()
                && c.uid() == 0
                && c.gid() == 0
                && c.nlink() == 1
                && c.mode() & 0o077 == 0
                && flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "Root-only original SMB share password file",
        )?;
        let credential_parent = shape(&files::directory(Path::new("/etc/enzimos"), Some(0))?)?;
        let password = password(credential)?;
        let ip = answering(endpoint)?;
        let text =
            |value: &str| CString::new(value).map_err(|_| Error("SMB option encoding".into()));
        let mut strings = vec![
            (c"source", text(&endpoint.unc())?),
            (c"ip", text(&ip.to_string())?),
            (c"vers", text("3")?),
            (c"username", text(endpoint.user())?),
            (c"uid", text("0")?),
            (c"gid", text("0")?),
            (c"file_mode", text("0600")?),
            (c"dir_mode", text("0700")?),
            (c"echo_interval", text("10")?),
            (c"iocharset", text("utf8")?),
        ];
        if let Some(domain) = endpoint.domain() {
            strings.push((c"domain", text(domain)?));
        }
        let creator = std::process::id();
        // SAFETY: pidfd_open takes no pointers.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, creator, 0) };
        require(fd >= 0, "original SMB creator pidfd")?;
        // SAFETY: `fd` was just returned by pidfd_open and is owned by nothing else.
        let creator_pidfd = unsafe { File::from_raw_fd(fd as i32) };
        let this = Self {
            creator,
            creator_pidfd,
            namespace,
            anchor_epoch: files::identity(&m),
            anchor_mount,
            anchor,
            credential_epoch: files::identity(&c),
            credential: credential.try_clone()?,
            credential_parent,
            strings,
            password,
        };
        this.recheck()?;
        Ok(this)
    }
    /// The creator, its namespace, the mount point and the password file are
    /// still the ones prepared.
    ///
    /// # Errors
    /// Any of them changed or was replaced.
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    pub fn recheck(&self) -> Result<()> {
        require(
            std::process::id() == self.creator
                && crate::process_identity::pidfd_target(self.creator_pidfd.as_fd())?
                    == self.creator,
            "original SMB attachment creator changed",
        )?;
        let current = File::open("/proc/self/ns/mnt")?;
        require(
            // SAFETY: Both descriptors are owned by live Files for the duration of the call.
            unsafe {
                crate::backup_mount_child::same_inode(
                    current.as_raw_fd(),
                    self.namespace.as_raw_fd(),
                )
            },
            "original SMB preparation namespace changed",
        )?;
        let named = files::directory(Path::new(MOUNT), Some(0))?;
        require(
            files::identity(&self.anchor.metadata()?) == self.anchor_epoch
                && files::identity(&named.metadata()?) == self.anchor_epoch
                && mount_identity::id(self.anchor.as_fd(), true)? == self.anchor_mount
                && mount_identity::id(named.as_fd(), true)? == self.anchor_mount,
            "original /backup-remote mount point changed or covered",
        )?;
        require(
            files::identity(&self.credential.metadata()?) == self.credential_epoch
                && shape(&files::directory(Path::new("/etc/enzimos"), Some(0))?)?
                    == self.credential_parent,
            "original SMB share password file changed",
        )
    }
    /// Mount the share at `/backup-remote` in a new private mount namespace.
    ///
    /// # Safety
    /// Only call from this creator's direct owned pre_exec child. The caller
    /// must then isolate networking, close all ambient descriptors, drop
    /// mount/ptrace capabilities, enter the mandatory remote Restic AppArmor
    /// profile and abort on any failure. No allocations, locks, parent mounts
    /// or parent privilege changes occur. A mount still waiting after
    /// `MOUNT_SECONDS` ends the child with SIGALRM.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (alarm, fsopen, fsconfig, fsmount, move_mount and others)."
    )]
    pub(crate) unsafe fn enter_child(&self) -> std::io::Result<()> {
        let denied = || std::io::Error::from_raw_os_error(libc::EPERM);
        if crate::process_identity::current_pid() == self.creator as i32
            || crate::process_identity::parent_pid() != self.creator as i32
            || crate::process_identity::effective_uid() != 0
        {
            return Err(denied());
        }
        let mut poll = libc::pollfd {
            fd: self.creator_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` is one writable pollfd and the count is 1.
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
            return Err(denied());
        }
        // SAFETY: prctl(PR_SET_PDEATHSIG) takes no pointers.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
            || crate::process_identity::parent_pid() != self.creator as i32
        {
            return Err(denied());
        }
        // SAFETY: The path is a NUL-terminated C string literal.
        let ns = unsafe {
            libc::open(
                c"/proc/self/ns/mnt".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if ns < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `ns` was just opened above and `self.namespace` is a live File.
        let same = unsafe { crate::backup_mount_child::same_inode(ns, self.namespace.as_raw_fd()) };
        // SAFETY: `ns` is owned by this function and closed exactly once.
        unsafe { libc::close(ns) };
        if !same {
            return Err(denied());
        }
        // SAFETY: unshare takes no pointers and affects only this pre_exec child.
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: All non-null pointers are NUL-terminated C string literals.
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
        // SAFETY: The path is a NUL-terminated C string literal.
        let target = unsafe {
            libc::open(
                c"/backup-remote".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if target < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // The new namespace has new mount IDs; the inode epoch identifies the
        // prepared mount point.
        // SAFETY: `target` was just opened above and is still open.
        if !unsafe { crate::backup_mount_child::exact(target, self.anchor_epoch, None) } {
            // SAFETY: `target` is owned by this function and closed exactly once.
            unsafe { libc::close(target) };
            return Err(denied());
        }
        // SAFETY: This is the pre_exec child required by `mount`, and `target` is an open directory
        // descriptor.
        let mounted = unsafe { self.mount(target) };
        // SAFETY: `target` is owned by this function and closed exactly once.
        unsafe { libc::close(target) };
        let mount = mounted?;
        // SAFETY: The path is a NUL-terminated C string literal.
        let root = unsafe {
            libc::open(
                c"/backup-remote".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if root < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: `mount` came from `self.mount` and is closed exactly once.
            unsafe { libc::close(mount) };
            return Err(error);
        }
        // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut status: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `root` is open and `status` is a writable `libc::statfs`.
        let valid = unsafe { libc::fstatfs(root, &mut status) } == 0
            && status.f_type as i64 == SMB2_SUPER_MAGIC
            // SAFETY: `root` and `mount` are both open descriptors owned by this function.
            && unsafe { same_mount(root, mount) };
        // SAFETY: Both descriptors are owned by this function and not used after this point.
        unsafe {
            libc::close(root);
            libc::close(mount)
        };
        if !valid {
            return Err(denied());
        }
        Ok(())
    }
    /// fsopen/fsconfig/fsmount/move_mount onto `target`; returns the mount
    /// descriptor. The password reaches only the kernel's mount context.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (alarm, fsopen, fsconfig, fsmount, move_mount and others)."
    )]
    unsafe fn mount(&self, target: i32) -> std::io::Result<i32> {
        // SAFETY: `libc::sigaction` is a plain C struct, for which all-zero bytes are a valid
        // value.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        // SAFETY: `libc::sigset_t` is a plain C struct, for which all-zero bytes are a valid value.
        let mut alarm: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `action` is a fully initialized sigaction and the old-action pointer may be null.
        if unsafe { libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) } != 0
            // SAFETY: `alarm` is a writable sigset_t.
            || unsafe { libc::sigemptyset(&mut alarm) } != 0
            // SAFETY: `alarm` was initialized by sigemptyset.
            || unsafe { libc::sigaddset(&mut alarm, libc::SIGALRM) } != 0
            // SAFETY: `alarm` is an initialized sigset_t and the old-mask pointer may be null.
            || unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &alarm, std::ptr::null_mut()) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: alarm takes no pointers.
        unsafe { libc::alarm(MOUNT_SECONDS) };
        let context =
            // SAFETY: The filesystem name is a NUL-terminated C string literal.
            unsafe { libc::syscall(libc::SYS_fsopen, c"cifs".as_ptr(), FSOPEN_CLOEXEC) } as i32;
        if context < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: alarm takes no pointers.
            unsafe { libc::alarm(0) };
            return Err(error);
        }
        // SAFETY: Callers pass NUL-terminated keys and values (or null where fsconfig allows it)
        // that outlive the call.
        let set = |command: u32, key: *const libc::c_char, value: *const libc::c_char| unsafe {
            libc::syscall(libc::SYS_fsconfig, context, command, key, value, 0) == 0
        };
        let mut configured = self
            .strings
            .iter()
            .all(|(key, value)| set(FSCONFIG_SET_STRING, key.as_ptr(), value.as_ptr()))
            && set(
                FSCONFIG_SET_STRING,
                c"password".as_ptr(),
                self.password.0.as_ptr().cast(),
            )
            && FLAGS
                .iter()
                .all(|flag| set(FSCONFIG_SET_FLAG, flag.as_ptr(), std::ptr::null()));
        configured = configured && set(FSCONFIG_CMD_CREATE, std::ptr::null(), std::ptr::null());
        let mount = if configured {
            // SAFETY: fsmount takes no pointers and `context` is the open fsopen descriptor.
            (unsafe {
                libc::syscall(
                    libc::SYS_fsmount,
                    context,
                    FSMOUNT_CLOEXEC,
                    MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
                )
            }) as i32
        } else {
            -1
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: alarm takes no pointers and `context` is owned here and closed exactly once.
        unsafe {
            libc::alarm(0);
            libc::close(context)
        };
        if mount < 0 {
            return Err(error);
        }
        // SAFETY: The empty paths are NUL-terminated literals and both descriptors are open.
        if unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                mount,
                c"".as_ptr(),
                target,
                c"".as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            // SAFETY: `mount` is owned by this function and closed exactly once on this path.
            unsafe { libc::close(mount) };
            return Err(error);
        }
        Ok(mount)
    }
}
// Namespace cloning creates new mount IDs. Verify the opened directory belongs
// to the mount this child just attached rather than to something else.
#[allow(unsafe_code, reason = "Linux syscall ABI (statx).")]
unsafe fn same_mount(left: i32, right: i32) -> bool {
    // SAFETY: `libc::statx` is a plain C struct, for which all-zero bytes are a valid value.
    let mut a: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: `libc::statx` is a plain C struct, for which all-zero bytes are a valid value.
    let mut b: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: Both paths are NUL-terminated literals, `a` and `b` are writable, and the caller
    // passes open descriptors.
    unsafe {
        libc::statx(
            left,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            0x4000,
            &mut a,
        ) == 0
            && libc::statx(
                right,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                0x4000,
                &mut b,
            ) == 0
            && a.stx_mask & 0x4000 != 0
            && b.stx_mask & 0x4000 != 0
            && a.stx_mnt_id == b.stx_mnt_id
    }
}
