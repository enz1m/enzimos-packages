// SPDX-License-Identifier: MIT
//! Named local handoff sockets retain a private parent and socket inode.
use crate::{Error, Result, fd_packet::Packet, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
fn address(path: &Path) -> Result<libc::sockaddr_un> {
    let body = path.as_os_str().as_bytes();
    // SAFETY: `libc::sockaddr_un` is a plain C struct, for which all-zero bytes are a valid value.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    require(
        path.is_absolute() && !body.contains(&0) && body.len() < address.sun_path.len(),
        "local packet socket path bound",
    )?;
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(body) {
        *target = *byte as _;
    }
    Ok(address)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (setsockopt, socket).")]
fn socket() -> Result<OwnedFd> {
    // SAFETY: socket takes no pointers.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    require(fd >= 0, "local packet socket unavailable")?;
    // SAFETY: `fd` was just returned by socket and is owned by nothing else.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let yes: i32 = 1;
    require(
        // SAFETY: The option value points at `yes` with its exact size, and `socket` is open.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&yes as *const i32).cast(),
                std::mem::size_of_val(&yes) as _,
            )
        } == 0,
        "local socket kernel credentials unavailable",
    )?;
    Ok(socket)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
fn wait(fd: i32, timeout: Duration, event: i16) -> Result<()> {
    require(
        !timeout.is_zero() && timeout <= Duration::from_secs(30),
        "local socket deadline bound",
    )?;
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        require(!left.is_zero(), "local socket deadline expired")?;
        let mut poll = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        // SAFETY: `poll` is one writable pollfd and the count is 1.
        let rc = unsafe {
            libc::poll(
                &mut poll,
                1,
                left.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(
            rc > 0
                && poll.revents & event != 0
                && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "local socket unavailable or deadline expired",
        )?;
        return Ok(());
    }
}
struct PathIdentity {
    path: PathBuf,
    parent: File,
    parent_identity: (u64, u64, u32, u32, u32),
    name: CString,
    inode: File,
    identity: files::FileIdentity,
    mount: u64,
    owner: u32,
}
fn parent(path: &Path, owner: u32) -> Result<File> {
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| Error("packet socket parent missing".into()))?,
        Some(owner),
    )?;
    let metadata = parent.metadata()?;
    require(
        metadata.uid() == owner && metadata.mode() & 0o7777 == 0o700,
        "private packet socket parent required",
    )?;
    Ok(parent)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn inode(parent: &File, name: &CString, owner: u32) -> Result<File> {
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, "packet socket inode unavailable")?;
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    require(
        metadata.mode() & libc::S_IFMT == libc::S_IFSOCK
            && metadata.uid() == owner
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1,
        "packet socket inode authority refused",
    )?;
    Ok(file)
}
fn parent_identity(parent: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = parent.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl PathIdentity {
    fn observe(path: &Path, owner: u32) -> Result<Self> {
        let parent = parent(path, owner)?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| Error("packet socket name missing".into()))?
                .as_bytes(),
        )
        .map_err(|_| Error("packet socket filename refused".into()))?;
        let inode = inode(&parent, &name, owner)?;
        let result = Self {
            path: path.into(),
            parent_identity: parent_identity(&parent)?,
            identity: files::identity(&inode.metadata()?),
            mount: mount_identity::id(inode.as_fd(), true)?,
            parent,
            name,
            inode,
            owner,
        };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&self) -> Result<()> {
        let current_parent = parent(&self.path, self.owner)?;
        let current_inode = inode(&self.parent, &self.name, self.owner)?;
        let named_inode = inode(&current_parent, &self.name, self.owner)?;
        require(
            parent_identity(&current_parent)? == self.parent_identity
                && parent_identity(&self.parent)? == self.parent_identity
                && files::identity(&self.inode.metadata()?) == self.identity
                && files::identity(&current_inode.metadata()?) == self.identity
                && files::identity(&named_inode.metadata()?) == self.identity
                && mount_identity::id(current_inode.as_fd(), true)? == self.mount
                && mount_identity::id(named_inode.as_fd(), true)? == self.mount,
            "packet socket directory or inode replaced",
        )
    }
}
/// A listening packet socket bound at a path owned by its creator.
pub struct Listener {
    socket: OwnedFd,
    path: PathIdentity,
}
impl Listener {
    /// Bind and listen at a new socket path, mode 0600, in a directory owned by `owner`.
    ///
    /// # Errors
    ///
    /// Fails unless the caller's effective UID is `owner`, when the path exists or its parent is
    /// unsafe or changes, or when bind or listen fails.
    #[allow(unsafe_code, reason = "Linux syscall ABI (bind, fchmodat, listen).")]
    pub fn bind(path: &Path, owner: u32) -> Result<Self> {
        require(
            crate::process_identity::effective_uid() == owner,
            "packet socket writer authority refused",
        )?;
        let held_parent = parent(path, owner)?;
        let before = parent_identity(&held_parent)?;
        let address = address(path)?;
        let socket = socket()?;
        require(
            // SAFETY: `address` is a complete sockaddr_un passed with its size, and `socket` is
            // open.
            unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } == 0,
            "packet socket exists or bind refused; never replace",
        )?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| Error("missing retained filename".into()))?
                .as_bytes(),
        )
        .map_err(|_| Error("invalid socket filename".into()))?;
        require(
            // SAFETY: `name` is a NUL-terminated CString and `held_parent` keeps the descriptor
            // open.
            unsafe { libc::fchmodat(held_parent.as_raw_fd(), name.as_ptr(), 0o600, 0) } == 0,
            "packet socket mode publication failed",
        )?;
        held_parent.sync_all()?;
        let retained = PathIdentity::observe(path, owner)?;
        require(
            retained.parent_identity == before,
            "packet socket parent changed during bind",
        )?;
        require(
            // SAFETY: listen takes no pointers and `socket` keeps the descriptor open.
            unsafe { libc::listen(socket.as_raw_fd(), 1) } == 0,
            "packet socket listen failed",
        )?;
        Ok(Self {
            socket,
            path: retained,
        })
    }
    /// Nonblocking readiness; no descriptor or pathname authority is exported.
    ///
    /// # Errors
    ///
    /// Fails when the socket path changed or polling fails.
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    pub fn pending(&self) -> Result<bool> {
        self.path.recheck()?;
        let mut poll = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` is one writable pollfd and the count is 1.
        let rc = unsafe { libc::poll(&mut poll, 1, 0) };
        require(
            rc >= 0 && poll.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) == 0,
            "original packet listener unavailable",
        )?;
        self.path.recheck()?;
        Ok(poll.revents & libc::POLLIN != 0)
    }
    /// Accept one connection within `timeout` as a [`Packet`].
    ///
    /// # Errors
    ///
    /// Fails when the socket path changed, the deadline passes, or the accepted socket is not a
    /// valid packet socket.
    #[allow(unsafe_code, reason = "Linux syscall ABI (accept4).")]
    pub fn accept(&self, timeout: Duration) -> Result<Packet> {
        self.path.recheck()?;
        wait(self.socket.as_raw_fd(), timeout, libc::POLLIN)?;
        // SAFETY: Null address pointers are allowed by accept4, and the socket is open.
        let fd = unsafe {
            libc::accept4(
                self.socket.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        require(fd >= 0, "packet socket accept failed")?;
        // SAFETY: `fd` was just returned by accept4 and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(fd) };
        self.path.recheck()?;
        Packet::from_file(file)
    }
    // Drop retains the named socket for inspection. A generation path is never reused.
}
/// Connect to the packet socket at `path`, owned by `owner`, within `timeout`.
///
/// # Errors
///
/// Fails when the path is not an owned socket, the connection is refused or not completed in time,
/// or the path changes. Connections are never retried.
#[allow(unsafe_code, reason = "Linux syscall ABI (connect, getsockopt).")]
pub fn connect(path: &Path, owner: u32, timeout: Duration) -> Result<Packet> {
    require(
        !timeout.is_zero() && timeout <= Duration::from_secs(30),
        "local socket deadline bound",
    )?;
    let retained = PathIdentity::observe(path, owner)?;
    let address = address(path)?;
    let socket = socket()?;
    // SAFETY: `address` is a complete sockaddr_un passed with its size, and `socket` is open.
    let rc = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as _,
        )
    };
    if rc < 0 {
        require(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS),
            "packet socket connect refused; no retry",
        )?;
        wait(socket.as_raw_fd(), timeout, libc::POLLOUT)?;
        let mut error: i32 = -1;
        let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
        require(
            // SAFETY: The option buffer is `error` with its size in `size`, and `socket` is open.
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut i32).cast(),
                    &mut size,
                )
            } == 0
                && error == 0,
            "packet socket connect failed",
        )?;
    }
    retained.recheck()?;
    Packet::from_file(File::from(socket))
}
