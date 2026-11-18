// SPDX-License-Identifier: MIT
//! One bounded Unix packet carries descriptors and kernel-stamped sender identity.
use crate::Error;
use crate::{Result, require};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    time::Duration,
};
pub const MAX_BYTES: usize = 65_536;
// Remote copy carries eighteen original descriptions. Older consumers retain
// their exact role-specific counts and cannot accept a remote packet.
pub const MAX_FILES: usize = 18;
#[derive(Debug, PartialEq, Eq)]
pub struct Credentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}
pub struct Message {
    pub body: Vec<u8>,
    pub files: Vec<OwnedFd>,
    pub sender: Credentials,
}
pub struct Packet(OwnedFd);
impl Packet {
    #[allow(unsafe_code, reason = "Linux syscall ABI (socketpair).")]
    pub fn pair() -> Result<(Self, Self)> {
        let mut fds = [-1; 2];
        require(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            } == 0,
            "packet socket creation failed",
        )?;
        let a = Self(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        let b = Self(unsafe { OwnedFd::from_raw_fd(fds[1]) });
        a.enable_credentials()?;
        b.enable_credentials()?;
        Ok((a, b))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (setsockopt).")]
    fn enable_credentials(&self) -> Result<()> {
        let yes: libc::c_int = 1;
        require(
            unsafe {
                libc::setsockopt(
                    self.0.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&yes as *const libc::c_int).cast(),
                    std::mem::size_of_val(&yes) as _,
                )
            } == 0,
            "packet kernel credentials unavailable",
        )
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (fcntl, getpeername, getsockopt)."
    )]
    pub fn from_file(file: File) -> Result<Self> {
        let socket = Self(file.into());
        let flags = unsafe { libc::fcntl(socket.0.as_raw_fd(), libc::F_GETFD) };
        require(
            flags >= 0
                && unsafe {
                    libc::fcntl(
                        socket.0.as_raw_fd(),
                        libc::F_SETFD,
                        flags | libc::FD_CLOEXEC,
                    )
                } == 0,
            "packet descriptor close-on-exec unavailable",
        )?;
        let mut kind: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
        require(
            unsafe {
                libc::getsockopt(
                    socket.0.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut kind as *mut libc::c_int).cast(),
                    &mut size,
                )
            } == 0
                && kind == libc::SOCK_SEQPACKET,
            "connected packet descriptor required",
        )?;
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&address) as libc::socklen_t;
        require(
            unsafe {
                libc::getpeername(
                    socket.0.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_un).cast(),
                    &mut size,
                )
            } == 0
                && address.sun_family == libc::AF_UNIX as libc::sa_family_t,
            "connected local packet socket required",
        )?;
        socket.enable_credentials()?;
        Ok(socket)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    fn wait(&self, events: i16, timeout: Duration) -> Result<()> {
        require(
            !timeout.is_zero() && timeout <= Duration::from_secs(30),
            "packet deadline bound",
        )?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            require(!remaining.is_zero(), "packet deadline expired")?;
            let mut p = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events,
                revents: 0,
            };
            let rc = unsafe {
                libc::poll(
                    &mut p,
                    1,
                    remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
                )
            };
            if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            require(
                rc > 0
                    && p.revents & (libc::POLLERR | libc::POLLNVAL) == 0
                    && p.revents & events != 0,
                "packet peer unavailable or deadline expired",
            )?;
            return Ok(());
        }
    }
    /// Wait for a verified live caller to finish bounded validation. This does
    /// not receive a packet or grant an operation; normal decoder deadlines,
    /// credentials, descriptor counts and nonce checks remain at the caller.
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    pub fn wait_ready(
        &self,
        caller: &crate::process_identity::Retained,
        timeout: Duration,
        checkpoint: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            !timeout.is_zero() && timeout <= Duration::from_secs(120),
            "original packet verification deadline bound",
        )?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            checkpoint()?;
            caller.recheck()?;
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            require(
                !remaining.is_zero(),
                "original packet verification deadline expired",
            )?;
            let mut polls = [
                libc::pollfd {
                    fd: self.as_fd().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: caller.pidfd().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let rc = unsafe {
                libc::poll(
                    polls.as_mut_ptr(),
                    2,
                    remaining.as_millis().min(100).max(1) as i32,
                )
            };
            if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            require(rc >= 0, "original packet verification poll failed")?;
            require(
                polls[1].revents == 0,
                "original packet caller exited during preparation",
            )?;
            require(
                polls[0].revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) == 0,
                "original packet verification peer closed",
            )?;
            if polls[0].revents & libc::POLLIN != 0 {
                checkpoint()?;
                caller.recheck()?;
                require(
                    std::time::Instant::now() < deadline,
                    "original packet verification deadline expired",
                )?;
                return Ok(());
            }
        }
    }

    /// Kernel connection peer, independent of credentials supplied in a packet.
    #[allow(unsafe_code, reason = "Linux syscall ABI (getsockopt).")]
    pub fn peer_credentials(&self) -> Result<Credentials> {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        require(
            unsafe {
                libc::getsockopt(
                    self.0.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut peer as *mut libc::ucred).cast(),
                    &mut size,
                )
            } == 0
                && size as usize == std::mem::size_of::<libc::ucred>()
                && peer.pid > 0,
            "original packet connection peer unavailable",
        )?;
        Ok(Credentials {
            pid: peer.pid as u32,
            uid: peer.uid,
            gid: peer.gid,
        })
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE and others)."
    )]
    pub fn send(&self, body: &[u8], files: &[BorrowedFd<'_>], timeout: Duration) -> Result<()> {
        require(
            !body.is_empty() && body.len() <= MAX_BYTES && files.len() <= MAX_FILES,
            "packet send bound",
        )?;
        self.wait(libc::POLLOUT, timeout)?;
        let mut iov = libc::iovec {
            iov_base: body.as_ptr().cast_mut().cast(),
            iov_len: body.len(),
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !files.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            let bytes = files.len() * std::mem::size_of::<libc::c_int>();
            message.msg_controllen = unsafe { libc::CMSG_SPACE(bytes as _) } as usize;
            require(
                message.msg_controllen <= std::mem::size_of_val(&control),
                "packet ancillary bound",
            )?;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(bytes as _) as _;
                let target = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for (index, fd) in files.iter().enumerate() {
                    target.add(index).write_unaligned(fd.as_raw_fd());
                }
            }
        }
        require(
            unsafe {
                libc::sendmsg(
                    self.0.as_raw_fd(),
                    &message,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            } == body.len() as isize,
            "packet send failed; no automatic retry",
        )
    }
    pub fn receive(
        &self,
        maximum: usize,
        expected_files: usize,
        timeout: Duration,
    ) -> Result<Message> {
        self.receive_counts(maximum, &[expected_files], timeout)
    }
    /// Accept only an explicit closed set of descriptor counts. The caller
    /// must then bind the wire version to its exact count before using any FD.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR and others)."
    )]
    pub fn receive_counts(
        &self,
        maximum: usize,
        expected_files: &[usize],
        timeout: Duration,
    ) -> Result<Message> {
        require(
            (1..=MAX_BYTES).contains(&maximum)
                && !expected_files.is_empty()
                && expected_files.len() <= MAX_FILES + 1
                && expected_files.iter().all(|n| *n <= MAX_FILES)
                && expected_files
                    .iter()
                    .enumerate()
                    .all(|(i, n)| !expected_files[..i].contains(n)),
            "packet receive bound",
        )?;
        self.wait(libc::POLLIN, timeout)?;
        let mut body = vec![0u8; maximum];
        let mut control = [0usize; 32];
        let mut iov = libc::iovec {
            iov_base: body.as_mut_ptr().cast(),
            iov_len: body.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let size = unsafe {
            libc::recvmsg(
                self.0.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        require(size >= 0, "packet receive failed")?;
        let mut files = Vec::new();
        let mut credentials = None;
        let mut valid = true;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let length = (*header).cmsg_len;
                let base = libc::CMSG_LEN(0) as usize;
                if length < base {
                    valid = false;
                    break;
                }
                let bytes = length - base;
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    valid &= bytes.is_multiple_of(std::mem::size_of::<libc::c_int>());
                    for index in 0..bytes / std::mem::size_of::<libc::c_int>() {
                        let fd = libc::CMSG_DATA(header)
                            .cast::<libc::c_int>()
                            .add(index)
                            .read_unaligned();
                        if fd >= 0 {
                            files.push(OwnedFd::from_raw_fd(fd));
                        } else {
                            valid = false;
                        }
                    }
                } else if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_CREDENTIALS
                {
                    if bytes != std::mem::size_of::<libc::ucred>() || credentials.is_some() {
                        valid = false;
                    } else {
                        let c = libc::CMSG_DATA(header)
                            .cast::<libc::ucred>()
                            .read_unaligned();
                        valid &= c.pid > 0;
                        credentials = Some(Credentials {
                            pid: c.pid as u32,
                            uid: c.uid,
                            gid: c.gid,
                        });
                    }
                } else {
                    valid = false;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        // OwnedFd drops every delivered descriptor on any malformed/truncated refusal.
        require(
            valid
                && size > 0
                && size as usize <= maximum
                && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && expected_files.contains(&files.len())
                && credentials.is_some(),
            "packet shape, descriptors or kernel credentials refused",
        )?;
        body.truncate(size as usize);
        Ok(Message {
            body,
            files,
            sender: credentials.ok_or_else(|| Error("packet credentials missing".into()))?,
        })
    }
}
impl AsFd for Packet {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
