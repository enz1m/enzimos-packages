// SPDX-License-Identifier: MIT
//! Credentials on an Assuan greeting identify its sender after daemonization.
use enzimos_platform::{Error, Result, require};
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    time::{Duration, Instant},
};
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
fn wait(fd: i32, events: i16, end: Instant) -> Result<()> {
    loop {
        let remaining = end.saturating_duration_since(Instant::now());
        require(
            !remaining.is_zero(),
            "development agent connection deadline",
        )?;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(
            result > 0
                && poll.revents & events != 0
                && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "development agent peer unavailable",
        )?;
        return Ok(());
    }
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR and others)."
)]
pub(crate) fn sender(path: &Path, owner: u32) -> Result<u32> {
    let bytes = path.as_os_str().as_encoded_bytes();
    require(
        bytes.len() < 108 && !bytes.contains(&0),
        "development agent socket address bound",
    )?;
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    require(raw >= 0, "development agent socket creation failed")?;
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let yes: libc::c_int = 1;
    // Enable before connecting: credentials must stamp data queued by the
    // daemon, rather than the PID that originally created its listening socket.
    require(
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&yes as *const i32).cast(),
                4,
            )
        } == 0,
        "development agent greeting credentials unavailable",
    )?;
    // SAFETY: `libc::sockaddr_un` is a plain C struct, for which all-zero bytes are a valid value.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    let result = unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_un).cast(),
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as _,
        )
    };
    require(
        result == 0
            || matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINPROGRESS | libc::EAGAIN)
            ),
        "development agent socket connect failed",
    )?;
    let end = Instant::now() + Duration::from_secs(5);
    wait(raw, libc::POLLOUT, end)?;
    let mut error: libc::c_int = 0;
    let mut size = 4u32;
    require(
        unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut size,
            )
        } == 0
            && error == 0,
        "development agent socket connect outcome",
    )?;
    let mut body = Vec::new();
    let mut sender = None;
    loop {
        wait(raw, libc::POLLIN, end)?;
        let mut bytes = [0u8; 4096];
        let mut ancillary = [0usize; 32];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: `libc::msghdr` is a plain C struct, for which all-zero bytes are a valid value.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        let count = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        require(count > 0, "development agent greeting unavailable")?;
        let mut credential = None;
        let mut valid = true;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let base = libc::CMSG_LEN(0) as usize;
                if (*header).cmsg_len < base {
                    valid = false;
                    break;
                }
                let length = (*header).cmsg_len - base;
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_CREDENTIALS
                    && length == std::mem::size_of::<libc::ucred>()
                    && credential.is_none()
                {
                    credential = Some(
                        libc::CMSG_DATA(header)
                            .cast::<libc::ucred>()
                            .read_unaligned(),
                    );
                } else {
                    valid = false;
                    if (*header).cmsg_level == libc::SOL_SOCKET
                        && (*header).cmsg_type == libc::SCM_RIGHTS
                    {
                        for index in 0..length / std::mem::size_of::<i32>() {
                            let fd = libc::CMSG_DATA(header)
                                .cast::<i32>()
                                .add(index)
                                .read_unaligned();
                            if fd >= 0 {
                                drop(OwnedFd::from_raw_fd(fd));
                            }
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        let credentials = credential
            .ok_or_else(|| Error("development agent greeting lacks kernel credentials".into()))?;
        require(
            valid
                && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && credentials.pid > 1
                && credentials.uid == owner
                && credentials.gid == enzimos_platform::process_identity::effective_gid(),
            "development agent greeting credentials differ",
        )?;
        let pid = credentials.pid as u32;
        require(
            sender.is_none_or(|before| before == pid),
            "development agent greeting sender changed",
        )?;
        sender = Some(pid);
        body.extend_from_slice(&bytes[..count as usize]);
        require(
            body.len() <= 4096 && !body.contains(&0),
            "development agent greeting byte bound",
        )?;
        if body.contains(&b'\n') {
            require(
                body.starts_with(b"OK "),
                "development agent Assuan greeting refused",
            )?;
            return Ok(pid);
        }
    }
}
