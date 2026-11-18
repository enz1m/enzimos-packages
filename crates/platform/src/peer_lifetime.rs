// SPDX-License-Identifier: MIT
//! Original user process lifetime, without restricting legitimate client images.
use crate::{Result, files, process_identity, require};
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
};
pub struct PeerLifetime {
    pid: u32,
    uid: u32,
    start: u64,
    pidfd: File,
}
fn observe(pid: u32, uid: u32) -> Result<u64> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = files::read_kernel_owned(&root.join("stat"), 8192, uid)?;
    let stat = process_identity::parse_stat(
        std::str::from_utf8(&stat).map_err(|_| crate::Error("peer process encoding".into()))?,
        pid,
    )?;
    require(
        !matches!(stat.state, 'Z' | 'X' | 'x') && stat.start_ticks > 0,
        "original caller process exited",
    )?;
    let status = files::read_kernel_owned(&root.join("status"), 65536, uid)?;
    let uids = process_identity::parse_uids(
        std::str::from_utf8(&status).map_err(|_| crate::Error("peer status encoding".into()))?,
    )?;
    require(
        uids.iter().all(|n| *n == uid),
        "original caller process UID changed",
    )?;
    let again = files::read_kernel_owned(&root.join("stat"), 8192, uid)?;
    let again = process_identity::parse_stat(
        std::str::from_utf8(&again).map_err(|_| crate::Error("peer process encoding".into()))?,
        pid,
    )?;
    require(
        again.start_ticks == stat.start_ticks && !matches!(again.state, 'Z' | 'X' | 'x'),
        "caller process changed during observation",
    )?;
    Ok(stat.start_ticks)
}
impl PeerLifetime {
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    pub fn capture(pid: u32, uid: u32) -> Result<Self> {
        require(
            (1..i32::MAX as u32).contains(&pid) && (1000..i32::MAX as u32).contains(&uid),
            "caller process identity bounds",
        )?;
        let start = observe(pid, uid)?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        require(fd >= 0, "caller process pidfd unavailable")?;
        let this = Self {
            pid,
            uid,
            start,
            pidfd: unsafe { File::from_raw_fd(fd) },
        };
        this.recheck()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    fn alive(&self) -> Result<()> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(
            unsafe { libc::poll(&mut descriptor, 1, 0) } == 0 && descriptor.revents == 0,
            "original caller process no longer alive",
        )
    }
    pub fn recheck(&self) -> Result<()> {
        self.alive()?;
        require(
            observe(self.pid, self.uid)? == self.start,
            "original caller PID/start changed",
        )?;
        self.alive()
    }
}
