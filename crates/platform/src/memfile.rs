// SPDX-License-Identifier: MIT
//! Read-only, immutable RAM files for signing and verified recovery handoff.
use crate::{Error, Result, require};
use std::{
    fs::File,
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::MetadataExt,
};
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, fcntl, memfd_create)."
)]
pub fn sealed(name: &str, body: &[u8]) -> Result<File> {
    require(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && !body.is_empty()
            && body.len() <= 256 * 1024 * 1024,
        "sealed RAM file bounds",
    )?;
    let name = std::ffi::CString::new(name).map_err(|_| Error("RAM file name".into()))?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    require(fd >= 0, "sealed RAM file creation failed")?;
    let mut writable = unsafe { File::from_raw_fd(fd) };
    require(
        unsafe { libc::fchmod(fd, 0o600) } == 0,
        "RAM file permissions",
    )?;
    writable.write_all(body)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    require(
        unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } == 0,
        "RAM file sealing failed",
    )?;
    // This is intentionally the descriptor we just created, not an input path.
    // kexec_file_load also requires a read-only open description after sealing.
    let readonly = File::open(format!("/proc/self/fd/{fd}"))?;
    let a = writable.metadata()?;
    let b = readonly.metadata()?;
    require(
        (a.dev(), a.ino(), a.uid(), a.mode(), a.len())
            == (b.dev(), b.ino(), b.uid(), b.mode(), b.len())
            && b.len() == body.len() as u64
            && unsafe { libc::fcntl(readonly.as_raw_fd(), libc::F_GET_SEALS) } == seals
            && unsafe { libc::fcntl(readonly.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                == libc::O_RDONLY,
        "sealed RAM file read-only identity",
    )?;
    drop(writable);
    Ok(readonly)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
pub fn read_sealed(file: &File, maximum: usize, owner: u32) -> Result<Vec<u8>> {
    require(
        (1..=256 * 1024 * 1024).contains(&maximum),
        "sealed RAM read bound",
    )?;
    let metadata = file.metadata()?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    require(
        metadata.is_file()
            && metadata.nlink() == 0
            && metadata.uid() == owner
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() > 0
            && metadata.len() <= maximum as u64
            && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == seals
            && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                == libc::O_RDONLY,
        "immutable read-only RAM request required",
    )?;
    crate::files::read_file(file, maximum, Some(owner), false)
}
