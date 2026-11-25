// SPDX-License-Identifier: MIT
//! Identity from a borrowed, already selected block descriptor. No device opens.
use enzimos_platform::{Result, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::fs::{FileTypeExt, MetadataExt},
    },
};
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn values(fd: i32) -> Result<(u64, u64, bool)> {
    let mut sequence = 0u64;
    let mut size = 0u64;
    let mut read_only = 0i32;
    for (request, ptr) in [
        (
            0x80081280u64,
            (&mut sequence as *mut u64).cast::<libc::c_void>(),
        ),
        (0x80081272u64, (&mut size as *mut u64).cast()),
        (0x125eu64, (&mut read_only as *mut i32).cast()),
    ] {
        require(
            // SAFETY: Each request is paired with a writable buffer of the size it writes (u64,
            // u64, int).
            unsafe { libc::ioctl(fd, request as libc::c_ulong, ptr) } == 0,
            "block identity ioctl failed",
        )?;
    }
    require(
        sequence > 0 && size > 0 && size < i64::MAX as u64 && matches!(read_only, 0 | 1),
        "invalid block identity",
    )?;
    Ok((sequence, size, read_only == 1))
}
pub fn observe(fd: BorrowedFd<'_>) -> Result<Value> {
    let file = File::from(fd.try_clone_to_owned()?);
    let before = file.metadata()?;
    require(
        before.file_type().is_block_device()
            && before.uid() == 0
            && before.mode() & 0o002 == 0
            && before.nlink() == 1,
        "protected block descriptor required",
    )?;
    let (sequence, size, ro) = values(file.as_raw_fd())?;
    let after = file.metadata()?;
    require(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.rdev(),
            before.nlink(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.gid(),
            after.rdev(),
            after.nlink(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) && values(file.as_raw_fd())? == (sequence, size, ro),
        "block identity changed during observation",
    )?;
    Ok(
        json!({"major":libc::major(before.rdev()),"minor":libc::minor(before.rdev()),"device_inode":before.ino(),"device_filesystem":before.dev(),"disk_sequence":sequence,"bytes":size,"read_only":ro}),
    )
}
