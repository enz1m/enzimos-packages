// SPDX-License-Identifier: MIT
//! Mount identity of open descriptors.
use crate::{Result, require};
use std::os::fd::{AsRawFd, BorrowedFd};
/// Linux statx, with a boot-unique ID when requested (kernel >= 6.8).
///
/// # Errors
///
/// Fails when statx fails or does not report the requested ID.
#[allow(unsafe_code, reason = "Linux syscall ABI (statx).")]
pub fn id(fd: BorrowedFd<'_>, unique: bool) -> Result<u64> {
    let requested = if unique { 0x4000 } else { 0x1000 };
    // SAFETY: `libc::statx` is a plain C struct, for which all-zero bytes are a valid value.
    let mut status: libc::statx = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: The empty path is a NUL-terminated literal, `status` is writable, and `fd` is
        // borrowed open.
        unsafe {
            libc::statx(
                fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                requested,
                &mut status,
            )
        } == 0
            && status.stx_mask & requested == requested
            && status.stx_mnt_id > 0,
        "mount identity unavailable",
    )?;
    Ok(status.stx_mnt_id)
}
