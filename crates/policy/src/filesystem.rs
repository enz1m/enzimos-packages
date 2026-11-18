// SPDX-License-Identifier: MIT
use enzimos_platform::{Result, require};
use serde_json::{Value, json};
use std::os::fd::{AsRawFd, BorrowedFd};

// Linux Btrfs UAPI: _IOR(0x94,31,struct btrfs_ioctl_fs_info_args).
const FILESYSTEM_INFO: libc::c_ulong = 0x8400941f;
// linux/fs.h FS_IOC_GETFSLABEL: _IOR(0x94,49,char[FSLABEL_MAX=256]).
const GET_LABEL: libc::c_ulong = 0x81009431;
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub fn label(fd: BorrowedFd<'_>) -> Result<Option<String>> {
    let before = observe(fd)?;
    let mut bytes = [0u8; 256];
    require(
        unsafe { libc::ioctl(fd.as_raw_fd(), GET_LABEL, bytes.as_mut_ptr()) } == 0,
        "original Btrfs filesystem label unavailable",
    )?;
    let label = label_bytes(&bytes)?;
    require(
        observe(fd)? == before,
        "original Btrfs label filesystem changed",
    )?;
    Ok(label)
}
fn label_bytes(bytes: &[u8; 256]) -> Result<Option<String>> {
    let length = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| enzimos_platform::Error("unterminated Btrfs label".into()))?;
    let label = std::str::from_utf8(&bytes[..length])
        .map_err(|_| enzimos_platform::Error("Btrfs label encoding".into()))?;
    require(
        !label.chars().any(|c| c < '\u{20}' || c == '\u{7f}'),
        "Btrfs label display control refused",
    )?;
    Ok((length != 0).then(|| label.to_owned()))
}

#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub fn observe(fd: BorrowedFd<'_>) -> Result<Value> {
    let mut buffer = [0u64; 128];
    require(
        unsafe { libc::ioctl(fd.as_raw_fd(), FILESYSTEM_INFO, buffer.as_mut_ptr()) } == 0,
        "Btrfs filesystem identity unavailable",
    )?;
    require(
        buffer[0] > 0 && buffer[1] > 0,
        "Btrfs filesystem members unavailable",
    )?;
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(16), 16) };
    let uuid = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            format!(
                "{}{b:02x}",
                if matches!(i, 4 | 6 | 8 | 10) { "-" } else { "" }
            )
        })
        .collect::<String>();
    Ok(json!({"filesystem_uuid":uuid,"members":buffer[1],"maximum_id":buffer[0]}))
}
