// SPDX-License-Identifier: MIT
//! Btrfs identities and creation use retained descriptors, never tool pathnames.
use crate::{identity, operation, storage_runtime};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::os::fd::{AsRawFd, BorrowedFd};

// Linux btrfs.h: GET_SUBVOL_INFO (504 bytes), VOL_ARGS_V2 (4096 bytes).
const INFO: libc::c_ulong = 0x81f8943c;
const SNAPSHOT: libc::c_ulong = 0x50009417;
const CREATE: libc::c_ulong = 0x50009418;
fn uuid(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            format!(
                "{}{b:02x}",
                if matches!(i, 4 | 6 | 8 | 10) { "-" } else { "" }
            )
        })
        .collect()
}
pub fn decode_info(bytes: &[u8], path: &str) -> Result<(Value, bool)> {
    require(bytes.len() == 504, "Btrfs subvolume info size")?;
    let number = |offset| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let id = number(0);
    require(
        id >= 256 && bytes[296..312].iter().any(|b| *b != 0),
        "Btrfs subvolume identity unavailable",
    )?;
    let parent = if bytes[312..328].iter().all(|b| *b == 0) {
        Value::Null
    } else {
        json!(uuid(&bytes[312..328]))
    };
    Ok((
        json!({"path":path,"id":id,"uuid":uuid(&bytes[296..312]),"parent_uuid":parent}),
        // GET_SUBVOL_INFO copies root-item flags (BTRFS_ROOT_SUBVOL_RDONLY,
        // bit0), not the creation/GETFLAGS BTRFS_SUBVOL_RDONLY bit1.
        // https://github.com/torvalds/linux/blob/master/include/uapi/linux/btrfs_tree.h
        number(288) & 1 != 0,
    ))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub fn observe(fd: BorrowedFd<'_>, path: &str) -> Result<(Value, bool)> {
    let mut buffer = [0u64; 63];
    require(
        unsafe { libc::ioctl(fd.as_raw_fd(), INFO, buffer.as_mut_ptr()) } == 0,
        "Btrfs subvolume identity unavailable",
    )?;
    // The aligned buffer has the exact UAPI size; decoding does not borrow beyond it.
    decode_info(
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 504) },
        path,
    )
}
/// Kernel identity of the containing root, including top-level ID5. Directory
/// inode256 alone does not distinguish different Btrfs subvolumes.
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub fn containing_identity(fd: BorrowedFd<'_>) -> Result<Value> {
    let mut buffer = [0u64; 63];
    require(
        unsafe { libc::ioctl(fd.as_raw_fd(), INFO, buffer.as_mut_ptr()) } == 0,
        "Btrfs containing root identity unavailable",
    )?;
    decode_containing_info(unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 504) })
}
pub fn decode_containing_info(bytes: &[u8]) -> Result<Value> {
    require(bytes.len() == 504, "Btrfs containing info size")?;
    let id = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let flags = u64::from_ne_bytes(bytes[288..296].try_into().unwrap());
    let present = bytes[296..312].iter().any(|byte| *byte != 0);
    require(
        (id == 5 || id >= 256) && (id == 5 || present) && flags & !1 == 0,
        "live Btrfs containing root ID/UUID/flags required",
    )?;
    Ok(
        json!({"id":id,"uuid":if present {Some(uuid(&bytes[296..312]))} else {None},
        "parent_uuid":if bytes[312..328].iter().any(|byte| *byte != 0) {Some(uuid(&bytes[312..328]))} else {None},"readonly":flags & 1 != 0}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub fn creation_time(fd: BorrowedFd<'_>) -> Result<i64> {
    let mut buffer = [0u64; 63];
    require(
        unsafe { libc::ioctl(fd.as_raw_fd(), INFO, buffer.as_mut_ptr()) } == 0,
        "Btrfs creation time unavailable",
    )?;
    // btrfs_ioctl_get_subvol_info_args.otime begins at byte 392.
    let seconds =
        i64::try_from(buffer[49]).map_err(|_| Error("Btrfs creation time bound".into()))?;
    require(
        (0..=253402300799).contains(&seconds),
        "Btrfs creation time bound",
    )?;
    Ok(seconds)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn create(
    parent: BorrowedFd<'_>,
    source: Option<BorrowedFd<'_>>,
    name: &str,
    readonly: bool,
) -> Result<()> {
    operation::root_only()?;
    storage_runtime::initial_namespace()?;
    if name != ".snapshots" {
        identity::safe_id(name)?;
    }
    require(
        name.len() <= 255 && (!readonly || source.is_some()),
        "invalid subvolume creation request",
    )?;
    let mut buffer = [0u64; 512];
    buffer[0] = source.map_or(-1i64, |fd| i64::from(fd.as_raw_fd())) as u64;
    buffer[2] = if readonly { 2 } else { 0 };
    let bytes = unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), 4096) };
    bytes[56..56 + name.len()].copy_from_slice(name.as_bytes());
    let request = if source.is_some() { SNAPSHOT } else { CREATE };
    if unsafe { libc::ioctl(parent.as_raw_fd(), request, buffer.as_mut_ptr()) } != 0 {
        return Err(Error(
            "new Btrfs subvolume creation refused; retain transaction for review".into(),
        ));
    }
    sync(parent)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub fn sync(fd: BorrowedFd<'_>) -> Result<()> {
    require(
        unsafe { libc::ioctl(fd.as_raw_fd(), 0x9408 as libc::c_ulong) } == 0,
        "Btrfs filesystem durability uncertain",
    )
}
/// Caller must hold the global operation lock and publish its intent first.
pub fn snapshot(
    parent: BorrowedFd<'_>,
    source: BorrowedFd<'_>,
    name: &str,
    readonly: bool,
) -> Result<()> {
    create(parent, Some(source), name, readonly)
}
/// Caller must hold the global operation lock and publish its intent first.
pub fn new(parent: BorrowedFd<'_>, name: &str) -> Result<()> {
    create(parent, None, name, false)
}

// Reviewed against Linux include/uapi/linux/btrfs.h and fs/btrfs/ioctl.c.
// Destroy-v2 SPEC_BY_ID selects the exact retained subvolume, never an equal name.
fn destruction_arguments(id: u64) -> Result<[u64; 512]> {
    require(
        id > 256 && id < (1u64 << 63),
        "refuse top-level or invalid snapshot subvolume",
    )?;
    let mut arguments = [0u64; 512];
    arguments[2] = 1 << 4; // flags: BTRFS_SUBVOL_SPEC_BY_ID
    arguments[7] = id; // union at byte56: subvolid
    Ok(arguments)
}
/// Private primitive: owning snapshot actor must enter durable cleanup first.
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub(crate) fn destroy_readonly_original(
    parent: BorrowedFd<'_>,
    original: BorrowedFd<'_>,
    expected: &Value,
) -> Result<()> {
    operation::root_only()?;
    storage_runtime::initial_namespace()?;
    let path = expected["path"]
        .as_str()
        .ok_or_else(|| Error("original snapshot path missing".into()))?;
    let (actual, readonly) = observe(original, path)?;
    require(
        readonly && actual == *expected,
        "readonly original subvolume identity changed",
    )?;
    require(
        crate::filesystem::observe(parent)?["filesystem_uuid"]
            == crate::filesystem::observe(original)?["filesystem_uuid"],
        "snapshot deletion crossed filesystem",
    )?;
    let mut arguments = destruction_arguments(actual["id"].as_u64().unwrap())?;
    require(
        unsafe {
            libc::ioctl(
                parent.as_raw_fd(),
                0x5000943fu64 as libc::c_ulong,
                arguments.as_mut_ptr(),
            )
        } == 0,
        "original snapshot deletion refused or uncertain; no name fallback/retry",
    )?;
    sync(parent)
}
