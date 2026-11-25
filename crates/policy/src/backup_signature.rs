// SPDX-License-Identifier: MIT
//! Low-level signature observations borrow a selected device; they grant no mount authority.
use crate::{backup_candidates::Selection, block, identity, settings_command::Command};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    os::fd::{AsRawFd, BorrowedFd},
    time::{Duration, Instant},
};
fn decode(bytes: &[u8], alias: &str, expected_uuid: &str) -> Result<Value> {
    identity::uuid(expected_uuid)?;
    require(bytes.len() <= 4096, "backup signature byte bound")?;
    let text = std::str::from_utf8(bytes).map_err(|_| Error("backup signature encoding".into()))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error("backup signature field required".into()))?;
        require(
            ["DEVNAME", "TYPE", "UUID", "UUID_SUB", "USAGE"].contains(&key)
                && fields.insert(key, value).is_none(),
            "unknown/duplicate backup signature field",
        )?;
    }
    require(
        fields.len() == 5
            && fields.get("DEVNAME") == Some(&alias)
            && fields.get("TYPE") == Some(&"btrfs")
            && fields.get("USAGE") == Some(&"filesystem")
            && fields.get("UUID") == Some(&expected_uuid),
        "backup signature identity mismatch",
    )?;
    let device = identity::uuid(fields["UUID_SUB"])?;
    require(
        device != expected_uuid,
        "backup signature device UUID aliases filesystem",
    )?;
    Ok(
        json!({"filesystem_uuid":expected_uuid,"device_uuid":device,"content":"btrfs-signature","filesystem_verified":false}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (lseek).")]
fn offset(fd: BorrowedFd<'_>) -> Result<i64> {
    require(
        enzimos_platform::files::status_flags(&fd) & libc::O_ACCMODE == libc::O_RDONLY,
        "read-only backup signature descriptor required",
    )?;
    let position = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) };
    require(
        position >= 0,
        "backup signature descriptor position unavailable",
    )?;
    Ok(position)
}
pub fn observe(selection: &Selection<'_>) -> Result<Value> {
    selection.recheck()?;
    let descriptor = selection.descriptor()?;
    let before = block::observe(descriptor)?;
    let position = offset(descriptor)?;
    let vendor = Command::open("/usr/bin/blkid")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let query = || -> Result<Value> {
        let (bytes, aliases) = vendor.descriptor_query(
            &[
                "--probe",
                "--output",
                "export",
                "--match-tag",
                "TYPE",
                "--match-tag",
                "UUID",
                "--match-tag",
                "UUID_SUB",
                "--match-tag",
                "USAGE",
                "--",
                "@fd:0",
            ],
            4096,
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(15)),
            &[descriptor],
        )?;
        require(
            aliases.len() == 1,
            "backup signature child descriptor mapping required",
        )?;
        decode(&bytes, &aliases[0], selection.uuid_hint())
    };
    let first = query()?;
    require(
        query()? == first
            && block::observe(descriptor)? == before
            && offset(descriptor)? == position,
        "backup signature changed during observation",
    )?;
    vendor.recheck()?;
    selection.recheck()?;
    require(
        block::observe(descriptor)? == before && offset(descriptor)? == position,
        "backup signature descriptor changed before return",
    )?;
    Ok(first)
}
