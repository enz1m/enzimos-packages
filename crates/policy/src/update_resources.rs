// SPDX-License-Identifier: MIT
//! Fixed update resource ceilings. Old boot generations and transient update
//! staging are retired automatically by `generation_retention` (daily timer and
//! before an apply that would exceed a ceiling); anything its boot-retirement
//! protections refuse stays and still blocks the next update for review.
use crate::{filesystem, operation};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub const BOOT_GENERATIONS: usize = 4;
pub const TRANSIENT_GENERATIONS: usize = 8;
pub const ROOT_RESERVE: u64 = 2 * 1024 * 1024 * 1024;
pub fn publication_required(artifact_bytes: u64, signed: bool) -> Result<u64> {
    artifact_bytes
        .checked_mul(if signed { 2 } else { 1 })
        .and_then(|bytes| bytes.checked_add(16 * 1024 * 1024))
        .ok_or_else(|| Error("generation ESP resource overflow".into()))
}
pub fn check(
    generations: usize,
    module_views: usize,
    boot_stages: usize,
    root_free: u64,
    esp_free: u64,
    artifact_bytes: u64,
    signed: bool,
) -> Result<()> {
    let root_required = ROOT_RESERVE
        .checked_add(artifact_bytes)
        .ok_or_else(|| Error("update root resource overflow".into()))?;
    let esp_required = publication_required(artifact_bytes, signed)?
        .checked_mul(2)
        .ok_or_else(|| Error("update ESP resource overflow".into()))?;
    require(
        generations
            .checked_add(2)
            .is_some_and(|count| count <= BOOT_GENERATIONS)
            && module_views < TRANSIENT_GENERATIONS
            && boot_stages < TRANSIENT_GENERATIONS,
        "update resource retention bound requires explicit review",
    )?;
    require(
        artifact_bytes > 0
            && artifact_bytes <= 4 * 128 * 1024 * 1024
            && root_free >= root_required
            && esp_free >= esp_required,
        "update filesystem space admission failed",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn available(directory: &File) -> Result<u64> {
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut info) } == 0,
        "update filesystem space unavailable",
    )?;
    info.f_bavail
        .checked_mul(info.f_frsize)
        .ok_or_else(|| Error("update filesystem space overflow".into()))
}
pub fn transient(name: &str, filesystem_uuid: &serde_json::Value) -> Result<usize> {
    require(
        matches!(name, "module-views" | "boot-stage"),
        "unknown update resource registry",
    )?;
    let state = files::directory(Path::new(operation::STATE), Some(0))?;
    let Some(directory) = files::optional_directory_relative(&state, Path::new(name), Some(0))?
    else {
        return Ok(0);
    };
    require(
        filesystem::observe(directory.as_fd())?["filesystem_uuid"] == *filesystem_uuid,
        "update resource filesystem differs",
    )?;
    let mount = mount_identity::id(directory.as_fd(), true)?;
    let entries = std::fs::read_dir(Path::new(operation::STATE).join(name))?
        .take(TRANSIENT_GENERATIONS + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    require(
        entries.len() < TRANSIENT_GENERATIONS,
        "update resource retention bound requires explicit review",
    )?;
    for entry in &entries {
        let name = entry.file_name();
        let text = name
            .to_str()
            .ok_or_else(|| Error("update resource name encoding".into()))?;
        crate::identity::safe_id(text)?;
        let held = files::directory_relative(&directory, Path::new(&name), Some(0))?;
        require(
            held.metadata()?.mode() & 0o7777 == 0o700
                && mount_identity::id(held.as_fd(), true)? == mount,
            "foreign or independently mounted update resource",
        )?;
    }
    Ok(entries.len())
}
