// SPDX-License-Identifier: MIT
//! Old preparing catalogs also block transitions, without acquiring a nested lock.
use crate::{catalog, control_record, generation_publication, operation, storage_runtime::Guard};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::Value;
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) fn document(data: &Value, active: Option<&Value>) -> Result<()> {
    catalog::validate(data, data["filesystem_uuid"].as_str().unwrap_or(""))?;
    for (name, row) in enzimos_platform::json::object(&data["generations"])? {
        if row["state"] == "ready" {
            continue;
        }
        let active = active.ok_or_else(|| {
            enzimos_platform::Error("unfinished boot catalog requires review".into())
        })?;
        generation_publication::validate(active, name)?;
        require(
            active["phase"] != "complete"
                && active["material"] == row["material"]
                && active["created_boot"] == row["created_boot"]
                && active["filesystem_uuid"] == data["filesystem_uuid"],
            "preparing generation differs from original publication intent",
        )?;
    }
    Ok(())
}
pub(crate) fn observe(guard: &Guard, active: Option<&Value>) -> Result<()> {
    observe_inner(guard, active, None)
}
pub(crate) fn observe_pending(
    guard: &Guard,
    active: Option<&Value>,
    pending: &enzimos_platform::publication::Prepared,
) -> Result<()> {
    observe_inner(guard, active, Some(pending))
}
fn observe_inner(
    guard: &Guard,
    active: Option<&Value>,
    pending: Option<&enzimos_platform::publication::Prepared>,
) -> Result<()> {
    guard.recheck()?;
    let path = Path::new(operation::CONTROL).join("generation-registry");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            require(
                pending.is_none(),
                "original catalog directory missing during pending publication",
            )?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    let directory = files::directory(&path, Some(0))?;
    let before = directory.metadata()?;
    require(
        before.mode() & 0o7777 == 0o700
            && mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
        "boot catalog directory protection or mount differs",
    )?;
    let pending_name = pending
        .map(|writer| writer.pending_name(&directory, Path::new("catalog.json")))
        .transpose()?;
    if let Some(writer) = pending {
        let original = control_record::Retained::optional_open(
            &directory,
            Path::new("catalog.json"),
            catalog::MAX_CATALOG,
            guard.control_mount_id(),
        )?
        .ok_or_else(|| {
            enzimos_platform::Error("pending catalog requires independently original record".into())
        })?;
        original.require_original_publication(writer)?;
    }
    let names = std::fs::read_dir(&path)?
        .take(5)
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    require(
        names.len() <= 2 + usize::from(pending.is_some())
            && names.iter().all(|name| {
                matches!(name.to_str(), Some("lock" | "catalog.json"))
                    || pending_name.is_some_and(|n| name == n)
            }),
        "interrupted boot catalog publication requires review",
    )?;
    if names.iter().any(|name| name == "catalog.json") {
        let data = control_record::read(
            &directory,
            Path::new("catalog.json"),
            catalog::MAX_CATALOG,
            guard.control_mount_id(),
        )?;
        require(
            data["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "boot catalog filesystem differs",
        )?;
        document(&data, active)?;
    }
    let named = files::directory(&path, Some(0))?;
    let after = named.metadata()?;
    require(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.gid(),
        ) == (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.gid(),
        ) && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
        "original boot catalog directory replaced",
    )?;
    guard.recheck()
}
