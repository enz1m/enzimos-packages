// SPDX-License-Identifier: MIT
//! The next global-lock entrant cannot replay an interrupted native apply.
use crate::{control_registry, operation, storage_runtime::Guard, update_apply_record};
use enzimos_platform::{Result, files, json, require};
use serde_json::Value;
use std::path::Path;
/// Every caller holds the operation lock, which the apply coordinator keeps
/// for the whole apply: an unfinished record seen here belongs to a
/// coordinator that already exited (error or crash). One that stopped after
/// its fallback snapshot was born but before publishing it to the boot
/// loaders (and so before any rebind) never changed what boots or runs, so it
/// ends as `failed-after-fallback` instead of blocking every operation.
fn resolve_interrupted(guard: &Guard, id: &str, row: &Value) -> Result<bool> {
    if !update_apply_record::fallback_only(row)
        || row["filesystem_uuid"] != guard.configuration["filesystem_uuid"]
    {
        return Ok(false);
    }
    // Publishing `old-<id>` makes it the default entry of both boot loaders
    // before the rebind starts. Only an apply that never began publishing its
    // fallback left the boot configuration untouched; anything later keeps
    // blocking for review, or the next reboot would silently boot the frozen
    // pre-update snapshot.
    if row["phase"] != "fallback-born" {
        return Ok(false);
    }
    if let Some(publications) = files::optional_directory_relative(
        guard.control(),
        Path::new("boot-publications"),
        Some(0),
    )? && files::optional_relative(&publications, Path::new(&format!("old-{id}.json")))?
        .is_some()
    {
        return Ok(false);
    }
    let name = format!("{id}.json");
    if let Some(rebinds) = files::optional_directory_relative(
        guard.control(),
        Path::new("root-rebind-journal"),
        Some(0),
    )? && files::optional_relative(&rebinds, Path::new(&name))?.is_some()
    {
        return Ok(false);
    }
    let next = update_apply_record::advance(
        row,
        update_apply_record::FAILED_FALLBACK,
        &serde_json::json!({"reason":"apply stopped before its root rebind"}),
        Some(update_apply_record::FAILED_FALLBACK_RESULT),
    )?;
    let directory =
        files::directory_relative(guard.control(), Path::new("update-applies"), Some(0))?;
    let original = files::open_relative(&directory, Path::new(&name))?;
    require(
        json::decode(
            &files::read_file(&original, crate::catalog::MAX_CATALOG, Some(0), true)?,
            crate::catalog::MAX_CATALOG,
        )? == *row,
        "interrupted apply changed before resolution",
    )?;
    guard.recheck()?;
    files::atomic_replace_original(
        &directory,
        Path::new(&name),
        &json::canonical(&next)?,
        0o600,
        Some(0),
        crate::catalog::MAX_CATALOG,
        &original,
    )?;
    Ok(true)
}
pub fn entry() -> Result<()> {
    let path = Path::new(operation::CONTROL);
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    let directory = files::directory(path, Some(0))?;
    // Early installer/media policy has no installed apply registry. A present
    // registry requires the complete independent installed storage guard.
    if files::optional_directory_relative(&directory, Path::new("update-applies"), Some(0))?
        .is_none()
    {
        return Ok(());
    }
    let guard = Guard::observe()?;
    let mut records = control_registry::read(
        &guard,
        "update-applies",
        update_apply_record::MAXIMUM,
        update_apply_record::validate,
    )?;
    let mut resolved = false;
    for (id, row) in &records {
        resolved |= resolve_interrupted(&guard, id, row)?;
    }
    if resolved {
        records = control_registry::read(
            &guard,
            "update-applies",
            update_apply_record::MAXIMUM,
            update_apply_record::validate,
        )?;
    }
    require(
        records.values().all(|row| {
            update_apply_record::finished(row)
                && row["filesystem_uuid"] == guard.configuration["filesystem_uuid"]
        }),
        "unfinished or foreign native update apply requires review",
    )
}

/// Independent recovery holds the actual top/control mounts and validated plan.
/// Completed update records remain mandatory; no interrupted apply is adopted.
pub fn independent_entry(plan: &serde_json::Value) -> Result<()> {
    let guard = crate::storage_runtime::IndependentGuard::observe(plan)?;
    let records = control_registry::read_independent(
        &guard,
        "update-applies",
        update_apply_record::MAXIMUM,
        update_apply_record::validate,
    )?;
    require(
        records.values().all(|row| {
            update_apply_record::finished(row) && row["filesystem_uuid"] == plan["filesystem_uuid"]
        }),
        "unfinished or foreign native update apply requires review",
    )?;
    guard.recheck()
}
