// SPDX-License-Identifier: MIT
//! Explicitly adopt a confirmed restored root; nothing is detached or deleted.
use crate::{
    birth_runtime, native_policy_files, operation, recovery_activation_runtime as runtime,
    recovery_confirmation,
    recovery_journal::{Journal, Kind},
    recovery_records as records,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::path::Path;
/// Adopt the confirmed restored root of activation `id` reviewed as `digest`.
///
/// # Errors
///
/// Fails when the activation is not selected with the reviewed intent, or adoption fails.
pub fn adopt_locked(id: &str, digest: &str, lock: &files::Lock) -> Result<Value> {
    records::job_id(id)?;
    crate::identity::sha(digest)?;
    let confirmation = recovery_confirmation::confirm_locked(lock)?;
    require(
        confirmation["id"] == id,
        "adoption identifier differs from actual restored boot",
    )?;
    let idle = Snapshot::adoption(id)?;
    let mut journal = Journal::open(Kind::Activations, false)?;
    let mut record = journal
        .records
        .get(id)
        .cloned()
        .ok_or_else(|| Error("selected activation missing".into()))?;
    require(
        record["phase"] == "selected" && record["intent"]["intent_sha256"] == digest,
        "selected activation with exact intent required",
    )?;
    let job = &record["intent"]["job"];
    let mode = if runtime::efi_guard()? {
        "uefi"
    } else {
        "bios"
    };
    require(
        record["observations"][mode]["boot_id"] == operation::boot_id()?
            && record["observations"][mode] == confirmation["observation"],
        "fresh actual restored-boot confirmation required",
    )?;
    let filesystem = records::text(&job["plan"], "filesystem_uuid")?;
    let target = records::text(&job["root"], "path")?;
    require(
        idle.guard.configuration["root_subvol"] == target
            && birth_runtime::observe(Path::new("/"), target, filesystem)?.1 == job["root"],
        "running restored root identity changed",
    )?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == record["intent"]["policy_files"],
        "running native policy changed",
    )?;
    let inventory = crate::recovery_context::subvolumes(Path::new("/"))?;
    let old = records::text(&job["plan"]["storage"], "root_subvol")?;
    let superseded = if old != target {
        inventory.get(old).cloned()
    } else {
        None
    };
    if let Some(expected) = &superseded {
        require(
            ["id", "uuid"]
                .iter()
                .all(|key| expected[*key] == job["plan"]["source_birth"]["source"][*key]),
            "superseded original root identity changed; adoption refused",
        )?;
        let mut top = crate::storage_runtime::TopMount::open(&idle.guard)?;
        require(
            birth_runtime::observe(&top.path().join(old), old, filesystem)?.1 == *expected,
            "superseded kernel identity changed",
        )?;
        top.recheck()?;
        top.close()?;
    }
    idle.recheck()?;
    journal.unchanged()?;
    let previous = record.clone();
    if let Some(identity) = superseded {
        record["superseded"] = json!({"identity":identity,"legacy_detached":false,"retired":false});
    }
    record["phase"] = json!("adopted");
    journal.save(id, record.clone(), Some(&previous), lock)?;
    idle.guard.recheck()?;
    Ok(
        json!({"status":"restored-root-adopted","id":id,"root_uuid":record["intent"]["job"]["root"]["uuid"],"updates_allowed_by_restored_policy":true,"old_roots_retired":false,"retirement_enabled":false}),
    )
}
