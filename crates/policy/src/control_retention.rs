// SPDX-License-Identifier: MIT
//! Bounded history for the update, boot and root control registries.
//!
//! Every update adds receipts to registries that transition-idle admission
//! reads with a fixed bound (32 to 128). Once one filled, nearly every system
//! operation refused. Completed rows are history, but some are also read as
//! references to generations or roots: boot retirement treats complete rows as
//! historical, while root retirement still protects a completed rebind's
//! source and snapshot and resolves a deleted Root through its birth. A row is
//! therefore retired only when it is finished *and* nothing it names is still
//! live: its generation is no longer in the boot catalog (and is not the last
//! update source), or its roots/snapshots no longer exist as subvolumes. The
//! newest rows are always kept. Runs under the operation lock before any
//! transition-idle snapshot of the caller observes these registries.
use crate::{
    control_registry::{self, Folder},
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files};
use serde_json::{Value, json};
use std::collections::BTreeSet;
/// Newest rows always kept in each registry.
pub(crate) const KEEP: usize = 8;
const LIMIT: usize = crate::catalog::MAX_CATALOG;
/// (folder, registry bound). Retirement starts at three quarters of the bound.
pub(crate) const REGISTRIES: [(&str, usize); 8] = [
    ("boot-publications", 128),
    ("update-workers", crate::update_worker_record::MAXIMUM),
    ("module-views", crate::module_view_record::MAXIMUM),
    ("authority-refresh", crate::authority_record::MAXIMUM),
    ("boot-retirements", crate::retirement_journal::MAX_RECORDS),
    ("root-rebind-journal", 32),
    ("root-births", crate::birth_runtime::MAX_RECORDS),
    ("root-retirements", 16),
];
pub(crate) const fn trigger(bound: usize) -> usize {
    bound * 3 / 4
}
/// Live state that keeps a finished row as a reference.
pub(crate) struct Live {
    pub filesystem: String,
    pub generations: BTreeSet<String>,
    pub last_update: Option<String>,
    /// UUIDs of every existing subvolume.
    pub subvolumes: BTreeSet<String>,
    /// Births still named by an unfinished root retirement or a recovery job.
    pub claimed_births: BTreeSet<String>,
}
impl Live {
    fn generation(&self, name: &str) -> bool {
        self.generations.contains(name) || self.last_update.as_deref() == Some(name)
    }
    /// Whether update apply `id` still has a generation (or is the last update).
    fn update(&self, id: &str) -> bool {
        self.generation(id) || self.generation(&format!("old-{id}"))
    }
    fn subvolume(&self, object: &Value) -> bool {
        // Unknown identity shape is treated as live.
        object["uuid"]
            .as_str()
            .is_none_or(|uuid| self.subvolumes.contains(uuid))
    }
}
fn same_filesystem(row: &Value, live: &Live) -> bool {
    [
        &row["filesystem_uuid"],
        &row["request"]["filesystem_uuid"],
        &row["intent"]["filesystem_uuid"],
    ]
    .iter()
    .any(|v| v.as_str() == Some(live.filesystem.as_str()))
}
/// Whether a validated row of `folder` is finished history that names nothing
/// live. Unknown folders and unknown phases are never retirable.
pub(crate) fn retirable(folder: &str, id: &str, row: &Value, live: &Live) -> bool {
    if !same_filesystem(row, live) {
        return false;
    }
    match folder {
        "boot-publications" => row["phase"] == "complete" && !live.generation(id),
        "update-workers" | "module-views" => row["phase"] == "complete" && !live.update(id),
        // Authority publications name no generation or root.
        "authority-refresh" => row["phase"] == "complete",
        "boot-retirements" => {
            row["phase"] == "complete"
                && id
                    .strip_prefix("boot-")
                    .is_some_and(|generation| !live.generation(generation))
        }
        // A rebind's source is always the configured live Root (protected as
        // such) and its snapshot the update's fallback Root. Once both boot
        // generations of that update are retired, the row names nothing
        // bootable; requiring the snapshot to vanish kept every row forever
        // (fallback Roots are only removed by an explicit root retirement),
        // filling the 32-row registry after about 32 updates.
        "root-rebind-journal" => row["phase"] == "complete" && !live.update(id),
        // A deleted Root resolves its finish through its birth.
        "root-births" => {
            row["phase"] == "retired"
                && !live.claimed_births.contains(id)
                && !live.subvolume(&row["root"])
                && !live.subvolume(&row["history"])
        }
        "root-retirements" => {
            (row["phase"] == "complete"
                && row["targets"]
                    .as_array()
                    .is_some_and(|targets| targets.iter().all(|t| !live.subvolume(t))))
                // An abandoned receipt owns nothing: its remaining targets stay
                // with their births and it no longer refuses transitions.
                || row["phase"] == "abandoned"
        }
        _ => false,
    }
}
fn validate(folder: &str, filesystem: &str, v: &Value, id: &str) -> Result<()> {
    match folder {
        "boot-publications" => crate::generation_publication::validate(v, id),
        "update-workers" => crate::update_worker_record::validate(v, id),
        "module-views" => crate::module_view_record::validate(v, id),
        "authority-refresh" => crate::authority_record::validate(v, id),
        "boot-retirements" => crate::retirement_journal::validate(v, id),
        "root-rebind-journal" => crate::root_rebind_record::validate(v, id),
        "root-births" => crate::birth::validate(v, id, filesystem),
        "root-retirements" => crate::root_retirement_record::validate(v, id),
        _ => Err(enzimos_platform::Error("unknown retention registry".into())),
    }
}
fn open(guard: &Guard, folder: &str, filesystem: &str) -> Result<Option<Folder>> {
    Folder::open(
        guard.control(),
        guard.control_mount_id(),
        0,
        folder,
        LIMIT,
        |v, id| validate(folder, filesystem, v, id),
    )
}
/// Whether any registry reached its retirement trigger.
pub(crate) fn needed(guard: &Guard) -> Result<bool> {
    for (folder, bound) in REGISTRIES {
        if let Some(directory) = files::optional_directory_relative(
            guard.control(),
            std::path::Path::new(folder),
            Some(0),
        )? && files::directory_names(&directory, 4096)?.len() >= trigger(bound)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Retire finished, unreferenced rows of every registry that reached its
/// trigger. The caller holds the operation lock.
pub(crate) fn retire_locked(
    guard: &Guard,
    lock: &files::Lock,
    generations: BTreeSet<String>,
    last_update: Option<String>,
) -> Result<Value> {
    crate::operation::root_only()?;
    guard.recheck()?;
    lock.recheck()?;
    if !needed(guard)? {
        return Ok(json!({}));
    }
    let filesystem = crate::recovery_records::text(&guard.configuration, "filesystem_uuid")?;
    let subvolumes = crate::birth_runtime::inventory(false)?
        .values()
        .filter_map(|row| row["uuid"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    // Every root retirement that is not complete or abandoned still names its birth.
    let claimed_births = open(guard, "root-retirements", filesystem)?
        .map(|registry| {
            registry
                .members
                .values()
                .filter(|m| {
                    m.value.as_ref().is_none_or(|v| {
                        !matches!(v["phase"].as_str(), Some("complete" | "abandoned"))
                    })
                })
                .filter_map(|m| m.value.as_ref())
                .filter_map(|v| v["birth"].as_str().map(str::to_owned))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    // A recovery plan names its source birth; keep any birth a job names.
    let mut claimed_births = claimed_births;
    let jobs = crate::recovery_journal::Journal::open(crate::recovery_journal::Kind::Jobs, false)?;
    for job in jobs.records.values() {
        if let Some(birth) = job["plan"]["source_birth"]["transaction"].as_str() {
            claimed_births.insert(birth.to_owned());
        }
    }
    jobs.unchanged()?;
    let live = Live {
        filesystem: filesystem.to_owned(),
        generations,
        last_update,
        subvolumes,
        claimed_births,
    };
    let mut result = serde_json::Map::new();
    for (folder, bound) in REGISTRIES {
        guard.recheck()?;
        lock.recheck()?;
        let Some(mut registry) = open(guard, folder, filesystem)? else {
            continue;
        };
        if registry.len() < trigger(bound) {
            continue;
        }
        // A root retirement whose row failed validation might name any birth.
        if folder == "root-births"
            && open(guard, "root-retirements", filesystem)?
                .is_some_and(|r| r.foreign > 0 || r.members.values().any(|m| m.value.is_none()))
        {
            continue;
        }
        let rows = registry.rows(|id, row| retirable(folder, id, row, &live));
        let mut retired = Vec::new();
        for id in control_registry::select(rows, KEEP, 0) {
            if registry.retire(&id)? {
                retired.push(id);
            }
        }
        if !retired.is_empty() {
            registry.sync()?;
            result.insert(folder.into(), json!(retired));
        }
    }
    guard.recheck()?;
    lock.recheck()?;
    Ok(Value::Object(result))
}
/// Whether a validated root receipt was abandoned before deleting anything.
pub(crate) fn unstarted_abandoned(row: &Value) -> bool {
    row["phase"] == "abandoned"
        && row.get("coordinator").is_none()
        && row["next_step"] == 0
        && row["inflight"].is_null()
}
/// Retire abandoned root receipts that never deleted anything, whatever the
/// registry size: such a row names nothing and, while it exists, its Root can
/// never be planned again. The caller holds the operation lock.
pub(crate) fn retire_unstarted_abandoned_locked(
    guard: &Guard,
    lock: &files::Lock,
) -> Result<Value> {
    crate::operation::root_only()?;
    guard.recheck()?;
    lock.recheck()?;
    let filesystem = crate::recovery_records::text(&guard.configuration, "filesystem_uuid")?;
    let Some(mut registry) = open(guard, "root-retirements", filesystem)? else {
        return Ok(json!([]));
    };
    let selected = registry
        .members
        .iter()
        .filter(|(_, m)| {
            m.value
                .as_ref()
                .is_some_and(|v| v["filesystem_uuid"] == filesystem && unstarted_abandoned(v))
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let mut retired = Vec::new();
    for id in selected {
        guard.recheck()?;
        lock.recheck()?;
        if registry.retire(&id)? {
            retired.push(id);
        }
    }
    if !retired.is_empty() {
        registry.sync()?;
    }
    guard.recheck()?;
    lock.recheck()?;
    Ok(json!(retired))
}
