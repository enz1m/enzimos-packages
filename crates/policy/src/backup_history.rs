// SPDX-License-Identifier: MIT
//! Bounded history of finished backups across the per-backup control registries.
//!
//! Every backup job `J` leaves one receipt in each of several bounded
//! registries (source capture, its snapshots, boot capture, inventory stage,
//! SQLite exports, read-only trees, source receiver, transfer launch and worker)
//! plus one completion keyed by its attempt. Without retirement, backups stop
//! once the smallest registry fills. A job is finished history only when its
//! source capture reached `retired`: that phase is published after the closed
//! transfer, the retired inventory stage, the removed boot tree and every
//! retired snapshot, so none of its records still describes a live object.
//! Unfinished jobs (failed or interrupted) are never touched; they stay for
//! review. Retirement runs under the backup operation lock before a new
//! attempt observes any of these registries.
use crate::{control_registry::Folder, storage_runtime::Guard};
use enzimos_platform::{Result, files, json, require};
use serde_json::Value;
/// Newest finished backups whose receipts are always kept.
pub const KEEP: usize = 8;
/// Completion receipts kept (completions are keyed by attempt, not by job).
const KEEP_COMPLETIONS: usize = 16;
const LIMIT: usize = 8 * 1024 * 1024;
const CAPTURES: &str = "backup-source-captures";
const SNAPSHOTS: &str = "backup-source-snapshots";
const COMPLETIONS: &str = "backup-completions";
/// The snapshot registry holds 127 receipts and a job adds one per source
/// (at most 32): older jobs are retired until a full job still fits.
const SNAPSHOT_ROOM: usize = 127 - 32;
/// Registries whose members belong to exactly one job, with the receipt names
/// of job `J` and the phase that proves the receipt finished (None: any phase,
/// because the retired source capture already proves the transfer closed).
const MEMBERS: [(&str, Option<&str>); 8] = [
    (SNAPSHOTS, Some("snapshot-retired")),
    ("backup-database-exports", Some("retired")),
    ("backup-boot-captures", Some("retired")),
    ("backup-inventory-stages", Some("retired")),
    ("backup-readonly-trees", None),
    ("backup-source-receivers", None),
    ("backup-transfer-launches", None),
    ("backup-transfer-workers", None),
];
fn job(id: &str) -> bool {
    crate::backup_worker_request::id(id).is_ok()
}
/// Whether receipt `name` in `folder` belongs to job `j`.
pub(crate) fn belongs(folder: &str, name: &str, j: &str) -> bool {
    let digest = || json::sha256(j.as_bytes())[..48].to_owned();
    let indexed = |prefix: &str| {
        name.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()))
    };
    match folder {
        SNAPSHOTS => indexed(j),
        "backup-database-exports" => indexed(&format!("db-{}", digest())),
        "backup-boot-captures" => name == format!("boot-{}", digest()),
        _ => name == j,
    }
}
/// Finished jobs to retire, oldest first: all finished jobs beyond the newest
/// `KEEP`, plus older finished jobs while the snapshot registry lacks room for
/// one more job. The newest finished job is always kept.
pub(crate) fn select(
    mut finished: Vec<((i64, i64), String, usize)>,
    snapshots: usize,
) -> Vec<String> {
    finished.sort();
    let mut remaining = snapshots;
    let total = finished.len();
    let mut selected = Vec::new();
    for (index, (_, j, owned)) in finished.into_iter().enumerate() {
        let newer = total - index - 1;
        if newer == 0 {
            break;
        }
        if newer >= KEEP || remaining > SNAPSHOT_ROOM {
            remaining = remaining.saturating_sub(owned);
            selected.push(j);
        }
    }
    selected
}
fn terminal(folder: &str, value: Option<&Value>, name: &str, phase: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    value["id"] == name
        && match phase {
            Some(phase) => value["phase"] == phase,
            None => true,
        }
        && (folder != "backup-boot-captures" || value["boot_tree_removed"] == true)
}
fn open(guard: &Guard, folder: &str) -> Result<Option<Folder>> {
    Folder::open(
        guard.control(),
        guard.control_mount_id(),
        0,
        folder,
        LIMIT,
        |_, _| Ok(()),
    )
}
/// Retire the receipts of old finished backups. The caller holds the backup
/// operation lock and has not yet observed any of these registries.
pub fn retire_locked(guard: &Guard, lock: &files::Lock) -> Result<Value> {
    crate::operation::root_only()?;
    guard.recheck()?;
    lock.recheck()?;
    let Some(mut captures) = open(guard, CAPTURES)? else {
        return Ok(serde_json::json!({"retired":[]}));
    };
    let mut members = MEMBERS
        .iter()
        .map(|(folder, phase)| Ok((*folder, *phase, open(guard, folder)?)))
        .collect::<Result<Vec<_>>>()?;
    let snapshot_count = members
        .iter()
        .find(|(f, _, _)| *f == SNAPSHOTS)
        .and_then(|(_, _, f)| f.as_ref().map(Folder::len))
        .unwrap_or(0);
    let mut finished = Vec::new();
    for (j, member) in &captures.members {
        if !job(j) {
            continue;
        }
        let Some(value) = member.value.as_ref() else {
            continue;
        };
        if value["id"] != j.as_str()
            || value["phase"] != "retired"
            || value["source_cleanup_complete"] != true
        {
            continue;
        }
        // Every receipt of this job must be finished, or the whole job stays.
        let mut owned = 0;
        let mut complete = true;
        for (folder, phase, registry) in &members {
            let Some(registry) = registry else { continue };
            for name in registry.members.keys().filter(|n| belongs(folder, n, j)) {
                if *folder == SNAPSHOTS {
                    owned += 1;
                }
                complete &= terminal(folder, registry.value(name), name, *phase);
            }
        }
        if complete {
            finished.push((member.mtime, j.clone(), owned));
        }
    }
    let mut retired = Vec::new();
    for j in select(finished, snapshot_count) {
        guard.recheck()?;
        lock.recheck()?;
        for (folder, _, registry) in &mut members {
            let Some(registry) = registry else { continue };
            let names = registry
                .members
                .keys()
                .filter(|n| belongs(folder, n, &j))
                .cloned()
                .collect::<Vec<_>>();
            for name in names {
                registry.retire(&name)?;
            }
        }
        // The source capture is the job's finished proof: it goes last, so an
        // interrupted retirement is completed by the next run.
        captures.retire(&j)?;
        retired.push(j);
    }
    for (_, _, registry) in &members {
        if let Some(registry) = registry {
            registry.sync()?;
        }
    }
    captures.sync()?;
    let completions = crate::control_registry::retire_terminal(
        guard,
        COMPLETIONS,
        KEEP_COMPLETIONS,
        KEEP_COMPLETIONS + 16,
        LIMIT,
        |v, id| require(v["id"] == id, "completion receipt identity"),
        |_, v| v["phase"] == "completed" && v["backup_complete"] == true,
    )?;
    guard.recheck()?;
    lock.recheck()?;
    Ok(serde_json::json!({"retired":retired,"completions":completions}))
}

/// Newest failed backups whose receipts are kept for diagnostics; their
/// snapshots and staging are removed as soon as no process can use them.
pub const KEEP_FAILED: usize = 8;
const WORKERS: &str = "backup-transfer-workers";
const BOOTS: &str = "backup-boot-captures";
const STAGES: &str = "backup-inventory-stages";
/// Whether failed job `capture` may still have a process: its attempt still
/// runs in this boot, or (as [`crate::backup_attempt::blocks_live`]) the job
/// is from this boot and its transfer worker was never proven closed
/// (`worker`: None no record, Some(None) an unreadable one), unless the
/// attempt was abandoned.
fn live(
    capture: &Value,
    attempt: Option<&Value>,
    worker: Option<Option<&Value>>,
    boot: &str,
) -> bool {
    // An abandoned attempt was proven to have no owner, worker or Restic left.
    if attempt.is_some_and(|row| row["state"] == "abandoned") {
        return false;
    }
    if attempt.is_some_and(|row| crate::backup_attempt::blocks(row, boot)) {
        return true;
    }
    let this_boot = capture["boot_id"] == boot || attempt.is_some_and(|row| row["boot_id"] == boot);
    this_boot
        && match worker {
            None => false,
            Some(None) => true,
            Some(Some(worker)) => worker["phase"] != "worker-kernel-closed",
        }
}
/// What one source snapshot receipt of a failed job still owns. A number is
/// recorded from `created` on; `entered` (Snapper failed or its outcome was
/// never read) names no snapshot, so none is guessed or adopted. A retirement
/// that already removed the subvolume stops for review.
fn snapshot_leftover(receipt: &Value) -> Result<bool> {
    match receipt["phase"].as_str() {
        Some("entered" | "snapshot-retired") => Ok(false),
        Some("created" | "capture-sealed" | "subvolume-retirement-entered") => Ok(true),
        _ => Err(enzimos_platform::Error(
            "failed backup snapshot retirement was interrupted; review required".into(),
        )),
    }
}
/// The `(source, Snapper number)` pairs that backup snapshot receipts still
/// own: recorded at creation and not yet retired by their backup.
pub(crate) fn receipt_snapshots(
    guard: &Guard,
) -> Result<std::collections::BTreeSet<(String, u64)>> {
    let Some(registry) = open(guard, SNAPSHOTS)? else {
        return Ok(Default::default());
    };
    Ok(registry
        .members
        .values()
        .filter_map(|member| member.value.as_ref())
        .filter(|receipt| {
            !matches!(
                receipt["phase"].as_str(),
                Some("entered" | "snapshot-retired")
            )
        })
        .filter_map(|receipt| {
            Some((
                receipt["source"]["name"].as_str()?.to_owned(),
                receipt["snapshot"]["number"].as_u64()?,
            ))
        })
        .collect())
}
fn folder(control: &std::fs::File, mount: u64, owner: u32, name: &str) -> Result<Option<Folder>> {
    Folder::open(control, mount, owner, name, LIMIT, |_, _| Ok(()))
}
/// Clean up failed backups. A backup failed when its source capture never
/// reached `retired` and its attempt never completed: nothing else will ever
/// retire its snapshots, boot copy, staging or receipts.
///
/// The data of every failed backup that can no longer have a live process
/// goes at once: its source snapshots through `destroy` (the same exact-ID
/// retirement a finished backup uses) together with their receipts, so a
/// reused Snapper number is never mistaken for them, and its boot copy and
/// staging trees. A receipt still `entered` names no snapshot and stays with
/// the others. Only the receipts of the newest [`KEEP_FAILED`] failures stay
/// for diagnostics; older ones go, the capture last, so an interrupted run is
/// completed by the next one. A job that may still be live, or whose
/// leftovers cannot be proven, stays as it is.
pub(crate) fn retire_failed_in(
    control: &std::fs::File,
    mount: u64,
    owner: u32,
    boot: &str,
    destroy: &mut dyn FnMut(&Value) -> Result<()>,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let Some(mut captures) = folder(control, mount, owner, CAPTURES)? else {
        return Ok(serde_json::json!({"retired":[],"cleared":[],"kept":[]}));
    };
    let attempts = Folder::open(control, mount, owner, "backup-attempts", 8192, |v, id| {
        crate::backup_attempt::validate(v, id)
    })?;
    let workers = folder(control, mount, owner, WORKERS)?;
    let mut members = MEMBERS
        .iter()
        .map(|(name, _)| Ok((*name, folder(control, mount, owner, name)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut failed = Vec::new();
    for (j, member) in &captures.members {
        let Some(value) = member.value.as_ref() else {
            continue;
        };
        if !job(j) || value["id"] != j.as_str() || value["phase"] == "retired" {
            continue;
        }
        let attempt = value["attempt"]["id"]
            .as_str()
            .and_then(|id| attempts.as_ref()?.value(id));
        if attempt.is_some_and(|row| row["state"] == "completed") {
            continue;
        }
        let worker = workers
            .as_ref()
            .filter(|w| w.members.contains_key(j))
            .map(|w| w.value(j));
        failed.push(crate::control_registry::Row {
            order: member.mtime,
            id: j.clone(),
            retirable: !live(value, attempt, worker, boot),
        });
    }
    let expired = crate::control_registry::select(failed.clone(), KEEP_FAILED, 0);
    let mut retired = Vec::new();
    let mut cleared = Vec::new();
    let mut kept = Vec::new();
    for row in failed.into_iter().filter(|row| row.retirable) {
        let j = row.id;
        let whole = expired.contains(&j);
        let outcome = (|| -> Result<bool> {
            check()?;
            let mut removed = false;
            for (name, registry) in &mut members {
                let Some(registry) = registry else { continue };
                if *name != SNAPSHOTS {
                    continue;
                }
                let ids = registry
                    .members
                    .keys()
                    .filter(|n| belongs(name, n, &j))
                    .cloned()
                    .collect::<Vec<_>>();
                for id in ids {
                    let receipt = registry.value(&id).ok_or_else(|| {
                        enzimos_platform::Error("unreadable failed snapshot receipt".into())
                    })?;
                    // Snapper may have made a snapshot that `entered` cannot
                    // name; this receipt is its only record until expiry.
                    if receipt["phase"] == "entered" {
                        continue;
                    }
                    if snapshot_leftover(receipt)? {
                        check()?;
                        destroy(receipt)?;
                    }
                    check()?;
                    registry.retire(&id)?;
                    removed = true;
                }
                registry.sync()?;
            }
            // Boot copies and inventory staging are private trees named like
            // their receipt; the receipt is written before the tree exists.
            for name in [BOOTS, STAGES] {
                let Some(registry) = members
                    .iter()
                    .find(|(n, _)| *n == name)
                    .and_then(|(_, r)| r.as_ref())
                else {
                    continue;
                };
                for id in registry.members.keys().filter(|n| belongs(name, n, &j)) {
                    if files::optional_directory_relative(
                        registry.directory(),
                        std::path::Path::new(id),
                        Some(owner),
                    )?
                    .is_some()
                    {
                        check()?;
                        crate::generation_retention::remove_owned_tree(
                            registry.directory(),
                            id,
                            owner,
                            check,
                        )?;
                        removed = true;
                    }
                }
            }
            if !whole {
                return Ok(removed);
            }
            for (name, registry) in &mut members {
                let Some(registry) = registry else { continue };
                let names = registry
                    .members
                    .keys()
                    .filter(|n| belongs(name, n, &j))
                    .cloned()
                    .collect::<Vec<_>>();
                for id in names {
                    check()?;
                    registry.retire(&id)?;
                }
                registry.sync()?;
            }
            check()?;
            captures.retire(&j)?;
            captures.sync()?;
            Ok(true)
        })();
        match outcome {
            Ok(_) if whole => retired.push(j),
            Ok(true) => cleared.push(j),
            Ok(false) => {}
            Err(error) => kept.push(
                serde_json::json!({"id":j,"reason":error.0.chars().take(160).collect::<String>()}),
            ),
        }
    }
    Ok(serde_json::json!({"retired":retired,"cleared":cleared,"kept":kept}))
}
/// Remove one failed backup's source snapshot through the same exact-ID
/// subvolume and Snapper metadata retirement a finished backup uses. The
/// source and snapshot must still be the recorded Btrfs objects; a number
/// directory that is already gone needs nothing.
fn destroy_snapshot(
    guard: &Guard,
    receipt: &Value,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    use crate::{
        backup_source::{Snapshot, Source},
        backup_source_layout::Dataset,
    };
    let recorded = &receipt["source"];
    let mut datasets = vec![
        Dataset {
            name: "root".into(),
            path: "/".into(),
            archive: "system".into(),
        },
        Dataset {
            name: "home".into(),
            path: "/home".into(),
            archive: "home".into(),
        },
    ];
    // Additional sources are resolved from the current configuration only.
    if let Ok(rows) = crate::backup_configuration::Configuration::open()
        .and_then(|c| crate::backup_source_layout::layout(c.value()))
    {
        datasets = rows;
    }
    let dataset = datasets
        .into_iter()
        .find(|d| recorded["name"] == d.name.as_str() && recorded["archive"] == d.archive.as_str())
        .ok_or_else(|| {
            enzimos_platform::Error("failed backup snapshot source no longer configured".into())
        })?;
    let source = Source::open(dataset, guard)?;
    require(
        source.evidence()?["object"] == recorded["object"],
        "failed backup snapshot source subvolume changed",
    )?;
    let number = receipt["snapshot"]["number"]
        .as_u64()
        .ok_or_else(|| enzimos_platform::Error("failed backup snapshot number".into()))?;
    let parent = files::directory_relative(
        source.original_directory()?,
        std::path::Path::new(".snapshots"),
        Some(0),
    )?;
    if files::optional_directory_relative(
        &parent,
        std::path::Path::new(&number.to_string()),
        Some(0),
    )?
    .is_none()
    {
        return Ok(());
    }
    let snapshot = Snapshot::open(&source, number)?;
    require(
        snapshot.evidence()?["object"] == receipt["snapshot"]["object"],
        "failed backup snapshot number names another snapshot",
    )?;
    authorize()?;
    snapshot.destroy_original()?.retire_metadata(authorize)?;
    Ok(())
}
/// Clean up failed backups (see [`retire_failed_in`]). The caller holds the
/// backup operation lock: at attempt start (again after abandoning an
/// interrupted attempt), after a backup failed in its own process, and after
/// a successful backup's own cleanup.
pub fn retire_failed_locked(guard: &Guard, lock: &files::Lock) -> Result<Value> {
    crate::operation::root_only()?;
    guard.recheck()?;
    lock.recheck()?;
    let boot = crate::operation::boot_id()?;
    let mut check = || {
        guard.recheck()?;
        lock.recheck()
    };
    let mut destroy = |receipt: &Value| {
        destroy_snapshot(guard, receipt, &mut || {
            guard.recheck()?;
            lock.recheck()
        })
    };
    let result = retire_failed_in(
        guard.control(),
        guard.control_mount_id(),
        0,
        &boot,
        &mut destroy,
        &mut check,
    )?;
    guard.recheck()?;
    lock.recheck()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_abandoned_attempt_frees_its_failed_capture_for_retirement() {
        let boot = "11111111-2222-3333-4444-555555555555";
        let capture = serde_json::json!({"boot_id":boot});
        let worker = serde_json::json!({"phase":"send-entered"});
        let mut attempt = serde_json::json!({"boot_id":boot,"state":"uncertain"});
        assert!(live(&capture, Some(&attempt), Some(Some(&worker)), boot));
        attempt["state"] = serde_json::json!("abandoned");
        assert!(!live(&capture, Some(&attempt), Some(Some(&worker)), boot));
        assert!(!live(&capture, Some(&attempt), Some(None), boot));
    }

    #[test]
    fn only_recorded_snapshots_are_destroyed_and_interrupted_retirement_stops() {
        for (phase, owned) in [
            ("entered", Some(false)),
            ("created", Some(true)),
            ("capture-sealed", Some(true)),
            ("subvolume-retirement-entered", Some(true)),
            ("subvolume-retired", None),
            ("metadata-retirement-entered", None),
            ("snapshot-retired", Some(false)),
        ] {
            let receipt = serde_json::json!({"phase":phase});
            assert_eq!(snapshot_leftover(&receipt).ok(), owned, "{phase}");
        }
    }

    struct Control {
        _dir: tempfile::TempDir,
        root: std::path::PathBuf,
        file: std::fs::File,
        mount: u64,
        owner: u32,
    }
    const BOOT: &str = "11111111-2222-3333-4444-555555555555";
    fn control() -> Control {
        use std::os::unix::fs::PermissionsExt;
        let base =
            std::env::var_os("ENZIMOS_TEST_TMPDIR").map_or_else(std::env::temp_dir, Into::into);
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .unwrap();
        // SAFETY: getuid has no preconditions.
        let owner = enzimos_platform::process_identity::real_uid();
        let file = files::directory(dir.path(), Some(owner)).unwrap();
        let mount =
            enzimos_platform::mount_identity::id(std::os::fd::AsFd::as_fd(&file), true).unwrap();
        Control {
            root: dir.path().to_owned(),
            _dir: dir,
            file,
            mount,
            owner,
        }
    }
    impl Control {
        fn write(&self, folder: &str, id: &str, value: &Value) {
            use std::os::unix::fs::PermissionsExt;
            let directory = self.root.join(folder);
            if !directory.exists() {
                std::fs::create_dir(&directory).unwrap();
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let path = directory.join(format!("{id}.json"));
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn has(&self, folder: &str, id: &str) -> bool {
            self.root.join(folder).join(format!("{id}.json")).exists()
        }
        /// One failed job `j` with attempt `a` in `state` and one snapshot.
        fn failed(&self, j: &str, a: &str, state: &str) {
            self.write(
                "backup-attempts",
                a,
                &serde_json::json!({"schema":1,"id":a,"boot_id":BOOT,
                "started_unix":1,"state":state,"snapshot_id":null}),
            );
            self.write(
                CAPTURES,
                j,
                &serde_json::json!({"id":j,"phase":"captured","boot_id":BOOT,
                "attempt":{"id":a}}),
            );
            self.write(
                SNAPSHOTS,
                &format!("{j}-0"),
                &serde_json::json!({"id":j,"phase":"created",
                "snapshot":{"number":7}}),
            );
        }
        fn retire(&self) -> (Value, Vec<Value>) {
            let mut destroyed = Vec::new();
            let outcome = retire_failed_in(
                &self.file,
                self.mount,
                self.owner,
                BOOT,
                &mut |receipt| {
                    destroyed.push(receipt.clone());
                    Ok(())
                },
                &mut || Ok(()),
            )
            .unwrap();
            (outcome, destroyed)
        }
    }
    fn id(n: u32) -> String {
        format!("{n:032x}")
    }

    #[test]
    fn an_abandoned_backup_loses_its_snapshots_at_once_but_keeps_unnamed_ones_and_its_capture() {
        let control = control();
        let (gone, live) = (id(1), id(2));
        control.failed(&gone, &id(101), "abandoned");
        control.failed(&live, &id(102), "uncertain");
        let unnamed = format!("{gone}-1");
        control.write(
            SNAPSHOTS,
            &unnamed,
            &serde_json::json!({"id":gone,"phase":"entered"}),
        );
        control.write(
            WORKERS,
            &live,
            &serde_json::json!({"id":live,"phase":"send-entered"}),
        );
        let (outcome, destroyed) = control.retire();
        assert_eq!(destroyed.len(), 1);
        assert_eq!(destroyed[0]["id"], gone.as_str());
        assert_eq!(outcome["cleared"], serde_json::json!([gone]));
        assert_eq!(outcome["retired"], serde_json::json!([]));
        assert!(!control.has(SNAPSHOTS, &format!("{gone}-0")));
        assert!(control.has(SNAPSHOTS, &unnamed));
        assert!(control.has(CAPTURES, &gone));
        assert!(control.has(SNAPSHOTS, &format!("{live}-0")));
        assert!(control.has(CAPTURES, &live));
        let (again, destroyed) = control.retire();
        assert!(destroyed.is_empty());
        assert_eq!(again["cleared"], serde_json::json!([]));
    }
    #[test]
    fn only_failures_beyond_the_diagnostics_window_lose_their_receipts() {
        let control = control();
        for n in 1..=(KEEP_FAILED as u32 + 1) {
            control.failed(&id(n), &id(100 + n), "uncertain");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (outcome, destroyed) = control.retire();
        assert_eq!(destroyed.len(), KEEP_FAILED + 1);
        assert_eq!(outcome["retired"], serde_json::json!([id(1)]));
        assert!(!control.has(CAPTURES, &id(1)));
        for n in 2..=(KEEP_FAILED as u32 + 1) {
            assert!(control.has(CAPTURES, &id(n)));
            assert!(!control.has(SNAPSHOTS, &format!("{}-0", id(n))));
        }
    }
}
