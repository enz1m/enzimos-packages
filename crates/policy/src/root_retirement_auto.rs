// SPDX-License-Identifier: MIT
//! Automatic online retirement of old fallback Roots under the one operation
//! lock (`root-retire auto`, run by `enzimos-generation-retention.service`
//! after boot generation retention).
//!
//! Each update keeps the previous Root as a fallback birth. Without retirement
//! the 64-row birth registry fills and disk use grows with every update. A run:
//! 1. resolves the (at most one) unfinished receipt: a `deleted` one is
//!    finished, an online `executing` one is resumed, an unstaged `prepared`
//!    one from a previous boot is abandoned (it never started deleting); a
//!    staged coordinator receipt or a prepared one of this boot is left alone
//!    and stops the run, since every receipt refuses other transitions;
//! 2. offers ready births, oldest Root subvolume first, except the newest
//!    [`KEEP_NEWEST`] (a rollback margin), the running Root, Roots a boot
//!    generation still names and Roots that already have a receipt, to the
//!    reviewed plan, prepare, online delete and finish, at most
//!    [`MAX_RETIREMENTS`] per run; the plan's protections decide, never this
//!    module;
//! 3. removes the read-only Snapper snapshot of the live Root each retired
//!    birth was born from (exact number and Btrfs identity only);
//! 4. lets control retention free the finished receipt and birth rows.
use crate::{
    birth, birth_runtime, catalog, control_registry, root_retirement_online_delete as online,
    root_retirement_online_finish_origin as finish, root_retirement_online_intent as intent,
    root_retirement_record, storage_runtime::Guard,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
type Records = std::collections::BTreeMap<String, Value>;
/// Ready fallback births never offered: the newest, by Root subvolume ID.
pub(crate) const KEEP_NEWEST: usize = 2;
/// A bounded number of Root retirements per run.
pub(crate) const MAX_RETIREMENTS: usize = 4;
/// Root receipt registry bound (as read by every transition snapshot).
const RECEIPTS: usize = 16;

fn names_root(identity: &Value, root: &Value) -> bool {
    let path = root["path"].as_str().unwrap_or("");
    identity["path"] == root["path"]
        || identity["path"]
            .as_str()
            .is_some_and(|p| p.starts_with(&format!("{path}/")))
        || identity["id"] == root["id"]
        || identity["uuid"] == root["uuid"]
}
type Candidates = Vec<(String, String)>;
/// Retirement candidates `(birth, root UUID)` oldest first, and every ready
/// birth that is kept with its reason.
pub(crate) fn candidates(
    births: &Records,
    generations: &Value,
    live: &Value,
    receipts: &Records,
    keep: usize,
) -> Result<(Candidates, Vec<Value>)> {
    let generations = generations
        .as_object()
        .ok_or_else(|| Error("generation catalog map required".into()))?;
    let mut ready = births
        .iter()
        .filter(|(_, row)| row["phase"] == "ready")
        .map(|(id, row)| {
            row["root"]["id"]
                .as_u64()
                .map(|order| (order, id, row))
                .ok_or_else(|| Error("ready birth Root ID required".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    ready.sort_by_key(|(order, id, _)| (*order, (*id).clone()));
    let older = ready.len().saturating_sub(keep);
    let mut offered = Vec::new();
    let mut kept = Vec::new();
    for (index, (_, id, row)) in ready.iter().enumerate() {
        let root = &row["root"];
        let uuid = root["uuid"]
            .as_str()
            .ok_or_else(|| Error("ready birth Root UUID required".into()))?;
        let reason = if index >= older {
            Some("newest-fallback-margin".to_owned())
        } else if names_root(live, root) {
            Some("running-root".to_owned())
        } else if let Some(name) = generations
            .iter()
            .find(|(_, g)| names_root(&g["material"]["root_identity"], root))
            .map(|(name, _)| name)
        {
            Some(format!("boot-generation:{name}"))
        } else {
            receipts
                .get(&format!("root-{}", uuid.replace('-', "")))
                .map(|receipt| {
                    format!(
                        "existing-receipt:{}",
                        receipt["phase"].as_str().unwrap_or("")
                    )
                })
        };
        match reason {
            Some(reason) => kept.push(value!({"birth":id,"root":root["path"],"reason":reason})),
            None => offered.push(((*id).clone(), uuid.to_owned())),
        }
    }
    Ok((offered, kept))
}
/// What a run does with one unfinished receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    Finish,
    Resume,
    Abandon,
    Keep(&'static str),
}
/// Terminal receipts need nothing (None). Only unstaged receipts that never
/// started deleting are abandoned automatically, and only from a previous
/// boot: one prepared during this boot may still be reviewed or staged.
pub(crate) fn disposition(row: &Value, boot: &str) -> Option<Disposition> {
    let staged = row.get("coordinator").is_some();
    match (row["phase"].as_str(), staged) {
        (Some("complete" | "abandoned"), _) => None,
        (Some("deleted"), _) => Some(Disposition::Finish),
        (Some("executing"), false) => Some(Disposition::Resume),
        (Some("executing"), true) => Some(Disposition::Keep(
            "offline coordinator deletion in progress; review required",
        )),
        (Some("prepared"), false) if row["created_boot"] != boot => Some(Disposition::Abandon),
        (Some("prepared"), false) => Some(Disposition::Keep("prepared during this boot")),
        (Some("prepared"), true) => Some(Disposition::Keep(
            "staged coordinator receipt awaits its offline boot",
        )),
        _ => Some(Disposition::Keep("unknown receipt phase")),
    }
}
/// Whether a receipt provably never started deleting.
pub(crate) fn unstarted(row: &Value) -> bool {
    row.get("coordinator").is_none()
        && (row["phase"] == "prepared"
            || row["phase"] == "executing" && row["next_step"] == 0 && row["inflight"].is_null())
}
fn receipts(guard: &Guard) -> Result<Records> {
    control_registry::read(
        guard,
        "root-retirements",
        RECEIPTS,
        root_retirement_record::validate,
    )
}
fn births(guard: &Guard) -> Result<Records> {
    let filesystem =
        crate::recovery_records::text(&guard.configuration, "filesystem_uuid")?.to_owned();
    control_registry::read(guard, "root-births", birth_runtime::MAX_RECORDS, |v, id| {
        birth::validate(v, id, &filesystem)
    })
}
fn resume_and_finish(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let deleted = online::delete_locked(guard, lock, id, authorize)?;
    let finished = finish::finish_locked(guard, lock, id, authorize)?;
    Ok(value!({"id":id,"deleted":deleted["deleted"],"status":finished["status"]}))
}
/// After a failed resume or retirement, abandon the receipt only when it never
/// started deleting; otherwise it stays for review.
fn after_failure(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    error: Error,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<std::result::Result<Option<Value>, Value>> {
    let Some(row) = receipts(guard)?.remove(id) else {
        return Ok(Ok(None));
    };
    if !unstarted(&row) {
        return Ok(Err(value!({"id":id,"phase":row["phase"],"reason":error.0})));
    }
    match online::abandon_locked(guard, lock, id, authorize) {
        Ok(mut abandoned) => {
            abandoned["reason"] = value!(error.0);
            Ok(Ok(Some(abandoned)))
        }
        Err(abandon) => Ok(Err(value!({"id":id,"phase":row["phase"],
            "reason":format!("{}; abandonment refused: {}", error.0, abandon.0)}))),
    }
}
fn retire_one(
    guard: &Guard,
    lock: &files::Lock,
    root_uuid: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<std::result::Result<Value, String>> {
    let plan = intent::plan_locked(guard, lock, root_uuid, authorize)?;
    if plan["retirable"] != true {
        let protection = plan["protection"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        return Ok(Err(if protection.is_empty() {
            "protected".into()
        } else {
            protection
        }));
    }
    let sha = plan["plan_sha256"]
        .as_str()
        .ok_or_else(|| Error("retirable Root plan digest missing".into()))?
        .to_owned();
    intent::prepare_locked(guard, lock, root_uuid, &sha, authorize, &mut |_| Ok(()))?;
    let id = format!("root-{}", root_uuid.replace('-', ""));
    resume_and_finish(guard, lock, &id, authorize).map(Ok)
}

/// Why the read-only Snapper snapshot a retired birth was born from must stay,
/// or None when it may be removed. `inventory` is the complete subvolume list.
pub(crate) fn snapshot_blocker(
    id: &str,
    row: &Value,
    live: &Value,
    root_subvol: &str,
    rebinds: &Records,
    claimed: &BTreeSet<String>,
    inventory: &Records,
) -> Option<&'static str> {
    let snapshot = &row["snapshot"]["object"];
    let source = &row["source"];
    if row["phase"] != "retired" {
        return Some("birth-not-retired");
    }
    if claimed.contains(id) {
        return Some("recovery-job-source");
    }
    let present = |object: &Value| inventory.values().any(|r| r["uuid"] == object["uuid"]);
    if present(&row["root"]) || present(&row["history"]) {
        return Some("fallback-root-present");
    }
    if source["path"] != root_subvol || source["id"] != live["id"] || source["uuid"] != live["uuid"]
    {
        return Some("source-root-changed");
    }
    if rebinds
        .values()
        .any(|r| r["snapshot"]["uuid"] == snapshot["uuid"] && r["phase"] != "complete")
    {
        return Some("unfinished-rebind");
    }
    if !present(snapshot) {
        return Some("already-removed");
    }
    match snapshot["path"].as_str().and_then(|p| inventory.get(p)) {
        Some(observed) if observed == snapshot => None,
        _ => Some("snapshot-identity-differs"),
    }
}
/// Remove one retired birth's source snapshot through the exact-ID subvolume
/// and Snapper metadata retirement that backups use for their own snapshots.
fn destroy_snapshot(
    guard: &Guard,
    row: &Value,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    use crate::{
        backup_source::{Snapshot, Source},
        backup_source_layout::Dataset,
    };
    let recorded = &row["snapshot"]["object"];
    let number = row["snapshot"]["number"]
        .as_u64()
        .ok_or_else(|| Error("birth snapshot number".into()))?;
    let namespaces = crate::namespaces::observe()?;
    intent::mount_protection(&namespaces, &value!([{"path":recorded["path"]}]))?;
    let source = Source::open(
        Dataset {
            name: "root".into(),
            path: "/".into(),
            archive: "system".into(),
        },
        guard,
    )?;
    let object = &source.evidence()?["object"];
    require(
        object["id"] == row["source"]["id"] && object["uuid"] == row["source"]["uuid"],
        "birth snapshot source is no longer the live Root",
    )?;
    let snapshot = Snapshot::open(&source, number)?;
    let observed = &snapshot.evidence()?["object"];
    require(
        ["id", "uuid", "parent_uuid"]
            .iter()
            .all(|key| observed[*key] == recorded[*key]),
        "birth snapshot number names another snapshot",
    )?;
    authorize()?;
    snapshot.destroy_original()?.retire_metadata(authorize)?;
    Ok(())
}
fn retire_snapshots(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let births = births(guard)?;
    let rebinds = control_registry::read(
        guard,
        "root-rebind-journal",
        32,
        crate::root_rebind_record::validate,
    )?;
    let jobs = crate::recovery_journal::Journal::open(crate::recovery_journal::Kind::Jobs, false)?;
    let claimed = jobs
        .records
        .values()
        .filter_map(|job| job["plan"]["source_birth"]["transaction"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    jobs.unchanged()?;
    let live = guard.backup_root_binding()?["root"].clone();
    let root_subvol = crate::recovery_records::text(&guard.configuration, "root_subvol")?;
    let inventory = birth_runtime::inventory(false)?;
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for (id, row) in &births {
        if row["phase"] != "retired" {
            continue;
        }
        match snapshot_blocker(id, row, &live, root_subvol, &rebinds, &claimed, &inventory) {
            Some("already-removed") => (),
            Some(reason) => kept.push(value!({"birth":id,"reason":reason})),
            None => {
                authorize()?;
                lock.recheck()?;
                match destroy_snapshot(guard, row, authorize) {
                    Ok(()) => removed.push(value!({"birth":id,"number":row["snapshot"]["number"]})),
                    Err(error) => kept.push(value!({"birth":id,"reason":error.0})),
                }
            }
        }
    }
    Ok(value!({"removed":removed,"kept":kept}))
}

/// One automatic run (see the module documentation). A receipt that started
/// deleting and then failed stops the run with `stopped` set; it stays for
/// review (`root-retire status`, `delete`, `finish` or `abandon`).
///
/// # Errors
///
/// Fails when the operation cannot be observed or a retirement fails.
pub fn retain_locked(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    let control_before = crate::generation_retention::retain_control(guard, lock);
    // Abandoned receipts that never deleted anything name nothing; dropping
    // them lets their Roots be planned again.
    let pruned_before = crate::control_retention::retire_unstarted_abandoned_locked(guard, lock)
        .unwrap_or_else(|error| value!({"error":error.0}));
    authorize()?;
    let boot = crate::operation::boot_id()?;
    let mut finished = Vec::new();
    let mut abandoned = Vec::new();
    let mut waiting = Vec::new();
    let mut stopped = Value::Null;
    for (id, row) in receipts(guard)? {
        let Some(disposition) = disposition(&row, &boot) else {
            continue;
        };
        authorize()?;
        lock.recheck()?;
        match disposition {
            Disposition::Keep(reason) => {
                waiting.push(value!({"id":id,"phase":row["phase"],"reason":reason}));
            }
            Disposition::Abandon => match online::abandon_locked(guard, lock, &id, authorize) {
                Ok(result) => abandoned.push(result),
                Err(error) => waiting.push(value!({"id":id,"phase":row["phase"],"reason":error.0})),
            },
            Disposition::Finish => match finish::finish_locked(guard, lock, &id, authorize) {
                Ok(result) => finished.push(result),
                Err(error) => {
                    stopped = value!({"id":id,"phase":row["phase"],"reason":error.0});
                }
            },
            Disposition::Resume => match resume_and_finish(guard, lock, &id, authorize) {
                Ok(result) => finished.push(result),
                Err(error) => match after_failure(guard, lock, &id, error, authorize)? {
                    Ok(Some(result)) => abandoned.push(result),
                    Ok(None) => (),
                    Err(review) => stopped = review,
                },
            },
        }
        if !stopped.is_null() {
            break;
        }
    }
    let mut retired = Vec::new();
    let mut skipped = Vec::new();
    let mut kept = Vec::new();
    if stopped.is_null() && waiting.is_empty() {
        let generations = {
            let transaction = catalog::Transaction::begin()?;
            let generations = transaction.data["generations"].clone();
            transaction.recheck()?;
            generations
        };
        let live = guard.backup_root_binding()?["root"].clone();
        let (offered, protected) = candidates(
            &births(guard)?,
            &generations,
            &live,
            &receipts(guard)?,
            KEEP_NEWEST,
        )?;
        kept = protected;
        let mut attempts = 0;
        for (birth, root_uuid) in offered {
            // Refused plans are cheap to retry tomorrow; bound the run's work.
            if retired.len() >= MAX_RETIREMENTS || attempts >= 2 * MAX_RETIREMENTS {
                kept.push(value!({"birth":birth,"reason":"run-limit"}));
                continue;
            }
            attempts += 1;
            authorize()?;
            lock.recheck()?;
            match retire_one(guard, lock, &root_uuid, authorize) {
                Ok(Ok(result)) => retired.push(value!({"birth":birth,"result":result})),
                Ok(Err(reason)) => skipped.push(value!({"birth":birth,"reason":reason})),
                Err(error) => {
                    let id = format!("root-{}", root_uuid.replace('-', ""));
                    let reason = error.0.clone();
                    match after_failure(guard, lock, &id, error, authorize)? {
                        Ok(Some(result)) => {
                            abandoned.push(result);
                            skipped.push(value!({"birth":birth,"reason":reason}));
                        }
                        Ok(None) => skipped.push(value!({"birth":birth,"reason":reason})),
                        Err(review) => {
                            stopped = review;
                            break;
                        }
                    }
                }
            }
        }
    }
    authorize()?;
    lock.recheck()?;
    let snapshots = if stopped.is_null() {
        retire_snapshots(guard, lock, authorize).unwrap_or_else(|error| value!({"error":error.0}))
    } else {
        value!({"skipped":"retirement-stopped"})
    };
    authorize()?;
    let pruned_after = crate::control_retention::retire_unstarted_abandoned_locked(guard, lock)
        .unwrap_or_else(|error| value!({"error":error.0}));
    let control_after = crate::generation_retention::retain_control(guard, lock);
    guard.recheck()?;
    lock.recheck()?;
    Ok(
        value!({"status":"root-retention","kept_newest":KEEP_NEWEST,"max_retirements":MAX_RETIREMENTS,
        "finished":finished,"abandoned":abandoned,"waiting":waiting,"retired":retired,
        "skipped":skipped,"kept":kept,"stopped":stopped,"source_snapshots":snapshots,
        "control":[control_before,control_after],"abandoned_pruned":[pruned_before,pruned_after]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u64) -> String {
        format!("{n:08x}-1111-4111-8111-111111111111")
    }
    fn birth(phase: &str, root_id: u64) -> Value {
        value!({"phase":phase,"root":{"path":format!("enzimos-old-b{root_id}"),"id":root_id,
            "uuid":uuid(root_id),"parent_uuid":null}})
    }
    fn births(rows: &[(&str, &str, u64)]) -> Records {
        rows.iter()
            .map(|(id, phase, root)| ((*id).to_owned(), birth(phase, *root)))
            .collect()
    }
    fn live() -> Value {
        value!({"path":"root","id":256,"uuid":uuid(256),"parent_uuid":null})
    }
    fn offered(list: &[(String, String)]) -> Vec<&str> {
        list.iter().map(|(id, _)| id.as_str()).collect()
    }
    #[test]
    fn candidates_skip_running_root_catalog_references_and_existing_receipts() {
        let rows = births(&[
            ("g", "ready", 300),
            ("run", "ready", 310),
            ("rec", "ready", 320),
            ("ok", "ready", 330),
            ("n1", "ready", 900),
            ("n2", "ready", 901),
        ]);
        // A generation naming the Root by UUID alone protects it.
        let generations = value!({"old-x":{"material":{"root_identity":
            {"path":"elsewhere","id":1,"uuid":uuid(300)}}}});
        let running = value!({"path":"enzimos-old-b310","id":310,"uuid":uuid(310)});
        let receipts: Records = [(
            format!("root-{}", uuid(320).replace('-', "")),
            value!({"phase":"abandoned"}),
        )]
        .into_iter()
        .collect();
        let (list, kept) = candidates(&rows, &generations, &running, &receipts, 2).unwrap();
        assert_eq!(offered(&list), ["ok"]);
        let reason = |b: &str| {
            kept.iter().find(|k| k["birth"] == b).unwrap()["reason"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(reason("g"), "boot-generation:old-x");
        assert_eq!(reason("run"), "running-root");
        assert_eq!(reason("rec"), "existing-receipt:abandoned");
        // A generation rooted below the fallback (nested path) also protects it.
        let nested = value!({"x":{"material":{"root_identity":
            {"path":"enzimos-old-b330/inner","id":2,"uuid":uuid(2)}}}});
        let (list, _) = candidates(&rows, &nested, &live(), &Records::new(), 2).unwrap();
        assert!(!offered(&list).contains(&"ok"));
        assert!(candidates(&rows, &value!([]), &live(), &Records::new(), 2).is_err());
    }
}
