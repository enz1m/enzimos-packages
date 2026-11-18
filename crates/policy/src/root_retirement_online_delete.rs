// SPDX-License-Identifier: MIT
//! Online deletion of an unstaged (no coordinator) Root receipt.
//!
//! A fallback Root is never mounted in normal use, so its deletion needs no
//! offline boot: every run re-observes the complete online protection family
//! (original reference registries and recovery journals with the idle
//! transition snapshot, generation catalog, pins, backend rows, loader texts,
//! mounts in every namespace and the complete kernel Root Tree) and then makes
//! exactly one durable change: one receipt publication along the offline
//! journal's progression (prepared, executing, in-flight n, next n + 1, ...,
//! deleted), or the exact-ID deletion of the one target the durable in-flight
//! step names. A crash anywhere leaves a receipt that the next run completes:
//! an in-flight target whose recorded ID, UUID and path are all gone counts as
//! deleted; one still present with its identical identity is deleted again;
//! anything else stops for review (and `root-retire abandon` ends the receipt).
use crate::{
    birth_runtime::Records,
    root_retirement_objects::Targets,
    root_retirement_online_boot::Boot,
    root_retirement_online_intent::{mount_protection, planned_for_receipt, unchanged_namespaces},
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::{Journal, Phase, next_progress},
    root_retirement_references::Observation,
    storage_runtime::{Guard, TopMount},
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json as value};

/// Observed state of one receipt target in a complete kernel inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// The exact recorded identity is present at its recorded path.
    Present,
    /// Neither its path, ID nor UUID exists any more.
    Absent,
}
fn identity(target: &Value) -> Result<Value> {
    let mut object = target
        .as_object()
        .ok_or_else(|| Error("Root target identity".into()))?
        .clone();
    object.remove("role");
    Ok(Value::Object(object))
}
/// Exact presence or exact absence; a partial match (replaced, renamed or
/// re-created object) is never interpreted.
pub(crate) fn state(inventory: &Records, target: &Value) -> Result<State> {
    let path = crate::recovery_records::text(target, "path")?;
    if inventory.get(path) == Some(&identity(target)?) {
        return Ok(State::Present);
    }
    require(
        inventory.values().all(|row| {
            row["path"] != target["path"]
                && row["id"] != target["id"]
                && row["uuid"] != target["uuid"]
        }),
        "Root retirement target identity changed; review required",
    )?;
    Ok(State::Absent)
}
/// The one durable change a run makes next.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Action {
    /// Publish this successor receipt.
    Publish(Value),
    /// Delete the target at this index (the durable in-flight step).
    Delete(usize),
    /// Every target is deleted; `root-retire finish` completes the receipt.
    Done,
}
/// Check a receipt's progress against complete kernel states and select the
/// next change. Deleted steps must be absent, not-yet-started steps present.
pub(crate) fn action(record: &Value, states: &[State]) -> Result<Action> {
    let id = crate::recovery_records::text(record, "id")?;
    crate::root_retirement_record::validate(record, id)?;
    require(
        record["schema"] == 1 && record.get("coordinator").is_none(),
        "staged coordinator receipts are deleted only by their offline boot",
    )?;
    let targets = record["targets"].as_array().unwrap();
    require(
        states.len() == targets.len(),
        "Root target state count differs",
    )?;
    let next = record["next_step"].as_u64().unwrap() as usize;
    let inflight = record["inflight"].as_u64().map(|n| n as usize);
    for (index, state) in states.iter().enumerate() {
        if Some(index) == inflight {
            continue;
        }
        require(
            (index < next) == (*state == State::Absent),
            "Root receipt progress differs from the kernel inventory; review required",
        )?;
    }
    match record["phase"].as_str() {
        Some("deleted") => Ok(Action::Done),
        Some("prepared" | "executing") => match inflight {
            Some(index) if states[index] == State::Present => Ok(Action::Delete(index)),
            _ => Ok(Action::Publish(next_progress(record)?)),
        },
        _ => Err(Error("Root receipt is not in online execution".into())),
    }
}
/// Ownership of an executing publisher receipt: the exact ready birth still
/// owns the Root and history it names, and nothing else claims that Root.
/// (A prepared receipt is checked by the complete planning comparison.)
pub(crate) fn executing_owner(original: &Value, record: &Value) -> Result<()> {
    let id = crate::recovery_records::text(record, "id")?;
    crate::root_retirement_record::validate(record, id)?;
    let records = &original["records"];
    require(
        record["phase"] == "executing" && records["root_retirement"][id] == *record,
        "online execution requires the exact original executing receipt",
    )?;
    let birth = crate::recovery_records::text(record, "birth")?;
    require(
        !birth.starts_with("superseded-"),
        "superseded Root receipts are not executed online",
    )?;
    let targets = record["targets"].as_array().unwrap();
    require(
        targets.len() == 2
            && targets[0]["role"] == "history-store"
            && targets[1]["role"] == "root-subvolume",
        "online publisher receipt must name exactly its history and Root",
    )?;
    let root = &targets[1];
    let row = &records["births"][birth];
    require(
        row["phase"] == "ready"
            && row["filesystem_uuid"] == record["filesystem_uuid"]
            && row["root"] == identity(root)?
            && row["history"] == identity(&targets[0])?,
        "executing Root receipt differs from its exact ready publisher birth",
    )?;
    let births = records["births"]
        .as_object()
        .ok_or_else(|| Error("original birth registry missing".into()))?;
    let activations = records["activations"]
        .as_object()
        .ok_or_else(|| Error("original activation registry missing".into()))?;
    require(
        births
            .values()
            .filter(|row| row["root"]["uuid"] == root["uuid"])
            .count()
            == 1
            && activations.values().all(|row| {
                !(row["phase"] == "adopted"
                    && row["superseded"]["identity"]["uuid"] == root["uuid"])
            }),
        "executing Root ownership is ambiguous",
    )
}
/// No subvolume below the Root other than its still-present history.
fn descendants(inventory: &Records, record: &Value, states: &[State]) -> Result<()> {
    let targets = record["targets"].as_array().unwrap();
    let root = crate::recovery_records::text(targets.last().unwrap(), "path")?;
    for (path, row) in inventory {
        if path.starts_with(&format!("{root}/")) {
            require(
                targets.iter().zip(states).any(|(target, state)| {
                    *state == State::Present && identity(target).ok().as_ref() == Some(row)
                }),
                "Root retirement target has an additional descendant",
            )?;
        }
    }
    Ok(())
}
/// The running Root is never a target, by path, ID or UUID.
pub(crate) fn not_running(record: &Value, live: &Value) -> Result<()> {
    for target in record["targets"].as_array().unwrap() {
        require(
            target["path"] != live["path"]
                && target["id"] != live["id"]
                && target["uuid"] != live["uuid"],
            "the running Root can never be retired",
        )?;
    }
    Ok(())
}

/// What one run did.
#[derive(Debug)]
enum Performed {
    Published(Value),
    Deleted(Value),
    Done,
}
fn step(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Performed> {
    authorize()?;
    let journal = Journal::observe_current(guard, lock, id)?;
    if journal.phase() == Phase::Deleted {
        return Ok(Performed::Done);
    }
    require(
        matches!(journal.phase(), Phase::Prepared | Phase::Executing),
        "Root receipt is not in online execution",
    )?;
    let record = journal.record()?.clone();
    require(
        record["schema"] == 1 && record.get("coordinator").is_none(),
        "staged coordinator receipts are deleted only by their offline boot",
    )?;
    let live = guard.backup_root_binding()?["root"].clone();
    not_running(&record, &live)?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let references = Observation::observe_journal(guard, lock, &journal, authorize)?;
        let boot = Boot::observe_journal(guard, lock, &references, &journal, authorize)?;
        let inventory = Inventory::observe(guard, &top, lock, authorize)?;
        {
            let original = references.original(authorize)?;
            require(
                original["records"]["root_retirement"][id] == record,
                "original Root receipt differs from its journal",
            )?;
            if journal.phase() == Phase::Prepared {
                require(
                    planned_for_receipt(original, inventory.records(authorize)?, &record)?
                        == record,
                    "prepared Root receipt no longer matches actual ownership",
                )?;
            } else {
                executing_owner(original, &record)?;
            }
        }
        let records = inventory.records(authorize)?.clone();
        let states = record["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|target| state(&records, target))
            .collect::<Result<Vec<_>>>()?;
        descendants(&records, &record, &states)?;
        let chosen = action(&record, &states)?;
        let present = record["targets"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&states)
            .filter(|(_, state)| **state == State::Present)
            .map(|(target, _)| target.clone())
            .collect::<Vec<_>>();
        let targets = if present.is_empty() {
            None
        } else {
            Some(Targets::observe(
                guard,
                &top,
                lock,
                &value!(present),
                authorize,
            )?)
        };
        references.require_remaining_references(targets.as_ref(), &record, authorize)?;
        if let Some(targets) = &targets {
            boot.protect(targets, authorize)?;
        }
        let namespaces = crate::namespaces::observe()?;
        mount_protection(&namespaces, &record["targets"])?;
        let mut barrier = || {
            authorize()?;
            references.root_receipt_barrier(authorize)?;
            if let Some(targets) = &targets {
                boot.root_receipt_barrier(targets, authorize)?;
                targets.recheck(authorize)?;
            }
            inventory.recheck(authorize)?;
            let current = crate::namespaces::observe()?;
            mount_protection(&current, &record["targets"])?;
            unchanged_namespaces(
                &current,
                &namespaces,
                "Root namespace mount observations changed during online execution",
            )?;
            authorize()
        };
        barrier()?;
        match chosen {
            Action::Done => Ok(Performed::Done),
            Action::Publish(next) => {
                let published = journal.publish_progress(&next, &mut barrier)?;
                drop(barrier);
                references.verify_staged_root_receipt(&published, authorize)?;
                if let Some(targets) = &targets {
                    boot.verify_staged_root_receipt(&published, targets, authorize)?;
                }
                published.recheck()?;
                Ok(Performed::Published(published.record()?.clone()))
            }
            Action::Delete(index) => {
                drop(barrier);
                let targets = targets
                    .as_ref()
                    .ok_or_else(|| Error("in-flight Root target not retained".into()))?;
                require(
                    targets
                        .rows(authorize)?
                        .as_array()
                        .and_then(|rows| rows.first())
                        == record["targets"].get(index),
                    "in-flight Root target is not the first remaining target",
                )?;
                // Final full protection immediately before the one deletion.
                references.require_remaining_references(Some(targets), &record, authorize)?;
                boot.protect(targets, authorize)?;
                let current = crate::namespaces::observe()?;
                mount_protection(&current, &record["targets"])?;
                unchanged_namespaces(
                    &current,
                    &namespaces,
                    "Root namespace mount observations changed before deletion",
                )?;
                inventory.recheck(authorize)?;
                journal.recheck()?;
                Ok(Performed::Deleted(
                    targets.destroy_first(&records, authorize)?,
                ))
            }
        }
    })();
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; online Root deletion inspection cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}

/// Delete every target of an unstaged prepared (or interrupted executing)
/// receipt online, one durable change per fully protected observation, until
/// the receipt is `deleted`. `root-retire finish` then retires its birth.
pub fn delete_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    let mut deleted = Vec::new();
    let mut published = 0;
    // Each target needs at most three changes (begin, delete, advance) plus entry.
    for _ in 0..(3 * 64 + 2) {
        match step(guard, lock, id, authorize)? {
            Performed::Done => {
                guard.recheck()?;
                lock.recheck()?;
                return Ok(value!({"id":id,"status":"root-retirement-deleted",
                    "deleted":deleted,"receipt_steps":published,"finish_required":true}));
            }
            Performed::Deleted(target) => deleted.push(target),
            Performed::Published(record) => {
                crate::root_retirement_record::validate(&record, id)?;
                published += 1;
            }
        }
    }
    Err(Error(
        "online Root deletion did not converge; review required".into(),
    ))
}

/// End an unstaged receipt that is prepared or executing. Nothing is deleted;
/// targets that remain stay where they are and transitions are admitted again.
pub fn abandon_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    let journal = Journal::observe_current(guard, lock, id)?;
    let before = journal.record()?.clone();
    require(
        matches!(journal.phase(), Phase::Prepared | Phase::Executing)
            && before["schema"] == 1
            && before.get("coordinator").is_none(),
        "only an unstaged prepared or executing Root receipt can be abandoned; a staged coordinator receipt is finished by its boot",
    )?;
    let references = Observation::observe_journal(guard, lock, &journal, authorize)?;
    require(
        references.original(authorize)?["records"]["root_retirement"][id] == before,
        "original Root receipt differs from its journal",
    )?;
    let published = journal.publish_abandoned(&mut || {
        authorize()?;
        references.root_receipt_barrier(authorize)
    })?;
    references.verify_staged_root_receipt(&published, authorize)?;
    published.recheck()?;
    let after = published.record()?.clone();
    guard.recheck()?;
    lock.recheck()?;
    Ok(
        value!({"id":id,"status":"root-retirement-abandoned","phase_before":before["phase"],
        "next_step":after["next_step"],"inflight":after["inflight"],
        "targets_possibly_remaining":after["targets"].as_array().unwrap()
            [after["next_step"].as_u64().unwrap() as usize..]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const FS: &str = "11111111-1111-4111-8111-111111111111";
    const ROOT: &str = "22222222-2222-4222-8222-222222222222";
    const HISTORY: &str = "44444444-4444-4444-8444-444444444444";
    fn root() -> Value {
        value!({"path":"enzimos-old-birth9","id":400,"uuid":ROOT,"parent_uuid":null})
    }
    fn history() -> Value {
        value!({"path":"enzimos-old-birth9/.snapshots","id":401,"uuid":HISTORY,"parent_uuid":null})
    }
    fn prepared() -> Value {
        let mut h = history();
        h["role"] = value!("history-store");
        let mut r = root();
        r["role"] = value!("root-subvolume");
        let targets = value!([h, r]);
        let sha = enzimos_platform::json::fingerprint(
            &value!({"filesystem_uuid":FS,"birth":"birth9","targets":targets}),
        )
        .unwrap();
        value!({"schema":1,"id":format!("root-{}", ROOT.replace('-', "")),"phase":"prepared",
            "filesystem_uuid":FS,"created_boot":"33333333-3333-4333-8333-333333333333",
            "birth":"birth9","targets":targets,"next_step":0,"inflight":null,"plan_sha256":sha})
    }
    fn inventory(rows: &[Value]) -> Records {
        let mut result = Records::from([(
            "live".to_owned(),
            value!({"path":"live","id":300,"uuid":"55555555-5555-4555-8555-555555555555","parent_uuid":null}),
        )]);
        for row in rows {
            result.insert(row["path"].as_str().unwrap().to_owned(), row.clone());
        }
        result
    }
    fn states(record: &Value, inventory: &Records) -> Result<Vec<State>> {
        record["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| state(inventory, t))
            .collect()
    }
    /// Drive the pure decision through a complete run, simulating deletion.
    fn run(mut record: Value, mut kernel: Records) -> (Value, Records) {
        for _ in 0..16 {
            let observed = states(&record, &kernel).unwrap();
            descendants(&kernel, &record, &observed).unwrap();
            match action(&record, &observed).unwrap() {
                Action::Done => return (record, kernel),
                Action::Publish(next) => record = next,
                Action::Delete(index) => {
                    // A deletion never publishes in the same run: the next
                    // run observes the outcome afresh, as after a crash.
                    let path = record["targets"][index]["path"].as_str().unwrap();
                    kernel.remove(path);
                }
            }
        }
        panic!("did not converge");
    }
    #[test]
    fn resume_counts_an_absent_inflight_target_as_deleted_and_deletes_a_present_one_again() {
        let entered = next_progress(&prepared()).unwrap();
        let inflight = next_progress(&entered).unwrap();
        // Crash after the history deletion but before the advance.
        let kernel = inventory(&[root()]);
        let observed = states(&inflight, &kernel).unwrap();
        assert_eq!(observed, [State::Absent, State::Present]);
        let Action::Publish(advanced) = action(&inflight, &observed).unwrap() else {
            panic!("absent in-flight target must advance");
        };
        assert_eq!(advanced["next_step"], 1);
        // Crash before the delete call: the identical target is deleted again.
        let both = inventory(&[root(), history()]);
        assert_eq!(
            action(&inflight, &states(&inflight, &both).unwrap()).unwrap(),
            Action::Delete(0)
        );
        let (record, kernel) = run(inflight, both);
        assert_eq!(record["phase"], "deleted");
        assert_eq!(kernel.len(), 1);
    }
    #[test]
    fn replaced_missing_or_reappearing_targets_stop_for_review() {
        let entered = next_progress(&prepared()).unwrap();
        let inflight = next_progress(&entered).unwrap();
        // Same path, different subvolume: never interpreted.
        let mut replaced = history();
        replaced["id"] = value!(999);
        replaced["uuid"] = value!("66666666-6666-4666-8666-666666666666");
        assert!(state(&inventory(&[root(), replaced]), &inflight["targets"][0]).is_err());
        // Same ID or UUID at another path (renamed): never interpreted.
        let mut renamed = history();
        renamed["path"] = value!("elsewhere");
        assert!(state(&inventory(&[root(), renamed]), &inflight["targets"][0]).is_err());
        // A not-yet-started target that vanished.
        let only_history = inventory(&[history()]);
        assert!(action(&inflight, &states(&inflight, &only_history).unwrap()).is_err());
        // A deleted step whose target reappeared.
        let advanced = next_progress(&inflight).unwrap();
        assert!(action(&advanced, &[State::Present, State::Present]).is_err());
        // An extra subvolume below the Root.
        let extra = value!({"path":"enzimos-old-birth9/new","id":402,
            "uuid":"77777777-7777-4777-8777-777777777777","parent_uuid":null});
        let kernel = inventory(&[root(), history(), extra]);
        assert!(descendants(&kernel, &inflight, &states(&inflight, &kernel).unwrap()).is_err());
    }
}
