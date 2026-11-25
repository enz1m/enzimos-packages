// SPDX-License-Identifier: MIT
//! Internal destructive transition engine. Its adapter supplies retained authority.
//! No wire data or journal itself grants ownership or a filesystem mutation capability.
use crate::{identity, recovery_journal::Records, recovery_records as records};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
pub(crate) const MAX_RECORDS: usize = 32;
pub fn intent(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema id filesystem_uuid boot_uuid created_boot observation_sha256 protected_sha256 steps intent_sha256",
    )?;
    require(v["schema"].as_u64() == Some(1), "retirement intent schema")?;
    identity::safe_id(records::text(v, "id")?)?;
    for key in ["filesystem_uuid", "created_boot"] {
        identity::uuid(records::text(v, key)?)?;
    }
    records::fat_uuid(records::text(v, "boot_uuid")?)?;
    for key in ["observation_sha256", "protected_sha256"] {
        identity::sha(records::text(v, key)?)?;
    }
    records::digest(v, "intent_sha256")?;
    let steps = v["steps"]
        .as_array()
        .ok_or_else(|| Error("retirement steps array".into()))?;
    require((1..=256).contains(&steps.len()), "retirement step bound")?;
    let mut ids = BTreeSet::new();
    let mut detached = BTreeSet::new();
    let mut resource = false;
    let mut catalog = false;
    for (index, step) in steps.iter().enumerate() {
        json::fields(step, "id kind before after")?;
        require(
            ids.insert(identity::safe_id(records::text(step, "id")?)?),
            "duplicate retirement step",
        )?;
        let kind = records::text(step, "kind")?;
        require(
            !catalog
                && matches!(
                    kind,
                    "uefi-entry"
                        | "bios-menu"
                        | "boot-file"
                        | "boot-directory"
                        | "history-subvolume"
                        | "root-subvolume"
                        | "source-snapshot"
                        | "catalog"
                ),
            "retirement step kind or order",
        )?;
        identity::sha(records::text(step, "before")?)?;
        identity::sha(records::text(step, "after")?)?;
        require(step["before"] != step["after"], "retirement no-op step")?;
        if matches!(kind, "uefi-entry" | "bios-menu") {
            require(!resource, "loader detach must precede resource deletion")?;
            detached.insert(kind);
        } else if kind != "catalog" {
            require(
                detached == BTreeSet::from(["uefi-entry", "bios-menu"]),
                "both loaders must detach before resource deletion",
            )?;
            resource = true;
        }
        if kind == "catalog" {
            catalog = true;
            require(index + 1 == steps.len(), "catalog tombstone must be last")?;
        }
    }
    require(
        catalog && resource,
        "retirement requires resource removal and terminal tombstone",
    )
}
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(v, "intent phase next_step inflight")?;
    intent(&v["intent"])?;
    require(
        v["intent"]["id"] == id,
        "retirement record filename mismatch",
    )?;
    let count = v["intent"]["steps"].as_array().unwrap().len() as u64;
    let next = v["next_step"]
        .as_u64()
        .ok_or_else(|| Error("retirement progress integer".into()))?;
    require(
        next <= count
            && matches!(
                v["phase"].as_str(),
                Some("prepared" | "executing" | "complete")
            ),
        "retirement phase or progress",
    )?;
    require(
        v["inflight"].is_null() || v["inflight"].as_u64() == Some(next) && next < count,
        "retirement in-flight step differs",
    )?;
    require(
        v["phase"] != "prepared" || next == 0 && v["inflight"].is_null(),
        "prepared retirement already advanced",
    )?;
    require(
        v["phase"] != "complete" || next == count && v["inflight"].is_null(),
        "incomplete retirement claimed complete",
    )
}
/// Implemented only by trusted native code. save must persist and fsync before
/// returning; apply must use anchored objects under its exclusive execution barrier.
pub trait Executor {
    fn records(&mut self) -> Result<Records>;
    fn save(&mut self, next: &Value, previous: Option<&Value>) -> Result<()>;
    fn verify_context(&mut self, intent: &Value) -> Result<()>;
    fn observe(&mut self, step: &Value) -> Result<String>;
    fn apply(&mut self, step: &Value) -> Result<()>;
}
fn unchanged(executor: &mut impl Executor, id: &str, record: &Value) -> Result<()> {
    require(
        executor.records()?.get(id) == Some(record),
        "retirement record changed during execution",
    )
}
fn checkpoint(
    executor: &mut impl Executor,
    id: &str,
    previous: &Value,
    next: &Value,
) -> Result<()> {
    unchanged(executor, id, previous)?;
    validate(next, id)?;
    executor.save(next, Some(previous))?;
    unchanged(executor, id, next)
}
pub fn start(executor: &mut impl Executor, intended: &Value) -> Result<Value> {
    intent(intended)?;
    let id = records::text(intended, "id")?;
    let current = executor.records()?;
    require(
        !current.contains_key(id) && current.len() < MAX_RECORDS,
        "retirement ID already attempted or registry full",
    )?;
    for (name, record) in &current {
        validate(record, name)?;
        require(
            record["phase"] == "complete",
            "another retirement incomplete",
        )?;
    }
    executor.verify_context(intended)?;
    let record = value!({"intent":intended,"phase":"prepared","next_step":0,"inflight":null});
    executor.save(&record, None)?;
    unchanged(executor, id, &record)?;
    Ok(record)
}
pub fn replay(executor: &mut impl Executor, id: &str) -> Result<Value> {
    identity::safe_id(id)?;
    let mut record = executor
        .records()?
        .get(id)
        .cloned()
        .ok_or_else(|| Error("retirement missing".into()))?;
    validate(&record, id)?;
    if record["phase"] == "complete" {
        return Ok(value!({"status":"retirement-already-complete","id":id}));
    }
    let intent = record["intent"].clone();
    executor.verify_context(&intent)?;
    if record["phase"] == "prepared" {
        let previous = record.clone();
        record["phase"] = value!("executing");
        checkpoint(executor, id, &previous, &record)?;
    }
    let steps = intent["steps"].as_array().unwrap();
    for number in record["next_step"].as_u64().unwrap() as usize..steps.len() {
        let step = &steps[number];
        executor.verify_context(&intent)?;
        for prior in &steps[..number] {
            require(
                executor.observe(prior)? == records::text(prior, "after")?,
                "completed retirement resource changed",
            )?;
        }
        let observed = executor.observe(step)?;
        if record["inflight"].is_null() {
            require(
                observed == records::text(step, "before")?,
                "unstarted retirement resource differs; adoption refused",
            )?;
            let previous = record.clone();
            record["inflight"] = value!(number);
            checkpoint(executor, id, &previous, &record)?;
        } else {
            require(
                record["inflight"].as_u64() == Some(number as u64)
                    && (observed == records::text(step, "before")?
                        || observed == records::text(step, "after")?),
                "interrupted retirement outcome unknown",
            )?;
        }
        executor.verify_context(&intent)?;
        if observed == records::text(step, "before")? {
            require(
                executor.observe(step)? == records::text(step, "before")?,
                "retirement resource changed before mutation",
            )?;
            unchanged(executor, id, &record)?;
            executor.apply(step)?;
        }
        require(
            executor.observe(step)? == records::text(step, "after")?,
            "retirement side effect not durably observed",
        )?;
        let previous = record.clone();
        record["next_step"] = value!(number + 1);
        record["inflight"] = Value::Null;
        checkpoint(executor, id, &previous, &record)?;
    }
    executor.verify_context(&intent)?;
    for step in steps {
        require(
            executor.observe(step)? == records::text(step, "after")?,
            "retirement final resource drift",
        )?;
    }
    let previous = record.clone();
    record["phase"] = value!("complete");
    checkpoint(executor, id, &previous, &record)?;
    Ok(value!({"status":"retirement-complete","id":id,"steps":steps.len()}))
}
