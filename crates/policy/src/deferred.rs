// SPDX-License-Identifier: MIT
//! Owed work records only typed pre-entry contention, never an operation failure.
use crate::{identity, operation};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
pub(crate) const ACTIONS: [(&str, &str); 4] = [
    ("scrub", "enzimos-scrub.service"),
    ("trim", "enzimos-trim.service"),
    ("backup", "enzimos-backup.service"),
    ("authority", "enzimos-authority-refresh.service"),
];
pub(crate) const MAX_DEFERRALS: u64 = 100_000;
pub fn unit(action: &str) -> Result<&'static str> {
    ACTIONS
        .iter()
        .find(|(name, _)| *name == action)
        .map(|(_, unit)| *unit)
        .ok_or_else(|| Error("unknown deferred action".into()))
}
pub fn validate(record: &Value, action: &str) -> Result<()> {
    unit(action)?;
    json::fields(
        record,
        "schema action first_deferred_unix last_deferred_unix last_boot_id deferrals",
    )?;
    require(
        record["schema"].as_u64() == Some(1) && record["action"] == action,
        "deferred marker schema or action refused",
    )?;
    let integer = |name: &str| {
        record[name]
            .as_u64()
            .ok_or_else(|| Error("deferred marker integer required".into()))
    };
    require(
        integer("first_deferred_unix")? <= integer("last_deferred_unix")?
            && (1..=MAX_DEFERRALS).contains(&integer("deferrals")?),
        "deferred marker counters refused",
    )?;
    identity::uuid(
        record["last_boot_id"]
            .as_str()
            .ok_or_else(|| Error("deferred marker boot missing".into()))?,
    )?;
    Ok(())
}
pub fn next(previous: Option<&Value>, action: &str, boot: &str, now: u64) -> Result<Value> {
    unit(action)?;
    identity::uuid(boot)?;
    if let Some(previous) = previous {
        validate(previous, action)?;
        require(
            now >= previous["last_deferred_unix"].as_u64().unwrap(),
            "clock moved backwards during deferred admission",
        )?;
    }
    let record = value!({"schema":1,"action":action,
        "first_deferred_unix":previous.map_or(now, |v| v["first_deferred_unix"].as_u64().unwrap()),
        "last_deferred_unix":now,"last_boot_id":boot,
        "deferrals":previous.map_or(1, |v| (v["deferrals"].as_u64().unwrap() + 1).min(MAX_DEFERRALS))});
    validate(&record, action)?;
    Ok(record)
}
pub(crate) fn previous_boot_actions(
    records: &std::collections::BTreeMap<String, Value>,
    boot: &str,
) -> Result<Vec<String>> {
    identity::uuid(boot)?;
    require(
        records.len() <= ACTIONS.len(),
        "deferred marker count bound",
    )?;
    let mut actions = Vec::new();
    for (action, record) in records {
        validate(record, action)?;
        if record["last_boot_id"] != boot {
            actions.push(action.clone());
        }
    }
    Ok(actions)
}
/// There is deliberately no public `record(error)` or command to manufacture debt.
pub enum Admission {
    Entered(enzimos_platform::files::Lock),
    Deferred(Value),
}
pub fn admit(action: &str) -> Result<Admission> {
    unit(action)?;
    operation::root_only()?;
    crate::storage_runtime::initial_namespace()?;
    match operation::try_lock()? {
        Some(lock) => {
            crate::deferred_runtime::clear(action)?;
            Ok(Admission::Entered(lock))
        }
        None => Ok(Admission::Deferred(crate::deferred_runtime::contended(
            action,
        )?)),
    }
}
/// The initial-namespace supervisor receives an authenticated update-hook notice.
/// A free lock is an error here; it never manufactures owed work or clears a marker.
pub fn defer_if_contended(action: &str) -> Result<Value> {
    unit(action)?;
    operation::root_only()?;
    crate::storage_runtime::initial_namespace()?;
    match operation::try_lock()? {
        Some(_) => Err(Error("update-hook operation lock is not held".into())),
        None => crate::deferred_runtime::contended(action),
    }
}
