// SPDX-License-Identifier: MIT
//! Each exact owed marker admits at most one boot-time start request.
use crate::{deferred, identity};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
pub(crate) const MAXIMUM: usize = 256;
/// Identifier of the start request for `action` owed by `marker`.
///
/// # Errors
///
/// Fails when the marker is invalid.
pub fn id(action: &str, marker: &Value) -> Result<String> {
    deferred::validate(marker, action)?;
    Ok(format!(
        "{action}-{}",
        json::sha256(&json::canonical(marker)?)
    ))
}
/// Validate deferred start record `key`.
///
/// # Errors
///
/// Fails when a field is missing or invalid.
pub fn validate(record: &Value, key: &str) -> Result<()> {
    json::fields(record, "schema id action boot_id marker phase")?;
    require(
        record["schema"].as_u64() == Some(1)
            && record["id"] == key
            && matches!(
                record["phase"].as_str(),
                Some("intent" | "requested" | "uncertain")
            ),
        "deferred start phase or identity refused",
    )?;
    let action = record["action"]
        .as_str()
        .ok_or_else(|| Error("deferred start action missing".into()))?;
    require(
        id(action, &record["marker"])? == key,
        "deferred start marker digest changed",
    )?;
    let boot = record["boot_id"]
        .as_str()
        .ok_or_else(|| Error("deferred start boot missing".into()))?;
    identity::uuid(boot)?;
    require(
        record["marker"]["last_boot_id"] != boot,
        "current boot debt cannot restart",
    )
}
/// Require that `after` is a valid successor of `before`.
///
/// # Errors
///
/// Fails when the record skips its intent, replays, or alters the intent.
pub fn transition(before: Option<&Value>, after: &Value, key: &str) -> Result<()> {
    validate(after, key)?;
    match before {
        None => require(
            after["phase"] == "intent",
            "deferred start must record intent first",
        ),
        Some(before) => {
            validate(before, key)?;
            let mut expected = before.clone();
            expected["phase"] = after["phase"].clone();
            require(
                before["phase"] == "intent" && after["phase"] != "intent" && expected == *after,
                "deferred start replay or altered intent refused",
            )
        }
    }
}
