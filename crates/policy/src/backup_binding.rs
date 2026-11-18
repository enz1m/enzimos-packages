// SPDX-License-Identifier: MIT
//! Closed repository and explicit schedule bindings. These do not grant source access.
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
pub const SCHEDULE: &str = "daily-with-up-to-30m-jitter";

pub fn pin(bytes: &[u8]) -> Result<Value> {
    let v = json::decode(bytes, crate::backup_configuration::LIMIT)?;
    require(
        v.as_object().is_some_and(|r| {
            r.len() == 5
                && [
                    "schema",
                    "filesystem_uuid",
                    "fsroot",
                    "repository",
                    "repository_sha256",
                ]
                .iter()
                .all(|k| r.contains_key(*k))
        }) && v["schema"].as_u64() == Some(1)
            && v["fsroot"] == "/"
            && v["repository"] == crate::backup_configuration::REPOSITORY,
        "invalid backup repository binding",
    )?;
    crate::identity::uuid(
        v["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("backup binding filesystem required".into()))?,
    )?;
    crate::identity::sha(v["repository_sha256"].as_str().ok_or_else(|| {
        enzimos_platform::Error("backup binding repository digest required".into())
    })?)?;
    Ok(v)
}

/// Bind original bytes rather than reserialized documents: formatting edits
/// also revoke automatic entry until explicit schedule reapproval.
pub fn schedule(configuration: &[u8], destination_pin: &[u8]) -> Result<Value> {
    let config = crate::backup_configuration::decode(configuration)?;
    let bound = pin(destination_pin)?;
    require(
        config["destination_uuid"] == bound["filesystem_uuid"],
        "backup schedule destination binding mismatch",
    )?;
    Ok(
        value!({"schema":1,"configuration_sha256":json::sha256(configuration),"destination_pin_sha256":json::sha256(destination_pin),"schedule":SCHEDULE,"opt_in":true}),
    )
}

pub fn verify_schedule(marker: &[u8], configuration: &[u8], destination_pin: &[u8]) -> Result<()> {
    let actual = json::decode(marker, crate::backup_configuration::LIMIT)?;
    require(
        actual == schedule(configuration, destination_pin)?,
        "automatic backup opt-in binding changed; reapproval required",
    )
}
