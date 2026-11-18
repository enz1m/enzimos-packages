// SPDX-License-Identifier: MIT
//! A fixed home timer can pause future history without deleting snapshots.
use crate::{operation, settings_command::Command, storage_runtime};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
const TIMER: &str = "enzimos-home-history.timer";
pub fn parse(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("history timer state encoding".into()))?
        .trim_end_matches('\n');
    require(
        matches!(
            text,
            "enabled"
                | "enabled-runtime"
                | "disabled"
                | "masked"
                | "masked-runtime"
                | "static"
                | "indirect"
                | "generated"
                | "transient"
                | "linked"
                | "linked-runtime"
        ),
        "history timer state differs",
    )?;
    Ok(json!({"enabled":text=="enabled","state":text}))
}
fn state(command: &Command) -> Result<Value> {
    parse(&command.run(&["is-enabled", TIMER], &[0, 1], 4096)?)
}
pub fn observe() -> Result<Value> {
    storage_runtime::initial_namespace()?;
    state(&Command::open("/usr/bin/systemctl")?)
}
pub fn plan() -> Result<Value> {
    storage_runtime::initial_namespace()?;
    let command = Command::open("/usr/bin/systemctl")?;
    Ok(json!({"timer":state(&command)?,"provider":command.evidence()?}))
}
pub fn set<F: FnMut() -> Result<()>>(
    enabled: bool,
    expected: &Value,
    mut authorization: F,
) -> Result<Value> {
    storage_runtime::initial_namespace()?;
    let lock = operation::lock()?;
    let command = Command::open("/usr/bin/systemctl")?;
    require(
        state(&command)? == expected["timer"] && command.evidence()? == expected["provider"],
        "home history plan changed",
    )?;
    authorization()?;
    lock.recheck()?;
    require(
        state(&command)? == expected["timer"],
        "home history changed before timer update",
    )?;
    command.run(
        &[if enabled { "enable" } else { "disable" }, "--now", TIMER],
        &[0],
        65536,
    )?;
    let after = state(&command)?;
    require(
        after["enabled"].as_bool() == Some(enabled),
        "home timer outcome differs; no automatic retry",
    )?;
    command.recheck()?;
    lock.recheck()?;
    Ok(json!({"enabled":enabled,"state":after["state"],"existing_history_removed":false}))
}
