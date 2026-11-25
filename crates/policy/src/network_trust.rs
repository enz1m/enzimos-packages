// SPDX-License-Identifier: MIT
//! Only a reviewed connection's zone changes; reconnect and secret access are absent.
use crate::{identity, operation, settings_command::Command, storage_runtime};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
pub(crate) const TRUSTED_ZONE: &str = "enzimos-trusted";
const KINDS: [&str; 4] = ["802-11-wireless", "802-3-ethernet", "vpn", "wireguard"];
pub(crate) fn terse(line: &str) -> Result<Vec<String>> {
    require(
        line.len() <= 8192 && !line.chars().any(char::is_control),
        "network connection row bound",
    )?;
    let mut rows = vec![String::new()];
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            require(matches!(c, ':' | '\\'), "network connection escape differs")?;
            rows.last_mut()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
                .push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ':' {
            require(rows.len() < 4, "network connection column bound")?;
            rows.push(String::new());
        } else {
            rows.last_mut()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
                .push(c);
        }
    }
    require(!escaped && rows.len() == 4, "network connection row shape")?;
    Ok(rows)
}
fn device(s: &str) -> bool {
    s.as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && s.len() < libc::IFNAMSIZ
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error("network provider encoding".into()))
}
fn connections_with(command: &Command) -> Result<Vec<Value>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let remaining = || deadline.saturating_duration_since(std::time::Instant::now());
    let body = command.run_timeout(
        &[
            "--wait",
            "10",
            "--terse",
            "--escape",
            "yes",
            "--fields",
            "UUID,TYPE,DEVICE,NAME",
            "connection",
            "show",
        ],
        &[0],
        1024 * 1024,
        remaining(),
    )?;
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for line in text(&body)?.lines() {
        require(seen.len() < 256, "network connection inventory bound")?;
        let row = terse(line)?;
        identity::uuid(&row[0])?;
        require(
            seen.insert(row[0].clone()),
            "duplicate network connection UUID",
        )?;
        if !KINDS.contains(&row[1].as_str()) {
            continue;
        }
        require(
            row[2].is_empty() || device(&row[2]),
            "network active device shape",
        )?;
        let zone = command.run_timeout(
            &[
                "--wait",
                "10",
                "--get-values",
                "connection.zone",
                "--escape",
                "no",
                "connection",
                "show",
                &row[0],
            ],
            &[0],
            4096,
            remaining(),
        )?;
        let zone = text(&zone)?.trim_end_matches('\n');
        require(
            zone.len() <= 128 && !zone.chars().any(char::is_control),
            "network zone shape",
        )?;
        rows.push(value!({"connection":row[0],"name":row[3].chars().take(128).collect::<String>(),"type":row[1],
            "active":!row[2].is_empty(),"device":if row[2].is_empty(){Value::Null}else{value!(row[2])},
            "zone":if zone.is_empty(){Value::Null}else{value!(zone)},"trusted":zone==TRUSTED_ZONE}));
    }
    rows.sort_by(|a, b| {
        // Rows are built above with a Boolean "active" and a string "name".
        (
            !a["active"].as_bool().unwrap_or(false),
            a["name"].as_str().unwrap_or(""),
        )
            .cmp(&(
                !b["active"].as_bool().unwrap_or(false),
                b["name"].as_str().unwrap_or(""),
            ))
    });
    Ok(rows)
}
fn selected(command: &Command, uuid: &str) -> Result<Value> {
    identity::uuid(uuid)?;
    let rows = connections_with(command)?
        .into_iter()
        .filter(|r| r["connection"] == uuid)
        .collect::<Vec<_>>();
    require(rows.len() == 1, "unknown or unsupported network connection")?;
    Ok(rows[0].clone())
}
/// NetworkManager connections with their firewall trust.
///
/// # Errors
///
/// Fails when nmcli fails or its output is invalid.
pub fn connections() -> Result<Value> {
    storage_runtime::initial_namespace()?;
    Ok(
        value!({"trusted_zone":TRUSTED_ZONE,"connections":connections_with(&Command::open("/usr/bin/nmcli")?)?}),
    )
}
/// One connection by UUID.
///
/// # Errors
///
/// Fails when the UUID is invalid or nmcli fails.
pub fn connection(uuid: &str) -> Result<Value> {
    storage_runtime::initial_namespace()?;
    selected(&Command::open("/usr/bin/nmcli")?, uuid)
}
/// Private backend plan material; provider identities do not enter Query replies.
///
/// # Errors
///
/// Fails when the UUID is invalid or nmcli fails.
pub fn plan(uuid: &str) -> Result<Value> {
    storage_runtime::initial_namespace()?;
    let command = Command::open("/usr/bin/nmcli")?;
    let before = selected(&command, uuid)?;
    Ok(value!({"connection":before,"provider":command.evidence()?}))
}
/// Set whether connection `uuid` is trusted, if it still matches `expected`.
///
/// # Errors
///
/// Fails when the plan or connection changed, authorization fails, or nmcli fails.
pub fn set<F: FnMut() -> Result<()>>(
    uuid: &str,
    trusted: bool,
    expected: &Value,
    mut authorization: F,
) -> Result<Value> {
    storage_runtime::initial_namespace()?;
    identity::uuid(uuid)?;
    let lock = operation::lock()?;
    let command = Command::open("/usr/bin/nmcli")?;
    let before = selected(&command, uuid)?;
    require(
        before == expected["connection"] && command.evidence()? == expected["provider"],
        "network trust plan changed",
    )?;
    authorization()?;
    lock.recheck()?;
    require(
        selected(&command, uuid)? == before,
        "network connection changed before modification",
    )?;
    command.run(
        &[
            "--wait",
            "10",
            "connection",
            "modify",
            uuid,
            "connection.zone",
            if trusted { TRUSTED_ZONE } else { "" },
        ],
        &[0],
        65536,
    )?;
    lock.recheck()?;
    let mut live = false;
    if let Some(interface) = before["device"].as_str() {
        let changed = selected(&command, uuid)?;
        require(
            changed["connection"] == before["connection"]
                && changed["type"] == before["type"]
                && changed["device"] == before["device"],
            "active network identity changed; modified outcome requires review",
        )?;
        authorization()?;
        lock.recheck()?;
        command.run(
            &["--wait", "10", "device", "reapply", interface],
            &[0],
            65536,
        )?;
        live = true;
    }
    let after = selected(&command, uuid)?;
    require(
        after["trusted"].as_bool() == Some(trusted)
            && after["connection"] == before["connection"]
            && after["type"] == before["type"]
            && after["device"] == before["device"],
        "network trust outcome differs; no automatic replay",
    )?;
    command.recheck()?;
    lock.recheck()?;
    Ok(value!({"connection":uuid,"trusted":trusted,"zone":after["zone"],"applied_live":live}))
}
