// SPDX-License-Identifier: MIT
//! Critical-battery action in the UPower configuration.
use crate::{operation, settings_file::Config};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
const CONFIG: &str = "/etc/UPower/UPower.conf";
const ACTIONS: &[(&str, &str)] = &[
    ("auto", "Auto"),
    ("suspend", "Suspend"),
    ("hibernate", "Hibernate"),
    ("power-off", "PowerOff"),
    ("ignore", "Ignore"),
];
pub(crate) fn risky(s: &str) -> bool {
    matches!(s, "suspend" | "ignore")
}
pub(crate) fn validate_selection(action: &str, risk: bool) -> Result<()> {
    require(
        ACTIONS.iter().any(|a| a.0 == action) && risk == risky(action),
        "critical power risk acknowledgement mismatch",
    )
}
fn header(line: &str) -> Result<Option<&str>> {
    let s = line.trim();
    if !s.starts_with('[') {
        return Ok(None);
    }
    let (head, tail) = s
        .split_once(']')
        .ok_or_else(|| Error("invalid power section".into()))?;
    let tail = tail.trim();
    require(
        tail.is_empty() || tail.starts_with(['#', ';']),
        "invalid power section",
    )?;
    require(head.len() > 1, "empty power section")?;
    Ok(Some(head.strip_prefix('[').unwrap_or(head).trim()))
}
pub(crate) fn parse(text: &str) -> Result<(String, bool)> {
    require(
        text.len() <= 65536 && !text.contains('\0'),
        "power configuration bound",
    )?;
    let mut section = "";
    let mut sections = BTreeSet::new();
    let mut values = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with(['#', ';']) {
            continue;
        }
        if let Some(h) = header(line)? {
            require(sections.insert(h), "duplicate power section")?;
            section = h;
            continue;
        }
        let (key, val) = s
            .split_once(['=', ':'])
            .ok_or_else(|| Error("invalid power configuration line".into()))?;
        let key = key.trim();
        require(
            !section.is_empty() && !key.is_empty() && seen.insert((section, key)),
            "duplicate or unscoped power option",
        )?;
        if section == "UPower" {
            values.insert(key, val.trim());
        }
    }
    require(sections.contains("UPower"), "missing UPower section")?;
    let action = values.get("CriticalPowerAction").copied().unwrap_or("Auto");
    require(
        ACTIONS.iter().any(|a| a.1 == action),
        "unsupported critical power action",
    )?;
    let risk = match values
        .get("AllowRiskyCriticalPowerAction")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false" | "no" | "off" | "0") => false,
        Some("true" | "yes" | "on" | "1") => true,
        _ => return Err(Error("invalid risky power preference".into())),
    };
    Ok((action.into(), risk))
}
pub(crate) fn replacement(text: &str, action: &str) -> Result<String> {
    parse(text)?;
    let configured = ACTIONS
        .iter()
        .find(|a| a.0 == action)
        .ok_or_else(|| Error("invalid power action".into()))?
        .1;
    let mut changes = BTreeMap::from([
        ("CriticalPowerAction", configured),
        (
            "AllowRiskyCriticalPowerAction",
            if risky(action) { "true" } else { "false" },
        ),
    ]);
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if let Some(h) = header(line)? {
            if inside {
                for (k, v) in &changes {
                    out.push(format!("{k}={v}"));
                }
                changes.clear();
            }
            inside = h == "UPower";
        }
        let key = line.split_once('=').map(|p| p.0.trim());
        if inside
            && let Some(key) = key
            && let Some(replacement) = changes.remove(key)
        {
            out.push(format!("{key}={replacement}"));
            continue;
        }
        out.push(line.into());
    }
    if inside {
        for (k, v) in changes {
            out.push(format!("{k}={v}"));
        }
    }
    let result = out.join("\n") + "\n";
    let (actual, risk) = parse(&result)?;
    require(
        actual == configured && risk == risky(action),
        "power replacement did not match request",
    )?;
    Ok(result)
}
fn read() -> Result<(String, String, bool, String)> {
    let b = Config::open(CONFIG, 65536)?.body;
    let text =
        String::from_utf8(b.clone()).map_err(|_| Error("power configuration encoding".into()))?;
    let (action, risk) = parse(&text)?;
    Ok((text, action, risk, json::sha256(&b)))
}
fn capabilities() -> BTreeSet<String> {
    let mut available = BTreeSet::new();
    for action in ["Suspend", "Hibernate"] {
        let method = format!("Can{action}");
        if let Ok(out) = operation::query(
            "/usr/bin/busctl",
            &[
                "--system",
                "--timeout=5",
                "call",
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                &method,
            ],
            Duration::from_secs(6),
            4096,
            &[0],
        ) && matches!(
            std::str::from_utf8(&out).map(str::trim),
            Ok("s \"yes\"" | "s \"challenge\"")
        ) {
            available.insert(action.to_ascii_lowercase());
        }
    }
    available
}
/// The configured critical-battery action and the supported actions.
///
/// # Errors
///
/// Fails when the configuration cannot be read.
pub fn policy() -> Result<Value> {
    let (_, action, risk, checksum) = read()?;
    let available = capabilities();
    Ok(
        value!({"configured_action":ACTIONS.iter().find(|a|a.1==action).ok_or_else(|| enzimos_platform::Error("missing element".into()))?.0,"risky_action_allowed":risk,"supported_actions":ACTIONS.iter().filter(|a|!matches!(a.0,"suspend"|"hibernate")||available.contains(a.0)).map(|a|a.0).collect::<Vec<_>>(),"risk_acknowledgement_required":["ignore","suspend"],"config_sha256":checksum,"effective_after":"next-boot","owner":"UPower"}),
    )
}
/// Set the critical-battery `action`, with `risk` acknowledging a risky choice.
///
/// # Errors
///
/// Fails for unsupported actions, unacknowledged risk, a changed configuration, or failed
/// authorization.
pub fn set_action<F: FnMut() -> Result<()>>(
    action: &str,
    risk: bool,
    mut authorization: F,
) -> Result<Value> {
    operation::root_only()?;
    validate_selection(action, risk)?;
    let lock = operation::lock()?;
    let mut config = Config::open(CONFIG, 65536)?;
    authorization()?;
    config.recheck()?;
    lock.recheck()?;
    let before = policy()?;
    require(
        enzimos_platform::json::array(&before["supported_actions"])?
            .iter()
            .any(|v| v == action),
        "critical power action unavailable",
    )?;
    let (text, _, _, checksum) = read()?;
    require(before["config_sha256"] == checksum, "power policy changed")?;
    let data = replacement(&text, action)?;
    authorization()?;
    require(read()?.3 == checksum, "power policy changed")?;
    config.recheck()?;
    lock.recheck()?;
    config.publish(data.as_bytes())?;
    config.recheck()?;
    lock.recheck()?;
    // Never restart UPower here: a new action on a critical battery could run now.
    Ok(
        value!({"configured_action":action,"risky_action_allowed":risk,"reboot_required":true,"applied_live":false,"owner":"UPower"}),
    )
}
/// The current observation under the operation lock.
///
/// # Errors
///
/// Fails when the lock is held or the observation fails.
pub fn plan() -> Result<Value> {
    let lock = operation::lock()?;
    let body = observation()?;
    lock.recheck()?;
    Ok(body)
}
/// Read-only binding also used inside the original setter's existing lock.
///
/// # Errors
///
/// Fails when the configuration cannot be read.
pub fn observation() -> Result<Value> {
    let config = Config::open(CONFIG, 65536)?;
    let state = policy()?;
    config.recheck()?;
    Ok(value!({"state":state,"configuration":config.evidence()?}))
}
