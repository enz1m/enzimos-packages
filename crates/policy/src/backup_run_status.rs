// SPDX-License-Identifier: MIT
//! The outcome of the most recent backup run, for Settings and notifications:
//! `ok`, `waiting-for-drive` (scheduled while the drive was not connected) or
//! `failed`. `since` is when the current state began, so "waiting since
//! Monday" and "one notification per episode" need no history.
use crate::operation;
use enzimos_platform::{Result, files, json};
use serde_json::{Value, json as value};
use std::path::Path;

const NAME: &str = "backup-run-status.json";
const LIMIT: usize = 4096;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The recorded status, or `{}` before the first run.
#[must_use]
pub fn read() -> Value {
    files::read_optional(
        &Path::new(operation::CONTROL).join(NAME),
        LIMIT,
        Some(0),
        true,
    )
    .ok()
    .flatten()
    .and_then(|bytes| json::decode(&bytes, LIMIT).ok())
    .unwrap_or_else(|| value!({}))
}

/// The next document after a run ended in `state` (pure, for tests).
#[must_use]
pub fn next(previous: &Value, state: &str, code: Option<&str>, at: u64) -> Value {
    let since = if previous["state"] == state {
        previous["since"].as_u64().unwrap_or(at)
    } else {
        at
    };
    let last_success = if state == "ok" {
        Some(at)
    } else {
        previous["last_success"].as_u64()
    };
    value!({"state":state,"since":since,"at":at,
        "code":code.map(|c| c.chars().take(160).collect::<String>()),
        "last_success":last_success})
}

/// Record how a run ended.
///
/// # Errors
/// Fails when the control directory cannot be written.
pub fn record(state: &str, code: Option<&str>) -> Result<()> {
    let document = next(&read(), state, code, now());
    files::atomic_bounded(
        &Path::new(operation::CONTROL).join(NAME),
        &json::canonical(&document)?,
        0o600,
        Some(0),
        true,
        LIMIT,
    )
}

/// Whether an error means the backup drive was not connected.
#[must_use]
pub fn is_absent(error: &str) -> bool {
    error.contains("backup-destination-absent")
}
