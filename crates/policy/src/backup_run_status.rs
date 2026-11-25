// SPDX-License-Identifier: MIT
//! The outcome of the most recent backup run, for Settings and notifications:
//! `ok`, `waiting-for-drive` (scheduled while the drive was not connected) or
//! `failed`. `since` is when the current state began, so "waiting since
//! Monday" and "one notification per episode" need no history.
//!
//! The automatic copy of a new local backup to the NAS share has its own
//! outcome (`remote_copy`); a failed copy never changes the run state.
use crate::operation;
use enzimos_platform::{Result, files, json};
use serde_json::{Value, json as value};
use std::path::Path;

const NAME: &str = "backup-run-status.json";
pub(crate) const REMOTE_COPY: &str = "backup-remote-copy-status.json";
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
pub(crate) fn next(previous: &Value, state: &str, code: Option<&str>, at: u64) -> Value {
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
pub(crate) fn record(state: &str, code: Option<&str>) -> Result<()> {
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

/// Record how a backup run ended: `ok`, `waiting-for-drive` when the drive
/// was not connected, otherwise `failed` with the error as its code.
pub fn record_outcome(error: Option<&str>) {
    let _ = record(outcome(error), error);
}

/// The run state of a run that ended with `error`, or succeeded without one.
#[must_use]
pub(crate) fn outcome(error: Option<&str>) -> &'static str {
    match error {
        None => "ok",
        Some(error) if is_absent(error) => "waiting-for-drive",
        Some(_) => "failed",
    }
}

/// The copy document after a copy ended in `state` (pure, for tests).
#[must_use]
pub(crate) fn remote_copy_document(state: &str, code: Option<&str>, at: u64) -> Value {
    value!({"state":state,"at":at,"code":code.map(|c| c.chars().take(160).collect::<String>())})
}

/// The last automatic copy to the NAS share, or `null` before the first one.
#[must_use]
pub fn remote_copy() -> Value {
    files::read_optional(
        &Path::new(operation::CONTROL).join(REMOTE_COPY),
        LIMIT,
        Some(0),
        true,
    )
    .ok()
    .flatten()
    .and_then(|bytes| json::decode(&bytes, LIMIT).ok())
    .filter(|document| {
        json::fields(document, "state at code").is_ok()
            && matches!(document["state"].as_str(), Some("ok" | "failed"))
    })
    .unwrap_or(Value::Null)
}

/// Record how the automatic copy to the NAS share ended (`ok` or `failed`).
///
/// # Errors
/// Fails when the control directory cannot be written.
pub fn record_remote_copy(state: &str, code: Option<&str>) -> Result<()> {
    enzimos_platform::require(
        matches!(state, "ok" | "failed"),
        "closed remote copy state required",
    )?;
    files::atomic_bounded(
        &Path::new(operation::CONTROL).join(REMOTE_COPY),
        &json::canonical(&remote_copy_document(state, code, now()))?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_success_replaces_a_stale_failure() {
        let failed = next(&value!({}), "failed", Some("job-plan-changed"), 100);
        assert_eq!(failed["state"], "failed");
        assert_eq!(failed["last_success"], Value::Null);
        let ok = next(&failed, "ok", None, 200);
        assert_eq!(
            ok,
            value!({"state":"ok","since":200,"at":200,"code":null,"last_success":200})
        );
    }
    #[test]
    fn manual_and_scheduled_outcomes_share_one_state_mapping() {
        assert_eq!(outcome(None), "ok");
        assert_eq!(
            outcome(Some("backup-destination-absent: drive not attached")),
            "waiting-for-drive"
        );
        assert_eq!(outcome(Some("job-plan-changed")), "failed");
    }
    #[test]
    fn remote_copy_document_is_closed_and_bounded() {
        let long = "remote-share-unreachable: ".to_owned() + &"x".repeat(400);
        let document = remote_copy_document("failed", Some(&long), 300);
        assert!(json::fields(&document, "state at code").is_ok());
        assert_eq!(document["at"], 300);
        assert_eq!(document["code"].as_str().unwrap().chars().count(), 160);
        assert_eq!(
            remote_copy_document("ok", None, 5),
            value!({"state":"ok","at":5,"code":null})
        );
    }
}
