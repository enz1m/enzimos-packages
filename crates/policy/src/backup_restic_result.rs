// SPDX-License-Identifier: MIT
//! Restic's exit status and bounded JSON are both required for an observed outcome.
use enzimos_platform::{Result, json, require};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    Success,
    IncompleteBackup,
    RepositoryLocked,
    IncorrectPassword,
    UnknownFailure,
}
pub(crate) fn exit(code: Option<i32>) -> Exit {
    match code {
        Some(0) => Exit::Success,
        Some(3) => Exit::IncompleteBackup,
        Some(11) => Exit::RepositoryLocked,
        Some(12) => Exit::IncorrectPassword,
        _ => Exit::UnknownFailure,
    }
}
pub(crate) fn backup(code: Option<i32>, bytes: &[u8]) -> Result<String> {
    Ok(enzimos_platform::json::string(&backup_summary(code, bytes)?["snapshot_id"])?.to_owned())
}
/// Preserve the exact terminal vendor summary, including compatible future fields.
pub(crate) fn backup_summary(code: Option<i32>, bytes: &[u8]) -> Result<serde_json::Value> {
    require(
        exit(code) == Exit::Success && bytes.len() <= 2 * 1024 * 1024,
        "backup transfer failed or unknown; no replay",
    )?;
    let mut summary = None;
    let mut count = 0;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        count += 1;
        require(
            count <= 8192 && summary.is_none(),
            "backup summary missing, repeated or not terminal",
        )?;
        let row = json::decode(line, 32768)?;
        let kind = row["message_type"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("backup JSON message type required".into()))?;
        require(kind != "error", "backup error message prevents completion")?;
        if let Some(errors) = row.get("error_count") {
            require(
                errors.as_u64() == Some(0),
                "backup source errors prevent completion",
            )?;
        }
        if kind == "summary" {
            require(
                row.get("dry_run")
                    .is_none_or(|dry| dry.as_bool() == Some(false)),
                "dry-run or malformed backup summary prevents completion",
            )?;
            let id = row["snapshot_id"].as_str().ok_or_else(|| {
                enzimos_platform::Error("actual backup snapshot ID required".into())
            })?;
            crate::identity::sha(id)?;
            summary = Some(row);
        }
    }
    summary.ok_or_else(|| {
        enzimos_platform::Error("actual backup summary unavailable; no replay".into())
    })
}
pub(crate) fn keys(code: Option<i32>, bytes: &[u8]) -> Result<BTreeMap<String, bool>> {
    require(
        exit(code) == Exit::Success,
        "repository key observation failed or unknown",
    )?;
    let v = json::decode(bytes, 1024 * 1024)?;
    let rows = v
        .as_array()
        .ok_or_else(|| enzimos_platform::Error("repository key list required".into()))?;
    require((1..=32).contains(&rows.len()), "repository key count bound")?;
    let mut result = BTreeMap::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("repository key ID required".into()))?;
        crate::identity::sha(id)?;
        let current = row["current"].as_bool().ok_or_else(|| {
            enzimos_platform::Error("repository current key status required".into())
        })?;
        require(
            result.insert(id.to_owned(), current).is_none(),
            "duplicate repository key identity",
        )?;
    }
    require(
        result.values().filter(|v| **v).count() == 1,
        "one authenticated current repository key required",
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn backup_rejects_dry_run_and_reported_source_errors_despite_success_exit() {
        let mut row = json!({"message_type":"summary","snapshot_id":"a".repeat(64)});
        for dry in [json!(true), json!(null), json!(0), json!("false")] {
            row["dry_run"] = dry;
            assert!(backup(Some(0), &serde_json::to_vec(&row).unwrap()).is_err());
        }
        row["dry_run"] = json!(false);
        backup(Some(0), &serde_json::to_vec(&row).unwrap()).unwrap();
        for errors in [json!(1), json!(-1), json!(null), json!("0")] {
            let mut bytes =
                serde_json::to_vec(&json!({"message_type":"status","error_count":errors})).unwrap();
            bytes.push(b'\n');
            bytes.extend(serde_json::to_vec(&row).unwrap());
            assert!(backup(Some(0), &bytes).is_err());
        }
    }
}
