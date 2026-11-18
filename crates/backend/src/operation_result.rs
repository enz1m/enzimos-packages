// SPDX-License-Identifier: MIT
//! Only the corresponding closed native reply can complete an operation.
use super::system_wire::hex;
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
fn fields(v: &Value, k: &str) -> Result<()> {
    json::fields(v, k).map_err(|_| Error("job-result-invalid".into()))
}
fn sha(v: &Value) -> bool {
    v.as_str().is_some_and(|s| hex(s, 64))
}
fn number(v: &Value) -> bool {
    v.as_u64().is_some()
}
fn next(v: &Value) -> bool {
    matches!(v.as_str(), Some("abandon" | "switch" | "discard"))
}
fn boundary(v: &Value, max: u64) -> bool {
    v.is_null() || v.as_u64().is_some_and(|n| n <= max)
}
fn advanced(action: &Value, remote: bool) -> Result<&'static str> {
    match (action.as_str(), remote) {
        (Some("abandon"), false) => Ok("rotation-abandoned"),
        (Some("switch"), false) => Ok("rotation-switched"),
        (Some("discard"), false) => Ok("rotation-complete"),
        (Some("abandon"), true) => Ok("remote-rotation-abandoned"),
        (Some("switch"), true) => Ok("remote-rotation-switched"),
        (Some("discard"), true) => Ok("remote-rotation-complete"),
        _ => Err(Error("job-result-invalid".into())),
    }
}
pub(crate) fn validate(record: &Value) -> Result<()> {
    let r = &record["result"];
    let p = &record["plan"];
    let s = &p["selection"];
    let valid = match record["operation"].as_str() {
        Some("backup-create") => {
            fields(r, "snapshot_id")?;
            sha(&r["snapshot_id"])
        }
        Some("delivery-cancel") => {
            fields(r, "grant_id status output_removed copy_replayed")?;
            r["grant_id"] == s["id"]
                && r["status"] == "delivery-grant-cancelled"
                && r["output_removed"] == false
                && r["copy_replayed"] == false
        }
        Some(role @ ("credential-review" | "credential-complete")) => {
            fields(
                r,
                "enrollment review_sha256 new_key receipt_completed key_creation_replayed old_access_revoked",
            )?;
            r["enrollment"] == s["id"]
                && sha(&r["review_sha256"])
                && sha(&r["new_key"])
                && r["receipt_completed"].as_bool() == Some(role == "credential-complete")
                && r["key_creation_replayed"] == false
                && r["old_access_revoked"] == false
        }
        Some("boot-retire") => {
            fields(
                r,
                "generation status root_subvolume_retained disclosed_unobservable",
            )?;
            r["generation"] == s["generation"]
                && r["status"] == "retirement-complete"
                && r["root_subvolume_retained"] == true
                && r["disclosed_unobservable"].as_array().is_some_and(|a| {
                    a.iter()
                        .all(|v| v == "EFI-loader-state-not-observable-on-this-boot")
                })
        }
        Some("rotation-review") => {
            fields(r, "rotation phase next_action boundary review_sha256")?;
            r["rotation"] == s["id"]
                && next(&r["next_action"])
                && boundary(&r["boundary"], 5)
                && sha(&r["review_sha256"])
        }
        Some("rotation-advance") => {
            fields(r, "rotation status old_access_revoked")?;
            r["rotation"] == s["id"]
                && r["status"] == advanced(&s["action"], false)?
                && r["old_access_revoked"] == false
        }
        Some("root-retire-prepare") => {
            fields(r, "id status deleted")?;
            let root = s["root_uuid"]
                .as_str()
                .ok_or_else(|| Error("job-result-invalid".into()))?;
            r["id"] == format!("root-{}", root.replace('-', ""))
                && r["status"] == "root-retirement-prepared"
                && r["deleted"] == false
        }
        Some("root-retire-stage") => {
            fields(r, "id image status reboot_required")?;
            r["id"] == s["id"]
                && r["image"] == s["image"]
                && r["status"] == "root-retirement-coordinator-staged"
                && r["reboot_required"] == true
        }
        Some("root-retire-finish") => {
            fields(r, "id status")?;
            r["id"] == s["id"] && r["status"] == "root-retirement-complete"
        }
        Some("remote-rotation-review") => {
            fields(r, "phase boundary next_action review_sha256")?;
            (next(&r["next_action"]) || r["next_action"].is_null())
                && boundary(&r["boundary"], 6)
                && sha(&r["review_sha256"])
        }
        Some("remote-rotation-advance") => {
            fields(r, "status old_remote_repository_deleted")?;
            r["status"] == advanced(&s["action"], true)?
                && r["old_remote_repository_deleted"] == false
        }
        Some("recovery-run-stage") => {
            fields(r, "id status uefi_mode reboot_required")?;
            r["id"] == s["id"]
                && r["status"] == "recovery-run-staged"
                && matches!(r["uefi_mode"].as_str(), Some("one-shot" | "default"))
                && r["reboot_required"] == true
        }
        Some("recovery-run-finish") => {
            fields(r, "id status old_roots_retired")?;
            r["id"] == s["id"]
                && r["status"] == "recovery-run-complete"
                && r["old_roots_retired"] == false
        }
        Some("file-restore-export") => {
            fields(r, "id status bytes sha256")?;
            r["id"] == s["id"]
                && r["status"] == "private-file-export-complete"
                && number(&r["bytes"])
                && sha(&r["sha256"])
        }
        Some("tree-restore-export") => {
            fields(r, "id status bytes sha256 entries")?;
            r["id"] == s["id"]
                && r["status"] == "private-tree-export-complete"
                && r["bytes"].as_u64().is_some_and(|n| n > 0)
                && r["entries"].as_u64().is_some_and(|n| n > 0)
                && sha(&r["sha256"])
        }
        Some("file-restore-grant") => {
            fields(r, "id recipient_uid grant_sha256 filename")?;
            r["id"] == s["id"]
                && r["recipient_uid"] == s["uid"]
                && sha(&r["grant_sha256"])
                && r["filename"]
                    == format!("enzimos-restored-{}.bin", s["id"].as_str().unwrap_or(""))
        }
        Some(role @ ("file-restore-deliver" | "own-file-restore")) => {
            fields(
                r,
                "id status recipient_uid filename bytes sha256 overwritten metadata_restored",
            )?;
            r["id"] == s["id"]
                && r["status"] == "delivered-new-private-file"
                && number(&r["recipient_uid"])
                && number(&r["bytes"])
                && sha(&r["sha256"])
                && r["overwritten"] == false
                && r["metadata_restored"] == false
                && if role == "own-file-restore" {
                    r["recipient_uid"] == record["owner_uid"]
                        && r["recipient_uid"] == p["uid"]
                        && r["filename"] == p["filename"]
                        && r["bytes"].as_u64().is_some_and(|n| n <= 16 * 1024 * 1024)
                } else {
                    r["filename"]
                        == format!("enzimos-restored-{}.bin", s["id"].as_str().unwrap_or(""))
                }
        }
        Some("memory-policy-set") => {
            fields(r, "mode applied_live reboot_required")?;
            r["mode"] == s["mode"] && r["applied_live"] == true && r["reboot_required"] == false
        }
        Some("home-retention-set") => {
            fields(r, "policy existing_history_removed cleanup_started")?;
            r["policy"] == *s
                && r["existing_history_removed"] == false
                && r["cleanup_started"] == false
        }
        Some("backup-retention-set") => {
            fields(
                r,
                "automatic last daily weekly monthly yearly existing_backups_removed",
            )?;
            crate::system_selection::RETENTION_TIERS
                .iter()
                .chain(&["automatic"])
                .all(|key| r[*key] == s[*key])
                && r["existing_backups_removed"] == false
        }
        Some("network-trust-set") => {
            fields(r, "connection trusted zone applied_live")?;
            r["connection"] == s["connection"]
                && r["trusted"] == s["trusted"]
                && r["applied_live"].is_boolean()
                && r["trusted"].as_bool() == Some(r["zone"] == "enzimos-trusted")
        }
        Some("battery-action-set") => {
            fields(
                r,
                "configured_action risky_action_allowed reboot_required applied_live owner",
            )?;
            r["configured_action"] == s["action"]
                && r["risky_action_allowed"].as_bool()
                    == Some(matches!(s["action"].as_str(), Some("suspend" | "ignore")))
                && r["reboot_required"] == true
                && r["applied_live"] == false
                && r["owner"] == "UPower"
        }
        Some("home-history-set") => {
            fields(r, "enabled state existing_history_removed")?;
            r["enabled"] == s["enabled"] && r["existing_history_removed"] == false
        }
        Some("backup-schedule-set") => {
            fields(r, "enabled status immediate_backup_started")?;
            r["enabled"] == s["enabled"] && r["immediate_backup_started"] == false
        }
        Some("remote-replicate") => {
            fields(r, "status source_snapshot remote_snapshot repository_id")?;
            r["status"] == "recovery-point-replicated"
                && r["source_snapshot"] == s["snapshot"]
                && sha(&r["remote_snapshot"])
                && sha(&r["repository_id"])
        }
        Some("remote-retrieve") => {
            fields(
                r,
                "id status remote_snapshot local_snapshot automatic_retry",
            )?;
            r["id"] == s["id"]
                && r["remote_snapshot"] == s["snapshot"]
                && r["status"] == "remote-point-retrieved-to-local"
                && r["automatic_retry"] == false
                && sha(&r["local_snapshot"])
        }
        Some("update-apply") => {
            fields(r, "generation status reboot_requested")?;
            r["generation"] == format!("api-{}", record["request_id"].as_str().unwrap_or(""))
                && matches!(
                    r["status"].as_str(),
                    Some("up-to-date" | "prepared-not-rebooted")
                )
                && r["reboot_requested"] == false
        }
        Some("recovery-prepare") => {
            fields(r, "recovery_id plan_sha256 activation_available")?;
            r["recovery_id"] == format!("api-{}", record["request_id"].as_str().unwrap_or(""))
                && sha(&r["plan_sha256"])
                && r["activation_available"] == false
        }
        _ => false,
    };
    require(valid, "job-result-invalid")
}
