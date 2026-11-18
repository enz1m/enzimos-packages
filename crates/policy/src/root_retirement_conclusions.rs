// SPDX-License-Identifier: MIT
//! Strict comparison of completed native preparation/staging history with the
//! actual original prepared retirement. No ownership or execution constructor.
use enzimos_platform::json;
use serde_json::Value;
pub(crate) fn historical(row: &Value, prepared: &Value) -> bool {
    let Some(root) = prepared["targets"].as_array().and_then(|rows| rows.last()) else {
        return false;
    };
    if prepared["phase"] != "prepared"
        || prepared["next_step"] != 0
        || !prepared["inflight"].is_null()
        || root["role"] != "root-subvolume"
        || row["state"] != "completed"
        || row["plan"]["schema"] != 1
        || row["plan"]["operation"] != row["operation"]
        || row["plan"]["observation"]["filesystem_uuid"] != prepared["filesystem_uuid"]
        || row["plan"]["observation"]["plan_sha256"] != prepared["plan_sha256"]
    {
        return false;
    }
    let Some(uuid) = root["uuid"].as_str() else {
        return false;
    };
    if crate::identity::uuid(uuid).is_err()
        || prepared["id"] != format!("root-{}", uuid.replace('-', ""))
    {
        return false;
    }
    let selection = &row["plan"]["selection"];
    let result = &row["result"];
    match row["operation"].as_str() {
        Some("root-retire-prepare") => {
            json::fields(selection, "root_uuid plan_sha256").is_ok()
                && json::fields(result, "id status deleted").is_ok()
                && selection["root_uuid"] == root["uuid"]
                && selection["plan_sha256"] == prepared["plan_sha256"]
                && result["id"] == prepared["id"]
                && result["status"] == "root-retirement-prepared"
                && result["deleted"] == false
        }
        Some("root-retire-stage") => {
            let coordinator = &prepared["coordinator"];
            let Some(options) = coordinator["options"].as_str() else {
                return false;
            };
            let Ok(parameters) = crate::root_retirement_parameters::Parameters::parse(options)
            else {
                return false;
            };
            json::fields(selection, "id image exit").is_ok()
                && json::fields(result, "id image status reboot_required").is_ok()
                && selection["id"] == prepared["id"]
                && selection["image"] == coordinator["image"]
                && selection["exit"] == parameters.exit
                && parameters.matches_record(prepared).is_ok()
                && result["id"] == prepared["id"]
                && result["image"] == coordinator["image"]
                && result["status"] == "root-retirement-coordinator-staged"
                && result["reboot_required"] == true
        }
        _ => false,
    }
}
