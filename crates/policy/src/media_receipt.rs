// SPDX-License-Identifier: MIT
//! Media restore completion never treats a failed receipt as retry authority.
use crate::{
    operation, recovery_adoption, recovery_confirmation,
    recovery_journal::{Journal, Kind},
    recovery_records as records,
};
use enzimos_platform::{Result, files, json, require};
use serde_json::{Value, json as value};
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(v, "schema id phase plan_sha256 media_origin")?;
    records::job_id(id)?;
    require(
        v["schema"] == 1
            && v["id"] == id
            && matches!(
                v["phase"].as_str(),
                Some("running" | "executed" | "failed" | "complete")
            ),
        "invalid media restore receipt",
    )?;
    crate::identity::sha(records::text(v, "plan_sha256")?)?;
    records::media_origin(&v["media_origin"])
}
pub fn complete_locked(id: &str, lock: &files::Lock) -> Result<bool> {
    records::job_id(id)?;
    operation::root_only()?;
    let mut receipts = Journal::open(Kind::Media, false)?;
    let Some(mut receipt) = receipts.records.get(id).cloned() else {
        return Ok(false);
    };
    require(
        matches!(receipt["phase"].as_str(), Some("executed" | "complete")),
        "media restore did not complete; no replay",
    )?;
    let activations = Journal::open(Kind::Activations, false)?;
    let activation = activations
        .records
        .get(id)
        .ok_or_else(|| enzimos_platform::Error("media activation missing".into()))?;
    require(
        activation["intent"]["schema"] == 2
            && activation["intent"]["job"]["plan"]["schema"] == 2
            && activation["intent"]["job"]["plan"]["plan_sha256"] == receipt["plan_sha256"]
            && activation["intent"]["job"]["plan"]["media_origin"] == receipt["media_origin"],
        "media receipt differs from native activation origin",
    )?;
    let workflows = Journal::open(Kind::Workflows, false)?;
    require(
        workflows.records.get(id).is_some_and(|v| {
            v["state"] == "complete" && v["plan_sha256"] == receipt["plan_sha256"]
        }),
        "media workflow did not complete",
    )?;
    let confirmation = recovery_confirmation::confirm_locked(lock)?;
    require(
        confirmation["id"] == id,
        "actual media restoration differs from receipt",
    )?;
    receipts.unchanged()?;
    workflows.unchanged()?;
    if activation["phase"] == "selected" {
        recovery_adoption::adopt_locked(
            id,
            records::text(&activation["intent"], "intent_sha256")?,
            lock,
        )?;
    } else {
        require(
            activation["phase"] == "adopted",
            "media activation requires review",
        )?;
    }
    if receipt["phase"] == "executed" {
        let previous = receipt.clone();
        receipt["phase"] = value!("complete");
        receipts.unchanged()?;
        receipts.save(id, receipt, Some(&previous), lock)?;
    }
    Ok(true)
}
