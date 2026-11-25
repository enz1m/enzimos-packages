// SPDX-License-Identifier: MIT
//! Exact private/public backup setup job contract; no credential material.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
pub(crate) const MAX_ATTEMPTS: u64 = 8;
pub(crate) fn validate(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema request_id owner_uid state attempts plan plan_sha256",
    )?;
    require(
        v["schema"] == 1
            && super::system_wire::hex(v["request_id"].as_str().unwrap_or(""), 32)
            && v["owner_uid"]
                .as_u64()
                .is_some_and(|n| (1000..i32::MAX as u64).contains(&n))
            && v["attempts"].as_u64().is_some_and(|n| n <= MAX_ATTEMPTS)
            && matches!(
                v["state"].as_str(),
                Some(
                    "review-awaiting-approval"
                        | "reviewing"
                        | "planned"
                        | "awaiting-approval"
                        | "running"
                        | "completed"
                        | "password-retry"
                        | "refused"
                        | "cancelled"
                        | "uncertain"
                        | "rolled-back"
                )
            ),
        "job-record-invalid",
    )?;
    let plan = &v["plan"];
    require(
        plan["schema"] == 1 && plan["id"] == v["request_id"] && plan["owner_uid"] == v["owner_uid"],
        "job-plan-invalid",
    )?;
    match plan["operation"].as_str() {
        Some("backup-device-review") => {
            json::fields(plan, "schema operation id owner_uid mode selection_id")?;
            enzimos_policy::backup_setup_plan::Mode::parse(plan["mode"].as_str().unwrap_or(""))?;
            enzimos_policy::identity::sha(plan["selection_id"].as_str().unwrap_or(""))?;
            require(
                v["attempts"] == 0
                    && matches!(
                        v["state"].as_str(),
                        Some(
                            "review-awaiting-approval"
                                | "reviewing"
                                | "refused"
                                | "cancelled"
                                | "uncertain"
                        )
                    ),
                "job-record-invalid",
            )?;
        }
        Some("backup-initial-setup") => {
            enzimos_policy::backup_setup_plan::validate(plan)?;
            require(
                (v["state"] == "planned" && v["attempts"] == 0)
                    || v["state"] == "cancelled"
                    || (!matches!(
                        v["state"].as_str(),
                        Some("planned" | "review-awaiting-approval" | "reviewing")
                    ) && enzimos_platform::json::unsigned(&v["attempts"])? > 0),
                "job-record-invalid",
            )?;
        }
        _ => return Err(Error("job-plan-invalid".into())),
    }
    require(
        v["plan_sha256"] == json::fingerprint(plan)?
            && json::canonical(v)?.len() <= super::operation_record::MAX_DOCUMENT,
        "job-plan-invalid",
    )
}
pub(crate) fn initial(id: &str, uid: u32, plan: Value) -> Result<Value> {
    let state = if plan["operation"] == "backup-device-review" {
        "review-awaiting-approval"
    } else {
        "planned"
    };
    let v = value!({"schema":1,"request_id":id,"owner_uid":uid,"state":state,"attempts":0,"plan_sha256":json::fingerprint(&plan)?,"plan":plan});
    validate(&v)?;
    Ok(v)
}
/// Public states. `rolled-back` (additive, enrollment only) means the job
/// failed after entry but the backend proved its rollback: no mount remains on
/// /backup-repository, no destination pin or opt-in exists, no repository was
/// created, and this attempt's configuration, credential and setup intent were
/// removed. It reports `retryable: true`, meaning a NEW review (new request ID)
/// can start; input on this request is refused. `uncertain` remains for every
/// failure whose rollback could not be proven: do not repeat automatically.
/// After `enzimos-policy backup-setup reset-uncertain` proves that rollback
/// for this request, the next status read records it as `rolled-back` too.
pub(crate) fn public(v: &Value) -> Result<Value> {
    validate(v)?;
    Ok(
        value!({"schema":v["schema"],"request_id":v["request_id"],"state":v["state"],"attempts":v["attempts"],"plan_sha256":v["plan_sha256"],
        "mode":v["plan"]["mode"],"automatic_backup_enabled":false,
        "retryable":v["state"] == "rolled-back" || (v["plan"]["operation"] == "backup-initial-setup" && matches!(v["state"].as_str(),Some("password-retry"|"refused")) && enzimos_platform::json::unsigned(&v["attempts"])? < MAX_ATTEMPTS),
        "cancellation_available":matches!(v["state"].as_str(),Some("review-awaiting-approval"|"planned"|"awaiting-approval"|"password-retry"|"refused"))}),
    )
}
pub(crate) fn transition(previous: &Value, next: &Value) -> Result<()> {
    validate(previous)?;
    validate(next)?;
    require(
        ["schema", "request_id", "owner_uid"]
            .iter()
            .all(|k| previous[*k] == next[*k]),
        "job-owner-mismatch",
    )?;
    let from = enzimos_platform::json::string(&previous["state"])?;
    let to = enzimos_platform::json::string(&next["state"])?;
    require(
        matches!(
            (from, to),
            (
                "review-awaiting-approval",
                "reviewing" | "refused" | "cancelled" | "uncertain"
            ) | ("reviewing", "planned" | "uncertain")
                | (
                    "planned" | "password-retry" | "refused",
                    "awaiting-approval" | "cancelled"
                )
                | (
                    "awaiting-approval",
                    "running" | "refused" | "cancelled" | "uncertain"
                )
                | (
                    "running",
                    "completed" | "password-retry" | "uncertain" | "rolled-back"
                )
                | ("uncertain", "rolled-back")
        ),
        "job-transition-refused",
    )?;
    // Only an enrollment can be rolled back, and only by the backend after
    // `reset-uncertain` proved the retraction (see SetupStore::reconcile_reset).
    require(
        to != "rolled-back" || next["plan"]["operation"] == "backup-initial-setup",
        "job-transition-refused",
    )?;
    if from == "reviewing" && to == "planned" {
        require(
            next["plan"]["operation"] == "backup-initial-setup"
                && ["id", "owner_uid", "mode", "selection_id"]
                    .iter()
                    .all(|k| previous["plan"][*k] == next["plan"][*k]),
            "job-plan-changed",
        )?;
    } else {
        require(
            previous["plan"] == next["plan"] && previous["plan_sha256"] == next["plan_sha256"],
            "job-plan-changed",
        )?;
    }
    let attempts = enzimos_platform::json::unsigned(&previous["attempts"])?;
    require(
        next["attempts"]
            == if to == "awaiting-approval" {
                attempts + 1
            } else {
                attempts
            },
        "job-transition-refused",
    )
}
#[cfg(test)]
#[path = "backup_setup_record_tests.rs"]
pub(crate) mod tests;
