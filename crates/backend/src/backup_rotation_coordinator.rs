// SPDX-License-Identifier: MIT
//! Stored rotation review uses fresh permission and original retained Root objects.
use enzimos_platform::{Result, json, require};
use enzimos_policy::{
    backup_configuration::Configuration, backup_rotation_context::Context, backup_rotation_review,
    storage_runtime::Guard,
};
use serde_json::{Value, json as value};
pub fn review(
    guard: &Guard,
    selection: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    json::fields(selection, "id")?;
    let id = selection["id"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("rotation ID required".into()))?;
    enzimos_policy::identity::safe_id(id)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let configuration = Configuration::open()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        configuration.recheck()
    };
    progress("validating")?;
    let context = Context::observe(guard, &lock, &configuration, id, &mut permission)?;
    require(
        backup_rotation_review::measure(&context, &mut permission)? == *expected,
        "job-plan-changed",
    )?;
    progress("finishing")?;
    context.recheck(&mut permission)?;
    let review = &expected["review"];
    let result = value!({"rotation":review["rotation"],"phase":review["phase"],"next_action":review["next_action"],
        "boundary":review["boundary"],"review_sha256":review["review_sha256"]});
    permission()?;
    context.recheck(&mut permission)?;
    Ok(result)
}

pub fn advance(
    guard: &Guard,
    selection: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    json::fields(selection, "id review_sha256 action")?;
    let id = selection["id"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("rotation ID required".into()))?;
    enzimos_policy::identity::safe_id(id)?;
    let sha = selection["review_sha256"].as_str().unwrap_or("");
    enzimos_policy::identity::sha(sha)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let configuration = Configuration::open()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        configuration.recheck()
    };
    progress("validating")?;
    let context = Context::observe(guard, &lock, &configuration, id, &mut permission)?;
    require(
        backup_rotation_review::measure_role(&context, "rotation-advance", &mut permission)?
            == *expected,
        "job-plan-changed",
    )?;
    progress("transferring")?;
    let result = match selection["action"].as_str() {
        Some("switch") => context.switch(sha, &mut permission)?,
        Some("discard") => context.discard(sha, &mut permission)?,
        Some("abandon") => context.abandon(sha, &mut permission)?,
        _ => {
            return Err(enzimos_platform::Error(
                "closed rotation action required".into(),
            ));
        }
    };
    permission()?;
    progress("finishing")?;
    permission()?;
    Ok(value!({"rotation":result["rotation"],"status":result["status"],"old_access_revoked":false}))
}
