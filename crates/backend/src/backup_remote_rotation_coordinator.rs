// SPDX-License-Identifier: MIT
//! Fresh Root review over original actual journal, pin and fixed input descriptions.
use enzimos_platform::{Result, require};
use enzimos_policy::{
    backup_remote_rotation_context::Context, backup_remote_rotation_review, storage_runtime::Guard,
};
use serde_json::{Value, json as value};
pub fn review(
    guard: &Guard,
    input: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    backup_remote_rotation_review::selection(input)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    progress("validating")?;
    let context = Context::observe(guard, &lock, &mut permission)?;
    require(
        backup_remote_rotation_review::measure(&context, &mut permission)? == *expected,
        "job-plan-changed",
    )?;
    let review = context.review(&mut permission)?;
    progress("finishing")?;
    permission()?;
    context.recheck(&mut permission)?;
    Ok(
        value!({"phase":review["phase"],"boundary":review["boundary"],"next_action":review["next_action"],"review_sha256":review["review_sha256"]}),
    )
}

pub fn advance(
    guard: &Guard,
    input: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    backup_remote_rotation_review::advance_selection(input)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    progress("validating")?;
    let context = Context::observe(guard, &lock, &mut permission)?;
    require(
        backup_remote_rotation_review::measure_role(
            &context,
            "remote-rotation-advance",
            &mut permission,
        )? == *expected,
        "job-plan-changed",
    )?;
    progress("transferring")?;
    let result = context.advance(
        input["review_sha256"].as_str().unwrap(),
        input["action"].as_str().unwrap(),
        &mut permission,
    )?;
    permission()?;
    progress("finishing")?;
    permission()?;
    Ok(value!({"status":result["status"],"old_remote_repository_deleted":false}))
}
