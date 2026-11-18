// SPDX-License-Identifier: MIT
//! Original Root review measurement. Evidence cannot construct a mutation actor.
use crate::{backup_remote_rotation_context::Context, storage_runtime::Guard};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
pub fn selection(input: &Value) -> Result<()> {
    json::fields(input, "rotation")?;
    require(
        input["rotation"] == "remote",
        "fixed remote rotation selection required",
    )
}
pub fn advance_selection(input: &Value) -> Result<()> {
    json::fields(input, "rotation review_sha256 action")?;
    require(
        input["rotation"] == "remote",
        "fixed remote rotation selection required",
    )?;
    crate::identity::sha(input["review_sha256"].as_str().unwrap_or(""))?;
    require(
        matches!(
            input["action"].as_str(),
            Some("abandon" | "switch" | "discard")
        ),
        "closed remote rotation action required",
    )
}
pub fn measure(context: &Context<'_>, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
    measure_role(context, "remote-rotation-review", authorize)
}
pub fn measure_role(
    context: &Context<'_>,
    role: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    require(
        matches!(role, "remote-rotation-review" | "remote-rotation-advance"),
        "closed remote rotation measurement role",
    )?;
    context.recheck(authorize)?;
    let review = context.review(authorize)?;
    let result = value!({"schema":1,"operation":role,"review":review,"context_sha256":json::fingerprint(&context.evidence(authorize)?)?});
    context.recheck(authorize)?;
    Ok(result)
}
pub fn observe(guard: &Guard, input: &Value) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    selection(input)?;
    let lock = crate::operation::lock()?;
    let context = Context::observe(guard, &lock, &mut || Ok(()))?;
    measure(&context, &mut || Ok(()))
}
pub fn observe_advance(guard: &Guard, input: &Value) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    advance_selection(input)?;
    let lock = crate::operation::lock()?;
    let context = Context::observe(guard, &lock, &mut || Ok(()))?;
    let measured = measure_role(&context, "remote-rotation-advance", &mut || Ok(()))?;
    require(
        measured["review"]["review_sha256"] == input["review_sha256"]
            && measured["review"]["next_action"] == input["action"],
        "remote rotation review changed; review again",
    )?;
    Ok(measured)
}
