// SPDX-License-Identifier: MIT
//! Read-only original-actor rotation review; no mutation actor is constructed here.
use crate::{
    backup_configuration::Configuration, backup_rotation_context::Context, storage_runtime::Guard,
};
use enzimos_platform::{Result, json};
use serde_json::{Value, json as value};
pub fn measure(context: &Context<'_>, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
    measure_role(context, "rotation-review", authorize)
}
pub fn measure_role(
    context: &Context<'_>,
    role: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    enzimos_platform::require(
        matches!(role, "rotation-review" | "rotation-advance"),
        "closed rotation role required",
    )?;
    context.recheck(authorize)?;
    let review = context.review(authorize)?;
    let original = context.evidence(authorize)?;
    let result = value!({"schema":1,"operation":role,"review":review,
        "context_sha256":json::fingerprint(&original)?});
    context.recheck(authorize)?;
    Ok(result)
}
pub fn observe(guard: &Guard, selection: &Value) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    json::fields(selection, "id")?;
    let id = selection["id"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("rotation ID required".into()))?;
    crate::identity::safe_id(id)?;
    let lock = crate::operation::lock()?;
    let configuration = Configuration::open()?;
    let context = Context::observe(guard, &lock, &configuration, id, &mut || Ok(()))?;
    measure(&context, &mut || Ok(()))
}

pub fn observe_advance(guard: &Guard, selection: &Value) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    json::fields(selection, "id review_sha256 action")?;
    let id = selection["id"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("rotation ID required".into()))?;
    crate::identity::safe_id(id)?;
    crate::identity::sha(selection["review_sha256"].as_str().unwrap_or(""))?;
    enzimos_platform::require(
        matches!(
            selection["action"].as_str(),
            Some("abandon" | "switch" | "discard")
        ),
        "closed rotation action required",
    )?;
    let lock = crate::operation::lock()?;
    let configuration = Configuration::open()?;
    let context = Context::observe(guard, &lock, &configuration, id, &mut || Ok(()))?;
    let observed = measure_role(&context, "rotation-advance", &mut || Ok(()))?;
    enzimos_platform::require(
        observed["review"]["review_sha256"] == selection["review_sha256"]
            && observed["review"]["next_action"] == selection["action"],
        "rotation review changed; review again",
    )?;
    Ok(observed)
}
