// SPDX-License-Identifier: MIT
//! Read-only original-actor rotation review; no mutation actor is constructed here.
use crate::{
    backup_configuration::Configuration, backup_rotation_context::Context, storage_runtime::Guard,
};
use enzimos_platform::{Result, json};
use serde_json::{Value, json as value};
/// Measure the rotation review document for `context`.
///
/// # Errors
///
/// Fails when the context changed or `authorize` fails.
pub fn measure(context: &Context<'_>, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
    measure_role(context, "rotation-review", authorize)
}
/// Measure the rotation document of `role` (review or advance) for `context`.
///
/// # Errors
///
/// Fails for unknown roles, when the context changed, or `authorize` fails.
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
/// Observe the rotation review for `selection` on `guard`'s storage.
///
/// # Errors
///
/// Fails when the selection is invalid or the rotation context cannot be observed.
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

/// Observe the rotation advance for `selection`, requiring its review digest to be current.
///
/// # Errors
///
/// Fails when the selection is invalid or the review changed.
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
