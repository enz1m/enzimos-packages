// SPDX-License-Identifier: MIT
//! Original backend ledger and original Root boot context remain one execution.
use super::system_jobs::ReferenceView;
use enzimos_platform::{Error, Result, json, require};
use enzimos_policy::{boot_retirement_context::Context, operation, storage_runtime::Guard};
use serde_json::{Value, json as value};
struct Joined<'r, 'g> {
    refs: &'r ReferenceView,
    conclusions: enzimos_policy::recovery_conclusions::Observation<'g>,
}
impl Joined<'_, '_> {
    fn protect(&self, generation: &str) -> Result<()> {
        self.refs
            .require_unmentioned_with_conclusions(generation, &self.conclusions)
    }
}
impl enzimos_policy::boot_retirement_context::runtime::References for Joined<'_, '_> {
    fn require_unmentioned(&self, generation: &str) -> Result<()> {
        self.protect(generation)
    }
}
fn selection(input: &Value) -> Result<(&str, &str)> {
    json::fields(input, "generation plan_sha256")?;
    let generation = input["generation"]
        .as_str()
        .ok_or_else(|| Error("boot retirement generation required".into()))?;
    let sha = input["plan_sha256"]
        .as_str()
        .ok_or_else(|| Error("boot retirement intent SHA required".into()))?;
    enzimos_policy::identity::safe_id(generation)?;
    enzimos_policy::identity::sha(sha)?;
    Ok((generation, sha))
}
fn measurement(
    context: &Context<'_, '_>,
    refs: &Joined<'_, '_>,
    expected: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let (intent, _) = context.planned_intent(authorize)?;
    require(
        intent["intent_sha256"] == expected,
        "original reviewed retirement intent changed",
    )?;
    let original = context.evidence(authorize)?;
    let result = value!({"context_sha256":json::fingerprint(original)?,
        "backend_sha256":json::fingerprint(&refs.refs.planning_evidence()?)?,
        "intent_sha256":intent["intent_sha256"],
        "steps":enzimos_platform::json::array(&intent["steps"])?.iter().map(|s|s["id"].clone()).collect::<Vec<_>>(),
        "root_subvolume_retained":true});
    refs.protect(enzimos_platform::json::string(&original["generation"])?)?;
    context.recheck(authorize)?;
    Ok(result)
}
pub(crate) fn observe(guard: &Guard, input: &Value, refs: &ReferenceView) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let (generation, sha) = selection(input)?;
    guard.recheck()?;
    let joined = Joined {
        refs,
        conclusions: enzimos_policy::recovery_conclusions::Observation::observe(guard)?,
    };
    joined.protect(generation)?;
    let lock = operation::lock()?;
    let mut permission = || {
        guard.recheck()?;
        lock.recheck()?;
        joined.protect(generation)
    };
    let context = Context::observe(guard, &lock, generation, &mut permission)?;
    context.bind_recovery_conclusions(&joined.conclusions, &mut permission)?;
    let measured = measurement(&context, &joined, sha, &mut permission)?;
    permission()?;
    Ok(measured)
}
pub(crate) fn run(
    guard: &Guard,
    input: &Value,
    expected: &Value,
    refs: &ReferenceView,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let (generation, sha) = selection(input)?;
    authorize()?;
    guard.recheck()?;
    let joined = Joined {
        refs,
        conclusions: enzimos_policy::recovery_conclusions::Observation::observe(guard)?,
    };
    joined.protect(generation)?;
    let lock = operation::lock()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        joined.protect(generation)
    };
    progress("validating")?;
    let context = Context::observe(guard, &lock, generation, &mut permission)?;
    context.bind_recovery_conclusions(&joined.conclusions, &mut permission)?;
    require(
        measurement(&context, &joined, sha, &mut permission)? == *expected,
        "job-plan-changed",
    )?;
    permission()?;
    context.retire(&joined, sha, &mut permission, progress)
}
