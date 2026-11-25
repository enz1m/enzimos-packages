// SPDX-License-Identifier: MIT
//! Standalone Root retirement retains every original backend row; no job exemption.
use crate::{
    boot_backend_references::Observation,
    boot_retirement_context::{Context, runtime::References},
    recovery_conclusions,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, require};
use serde_json::Value;
struct Joined<'a, 'g> {
    backend: Observation<'g>,
    conclusions: recovery_conclusions::Observation<'g>,
    guard: &'g Guard,
    lock: &'a files::Lock,
}
impl References for Joined<'_, '_> {
    fn require_unmentioned(&self, generation: &str) -> Result<()> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.backend
            .require_unmentioned_with_conclusions(generation, &self.conclusions)
    }
}
/// Retire `generation` reviewed as `sha` while `lock` is held.
///
/// # Errors
///
/// Fails when the review changed or a step fails.
pub fn retire_locked(
    guard: &Guard,
    lock: &files::Lock,
    generation: &str,
    sha: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(generation)?;
    crate::identity::sha(sha)?;
    authorize()?;
    let joined = Joined {
        backend: Observation::observe(guard)?,
        conclusions: recovery_conclusions::Observation::observe(guard)?,
        guard,
        lock,
    };
    joined.require_unmentioned(generation)?;
    let mut permission = || {
        authorize()?;
        joined.require_unmentioned(generation)
    };
    let context = Context::observe(guard, lock, generation, &mut permission)?;
    context.bind_recovery_conclusions(&joined.conclusions, &mut permission)?;
    let (intent, _) = context.planned_intent(&mut permission)?;
    require(
        intent["intent_sha256"] == sha,
        "reviewed boot retirement plan changed; plan again",
    )?;
    progress("validating")?;
    context.retire(&joined, sha, &mut permission, progress)
}

/// Status of boot retirement journals.
///
/// # Errors
///
/// Fails when a journal cannot be read.
pub fn status_locked(guard: &Guard, lock: &files::Lock) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    let records = crate::control_registry::read(
        guard,
        "boot-retirements",
        crate::retirement_journal::MAX_RECORDS,
        crate::retirement_journal::validate,
    )?;
    guard.recheck()?;
    lock.recheck()?;
    Ok(
        serde_json::json!({"journals":records.into_iter().map(|(id,row)| (id,serde_json::json!({"phase":row["phase"],"next_step":row["next_step"]}))).collect::<std::collections::BTreeMap<_,_>>()}),
    )
}
