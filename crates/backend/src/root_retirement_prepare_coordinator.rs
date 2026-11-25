// SPDX-License-Identifier: MIT
//! One protected original Root prepare context and actual server-held job ledger.
use super::system_jobs::ReferenceView;
use enzimos_platform::{Error, Result, json, require};
use enzimos_policy::{
    operation,
    root_retirement_online_boot::Boot,
    root_retirement_online_intent::Intent,
    root_retirement_online_inventory::Inventory,
    root_retirement_references::Observation,
    storage_runtime::{Guard, TopMount},
};
use serde_json::Value;
fn selection(input: &Value) -> Result<(&str, &str)> {
    json::fields(input, "root_uuid plan_sha256")?;
    let root = enzimos_policy::identity::uuid(input["root_uuid"].as_str().unwrap_or(""))?;
    let sha = enzimos_policy::identity::sha(input["plan_sha256"].as_str().unwrap_or(""))?;
    Ok((root, sha))
}
fn execute(
    guard: &Guard,
    input: &Value,
    refs: &ReferenceView,
    expected: Option<&Value>,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let (root, sha) = selection(input)?;
    guard.recheck()?;
    refs.require_root_target(
        enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?,
        root,
        sha,
    )?;
    let lock = operation::lock()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        refs.require_root_target(
            enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?,
            root,
            sha,
        )
    };
    permission()?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        permission()?;
        let original = Observation::observe_referenced(guard, &lock, refs, &mut permission)?;
        // Reuse the actual retained catalog lock, never acquire a second OFD lock.
        let boot = Boot::observe(guard, &lock, &original, &mut permission)?;
        let inventory = Inventory::observe(guard, &top, &lock, &mut permission)?;
        let intent = Intent::observe(
            guard,
            &top,
            &lock,
            original,
            &inventory,
            root,
            &mut permission,
        )?
        .protect(boot, &mut permission)?;
        let measured = intent.measurement(&mut permission)?;
        require(
            measured["root_uuid"] == root && measured["plan_sha256"] == sha,
            "reviewed original Root retirement intent changed",
        )?;
        match expected {
            None => Ok(measured),
            Some(expected) => {
                require(measured == *expected, "job-plan-changed")?;
                progress("validating")?;
                intent.prepare(expected, &mut permission, progress)
            }
        }
    })();
    // All borrowed inspection descriptions have ended before one explicit normal
    // unmount. A refusal is preserved; Drop cannot retry or lazily detach it.
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => {
            permission()?;
            Ok(value)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root inspection cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}
pub(crate) fn observe(guard: &Guard, input: &Value, refs: &ReferenceView) -> Result<Value> {
    execute(guard, input, refs, None, &mut || Ok(()), &mut |_| Ok(()))
}
pub(crate) fn run(
    guard: &Guard,
    input: &Value,
    expected: &Value,
    refs: &ReferenceView,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    execute(guard, input, refs, Some(expected), authorize, progress)
}
