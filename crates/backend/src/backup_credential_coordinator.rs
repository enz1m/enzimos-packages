// SPDX-License-Identifier: MIT
//! Original credential review/completion from a stored System1 plan and fresh permission.
use enzimos_platform::{Result, require};
use enzimos_policy::{
    backup_configuration::Configuration, backup_credential_candidate::Candidate,
    backup_credential_context::Context, backup_credential_journal::Enrollment,
    backup_credential_review, backup_destination::Destination, storage_runtime::Guard,
};
use serde_json::Value;
pub(crate) fn run(
    guard: &Guard,
    operation: &str,
    id: &str,
    selection: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    backup_credential_review::role(operation)?;
    enzimos_policy::backup_worker_request::id(id)?;
    let enrollment_id = selection["id"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("credential enrollment ID required".into()))?;
    enzimos_policy::identity::safe_id(enrollment_id)?;
    enzimos_platform::json::fields(
        selection,
        if operation == "credential-complete" {
            "id review_sha256"
        } else {
            "id"
        },
    )?;
    let expected_review = if operation == "credential-complete" {
        Some(enzimos_policy::identity::sha(
            selection["review_sha256"].as_str().unwrap_or(""),
        )?)
    } else {
        None
    };
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, guard)?;
    let enrollment = Enrollment::observe(guard, &lock, enrollment_id)?;
    let candidate = Candidate::observe(guard)?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        configuration.recheck()
    };
    progress("validating")?;
    let closed = {
        let context = Context::observe(
            guard,
            &lock,
            &enrollment,
            &candidate,
            &destination,
            id,
            &mut permission,
        )?;
        require(
            backup_credential_review::measure(&context, operation, &mut permission)? == *expected,
            "job-plan-changed",
        )?;
        super::backup_credential_client::launch(&context, &|| {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            configuration.recheck()
        })?
    };
    closed.recheck()?;
    permission()?;
    progress("finishing")?;
    if let Some(expected_review) = expected_review {
        let completed =
            enrollment.complete(closed, &candidate, expected_review, &mut permission)?;
        permission()?;
        completed.result()
    } else {
        enrollment.require_input(&candidate)?;
        permission()?;
        closed.result()
    }
}
