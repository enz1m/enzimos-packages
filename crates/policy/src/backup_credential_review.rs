// SPDX-License-Identifier: MIT
//! Review data measured from original credential actors, never launch authority.
use crate::{
    backup_configuration::Configuration, backup_credential_candidate::Candidate,
    backup_credential_context::Context, backup_credential_journal::Enrollment,
    backup_destination::Destination, storage_runtime::Guard,
};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
/// Require a credential review operation name.
///
/// # Errors
///
/// Fails for any other operation.
pub fn role(operation: &str) -> Result<()> {
    require(
        matches!(operation, "credential-review" | "credential-complete"),
        "closed credential operation required",
    )
}
/// Review document of credential `operation` for enrollment `id`.
///
/// # Errors
///
/// Fails when the operation or enrollment is invalid or its context cannot be observed.
pub fn observe(guard: &Guard, operation: &str, id: &str) -> Result<Value> {
    role(operation)?;
    let lock = crate::operation::lock()?;
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, guard)?;
    let enrollment = Enrollment::observe(guard, &lock, id)?;
    let candidate = Candidate::observe(guard)?;
    // No launch intent or worker is created during plan observation. The ID is
    // discarded from review data; the real execution uses its stored request ID.
    let mut permission = || Ok(());
    let context = Context::observe(
        guard,
        &lock,
        &enrollment,
        &candidate,
        &destination,
        &"0".repeat(32),
        &mut permission,
    )?;
    measure(&context, operation, &mut permission)
}
/// Measure the review document of `operation` for `context`.
///
/// # Errors
///
/// Fails when the context changed or `authorize` fails.
pub fn measure(
    context: &Context<'_, '_>,
    operation: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    role(operation)?;
    context.recheck(authorize)?;
    let original = context.evidence(authorize)?;
    let mut metadata = original.clone();
    enzimos_platform::json::object_mut(&mut metadata)?.remove("id");
    let review = value!({"schema":1,"operation":operation,"enrollment":original["enrollment"]["id"],
        "boot_id":original["boot_id"],"context_sha256":json::fingerprint(&metadata)?});
    context.recheck(authorize)?;
    Ok(review)
}
