// SPDX-License-Identifier: MIT
//! Standalone enrollment from original Root actors. Only one explicit incorrect
//! password probe permits one key addition after an exclusive durable schema2
//! intent. Unknown outcomes remain prepared for the existing review path.
use super::{Image, Runtime};
use crate::{
    backup_admission::Repository,
    backup_configuration::Configuration,
    backup_credential_candidate::Candidate,
    backup_credential_record as record,
    backup_destination::{self, Destination},
    backup_repository_header::Header,
    backup_restic_result, operation,
    storage_runtime::Guard,
};
use enzimos_platform::{
    Result, files, json,
    local_restic::{self, CredentialReview},
    require,
};
use serde_json::{Value, json as value};
use std::fs::File;

fn require_incorrect(code: Option<i32>) -> Result<()> {
    require(
        code == Some(12),
        "candidate already authenticates or probe outcome unknown; no key creation",
    )
}
fn prepared(
    id: &str,
    binding: &Value,
    before: &std::collections::BTreeMap<String, bool>,
    identity: &Value,
    boot: &str,
) -> Result<Value> {
    require((1..32).contains(&before.len()), "repository key limit")?;
    let binding = value!({"filesystem_uuid":binding["filesystem_uuid"],"mount":binding["mount"],"repository_sha256":binding["repository_sha256"]});
    let row = value!({"schema":2,"id":id,"phase":"prepared","repository_binding":binding,"before_keys":before.keys().collect::<Vec<_>>(),"new_key":null,"created_boot":boot,"input_identity":identity});
    record::validate(&row, id)?;
    Ok(row)
}
fn body(row: &Value) -> Result<Vec<u8>> {
    let mut bytes = json::canonical(row)?;
    bytes.push(b'\n');
    Ok(bytes)
}
/// Enroll prepared credential `id` in the repository while `lock` is held.
///
/// # Errors
///
/// Fails when the image changed, the key limit is reached, `authorize` fails, or the readback
/// differs.
pub fn enroll_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    authorize()?;
    lock.recheck()?;
    guard.recheck()?;
    let config = Configuration::open()?;
    let destination = Destination::open(&config, guard)?;
    destination.require_writable()?;
    let pin = Repository::open(&destination)?;
    let candidate = Candidate::observe(guard)?;
    let image = Image::open()?;
    let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
    let (current, next) = candidate.descriptors(guard)?;
    let current = File::from(current.try_clone_to_owned()?);
    let next = File::from(next.try_clone_to_owned()?);
    let header = Header::observe(&repository)?;
    let mut source = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        config.recheck()?;
        destination.require_writable()?;
        pin.recheck()?;
        candidate.recheck()?;
        header.recheck(&repository)?;
        image.evidence()?;
        authorize()
    };
    source()?;
    let mut journal = crate::backup_credential_journal::new_registry(guard, id)?;
    let runtime = Runtime::create(&files::random_hex(16)?, &mut source)?;
    require(
        runtime.image_evidence()? == image.evidence()?,
        "enrollment original vendor image changed",
    )?;
    let mut ongoing = || {
        source()?;
        runtime.recheck()?;
        journal.recheck()
    };
    runtime.empty()?;
    let before = local_restic::credential_review(
        CredentialReview::Keys,
        image.descriptor()?,
        &repository,
        &current,
        &runtime.scratch,
        &mut ongoing,
    )?;
    ongoing()?;
    runtime.empty()?;
    let before = backup_restic_result::keys(before.status.code(), &before.stdout)?;
    require(before.len() < 32, "repository key limit")?;
    let probe = local_restic::credential_review(
        CredentialReview::Keys,
        image.descriptor()?,
        &repository,
        &next,
        &runtime.scratch,
        &mut ongoing,
    )?;
    ongoing()?;
    runtime.empty()?;
    require_incorrect(probe.status.code())?;
    let row = prepared(
        id,
        &backup_destination::legacy_binding(&destination.evidence()?, guard)?,
        &before,
        candidate.persistent_identity()?,
        &operation::boot_id()?,
    )?;
    journal.publish(&body(&row)?, &mut source)?;
    require(
        files::read_file(journal.descriptor()?, record::LIMIT, Some(0), true)? == body(&row)?,
        "actual prepared enrollment readback differs",
    )?;
    let mut ongoing = || {
        source()?;
        runtime.recheck()?;
        journal.recheck()
    };
    ongoing()?;
    // A single lexical invocation follows the actual exclusive publication.
    // No retry, remove/passwd, credential write, export or rollback path exists.
    let added = local_restic::credential_enroll(
        image.descriptor()?,
        &repository,
        &current,
        &next,
        &runtime.scratch,
        &mut ongoing,
    )?;
    ongoing()?;
    runtime.empty()?;
    require(
        added.status.code() == Some(0),
        "key addition failed or uncertain; prepared receipt requires review; no replay",
    )?;
    let mut query = |credential: &File| -> Result<_> {
        ongoing()?;
        let output = local_restic::credential_review(
            CredentialReview::Keys,
            image.descriptor()?,
            &repository,
            credential,
            &runtime.scratch,
            &mut ongoing,
        )?;
        ongoing()?;
        runtime.empty()?;
        backup_restic_result::keys(output.status.code(), &output.stdout)
    };
    let after = query(&current)?;
    let recovered = query(&next)?;
    let new_key = record::sole_added_key(&row, &after, &recovered)?;
    let checked = local_restic::credential_review(
        CredentialReview::Metadata,
        image.descriptor()?,
        &repository,
        &next,
        &runtime.scratch,
        &mut ongoing,
    )?;
    ongoing()?;
    runtime.empty()?;
    require(
        checked.status.code() == Some(0),
        "candidate metadata verification failed or uncertain; prepared receipt requires review",
    )?;
    // Reobserve the exact key inventories after the metadata consumer.
    for (credential, expected) in [(&current, &after), (&next, &recovered)] {
        let output = local_restic::credential_review(
            CredentialReview::Keys,
            image.descriptor()?,
            &repository,
            credential,
            &runtime.scratch,
            &mut ongoing,
        )?;
        ongoing()?;
        runtime.empty()?;
        require(
            backup_restic_result::keys(output.status.code(), &output.stdout)? == *expected,
            "repository keys changed during enrollment verification; review required",
        )?;
    }
    ongoing()?;
    let mut complete = row;
    complete["phase"] = value!("complete");
    complete["new_key"] = value!(new_key);
    record::validate(&complete, id)?;
    journal.publish(&body(&complete)?, &mut || {
        source()?;
        runtime.recheck()?;
        runtime.empty()
    })?;
    source()?;
    journal.recheck()?;
    require(
        files::read_file(journal.descriptor()?, record::LIMIT, Some(0), true)? == body(&complete)?,
        "actual complete enrollment readback differs",
    )?;
    Ok(
        value!({"status":"additional-recovery-password-verified","enrollment":id,"new_key":new_key,"current_password_replaced":false,"old_access_revoked":false,"credential_exported":false}),
    )
}
