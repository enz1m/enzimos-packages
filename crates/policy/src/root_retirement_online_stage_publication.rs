// SPDX-License-Identifier: MIT
//! One consuming default-mode Root staging body, using actual original actors.
//! Source candidate provider wiring remains separate from installed qualification.
use crate::{
    root_retirement_online_image::Image, root_retirement_online_journal::Published as Receipt,
    root_retirement_online_stage_targets::Protected, storage_runtime::Guard,
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json};

/// Run only from actual original guarded actors and the sole staged receipt.
/// Errors preserve durable partial evidence; callers must never replay this body.
/// No decoded plan, receipt, path or success marker supplies these actors.
pub(crate) fn publish_default(
    guard: &Guard,
    lock: &files::Lock,
    receipt: &Receipt<'_>,
    image: &Image<'_>,
    protected: &Protected<'_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    receipt.require_source(guard, lock)?;
    image.require_staged_source(guard, lock, receipt, authorize)?;
    image.recheck_staged(receipt, authorize)?;
    let record = receipt.record()?;
    require(
        record["coordinator"]["uefi_mode"] == "default"
            && record["coordinator"]["image"] == image.staged_record(receipt, authorize)?["id"],
        "default Root publication requires actual reviewed mode and original ready image",
    )?;
    protected.recheck_staged(receipt, authorize)?;
    let namespace =
        crate::root_retirement_signed_namespace::Original::observe(guard, lock, authorize)?;
    let signer = namespace
        .prepare(authorize)?
        .sign(receipt, protected, authorize)?;
    image.recheck_staged(receipt, authorize)?;
    let original = crate::root_retirement_loader_publication::Original::observe(
        guard, lock, receipt, &signer, protected, authorize,
    )?;
    let defaults = original
        .prepare_entry(authorize)?
        .commit(authorize)?
        .prepare_bios(authorize)?
        .commit(authorize)?
        .prepare_defaults(authorize)?
        .commit(authorize)?;
    image.recheck_staged(receipt, authorize)?;
    protected.recheck_committed_defaults(receipt, &signer, &defaults, authorize)?;
    let evidence = defaults.evidence(authorize)?;
    image.recheck_staged(receipt, authorize)?;
    protected.recheck_committed_defaults(receipt, &signer, &defaults, authorize)?;
    Ok(
        json!({"receipt":receipt.record()?,"loader_publication":evidence,
        "coordinator_selected":true,"deletion_authorized":false,
        "root_stage_provider_enabled":true,"installed_qualification":false}),
    )
}

/// Compare the reviewed original default-mode plan before the sole durable
/// coordinator receipt replacement, then consume the actual staged publication.
/// A copied expected value supplies only equality, never an actor or replay grant.
pub fn prepare_and_publish_default(
    guard: &Guard,
    lock: &files::Lock,
    journal: crate::root_retirement_online_journal::Journal<'_>,
    image: &Image<'_>,
    protected: &Protected<'_>,
    source: &crate::root_retirement_online_encryption::Source<'_>,
    exit: &str,
    expected: &Value,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    journal.require_original_source(guard, lock)?;
    let mode = crate::root_retirement_stage_contract::UefiMode::Default;
    let measured = protected.stage_measurement(image, source, exit, mode, authorize)?;
    require(measured == *expected, "job-plan-changed")?;
    progress("validating")?;
    let staged = protected.compile_stage(image, source, exit, mode, authorize)?;
    require(
        staged.record == measured["staged_record"],
        "original Root staging coordinator changed",
    )?;
    // The fixed staged receipt precedes all namespace/signing/loader mutations.
    protected.recheck(authorize)?;
    image.recheck(authorize)?;
    source.recheck(authorize)?;
    let receipt = journal.publish_staged(&staged.record, &mut || source.recheck(authorize))?;
    protected.recheck_staged(&receipt, authorize)?;
    image.require_staged_source(guard, lock, &receipt, authorize)?;
    source.recheck(authorize)?;
    progress("publishing")?;
    let result = publish_default(guard, lock, &receipt, image, protected, &mut || {
        source.recheck(authorize)
    })?;
    source.recheck(authorize)?;
    image.recheck_staged(&receipt, authorize)?;
    Ok(result)
}

/// Measurement includes the actual original firmware descriptors before
/// the coordinator intent. Metadata can compare this value but cannot mint them.
pub fn measure_one_shot(
    guard: &Guard,
    lock: &files::Lock,
    image: &Image<'_>,
    protected: &Protected<'_>,
    source: &crate::root_retirement_online_encryption::Source<'_>,
    firmware: &crate::root_retirement_firmware_publication::Original<'_>,
    exit: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    firmware.require_source(guard, lock, authorize)?;
    let mut measured = protected.stage_measurement(
        image,
        source,
        exit,
        crate::root_retirement_stage_contract::UefiMode::OneShot,
        authorize,
    )?;
    measured["firmware"] = firmware.evidence(authorize)?;
    protected.recheck(authorize)?;
    firmware.require_source(guard, lock, authorize)?;
    Ok(measured)
}
/// Complete the one-shot path using only actual original/owned producers.
/// Firmware selection follows the durable receipt, retained signing and loaders.
pub(crate) fn publish_one_shot(
    guard: &Guard,
    lock: &files::Lock,
    receipt: &Receipt<'_>,
    image: &Image<'_>,
    protected: &Protected<'_>,
    firmware: crate::root_retirement_firmware_publication::Original<'_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    receipt.require_source(guard, lock)?;
    firmware.require_source(guard, lock, authorize)?;
    image.require_staged_source(guard, lock, receipt, authorize)?;
    let record = receipt.record()?;
    require(
        record["coordinator"]["uefi_mode"] == "one-shot"
            && record["coordinator"]["image"] == image.staged_record(receipt, authorize)?["id"],
        "one-shot publication requires reviewed actual firmware mode and ready image",
    )?;
    protected.recheck_staged(receipt, authorize)?;
    let namespace =
        crate::root_retirement_signed_namespace::Original::observe(guard, lock, authorize)?;
    let signer = namespace
        .prepare(authorize)?
        .sign(receipt, protected, authorize)?;
    image.recheck_staged(receipt, authorize)?;
    let original = crate::root_retirement_loader_publication::Original::observe(
        guard, lock, receipt, &signer, protected, authorize,
    )?;
    let bios = original
        .prepare_entry(authorize)?
        .commit(authorize)?
        .prepare_bios(authorize)?
        .commit(authorize)?;
    firmware.recheck(authorize)?;
    let selected = firmware.select(bios, authorize)?;
    image.recheck_staged(receipt, authorize)?;
    protected.recheck_firmware_publication(receipt, &signer, &selected, authorize)?;
    let evidence = selected.evidence(authorize)?;
    image.recheck_staged(receipt, authorize)?;
    protected.recheck_firmware_publication(receipt, &signer, &selected, authorize)?;
    Ok(
        json!({"receipt":receipt.record()?,"firmware_publication":evidence,
        "coordinator_selected":true,"deletion_authorized":false,
        "root_stage_provider_enabled":true,"installed_qualification":false}),
    )
}
/// Compare the reviewed original one-shot plan before the sole durable intent.
pub fn prepare_and_publish_one_shot(
    guard: &Guard,
    lock: &files::Lock,
    journal: crate::root_retirement_online_journal::Journal<'_>,
    image: &Image<'_>,
    protected: &Protected<'_>,
    source: &crate::root_retirement_online_encryption::Source<'_>,
    firmware: crate::root_retirement_firmware_publication::Original<'_>,
    exit: &str,
    expected: &Value,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    journal.require_original_source(guard, lock)?;
    let measured = measure_one_shot(
        guard, lock, image, protected, source, &firmware, exit, authorize,
    )?;
    require(measured == *expected, "job-plan-changed")?;
    progress("validating")?;
    let staged = protected.compile_stage(
        image,
        source,
        exit,
        crate::root_retirement_stage_contract::UefiMode::OneShot,
        authorize,
    )?;
    require(
        staged.record == measured["staged_record"],
        "original one-shot coordinator changed",
    )?;
    protected.recheck(authorize)?;
    image.recheck(authorize)?;
    firmware.recheck(authorize)?;
    let receipt = journal.publish_staged(&staged.record, &mut || source.recheck(authorize))?;
    protected.recheck_staged(&receipt, authorize)?;
    image.require_staged_source(guard, lock, &receipt, authorize)?;
    firmware.recheck(authorize)?;
    progress("publishing")?;
    let result = publish_one_shot(
        guard,
        lock,
        &receipt,
        image,
        protected,
        firmware,
        &mut || source.recheck(authorize),
    )?;
    source.recheck(authorize)?;
    image.recheck_staged(&receipt, authorize)?;
    Ok(result)
}
