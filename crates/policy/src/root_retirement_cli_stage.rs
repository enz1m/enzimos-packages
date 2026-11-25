// SPDX-License-Identifier: MIT
//! Standalone coordinator stage from the actual prepared journal and all original
//! backend rows. One ordinary inspection close; no offline deletion authority.
use crate::{
    root_retirement_online_boot::Boot,
    root_retirement_online_encryption::Source,
    root_retirement_online_image::Image,
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::{Journal, Phase},
    root_retirement_online_stage_targets::Protected,
    root_retirement_references::Observation,
    root_retirement_stage_contract::UefiMode,
    storage_runtime::{Guard, TopMount},
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;
/// Stage the coordinator for prepared receipt `id` with image `image_id` and power action `exit`.
///
/// # Errors
///
/// Fails for other exit actions, when the receipt is not prepared, or staging fails.
pub fn stage_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    image_id: &str,
    exit: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    crate::identity::safe_id(image_id)?;
    require(
        matches!(exit, "reboot" | "poweroff"),
        "closed coordinator exit required",
    )?;
    authorize()?;
    let journal = Journal::observe(guard, lock, id, Phase::Prepared)?;
    let original_row = journal.record()?;
    let plan = enzimos_platform::json::string(&original_row["plan_sha256"])?.to_owned();
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    permission()?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let original = Observation::observe_journal(guard, lock, &journal, &mut permission)?;
        let boot = Boot::observe_journal(guard, lock, &original, &journal, &mut permission)?;
        let inventory = Inventory::observe(guard, &top, lock, &mut permission)?;
        let image = Image::observe(guard, lock, &original, &journal, image_id, &mut permission)?;
        let source = Source::observe(guard, lock, &mut permission)?;
        let protected = Protected::observe(
            guard,
            &top,
            lock,
            &original,
            &inventory,
            &journal,
            boot,
            &mut permission,
        )?;
        let firmware = if crate::recovery_activation_runtime::efi_guard()? {
            Some(
                crate::root_retirement_firmware_publication::Original::observe(
                    guard,
                    lock,
                    &mut permission,
                )?,
            )
        } else {
            None
        };
        let measured = match &firmware {
            Some(firmware) => crate::root_retirement_online_stage_publication::measure_one_shot(
                guard,
                lock,
                &image,
                &protected,
                &source,
                firmware,
                exit,
                &mut permission,
            )?,
            None => protected.stage_measurement(
                &image,
                &source,
                exit,
                UefiMode::Default,
                &mut permission,
            )?,
        };
        require(
            measured["filesystem_uuid"] == guard.configuration["filesystem_uuid"]
                && measured["plan_sha256"] == plan
                && measured["staged_record"]["id"] == id,
            "original Root stage measurement identity changed",
        )?;
        let expected = &measured;
        let published = match firmware {
            Some(firmware) => {
                crate::root_retirement_online_stage_publication::prepare_and_publish_one_shot(
                    guard,
                    lock,
                    journal,
                    &image,
                    &protected,
                    &source,
                    firmware,
                    exit,
                    expected,
                    &mut permission,
                    progress,
                )
            }
            None => crate::root_retirement_online_stage_publication::prepare_and_publish_default(
                guard,
                lock,
                journal,
                &image,
                &protected,
                &source,
                exit,
                expected,
                &mut permission,
                progress,
            ),
        }?;
        let row = &published["receipt"];
        crate::root_retirement_record::validate(row, id)?;
        require(
            row["schema"] == 2
                && row["phase"] == "prepared"
                && row["next_step"] == 0
                && row["inflight"].is_null()
                && row["coordinator"]["image"] == image_id
                && published["coordinator_selected"] == true
                && published["deletion_authorized"] == false,
            "actual Root stage publication result differs",
        )?;
        progress("finishing")?;
        Ok(serde_json::json!({"id":id,"image":image_id,
                    "status":"root-retirement-coordinator-staged","reboot_required":true}))
    })();
    // Every borrowed Root filesystem actor ends before the one normal unmount.
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => {
            permission()?;
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root stage inspection cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}
