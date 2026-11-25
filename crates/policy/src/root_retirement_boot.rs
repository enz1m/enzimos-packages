// SPDX-License-Identifier: MIT
//! Direct independent RAM PID1 retirement orchestration, without cold replay.
use crate::{
    recovery_bootstrap as bootstrap, recovery_devices::Block, root_retirement_boot_artifacts,
    root_retirement_parameters::Parameters,
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json};
use std::{os::fd::AsFd, path::Path};
/// Run the root retirement described by `parameters` as PID 1 on the RAM root.
///
/// # Errors
///
/// Fails when the parameters differ from the boot, the control is not writable, or a step fails.
pub fn run(parameters: &Parameters) -> Result<Value> {
    bootstrap::quiet()?;
    crate::recovery_devices::coldplug()?;
    let scope = crate::root_retirement_offline_scope::Scope::observe()?;
    let kernel = crate::root_retirement_kernel_boot::Original::observe(&scope)?;
    require(
        kernel.parameters()? == parameters,
        "decoded dispatch parameters differ from actual original kernel boot",
    )?;
    let esp = Block::by_uuid(&parameters.esp, true)?;
    let mut esp_mounts = crate::recovery_mounts::Mounts::default();
    esp.recheck()?;
    esp_mounts.esp(esp.file.as_fd())?;
    esp.recheck()?;
    scope.recheck()?;
    let running = crate::root_retirement_running_image::Original::observe(&scope)?;
    let boot = root_retirement_boot_artifacts::Original::observe(&scope, &kernel, &running)?
        .restore_defaults()?;
    let restoration = boot.restoration_status()?;
    let encrypted = Block::by_uuid(&parameters.luks, false)?;
    let source =
        crate::root_retirement_unlock_source::Source::observe(&scope, &kernel, &boot, &encrypted)?;
    let verified = source.open_mapping()?;
    let dm = crate::root_retirement_dm_control::Original::observe(&verified)?;
    let owner = crate::root_retirement_offline_mount::OwnedTop::mount(verified.mapping()?)?;
    let _targets_count = {
        let mounts = owner.observation()?;
        let file = files::directory_relative(
            mounts.original_top()?,
            Path::new(&parameters.control),
            Some(0),
        )?;
        let (identity, readonly) = crate::subvolume::observe(file.as_fd(), &parameters.control)?;
        require(!readonly, "actual original control must be writable")?;
        let control = crate::root_retirement_offline_control::Control::observe(
            verified.mapping()?,
            &mounts,
            &parameters.control,
            &identity,
        )?;
        let receipt = crate::root_retirement_image_receipt::Receipt::observe(&control, &boot)?;
        let journal =
            crate::root_retirement_offline_journal::Journal::observe(&control, &parameters.id)?;
        kernel.matches_record(&journal.record()?)?;
        let origins = crate::root_retirement_offline_origins::Origins::observe(&control)?;
        let targets = crate::root_retirement_offline_targets::Targets::observe(
            &control, &mounts, &journal, &origins,
        )?;
        let inventory =
            crate::root_retirement_offline_inventory::Inventory::observe(&mounts, &targets)?;
        let ledgers = crate::root_retirement_offline_ledgers::Ledgers::observe(&control, &journal)?;
        let catalog = crate::root_retirement_offline_catalog::Catalog::observe(&control, &ledgers)?;
        let certificate =
            crate::root_retirement_offline_certificate::Certificate::observe(&control)?;
        let loaders = crate::root_retirement_offline_loaders::Loaders::observe(
            &control,
            &catalog,
            &boot,
            &certificate,
        )?;
        let publications = crate::root_retirement_offline_publications::Publications::observe(
            &control, &ledgers, &loaders, &boot,
        )?;
        let protection = crate::root_retirement_offline_protection::Protection::observe(
            &control, &mounts, &catalog, &boot,
        )?;
        // Autoload may be needed during initial driver/unlock/filesystem admission.
        // Before the seal and any destructive call, its actual proc controls are
        // cleared, retained and checked along with the original sole-PID1 scope.
        let helpers = crate::root_retirement_kernel_helpers::Disabled::disable(&scope)?;
        let sealed = crate::root_retirement_seal::Installed::install(
            &scope,
            &mounts,
            &owner,
            &verified,
            &kernel,
            &receipt,
            &inventory,
            &dm,
            &ledgers,
            &catalog,
            &loaders,
            &publications,
            &protection,
            &helpers,
        )?;
        let count = enzimos_platform::json::array(&journal.record()?["targets"])?.len();
        let advanced = journal
            .enter(&sealed)?
            .begin_first()?
            .prepare_first_delete()?
            .delete()?
            .advance()?;
        if count == 1 {
            advanced.recheck()?;
            drop(advanced);
        } else {
            let mut cursor = advanced.begin_next()?.into_cursor()?;
            let completed = loop {
                let progress = cursor.delete()?.advance()?;
                if progress.finished()? {
                    break progress;
                }
                cursor = progress.begin_next()?;
            };
            completed.recheck()?;
            drop(completed);
        }
        let final_record = journal.record()?;
        require(
            final_record["phase"] == "deleted"
                && final_record["next_step"] == count
                && final_record["inflight"].is_null(),
            "original owned retirement progress did not durably finish all targets",
        )?;
        helpers.recheck()?;
        scope.recheck()?;
        count
    }; // All borrowed source filesystem descriptions end before normal unmount.
    let unmounted = owner.unmount()?.release()?;
    let mapping = verified.into_mapping()?;
    let removed = dm
        .prepare_close(unmounted, &mapping)?
        .close_description(mapping)?
        .remove()?;
    removed.recheck()?;
    drop(removed);
    drop(boot);
    esp_mounts.close()?;
    scope.recheck()?;
    Ok(
        json!({"status":"root-retirement-deleted-offline","id":parameters.id,
        "defaults_restored":restoration,"loader_started":true,
        "syscall_filter_active":true,"exclusive_before_mount":true,"exclusive_after_unmount":true,
        "initial_namespaces":crate::namespaces::KINDS,
        "namespace_origin_proven":true,"origin_scope":"kernel-reported-initial-namespaces-same-kernel-trust"}),
    )
}
