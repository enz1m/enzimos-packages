// SPDX-License-Identifier: MIT
//! Original configured capture pipeline; no transfer or completion shortcut.
use crate::{
    backup_admission::Repository, backup_archive_inputs::Inputs, backup_attempt::Attempt,
    backup_configuration::Configuration, backup_credential::Credential,
    backup_destination::Destination, backup_inventory_stage, backup_readonly_trees::Prepared,
    backup_source_capture, backup_source_inventory::Inventory, storage_runtime::Guard,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
fn free(destination: &Destination<'_>, minimum: u64) -> Result<()> {
    destination.require_writable()?;
    let fd = destination.repository_descriptor()?;
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `status` is a writable `libc::statvfs` and `fd` keeps the descriptor open.
        unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut status) } == 0,
        "original backup destination space observation failed",
    )?;
    let available = status
        .f_bavail
        .checked_mul(status.f_frsize)
        .ok_or_else(|| Error("backup destination available bytes overflow".into()))?;
    require(
        available >= minimum,
        "backup destination space admission failed",
    )
}
/// Internal bring-up entry, invoked only in a fresh disposable guest. It performs
/// real capture/staging, durably fences the unfinished attempt, and intentionally
/// preserves original snapshots/staging for review. It never reports a backup.
///
/// # Errors
///
/// Fails when `authorize` or `progress` fails, or a capture step fails.
pub fn stage_review(
    lock: &files::Lock,
    progress: &mut dyn FnMut(&str) -> Result<()>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    lock.recheck()?;
    let guard = Guard::observe()?;
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, &guard)?;
    let repository = Repository::open(&destination)?;
    let credential = Credential::open()?;
    let mut boundary = || {
        authorize()?;
        lock.recheck()?;
        guard.recheck()?;
        configuration.recheck()?;
        destination.recheck()?;
        repository.recheck()?;
        credential.recheck()?;
        free(&destination, configuration.minimum_free_bytes())
    };
    boundary()?;
    let inventory = Inventory::observe(&configuration, &guard)?;
    boundary()?;
    let attempt = Attempt::begin(&guard, lock)?;
    let id = attempt.id()?.to_owned();
    let review = {
        progress("capturing")?;
        let capture =
            backup_source_capture::capture(&inventory, &attempt, lock, &id, &mut boundary)?;
        boundary()?;
        progress("staging")?;
        let stage = backup_inventory_stage::stage(&capture, lock, &id, &mut boundary)?;
        boundary()?;
        let inputs = Inputs::observe(&capture, &stage)?;
        let trees = Prepared::prepare(&inputs, lock, &id, &mut boundary)?;
        boundary()?;
        inputs.recheck()?;
        trees.recheck()?;
        json!({"input_sha256":enzimos_platform::json::sha256(&enzimos_platform::json::canonical(&inputs.evidence()?)?),
            "readonly_trees":trees.evidence()?,"arguments":inputs.arguments()?})
    };
    // Only our still-private detached mounts have dropped. No attached mount,
    // source snapshot or staging directory is guessed or deleted on this path.
    boundary()?;
    progress("awaiting-transfer")?;
    let fenced = attempt.fence()?;
    Ok(
        json!({"status":"capture-staged-awaiting-transfer","attempt":fenced,"review":review,
        "transfer_complete":false,"cleanup_complete":false,"backup_complete":false}),
    )
}
