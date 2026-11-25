// SPDX-License-Identifier: MIT
//! Configured destination lifetime for runtime operations.
//!
//! Configured backups need no fstab entry or permanent mount. A valid existing
//! fixed-path mount is borrowed unchanged. Otherwise the operation finds the
//! configured drive by its pinned filesystem UUID among the attached block
//! devices, reviews it read-only against the stored repository pin and owns one
//! temporary mount (private stub plus destination, as setup does) that it
//! closes normally afterwards. Planning never mounts: it validates the attached
//! device's identity read-only and binds only mount-independent evidence.
use crate::{
    backup_admission::StoredPin,
    backup_candidates::{Discovery, Selection},
    backup_configuration::Configuration,
    backup_setup_mount::Active,
    storage_runtime::{self, Guard},
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;

const TARGET: &str = "/backup-repository";
/// Typed refusal: the configured backup drive is not attached.
pub(crate) const ABSENT: &str = "backup-destination-absent";
/// Typed refusal: neither a backup drive nor a ready NAS share is set up.
pub const NOT_CONFIGURED: &str = "backup-destination-not-configured";
/// Typed refusal: a read-only query found the configured repository unmounted.
pub(crate) const NOT_MOUNTED: &str = "backup-destination-not-mounted";

/// Whether the fixed target currently holds a mount to borrow. Nested or
/// stacked mounts are never borrowed or treated as absent.
///
/// # Errors
///
/// Fails when the destination mount is ambiguous or nested.
pub fn mounted() -> Result<bool> {
    let rows = storage_runtime::rows()?;
    let mounts = rows
        .iter()
        .filter(|row| row.target == TARGET || row.target.starts_with("/backup-repository/"))
        .collect::<Vec<_>>();
    require(
        mounts.is_empty() || mounts.len() == 1 && mounts[0].target == TARGET,
        "ambiguous or nested configured destination mount refused",
    )?;
    Ok(!mounts.is_empty())
}
/// The one attached candidate whose filesystem UUID is the configured one.
/// No candidate at all is the typed `backup-destination-absent` refusal.
pub(crate) fn configured_selection(candidates: &[Value], uuid: &str) -> Result<String> {
    crate::identity::uuid(uuid)?;
    let matching = candidates
        .iter()
        .filter(|candidate| candidate["filesystem_uuid_hint"] == uuid)
        .collect::<Vec<_>>();
    require(!matching.is_empty(), ABSENT)?;
    require(matching.len() == 1, "configured backup drive is ambiguous")?;
    let token = matching[0]["selection_id"].as_str().ok_or_else(|| {
        Error(format!(
            "configured backup drive cannot be safely selected ({})",
            matching[0]["reason"].as_str().unwrap_or("unavailable")
        ))
    })?;
    crate::identity::sha(token)?;
    Ok(token.into())
}
fn select<'d>(
    discovery: &'d Discovery,
    configuration: &Configuration,
    guard: &Guard,
) -> Result<Selection<'d>> {
    let uuid = configuration.value()["destination_uuid"]
        .as_str()
        .ok_or_else(|| Error("configured destination UUID required".into()))?;
    let inventory = discovery.inventory()?;
    let candidates = inventory["candidates"]
        .as_array()
        .ok_or_else(|| Error("original backup candidate inventory unavailable".into()))?;
    let token = configured_selection(candidates, uuid)?;
    let selection = discovery.select(&token)?;
    require(
        selection.uuid_hint() == uuid,
        "configured original destination selection changed",
    )?;
    require(
        selection.guard().backup_root_binding()? == guard.backup_root_binding()?,
        "backup discovery observed another source system",
    )?;
    Ok(selection)
}
/// Mount-independent destination evidence for a plan made while the drive is
/// attached but not mounted. The device is found by its pinned UUID and its
/// on-disk signature is probed read-only (no mount, no journal); its disk
/// topology must be independent of the protected source. The repository is
/// represented by the stored pin; execution verifies the actual repository.
pub(crate) fn detached_evidence(
    guard: &Guard,
    configuration: &Configuration,
    pin: &StoredPin<'_>,
) -> Result<Value> {
    pin.recheck()?;
    let discovery = Discovery::observe()?;
    let selection = select(&discovery, configuration, guard)?;
    let signature = crate::backup_signature::observe(&selection)?;
    let uuid = selection.uuid_hint().to_owned();
    require(
        signature["filesystem_uuid"] == uuid.as_str(),
        "backup destination signature differs from the configured filesystem",
    )?;
    let stored = crate::backup_binding::pin(pin.public_bytes()?)?;
    require(
        stored["filesystem_uuid"] == uuid.as_str(),
        "stored backup pin names another filesystem",
    )?;
    let evidence = selection.evidence()?;
    crate::backup_destination::independent(
        &evidence["topology"],
        &crate::topology::mounted_btrfs(enzimos_platform::json::string(
            &guard.configuration["filesystem_uuid"],
        )?)?
        .json(),
    )?;
    let result = crate::backup_destination::stable(
        &uuid,
        &stored["repository_sha256"],
        &evidence["topology"],
    );
    selection.recheck()?;
    pin.recheck()?;
    Ok(result)
}
/// Run `body` with the configured destination available at its fixed path.
/// `None`: an existing mount is borrowed. `Some(active)`: this call owns one
/// reviewed temporary mount; the body must close it (`close`/`close_result`),
/// otherwise its rollback guard detaches it and the intent stays unfinished.
///
/// # Errors
///
/// Fails when the destination differs from the configuration, `authorize` fails, or the body fails.
pub fn attach<T>(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
    body: impl FnOnce(Option<Active<'_, '_, '_>>) -> Result<T>,
) -> Result<T> {
    lock.recheck()?;
    authorize()?;
    if mounted()? {
        return body(None);
    }
    // An earlier attachment that failed or was interrupted must not block
    // this one when its outcome is provable (lock held, nothing mounted).
    crate::backup_setup_mount::settle_runtime(guard, lock)?;
    let configuration = Configuration::open()?;
    let pin = StoredPin::open(&configuration, guard)?;
    let discovery = Discovery::observe()?;
    let selection = select(&discovery, &configuration, guard)?;
    let review_id = format!("runtime-review-{}", files::random_hex(16)?);
    crate::backup_mount_review::review(&selection, &review_id, lock, authorize)?;
    let review = crate::backup_mount_review::Review::open(&selection, &review_id, lock, authorize)?;
    let observed = review.repository()?;
    let stored = crate::backup_binding::pin(pin.public_bytes()?)?;
    require(
        observed["state"] == "existing"
            && observed["configuration_sha256"] == stored["repository_sha256"],
        "configured destination differs from original encrypted repository pin",
    )?;
    authorize()?;
    let mount_id = format!("runtime-mount-{}", files::random_hex(16)?);
    let active = Active::open(&review, &mount_id, lock, authorize)?;
    let result = body(Some(active));
    pin.recheck()?;
    configuration.recheck()?;
    result
}
/// `attach` for bodies that do not need to close the destination early: an
/// owned mount is closed normally after the body, also when it failed.
///
/// # Errors
///
/// Fails when the destination is unavailable or differs, or the body fails.
pub fn with_destination<T>(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
    body: impl FnOnce() -> Result<T>,
) -> Result<T> {
    attach(guard, lock, authorize, |active| match active {
        None => body(),
        Some(active) => {
            let outcome = active.recheck().and_then(|()| body());
            active.close_result(outcome)?.into_result()
        }
    })
}
