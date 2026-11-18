// SPDX-License-Identifier: MIT
//! Server review data measured from actual retained local backup inputs.
use crate::{
    backup_admission::{Repository, StoredPin},
    backup_configuration::Configuration,
    backup_destination::Destination,
    backup_restic_runtime::Image,
    backup_source_inventory::Inventory,
    catalog, operation,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, require, stream_copy};
use serde_json::{Value, json as value};
use std::path::Path;

/// Plan observation. A mounted destination is measured directly; a configured
/// drive that is attached but not mounted is validated read-only by its pinned
/// identity without mounting. Both bind the same mount-independent evidence,
/// so execution may borrow the mount or own a fresh temporary one.
pub fn observe(guard: &Guard) -> Result<Value> {
    let lock = operation::lock()?;
    let configuration = Configuration::open()?;
    let inventory = Inventory::observe(&configuration, guard)?;
    if crate::backup_destination_attach::mounted()? {
        let destination = Destination::open(&configuration, guard)?;
        return measure(guard, &lock, &configuration, &inventory, &destination);
    }
    let pin = StoredPin::open(&configuration, guard)?;
    let destination =
        crate::backup_destination_attach::detached_evidence(guard, &configuration, &pin)?;
    document(
        guard,
        &lock,
        (&configuration, &inventory),
        &destination,
        &pin.evidence()?,
        &|| pin.recheck(),
    )
}
/// A review document supplies no capture, worker or cleanup authority. Running
/// compares this measurement under the already-owned operation lock, before a
/// durable attempt, and retains the actual measured configuration/source actors.
pub fn measure(
    guard: &Guard,
    lock: &files::Lock,
    configuration: &Configuration,
    inventory: &Inventory<'_, '_>,
    destination: &Destination<'_>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    guard.recheck()?;
    inventory.require_pair(configuration, guard)?;
    require(
        std::ptr::eq(destination.storage(), guard),
        "review destination guard actor differs",
    )?;
    require(
        std::ptr::eq(destination.configuration()?, configuration),
        "review configuration actor differs",
    )?;
    destination.require_free_space()?;
    let pin = Repository::open(destination)?;
    let stable = destination.stable_evidence()?;
    document(
        guard,
        lock,
        (configuration, inventory),
        &stable,
        &pin.evidence()?,
        &|| {
            destination.require_free_space()?;
            pin.recheck()
        },
    )
}
fn document(
    guard: &Guard,
    lock: &files::Lock,
    (configuration, inventory): (&Configuration, &Inventory<'_, '_>),
    destination: &Value,
    pin: &Value,
    recheck: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    guard.recheck()?;
    inventory.require_pair(configuration, guard)?;
    recheck()?;
    let idle = crate::transition_idle::Snapshot::online()?;
    require(
        idle.guard.backup_root_binding()? == guard.backup_root_binding()?,
        "review transition source changed",
    )?;
    let registry = catalog::Transaction::begin()?;
    require(
        registry.config == guard.configuration,
        "review registry source changed",
    )?;
    let image = Image::open()?;
    let authority = crate::authority_mount::Authority::observe(guard)?;
    let kernels = crate::update_plan::installed_kernels()?;
    let modules = files::directory(Path::new("/usr/lib/modules"), Some(0))?;
    let mut hashes = value!({});
    let mut held = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        let version = kernels[flavor].as_str().unwrap();
        crate::identity::safe_id(version)?;
        let file = files::open_relative(&modules, Path::new(&format!("{version}/vmlinuz")))?;
        let (_, hash) = stream_copy::hash_borrowed(&file, 128 * 1024 * 1024, Some(0))?;
        hashes[flavor] = value!(hash);
        held.push((file, hash));
    }
    let document = value!({"schema":1,"operation":"backup-create","boot_id":operation::boot_id()?,
        "source":guard.backup_root_binding()?,"configuration_sha256":json::fingerprint(&configuration.evidence()?)?,
        "destination_sha256":json::fingerprint(destination)?,"pin_sha256":json::fingerprint(pin)?,
        "inventory_sha256":json::fingerprint(&inventory.evidence()?)?,
        "registry_sha256":json::fingerprint(&registry.data)?,"kernels":kernels,"kernel_sha256":hashes,
        "authority":{"identity":authority.identity(),"hashes":authority.hashes()?},
        "restic_sha256":json::fingerprint(&image.evidence()?)?,"scope":"local snapshot-backed backup; crash-consistent applications; no retention"});
    for (file, hash) in held {
        require(
            stream_copy::hash_borrowed(&file, 128 * 1024 * 1024, Some(0))?.1 == hash,
            "review kernel changed during observation",
        )?;
    }
    require(
        crate::update_plan::installed_kernels()? == document["kernels"],
        "review kernel packages changed",
    )?;
    authority.recheck(guard)?;
    require(
        authority.hashes()? == document["authority"]["hashes"],
        "review authority material changed",
    )?;
    registry.recheck()?;
    idle.recheck()?;
    inventory.require_pair(configuration, guard)?;
    recheck()?;
    require(
        json::fingerprint(&image.evidence()?)? == document["restic_sha256"],
        "review vendor image changed",
    )?;
    lock.recheck()?;
    require(
        json::canonical(&document)?.len() <= 4096,
        "backup review exceeds original durable job document budget",
    )?;
    Ok(document)
}
