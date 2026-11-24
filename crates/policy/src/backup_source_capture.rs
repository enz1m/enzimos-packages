// SPDX-License-Identifier: MIT
//! One original source inventory captured under actual cooperating barriers.
use crate::{
    backup_attempt::Attempt,
    backup_boot_capture, backup_flatpak_capture, backup_package_capture,
    backup_snapshot_creation::{self, Captured},
    backup_source_inventory::Inventory,
    control_record::Retained,
    identity, operation,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "backup-source-captures";
// A boot receipt can occupy up to 4 MiB, in addition to the bounded snapshot catalog.
const LIMIT: usize = 8 * 1024 * 1024;
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original private source-capture registry required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
fn registry(inventory: &Inventory<'_, '_>, directory: &File, expected: Shape) -> Result<()> {
    inventory.guard().recheck()?;
    let named = files::directory_relative(inventory.guard().control(), Path::new(FOLDER), Some(0))?;
    require(
        shape(directory)? == expected
            && shape(&named)? == expected
            && expected.5 == inventory.guard().control_mount_id(),
        "original capture registry changed or covered",
    )
}
/// This actor can only result from actual capture and successful normal release.
/// Readonly snapshot descriptions remain retained; evidence cannot reconstruct it.
pub struct Released<'s, 'cfg, 'g> {
    inventory: &'s Inventory<'cfg, 'g>,
    attempt: &'s Attempt<'g>,
    lock: &'s files::Lock,
    snapshots: Vec<Captured<'s, 'g>>,
    boot: backup_boot_capture::Captured<'s, 'g>,
    directory: File,
    directory_shape: Shape,
    record: Retained,
    value: Value,
}
impl<'s, 'cfg, 'g> Released<'s, 'cfg, 'g> {
    /// Consume one original aggregate after its original inventory stage is gone.
    /// Boot retires before snapshots because it retains the original root capture.
    pub fn retire(
        mut self,
        stage: &crate::backup_inventory_stage::Retired<'s, 'g>,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Retired<'s, 'g>> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck()?;
        stage.require_original(&self, closed)?;
        let guard = self.inventory.guard();
        self.value["phase"] = json!("retirement-entered");
        self.value["closed_transfer"] = closed.evidence()?;
        self.value["inventory_retired_sha256"] =
            json!(enzimos_platform::json::fingerprint(&stage.evidence()?)?);
        self.record.replace(&self.value)?;
        let mut boundary = || {
            authorize()?;
            crate::namespaces::initial()?;
            closed.recheck()?;
            stage.evidence()?;
            guard.recheck()?;
            self.lock.recheck()?;
            registry(self.inventory, &self.directory, self.directory_shape)?;
            self.record.recheck()
        };
        let started = std::time::Instant::now();
        let boot = self.boot.retire(closed, &mut boundary)?;
        eprintln!(
            "enzimos-backup: finishing boot-capture-retired {} ms",
            started.elapsed().as_millis()
        );
        let mut snapshots = Vec::new();
        for snapshot in self.snapshots.into_iter().rev() {
            let started = std::time::Instant::now();
            boundary()?;
            let retired = snapshot
                .retire_subvolume(closed, &mut boundary)?
                .retire_metadata(closed, &mut boundary)?;
            retired.evidence()?;
            snapshots.push(retired);
            eprintln!(
                "enzimos-backup: finishing snapshot-retired {} ms",
                started.elapsed().as_millis()
            );
        }
        boundary()?;
        self.value["phase"] = json!("retired");
        self.value["source_cleanup_complete"] = json!(true);
        self.value["retired_boot_sha256"] =
            json!(enzimos_platform::json::fingerprint(&boot.evidence()?)?);
        self.value["retired_snapshots_sha256"] = json!(
            snapshots
                .iter()
                .map(|s| enzimos_platform::json::fingerprint(&s.evidence()?))
                .collect::<Result<Vec<_>>>()?
        );
        self.record.replace(&self.value)?;
        let retired = Retired {
            guard,
            lock: self.lock,
            directory: self.directory,
            directory_shape: self.directory_shape,
            record: self.record,
            value: self.value,
            boot,
            snapshots,
        };
        retired.evidence()?;
        Ok(retired)
    }
    pub fn recheck(&self) -> Result<()> {
        enzimos_platform::recheck_scope::once(self, "source-capture", || self.recheck_fresh())
    }
    fn recheck_fresh(&self) -> Result<()> {
        self.lock.recheck()?;
        self.attempt.recheck()?;
        self.inventory.recheck()?;
        self.boot.recheck()?;
        require(
            self.value["boot_capture"] == self.boot.evidence()?,
            "original protected boot capture changed",
        )?;
        let named = files::directory_relative(
            self.inventory.guard().control(),
            Path::new(FOLDER),
            Some(0),
        )?;
        require(
            shape(&self.directory)? == self.directory_shape
                && shape(&named)? == self.directory_shape,
            "original source-capture registry changed or covered",
        )?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value
                && self.value["phase"] == "barriers-released"
                && self.value["attempt"] == self.attempt.evidence()?
                && self.value["inventory"] == self.inventory.evidence()?
                && self.value["snapshots"]
                    == json!(
                        self.snapshots
                            .iter()
                            .map(Captured::evidence)
                            .collect::<Result<Vec<_>>>()?
                    )
                && self.snapshots.len() == self.inventory.sources().len(),
            "original released capture or inventory changed",
        )
    }
    pub(crate) fn attempt(&self) -> &'s Attempt<'g> {
        self.attempt
    }
    pub(crate) fn lock(&self) -> &'s files::Lock {
        self.lock
    }
    pub(crate) fn guard(&self) -> &'g crate::storage_runtime::Guard {
        self.inventory.guard()
    }
    pub(crate) fn require_original(&self, lock: &files::Lock) -> Result<()> {
        self.recheck()?;
        require(
            std::ptr::eq(self.lock, lock),
            "original released capture lock required",
        )?;
        self.attempt.require_original(self.guard(), lock)
    }
    pub(crate) fn boot(&self) -> Result<&backup_boot_capture::Captured<'s, 'g>> {
        self.recheck()?;
        self.boot.require_original(self)?;
        Ok(&self.boot)
    }
    pub fn snapshots(&self) -> Result<&[Captured<'s, 'g>]> {
        self.recheck()?;
        Ok(&self.snapshots)
    }
    /// Exact package inventory copied before and checked after snapshot birth,
    /// while both cooperating barriers were still held. No later live refresh.
    pub fn installed_packages(&self) -> Result<std::collections::BTreeMap<String, String>> {
        self.recheck()?;
        let rows = serde_json::from_value(self.value["installed_packages"].clone())
            .map_err(|_| enzimos_platform::Error("original installed inventory shape".into()))?;
        self.recheck()?;
        Ok(rows)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(json!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}
/// Captures each configured dataset exactly once. Unknown outcomes leave original
/// intents and snapshots for review; there is no retry, deletion or Drop cleanup.
pub fn capture<'s, 'cfg, 'g, F: FnMut() -> Result<()>>(
    inventory: &'s Inventory<'cfg, 'g>,
    attempt: &'s Attempt<'g>,
    lock: &'s files::Lock,
    id: &str,
    authorize: &mut F,
) -> Result<Released<'s, 'cfg, 'g>> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    identity::safe_id(id)?;
    require(
        id.len() <= 64 && (1..=32).contains(&inventory.sources().len()),
        "source capture ID or dataset bound",
    )?;
    authorize()?;
    lock.recheck()?;
    attempt.require_original(inventory.guard(), lock)?;
    inventory.recheck()?;
    let directory =
        files::ensure_directory_relative(inventory.guard().control(), Path::new(FOLDER), 0o700, 0)?;
    let directory_shape = shape(&directory)?;
    require(
        directory_shape.5 == inventory.guard().control_mount_id(),
        "source capture registry left original control mount",
    )?;
    let members = files::directory_names(&directory, 128)?;
    require(members.len() < 128, "source capture receipt capacity")?;
    for name in members {
        let name = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .ok_or_else(|| {
                enzimos_platform::Error(
                    "interrupted source capture registry requires review".into(),
                )
            })?;
        identity::safe_id(name)?;
    }
    require(
        files::optional_relative(&directory, Path::new(&format!("{id}.json")))?.is_none(),
        "source capture ID already entered; no replay",
    )?;
    let packages = backup_package_capture::Capture::acquire(attempt, lock, authorize)?;
    let flatpak = backup_flatpak_capture::Capture::acquire(attempt, lock, authorize)?;
    let mut value = json!({"schema":1,"id":id,"role":"backup-source-capture","phase":"entered",
        "boot_id":operation::boot_id()?,"attempt":attempt.evidence()?,"inventory":inventory.evidence()?,
        "package_capture":packages.evidence()?,"flatpak_capture":flatpak.evidence()?,"snapshots":[],
        "installed_packages":packages.installed_packages()?,
        "transfer_complete":false,"cleanup_complete":false,"global_atomicity":false});
    authorize()?;
    inventory.recheck()?;
    packages.require_original(attempt, lock)?;
    flatpak.require_original(attempt, lock)?;
    registry(inventory, &directory, directory_shape)?;
    let mut record = Retained::create(
        &directory,
        Path::new(&format!("{id}.json")),
        &value,
        LIMIT,
        directory_shape.5,
    )?;
    let mut snapshots = Vec::new();
    for (index, source) in inventory.sources().iter().enumerate() {
        authorize()?;
        inventory.recheck()?;
        record.recheck()?;
        registry(inventory, &directory, directory_shape)?;
        let created = backup_snapshot_creation::create(
            source,
            attempt,
            lock,
            &flatpak,
            &packages,
            &format!("{id}-{index}"),
            authorize,
        )?;
        inventory.advance_created(&created)?;
        snapshots.push(created.seal(authorize)?);
    }
    authorize()?;
    inventory.recheck()?;
    record.recheck()?;
    registry(inventory, &directory, directory_shape)?;
    for snapshot in &snapshots {
        snapshot.recheck()?;
    }
    require(
        value["installed_packages"] == json!(packages.installed_packages()?),
        "installed package inventory changed while snapshots were captured",
    )?;
    value["phase"] = json!("snapshots-sealed");
    value["inventory"] = inventory.evidence()?;
    value["snapshots"] = json!(
        snapshots
            .iter()
            .map(Captured::evidence)
            .collect::<Result<Vec<_>>>()?
    );
    record.replace(&value)?;
    let root = snapshots
        .first()
        .ok_or_else(|| enzimos_platform::Error("missing original root capture".into()))?
        .snapshot()?;
    let boot_id = format!(
        "boot-{}",
        &enzimos_platform::json::sha256(id.as_bytes())[..48]
    );
    let boot = {
        let mut checkpoint = || {
            authorize()?;
            inventory.recheck()?;
            record.recheck()?;
            registry(inventory, &directory, directory_shape)?;
            packages.require_original(attempt, lock)?;
            flatpak.require_original(attempt, lock)?;
            for captured in &snapshots {
                captured.recheck()?;
            }
            Ok(())
        };
        backup_boot_capture::capture(
            root,
            attempt,
            lock,
            &packages,
            &flatpak,
            &boot_id,
            &mut checkpoint,
        )?
    };
    require(
        value["installed_packages"] == json!(packages.installed_packages()?),
        "original package inventory changed during boot capture",
    )?;
    value["boot_capture"] = boot.evidence()?;
    record.replace(&value)?;
    // These are explicit normal releases, not destructor guesses. No transfer
    // actor is returned if either release or the subsequent publication fails.
    authorize()?;
    record.recheck()?;
    registry(inventory, &directory, directory_shape)?;
    packages.close()?;
    authorize()?;
    record.recheck()?;
    registry(inventory, &directory, directory_shape)?;
    flatpak.close()?;
    authorize()?;
    lock.recheck()?;
    attempt.evidence()?;
    inventory.recheck()?;
    for snapshot in &snapshots {
        snapshot.recheck()?;
    }
    record.recheck()?;
    registry(inventory, &directory, directory_shape)?;
    let named = files::directory_relative(inventory.guard().control(), Path::new(FOLDER), Some(0))?;
    require(
        shape(&directory)? == directory_shape && shape(&named)? == directory_shape,
        "original capture registry changed before release publication",
    )?;
    value["phase"] = json!("barriers-released");
    record.replace(&value)?;
    let released = Released {
        inventory,
        attempt,
        lock,
        snapshots,
        boot,
        directory,
        directory_shape,
        record,
        value,
    };
    released.recheck()?;
    authorize()?;
    released.recheck()?;
    Ok(released)
}

/// Actual aggregate source snapshots/metadata and boot tree retired. Original
/// stage retirement and closed transfer remain required for final completion.
pub struct Retired<'s, 'g> {
    guard: &'g crate::storage_runtime::Guard,
    lock: &'s files::Lock,
    directory: File,
    directory_shape: Shape,
    record: Retained,
    value: Value,
    boot: backup_boot_capture::Retired<'s, 'g>,
    snapshots: Vec<backup_snapshot_creation::MetadataRetired<'s, 'g>>,
}
impl<'s, 'g> Retired<'s, 'g> {
    pub(crate) fn guard(&self) -> &'g crate::storage_runtime::Guard {
        self.guard
    }
    pub(crate) fn lock(&self) -> &'s files::Lock {
        self.lock
    }
    pub(crate) fn require_completion(
        &self,
        attempt: &Attempt<'_>,
        stage: &crate::backup_inventory_stage::Retired<'_, '_>,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
    ) -> Result<()> {
        self.evidence()?;
        stage.evidence()?;
        closed.recheck()?;
        attempt.require_original(self.guard, self.lock)?;
        stage.require_pair(self.guard, self.lock)?;
        require(
            self.value["attempt"] == attempt.evidence()?
                && self.value["inventory_retired_sha256"]
                    == json!(enzimos_platform::json::fingerprint(&stage.evidence()?)?)
                && self.value["closed_transfer"] == closed.evidence()?,
            "completion differs from original attempt/stage/source/closed transfer",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.record.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.directory)? == self.directory_shape
                && shape(&named)? == self.directory_shape
                && self.record.value()? == &self.value
                && self.value["phase"] == "retired"
                && self.value["source_cleanup_complete"] == true
                && !self.snapshots.is_empty()
                && self.value["snapshots"]
                    .as_array()
                    .is_some_and(|s| s.len() == self.snapshots.len())
                && self.value["retired_boot_sha256"]
                    == json!(enzimos_platform::json::fingerprint(&self.boot.evidence()?)?)
                && self.value["retired_snapshots_sha256"]
                    == json!(
                        self.snapshots
                            .iter()
                            .map(|s| enzimos_platform::json::fingerprint(&s.evidence()?))
                            .collect::<Result<Vec<_>>>()?
                    ),
            "original aggregate source retirement actors/receipt changed",
        )?;
        Ok(json!({"receipt":self.value,"source_cleanup_complete":true,"backup_complete":false}))
    }
}
