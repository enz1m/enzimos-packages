// SPDX-License-Identifier: MIT
//! Source snapshot creation is durably entered once and never guesses an outcome.
use crate::{
    backup_attempt::Attempt,
    backup_flatpak_capture::Capture,
    backup_package_capture::Capture as PackageCapture,
    backup_source::{Snapshot, Source},
    control_record::Retained,
    identity, operation,
    settings_command::Command,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "backup-source-snapshots";
const LIMIT: usize = 32768;
const CAPACITY: usize = 128;
const SNAPSHOT_NAMES: usize = 8192;
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "original protected backup snapshot directory required",
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
fn names(file: &File, maximum: usize) -> Result<BTreeSet<String>> {
    files::directory_names(file, maximum)?
        .into_iter()
        .map(|name| {
            name.into_string()
                .map_err(|_| Error("backup snapshot directory name encoding".into()))
        })
        .collect()
}
fn parent_recheck(source: &Source<'_>, parent: &File, expected: Shape) -> Result<()> {
    source.recheck()?;
    let named = files::directory_relative(
        source.original_directory()?,
        Path::new(".snapshots"),
        Some(0),
    )?;
    require(
        shape(parent)? == expected && shape(&named)? == expected,
        "original backup snapshot directory replaced or covered",
    )
}
fn registry_recheck(source: &Source<'_>, directory: &File, expected: Shape) -> Result<()> {
    source.guard().recheck()?;
    let named = files::directory_relative(source.guard().control(), Path::new(FOLDER), Some(0))?;
    require(
        shape(directory)? == expected
            && shape(&named)? == expected
            && expected.5 == source.guard().control_mount_id(),
        "original backup snapshot receipt directory replaced or covered",
    )
}
fn number(body: &[u8]) -> Result<u64> {
    require(
        !body.is_empty() && body.len() <= 32,
        "backup snapshot number output bound",
    )?;
    let text =
        std::str::from_utf8(body).map_err(|_| Error("backup snapshot number encoding".into()))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    require(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "backup snapshot number must be one decimal line",
    )?;
    let number = text
        .parse::<u64>()
        .map_err(|_| Error("backup snapshot number bound".into()))?;
    require(
        number > 0 && number < i64::MAX as u64 && number.to_string() == text,
        "backup snapshot number is not canonical",
    )?;
    Ok(number)
}
fn added(before: &BTreeSet<String>, after: &BTreeSet<String>, number: u64) -> Result<()> {
    let name = number.to_string();
    let mut expected = before.clone();
    require(
        expected.insert(name),
        "backup snapshot number already existed; no adoption",
    )?;
    require(
        *after == expected,
        "backup snapshot directory has unknown changes",
    )
}
pub struct Created<'a, 'c, 'g> {
    snapshot: Snapshot<'a, 'g>,
    record: Retained,
    directory: File,
    directory_shape: Shape,
    parent: File,
    parent_shape: Shape,
    source: &'a Source<'g>,
    attempt: &'a Attempt<'g>,
    lock: &'a files::Lock,
    capture: &'c Capture<'a, 'g>,
    packages: &'c PackageCapture<'a, 'g>,
    id: String,
    value: Value,
}
impl<'a, 'c, 'g> Created<'a, 'c, 'g> {
    pub(crate) fn inventory_addition(&self) -> Result<(&Source<'g>, String, Value)> {
        self.recheck()?;
        let snapshot = self.snapshot.evidence()?;
        let number = snapshot["number"]
            .as_u64()
            .ok_or_else(|| Error("actual created snapshot number required".into()))?;
        let path = format!(
            "{}/.snapshots/{number}/snapshot",
            self.source.filesystem_path()
        );
        let object = &snapshot["object"];
        Ok((
            self.source,
            path.clone(),
            value!({"path":path,"id":object["id"],
            "uuid":object["uuid"],"parent_uuid":object["parent_uuid"]}),
        ))
    }
    pub fn recheck(&self) -> Result<()> {
        self.capture.require_original(self.attempt, self.lock)?;
        self.packages.require_original(self.attempt, self.lock)?;
        self.lock.recheck()?;
        self.attempt.recheck()?;
        self.source.recheck()?;
        registry_recheck(self.source, &self.directory, self.directory_shape)?;
        let named =
            files::directory_relative(self.source.guard().control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.directory)? == self.directory_shape
                && shape(&named)? == self.directory_shape,
            "original snapshot receipt directory changed or covered",
        )?;
        let parent = files::directory_relative(
            self.source.original_directory()?,
            Path::new(".snapshots"),
            Some(0),
        )?;
        require(
            shape(&self.parent)? == self.parent_shape && shape(&parent)? == self.parent_shape,
            "original snapshot source directory changed or covered",
        )?;
        self.snapshot.original_parent(&self.parent)?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value
                && self.value["id"] == self.id
                && self.value["attempt"] == self.attempt.evidence()?
                && self.value["flatpak_capture"] == self.capture.evidence()?
                && self.value["package_capture"] == self.packages.evidence()?
                && self.snapshot.evidence()? == self.value["snapshot"],
            "original created snapshot receipt or actual snapshot changed",
        )
    }
    /// Transfer the actual readonly snapshot and original receipt while both
    /// cooperating capture barriers are still held. Their later normal release
    /// cannot invalidate the factual capture evidence. This grants no deletion
    /// or completed backup, and has no observation/pathname constructor.
    pub fn seal<F: FnMut() -> Result<()>>(mut self, authorize: &mut F) -> Result<Captured<'a, 'g>> {
        authorize()?;
        self.recheck()?;
        let mut next = self.value.clone();
        next["phase"] = value!("capture-sealed");
        next["capture_sealed"] = value!(true);
        authorize()?;
        self.recheck()?;
        self.record.replace(&next)?;
        let captured = Captured {
            snapshot: self.snapshot,
            record: self.record,
            directory: self.directory,
            directory_shape: self.directory_shape,
            parent: self.parent,
            parent_shape: self.parent_shape,
            source: self.source,
            attempt: self.attempt,
            lock: self.lock,
            id: self.id,
            value: next,
        };
        captured.recheck()?;
        authorize()?;
        captured.recheck()?;
        Ok(captured)
    }
    pub fn snapshot(&self) -> Result<&Snapshot<'a, 'g>> {
        self.recheck()?;
        Ok(&self.snapshot)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}
/// An original readonly snapshot retained beyond normal capture-barrier release.
/// The stored barrier evidence describes the completed capture interval only.
pub struct Captured<'a, 'g> {
    snapshot: Snapshot<'a, 'g>,
    record: Retained,
    directory: File,
    directory_shape: Shape,
    parent: File,
    parent_shape: Shape,
    source: &'a Source<'g>,
    attempt: &'a Attempt<'g>,
    lock: &'a files::Lock,
    id: String,
    value: Value,
}
impl<'a, 'g> Captured<'a, 'g> {
    pub fn recheck(&self) -> Result<()> {
        self.lock.recheck()?;
        self.attempt.recheck()?;
        self.source.recheck()?;
        registry_recheck(self.source, &self.directory, self.directory_shape)?;
        parent_recheck(self.source, &self.parent, self.parent_shape)?;
        self.snapshot.original_parent(&self.parent)?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value
                && self.value["id"] == self.id
                && self.value["phase"] == "capture-sealed"
                && self.value["capture_sealed"] == true
                && self.value["transfer_complete"] == false
                && self.value["cleanup_complete"] == false
                && self.value["attempt"] == self.attempt.evidence()?
                && self.value["snapshot"] == self.snapshot.evidence()?,
            "original sealed capture receipt or readonly snapshot changed",
        )
    }
    pub(crate) fn original_root(&self) -> Result<Value> {
        self.recheck()?;
        self.source.guard().backup_root_binding()
    }
    pub(crate) fn original_epoch(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!(files::identity(
            &self.snapshot.original_directory()?.metadata()?
        )))
    }
    /// Consume this actual capture after typed worker/source retirement. Intent
    /// precedes the exact-ID ioctl; uncertain outcomes cannot reopen this actor.
    pub fn retire_subvolume(
        mut self,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Retired<'a, 'g>> {
        authorize()?;
        self.recheck()?;
        closed.require_snapshot(&self)?;
        let original_epoch = self.original_epoch()?;
        self.value["phase"] = value!("subvolume-retirement-entered");
        self.value["closed_transfer"] = closed.evidence()?;
        self.record.replace(&self.value)?;
        authorize()?;
        closed.recheck()?;
        self.source.recheck()?;
        self.lock.recheck()?;
        registry_recheck(self.source, &self.directory, self.directory_shape)?;
        parent_recheck(self.source, &self.parent, self.parent_shape)?;
        self.record.recheck()?;
        require(
            value!(files::identity(
                &self.snapshot.original_directory()?.metadata()?
            )) == original_epoch,
            "original transferred snapshot epoch changed before retirement",
        )?;
        let snapshot = self.snapshot.destroy_original()?;
        authorize()?;
        closed.recheck()?;
        snapshot.recheck()?;
        self.value["phase"] = value!("subvolume-retired");
        self.value["subvolume_removed"] = value!(true);
        self.record.replace(&self.value)?;
        let retired = Retired {
            snapshot,
            record: self.record,
            value: self.value,
            directory: self.directory,
            directory_shape: self.directory_shape,
            parent: self.parent,
            parent_shape: self.parent_shape,
            source: self.source,
            lock: self.lock,
        };
        retired.evidence()?;
        Ok(retired)
    }
    pub fn dataset(&self) -> Result<&crate::backup_source_layout::Dataset> {
        self.recheck()?;
        Ok(self.source.dataset())
    }
    pub fn snapshot(&self) -> Result<&Snapshot<'a, 'g>> {
        self.recheck()?;
        Ok(&self.snapshot)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}
/// Caller must retain the complete source inventory and package/Flatpak capture barriers.
/// This creates one source only; it grants no transfer, deletion or completed backup.
pub fn create<'a, 'c, 'g, F: FnMut() -> Result<()>>(
    source: &'a Source<'g>,
    attempt: &'a Attempt<'g>,
    lock: &'a files::Lock,
    capture: &'c Capture<'a, 'g>,
    packages: &'c PackageCapture<'a, 'g>,
    id: &str,
    authorize: &mut F,
) -> Result<Created<'a, 'c, 'g>> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    identity::safe_id(id)?;
    authorize()?;
    lock.recheck()?;
    attempt.recheck()?;
    capture.require_original(attempt, lock)?;
    packages.require_original(attempt, lock)?;
    source.recheck()?;
    let guard = source.guard();
    attempt.require_original(guard, lock)?;
    let directory = files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
    let directory_shape = shape(&directory)?;
    require(
        directory_shape.4 & 0o7777 == 0o700 && directory_shape.5 == guard.control_mount_id(),
        "private snapshot intent directory on original control required",
    )?;
    for name in names(&directory, CAPACITY)? {
        let existing = name
            .strip_suffix(".json")
            .ok_or_else(|| Error("interrupted backup snapshot receipt requires review".into()))?;
        identity::safe_id(existing)?;
    }
    require(
        names(&directory, CAPACITY)?.len() < CAPACITY,
        "backup snapshot receipt capacity",
    )?;
    let parent = files::directory_relative(
        source.original_directory()?,
        Path::new(".snapshots"),
        Some(0),
    )?;
    let parent_shape = shape(&parent)?;
    let before = names(&parent, SNAPSHOT_NAMES)?;
    let vendor = Command::open("/usr/bin/snapper")?;
    let mut entered = value!({"schema":1,"id":id,"role":"backup-source-snapshot",
        "phase":"entered","boot_id":operation::boot_id()?,"attempt":attempt.evidence()?,"source":source.evidence()?,
        "source_parent":parent_shape,"vendor":vendor.evidence()?,"flatpak_capture":capture.evidence()?,"package_capture":packages.evidence()?,"snapshot":null,
        "transfer_complete":false,"cleanup_complete":false});
    authorize()?;
    lock.recheck()?;
    attempt.recheck()?;
    capture.require_original(attempt, lock)?;
    packages.require_original(attempt, lock)?;
    source.recheck()?;
    parent_recheck(source, &parent, parent_shape)?;
    require(
        names(&parent, SNAPSHOT_NAMES)? == before,
        "original snapshot source changed before durable entry",
    )?;
    registry_recheck(source, &directory, directory_shape)?;
    let mut record = Retained::create(
        &directory,
        Path::new(&format!("{id}.json")),
        &entered,
        LIMIT,
        guard.control_mount_id(),
    )?;
    // No execution precedes this durable original receipt. Failures keep entered intent.
    authorize()?;
    lock.recheck()?;
    attempt.recheck()?;
    capture.require_original(attempt, lock)?;
    packages.require_original(attempt, lock)?;
    source.recheck()?;
    record.recheck()?;
    vendor.recheck()?;
    registry_recheck(source, &directory, directory_shape)?;
    parent_recheck(source, &parent, parent_shape)?;
    require(
        shape(&directory)? == directory_shape
            && shape(&parent)? == parent_shape
            && names(&parent, SNAPSHOT_NAMES)? == before,
        "snapshot entry epochs changed; no replay",
    )?;
    let body = vendor.run(
        &[
            "--no-dbus",
            "-c",
            &source.dataset().name,
            "create",
            "--type",
            "single",
            "--read-only",
            "--cleanup-algorithm",
            "",
            "--print-number",
            "--description",
            "enzimOS package-locked backup source",
        ],
        &[0],
        // number() still requires one short decimal line; a wider read bound
        // reports unexpected output as itself instead of a bound violation.
        4096,
    )?;
    let number = number(&body)?;
    source.recheck()?;
    lock.recheck()?;
    attempt.recheck()?;
    capture.require_original(attempt, lock)?;
    packages.require_original(attempt, lock)?;
    record.recheck()?;
    vendor.recheck()?;
    parent_recheck(source, &parent, parent_shape)?;
    added(&before, &names(&parent, SNAPSHOT_NAMES)?, number)?;
    let snapshot = Snapshot::open(source, number)?;
    snapshot.original_parent(&parent)?;
    entered["phase"] = value!("created");
    entered["snapshot"] = snapshot.evidence()?;
    authorize()?;
    lock.recheck()?;
    attempt.recheck()?;
    capture.require_original(attempt, lock)?;
    packages.require_original(attempt, lock)?;
    source.recheck()?;
    snapshot.recheck()?;
    registry_recheck(source, &directory, directory_shape)?;
    parent_recheck(source, &parent, parent_shape)?;
    added(&before, &names(&parent, SNAPSHOT_NAMES)?, number)?;
    record.replace(&entered)?;
    let created = Created {
        snapshot,
        record,
        directory,
        directory_shape,
        parent,
        parent_shape,
        source,
        attempt,
        lock,
        capture,
        packages,
        id: id.into(),
        value: entered,
    };
    created.recheck()?;
    Ok(created)
}

/// Original capture receipt plus actual removed subvolume. Metadata/stage cleanup
/// is still pending; no filesystem pathname can construct this actor.
pub struct Retired<'a, 'g> {
    directory: File,
    directory_shape: Shape,
    parent: File,
    parent_shape: Shape,
    source: &'a Source<'g>,
    lock: &'a files::Lock,
    snapshot: crate::backup_source::RemovedSnapshot<'a, 'g>,
    record: Retained,
    value: Value,
}
impl<'a, 'g> Retired<'a, 'g> {
    /// One-use metadata intent precedes both original metadata and empty-parent
    /// retirement. Any quarantined/partial outcome remains for explicit review.
    pub fn retire_metadata(
        mut self,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<MetadataRetired<'a, 'g>> {
        authorize()?;
        self.evidence()?;
        closed.recheck()?;
        require(
            self.value["closed_transfer"] == closed.evidence()?,
            "metadata cleanup differs from original closed transfer",
        )?;
        self.value["phase"] = value!("metadata-retirement-entered");
        self.record.replace(&self.value)?;
        let mut boundary = || {
            authorize()?;
            closed.recheck()?;
            self.lock.recheck()?;
            self.source.recheck()?;
            registry_recheck(self.source, &self.directory, self.directory_shape)?;
            parent_recheck(self.source, &self.parent, self.parent_shape)?;
            self.record.recheck()
        };
        let snapshot = self.snapshot.retire_metadata(&mut boundary)?;
        self.value["phase"] = value!("snapshot-retired");
        self.value["metadata_removed"] = value!(true);
        self.record.replace(&self.value)?;
        let retired = MetadataRetired {
            snapshot,
            record: self.record,
            value: self.value,
            directory: self.directory,
            directory_shape: self.directory_shape,
            parent: self.parent,
            parent_shape: self.parent_shape,
            source: self.source,
            lock: self.lock,
        };
        retired.evidence()?;
        Ok(retired)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.lock.recheck()?;
        self.source.recheck()?;
        registry_recheck(self.source, &self.directory, self.directory_shape)?;
        parent_recheck(self.source, &self.parent, self.parent_shape)?;
        self.snapshot.recheck()?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value && self.value["phase"] == "subvolume-retired",
            "original snapshot retirement receipt changed",
        )?;
        Ok(
            value!({"receipt":self.value,"subvolume":self.snapshot.evidence()?,
            "source_cleanup_complete":false,"backup_complete":false}),
        )
    }
}

/// One source snapshot retired. Aggregate capture/boot/stage cleanup still pending.
pub struct MetadataRetired<'a, 'g> {
    snapshot: crate::backup_source::RemovedMetadata<'a, 'g>,
    record: Retained,
    value: Value,
    directory: File,
    directory_shape: Shape,
    parent: File,
    parent_shape: Shape,
    source: &'a Source<'g>,
    lock: &'a files::Lock,
}
impl MetadataRetired<'_, '_> {
    pub fn evidence(&self) -> Result<Value> {
        self.lock.recheck()?;
        self.source.recheck()?;
        registry_recheck(self.source, &self.directory, self.directory_shape)?;
        parent_recheck(self.source, &self.parent, self.parent_shape)?;
        self.snapshot.recheck()?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value && self.value["phase"] == "snapshot-retired",
            "original complete snapshot retirement receipt changed",
        )?;
        Ok(
            value!({"receipt":self.value,"snapshot":self.snapshot.evidence()?,
            "source_cleanup_complete":false,"backup_complete":false}),
        )
    }
}
