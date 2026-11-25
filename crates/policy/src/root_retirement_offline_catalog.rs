// SPDX-License-Identifier: MIT
//! Original catalog and lock descriptions for offline Root protection checks.
//! The lock is retained as a file observation, not advertised as live exclusion.
use crate::{
    control_record::Retained, root_retirement_offline_control::Control,
    root_retirement_offline_ledgers::Ledgers,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "generation-registry";
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline catalog read-only description required",
    )?;
    Ok(flags)
}
fn directory(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let metadata = file.metadata()?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o700
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original private offline catalog directory required",
    )?;
    Ok(files::identity(&metadata))
}
fn names(file: &File) -> Result<()> {
    require(
        files::directory_names(file, 2)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([
                std::ffi::OsString::from("catalog.json"),
                std::ffi::OsString::from("lock"),
            ]),
        "interrupted or incomplete original offline catalog requires review",
    )
}
pub(crate) fn unmentioned(data: &Value, targets: &Value) -> Result<()> {
    let targets = targets
        .as_array()
        .filter(|v| (1..=64).contains(&v.len()))
        .ok_or_else(|| Error("original offline catalog target list bound".into()))?;
    let root = targets
        .last()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["path"]
        .as_str()
        .ok_or_else(|| Error("original offline final root path".into()))?;
    crate::identity::safe_id(root)?;
    let generations = data["generations"]
        .as_object()
        .ok_or_else(|| Error("original offline catalog generations".into()))?;
    for generation in generations.values() {
        let identity = &generation["material"]["root_identity"];
        let path = identity["path"]
            .as_str()
            .ok_or_else(|| Error("original registered root path".into()))?;
        let id = identity["id"]
            .as_u64()
            .filter(|v| *v >= 256)
            .ok_or_else(|| Error("original registered root ID".into()))?;
        let uuid = identity["uuid"]
            .as_str()
            .ok_or_else(|| Error("original registered root UUID".into()))?;
        crate::identity::uuid(uuid)?;
        require(
            path != root && !path.starts_with(&format!("{root}/")),
            "original generation catalog protects retired root subtree",
        )?;
        for target in targets {
            require(
                identity["path"] != target["path"] && target["id"] != id && target["uuid"] != uuid,
                "original generation catalog protects target by path, ID or UUID",
            )?;
        }
    }
    Ok(())
}
pub struct Catalog<'a, 's> {
    control: &'a Control<'a, 's>,
    ledgers: &'a Ledgers<'a, 's>,
    folder: File,
    epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    record: Retained,
    record_flags: i32,
    lock: File,
    lock_epoch: files::FileIdentity,
    lock_flags: i32,
    lock_bytes: Vec<u8>,
    filesystem: String,
}
impl<'a, 's> Catalog<'a, 's> {
    pub(crate) fn require_registered_root(&self, identity: &Value) -> Result<()> {
        self.recheck()?;
        require(
            enzimos_platform::json::object(&self.record.value()?["generations"])?
                .values()
                .any(|row| {
                    ["path", "id", "uuid"]
                        .iter()
                        .all(|key| row["material"]["root_identity"][*key] == identity[*key])
                }),
            "original restored configuration root is not registered by actual catalog identity",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_ledgers(&self, ledgers: &Ledgers<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.ledgers, ledgers),
            "original offline catalog belongs to another ledger actor",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_control(&self, control: &Control<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.control, control),
            "original offline catalog belongs to another control actor",
        )?;
        self.recheck()
    }
    pub(crate) fn observe(
        control: &'a Control<'a, 's>,
        ledgers: &'a Ledgers<'a, 's>,
    ) -> Result<Self> {
        ledgers.require_original_control(control)?;
        let filesystem =
            crate::filesystem::observe(control.descriptor()?.as_fd())?["filesystem_uuid"]
                .as_str()
                .ok_or_else(|| Error("original offline catalog filesystem UUID".into()))?
                .to_owned();
        let mount = control.mount_id()?;
        let folder = files::directory_relative(control.descriptor()?, Path::new(FOLDER), Some(0))?;
        let epoch = directory(&folder, mount)?;
        names(&folder)?;
        let record = Retained::open(
            &folder,
            Path::new("catalog.json"),
            crate::catalog::MAX_CATALOG,
            mount,
        )?;
        crate::catalog::validate(record.value()?, &filesystem)?;
        let lock = files::open_relative(&folder, Path::new("lock"))?;
        let metadata = lock.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() <= 4096
                && mount_identity::id(lock.as_fd(), true)? == mount,
            "original private offline catalog lock file required",
        )?;
        let lock_bytes = files::read_file(&lock, 4096, Some(0), true)?;
        let result = Self {
            control,
            ledgers,
            flags: flags(&folder)?,
            epoch,
            folder,
            mount,
            record_flags: flags(record.checkpoint_descriptor()?)?,
            record,
            lock_epoch: files::identity(&metadata),
            lock_flags: flags(&lock)?,
            lock,
            lock_bytes,
            filesystem,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.ledgers.require_original_control(self.control)?;
        let named =
            files::directory_relative(self.control.descriptor()?, Path::new(FOLDER), Some(0))?;
        require(
            directory(&self.folder, self.mount)? == self.epoch
                && directory(&named, self.mount)? == self.epoch
                && flags(&self.folder)? == self.flags,
            "original offline catalog directory changed, replaced or covered",
        )?;
        names(&self.folder)?;
        names(&named)?;
        self.record.recheck()?;
        require(
            flags(self.record.checkpoint_descriptor()?)? == self.record_flags,
            "original offline catalog shared descriptor flags changed",
        )?;
        crate::catalog::validate(self.record.value()?, &self.filesystem)?;
        let record = files::open_relative(&self.folder, Path::new("catalog.json"))?;
        let lock = files::open_relative(&self.folder, Path::new("lock"))?;
        require(
            files::identity(&record.metadata()?)
                == files::identity(&self.record.checkpoint_descriptor()?.metadata()?)
                && mount_identity::id(record.as_fd(), true)? == self.mount
                && files::identity(&self.lock.metadata()?) == self.lock_epoch
                && files::identity(&lock.metadata()?) == self.lock_epoch
                && mount_identity::id(self.lock.as_fd(), true)? == self.mount
                && mount_identity::id(lock.as_fd(), true)? == self.mount
                && flags(&self.lock)? == self.lock_flags
                && files::read_file(&self.lock, 4096, Some(0), true)? == self.lock_bytes
                && files::identity(&self.lock.metadata()?) == self.lock_epoch,
            "original offline catalog/lock member changed or replaced",
        )?;
        self.ledgers.require_original_control(self.control)
    }
    pub(crate) fn require_unmentioned(
        &self,
        targets: &crate::root_retirement_offline_targets::Targets<'a, 's>,
    ) -> Result<()> {
        self.recheck()?;
        targets.require_original_catalog(self)?;
        unmentioned(self.record.value()?, targets.rows()?)?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"original_offline_catalog_and_lock_retained":true,"live_catalog_lock_exclusion_claimed":false,
            "catalog":self.record.evidence()?,"execution_authorized":false}),
        )
    }
}
