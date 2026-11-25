// SPDX-License-Identifier: MIT
//! Complete original online Kernel Root Tree observation. No mutation capability.
use crate::{
    birth_runtime::Records,
    filesystem, operation,
    storage_runtime::{Guard, TopMount},
    subvolume,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
};

/// The complete subvolume inventory of the online root tree.
pub struct Inventory<'a> {
    guard: &'a Guard,
    top: &'a TopMount,
    lock: &'a files::Lock,
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    filesystem: Value,
    root: Value,
    records: Records,
}
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original online inventory requires a read-only descriptor",
    )?;
    Ok(flags)
}
fn absent(records: &Records, targets: &Value) -> Result<()> {
    let rows = targets
        .as_array()
        .filter(|rows| (1..=64).contains(&rows.len()))
        .ok_or_else(|| enzimos_platform::Error("completed Root targets bound".into()))?;
    let root = rows
        .last()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["path"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("completed Root target path".into()))?;
    crate::identity::safe_id(root)?;
    for observed in records.values() {
        let path = crate::recovery_records::text(observed, "path")?;
        require(
            path != root && !path.starts_with(&format!("{root}/")),
            "completed Root still has a live path or descendant",
        )?;
        for target in rows {
            require(
                observed["path"] != target["path"]
                    && observed["id"] != target["id"]
                    && observed["uuid"] != target["uuid"],
                "completed Root target remains live by path/ID/UUID",
            )?;
        }
    }
    Ok(())
}
impl<'a> Inventory<'a> {
    /// Observe the inventory on the top-level mount.
    ///
    /// # Errors
    ///
    /// Fails when the tree is incomplete or on another filesystem, or `authorize` fails.
    pub fn observe(
        guard: &'a Guard,
        top: &'a TopMount,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        top.recheck()?;
        lock.recheck()?;
        let file = top.directory()?.try_clone()?;
        let epoch = files::identity(&file.metadata()?);
        let flags = flags(&file)?;
        let mount = mount_identity::id(file.as_fd(), true)?;
        let filesystem = filesystem::observe(file.as_fd())?;
        let root = subvolume::containing_identity(file.as_fd())?;
        require(
            file.metadata()?.ino() == 256
                && file.metadata()?.uid() == 0
                && file.metadata()?.gid() == 0
                && file.metadata()?.mode() & 0o022 == 0
                && root["id"] == 5
                && root["readonly"] == false
                && filesystem["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "original online inventory requires the selected filesystem top",
        )?;
        let records = crate::root_retirement_kernel_inventory::query(&file)?;
        let this = Self {
            guard,
            top,
            lock,
            file,
            epoch,
            flags,
            mount,
            filesystem,
            root,
            records,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.top.recheck()?;
        self.lock.recheck()?;
        for file in [&self.file, self.top.directory()?] {
            require(
                files::identity(&file.metadata()?) == self.epoch
                    && flags(file)? == self.flags
                    && mount_identity::id(file.as_fd(), true)? == self.mount
                    && filesystem::observe(file.as_fd())? == self.filesystem
                    && subvolume::containing_identity(file.as_fd())? == self.root,
                "original online inventory top changed/covered",
            )?;
        }
        require(
            crate::root_retirement_kernel_inventory::query(&self.file)? == self.records,
            "complete original online Root Tree inventory changed",
        )?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch,
            "original inventory top changed during complete query",
        )?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    pub(crate) fn require_deleted(
        &self,
        journal: &crate::root_retirement_online_journal::Journal<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        let record = journal.record()?;
        require(
            record["phase"] == "deleted"
                && record["filesystem_uuid"] == self.filesystem["filesystem_uuid"],
            "actual deleted Root receipt must match observed filesystem",
        )?;
        absent(&self.records, &record["targets"])?;
        journal.recheck()?;
        self.recheck(authorize)
    }
    /// Recheck the independently retained deleted receipt after its journal
    /// borrow ends. This comparison supplies no deletion or completion actor.
    pub(crate) fn require_deleted_record(
        &self,
        receipt: &crate::control_record::Observation,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        receipt.recheck()?;
        let record = receipt.value()?;
        crate::root_retirement_record::validate(
            record,
            crate::recovery_records::text(record, "id")?,
        )?;
        require(
            record["phase"] == "deleted"
                && record["filesystem_uuid"] == self.filesystem["filesystem_uuid"],
            "retained deleted receipt differs from actual inventory filesystem",
        )?;
        absent(&self.records, &record["targets"])?;
        receipt.recheck()?;
        self.recheck(authorize)
    }
    pub(crate) fn require_completed(
        &self,
        receipt: &crate::root_retirement_online_journal::Completed<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        receipt.recheck()?;
        let row = receipt.record()?;
        require(
            row["phase"] == "complete"
                && row["filesystem_uuid"] == self.filesystem["filesystem_uuid"],
            "completed receipt differs from actual absence inventory",
        )?;
        absent(&self.records, &row["targets"])?;
        receipt.recheck()?;
        self.recheck(authorize)
    }
    pub(crate) fn records(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Records> {
        self.recheck(authorize)?;
        Ok(&self.records)
    }
    pub(crate) fn require_original_source(
        &self,
        guard: &Guard,
        top: &TopMount,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard)
                && std::ptr::eq(self.top, top)
                && std::ptr::eq(self.lock, lock),
            "online inventory belongs to another original source actor",
        )?;
        self.recheck(authorize)
    }
    /// JSON evidence for the inventory.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed or `authorize` fails.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = json!({"filesystem":self.filesystem,"top_epoch":self.epoch,"mount":self.mount,
            "root":self.root,"records":self.records,"execution_authorized":false});
        self.recheck(authorize)?;
        Ok(result)
    }
}
