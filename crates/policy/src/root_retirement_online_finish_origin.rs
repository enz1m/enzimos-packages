// SPDX-License-Identifier: MIT
//! Actual deleted receipt, complete absence inventory and original origin record.
//! This observer grants no offline deletion, boot cleanup or metadata write.
use crate::{
    control_record::Observation as Record,
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::Journal,
    root_retirement_references::Observation,
    storage_runtime::{Guard, TopMount},
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
struct Selection {
    folder: &'static str,
    id: String,
    before: Value,
    next: Value,
    maximum: usize,
}
fn object(row: &Value) -> Value {
    value!({"path":row["path"],"id":row["id"],"uuid":row["uuid"],"parent_uuid":row["parent_uuid"]})
}
fn select(original: &Value, deleted: &Value) -> Result<Selection> {
    let id = crate::recovery_records::text(deleted, "id")?;
    crate::root_retirement_record::validate(deleted, id)?;
    require(
        deleted["phase"] == "deleted" && original["records"]["root_retirement"][id] == *deleted,
        "finish requires the exact originally observed deleted receipt",
    )?;
    let records = &original["records"];
    let root = deleted["targets"].as_array().unwrap().last().unwrap();
    let identity = object(root);
    let births = records["births"]
        .as_object()
        .ok_or_else(|| Error("original finish births missing".into()))?;
    let activations = records["activations"]
        .as_object()
        .ok_or_else(|| Error("original finish activations missing".into()))?;
    let publisher_owners = births
        .iter()
        .filter(|(_, row)| row["root"]["uuid"] == root["uuid"])
        .collect::<Vec<_>>();
    let activation_owners = activations
        .iter()
        .filter(|(_, row)| {
            row["phase"] == "adopted" && row["superseded"]["identity"]["uuid"] == root["uuid"]
        })
        .collect::<Vec<_>>();
    let birth = crate::recovery_records::text(deleted, "birth")?;
    if let Some(activation) = birth.strip_prefix("superseded-") {
        require(
            publisher_owners.is_empty() && activation_owners.len() == 1,
            "deleted superseded Root ownership is ambiguous",
        )?;
        let (owner, row) = activation_owners[0];
        crate::recovery_activation::validate(row, owner)?;
        let job = records["jobs"]
            .get(activation)
            .ok_or_else(|| Error("original finish activation job missing".into()))?;
        require(
            owner == activation
                && row["superseded"]["identity"] == identity
                && row["superseded"]["legacy_detached"] == true
                && *job == row["intent"]["job"]
                && job["phase"] == "staged",
            "deleted Root differs from original adopted detached activation/job",
        )?;
        let mut next = row.clone();
        next["superseded"]["retired"] = value!(true);
        crate::recovery_activation::validate(&next, owner)?;
        Ok(Selection {
            folder: "recovery-activations",
            id: activation.into(),
            before: row.clone(),
            next,
            maximum: crate::recovery_journal::Kind::Activations.maximum(),
        })
    } else {
        require(
            publisher_owners.len() == 1 && activation_owners.is_empty(),
            "deleted publisher Root ownership is ambiguous",
        )?;
        let (owner, row) = publisher_owners[0];
        crate::birth::validate(
            row,
            owner,
            crate::recovery_records::text(deleted, "filesystem_uuid")?,
        )?;
        let history = value!({"role":"history-store","path":row["history"]["path"],"id":row["history"]["id"],
            "uuid":row["history"]["uuid"],"parent_uuid":row["history"]["parent_uuid"]});
        let last = value!({"role":"root-subvolume","path":row["root"]["path"],"id":row["root"]["id"],
            "uuid":row["root"]["uuid"],"parent_uuid":row["root"]["parent_uuid"]});
        require(
            owner == birth
                && matches!(row["phase"].as_str(), Some("ready" | "retired"))
                && row["root"] == identity
                && deleted["targets"] == value!([history, last]),
            "deleted Root/history differ from exact original publisher birth",
        )?;
        let mut next = row.clone();
        next["phase"] = value!("retired");
        crate::birth::validate(
            &next,
            owner,
            crate::recovery_records::text(deleted, "filesystem_uuid")?,
        )?;
        Ok(Selection {
            folder: "root-births",
            id: birth.into(),
            before: row.clone(),
            next,
            maximum: crate::birth_runtime::MAX_RECORDS,
        })
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn flags(file: &File) -> Result<i32> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original finish read-only descriptor required",
    )?;
    Ok(flags)
}
pub struct Original<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    references: &'a Observation<'a>,
    inventory: &'a Inventory<'a>,
    receipt: Record,
    record: Value,
    selection: Selection,
    parent: File,
    epoch: files::FileIdentity,
    parent_flags: i32,
    names: BTreeSet<std::ffi::OsString>,
    origin: Record,
    origin_flags: i32,
}
impl<'a> Original<'a> {
    pub fn observe(
        guard: &'a Guard,
        top: &'a TopMount,
        lock: &'a files::Lock,
        references: &'a Observation<'a>,
        inventory: &'a Inventory<'a>,
        journal: &Journal<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        journal.require_original_source(guard, lock)?;
        references.require_original_source(guard, lock, authorize)?;
        inventory.require_original_source(guard, top, lock, authorize)?;
        inventory.require_deleted(journal, authorize)?;
        let receipt = journal.duplicate_observation()?;
        let record = receipt.value()?.clone();
        let selection = select(references.original(authorize)?, &record)?;
        let parent =
            files::directory_relative(guard.control(), Path::new(selection.folder), Some(0))?;
        let epoch = files::identity(&parent.metadata()?);
        let parent_flags = flags(&parent)?;
        let names = files::directory_names(&parent, selection.maximum)?
            .into_iter()
            .collect();
        let origin = Record::open(
            &parent,
            Path::new(&format!("{}.json", selection.id)),
            crate::catalog::MAX_CATALOG,
            guard.control_mount_id(),
        )?;
        let origin_flags = flags(origin.descriptor()?)?;
        require(
            origin.value()? == &selection.before,
            "actual original finish origin differs from full reference family",
        )?;
        let result = Self {
            guard,
            lock,
            references,
            inventory,
            receipt,
            record,
            selection,
            parent,
            epoch,
            parent_flags,
            names,
            origin,
            origin_flags,
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.references
            .require_original_source(self.guard, self.lock, authorize)?;
        self.inventory.recheck(authorize)?;
        self.receipt.recheck()?;
        require(
            self.receipt.value()? == &self.record,
            "original deleted receipt changed",
        )?;
        self.inventory
            .require_deleted_record(&self.receipt, authorize)?;
        let selected = select(self.references.original(authorize)?, &self.record)?;
        require(
            selected.folder == self.selection.folder
                && selected.id == self.selection.id
                && selected.before == self.selection.before
                && selected.next == self.selection.next,
            "original finish ownership changed",
        )?;
        let named = files::directory_relative(
            self.guard.control(),
            Path::new(self.selection.folder),
            Some(0),
        )?;
        require(
            files::identity(&self.parent.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.parent)? == self.parent_flags
                && mount_identity::id(self.parent.as_fd(), true)? == self.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == self.guard.control_mount_id()
                && files::directory_names(&self.parent, self.selection.maximum)?
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    == self.names
                && flags(self.origin.descriptor()?)? == self.origin_flags
                && self.origin.value()? == &self.selection.before,
            "original finish origin directory/record changed/replaced/covered",
        )?;
        self.origin.recheck()?;
        self.receipt.recheck()?;
        self.inventory.recheck(authorize)?;
        authorize()
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            value!({"filesystem_uuid":self.record["filesystem_uuid"],"plan_sha256":self.record["plan_sha256"],
            "receipt":self.record,"origin_folder":self.selection.folder,"origin_id":self.selection.id,
            "origin_before_sha256":json::fingerprint(&self.selection.before)?,"origin_next_sha256":json::fingerprint(&self.selection.next)?,
            "origin_epoch":self.origin.evidence()?,"origin_flags":self.origin_flags,"parent_epoch":self.epoch,"parent_flags":self.parent_flags,
            "targets_absent":true,"mutation_authorized":false,"deletion_authorized":false}),
        )
    }
}

/// A single consumed original observation produces retirement metadata only.
/// It cannot be reconstructed from a retired row or authorize offline deletion.
pub struct Published<'a> {
    original: Original<'a>,
    predecessor: Option<crate::control_record::Predecessor>,
    before_epoch: files::FileIdentity,
    after_epoch: files::FileIdentity,
    others: BTreeMap<String, Record>,
    successor_flags: i32,
}
impl<'a> Original<'a> {
    pub fn publish(mut self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Published<'a>> {
        self.recheck(authorize)?;
        let mut others = BTreeMap::new();
        for name in &self.names {
            let name = name
                .to_str()
                .ok_or_else(|| Error("finish origin filename encoding".into()))?;
            let id = name
                .strip_suffix(".json")
                .ok_or_else(|| Error("interrupted finish origin directory".into()))?;
            crate::identity::safe_id(id)?;
            if id != self.selection.id {
                others.insert(
                    id.to_owned(),
                    Record::open(
                        &self.parent,
                        Path::new(name),
                        crate::catalog::MAX_CATALOG,
                        self.guard.control_mount_id(),
                    )?,
                );
            }
        }
        self.recheck(authorize)?;
        for row in others.values() {
            row.recheck()?;
        }
        let before_epoch = self.epoch;
        let predecessor = if self.selection.before == self.selection.next {
            None
        } else {
            Some(self.origin.replace_with_predecessor(&self.selection.next)?)
        };
        let after_epoch = files::identity(&self.parent.metadata()?);
        require(
            (
                before_epoch.0,
                before_epoch.1,
                before_epoch.7,
                before_epoch.8,
                before_epoch.9,
                before_epoch.10,
            ) == (
                after_epoch.0,
                after_epoch.1,
                after_epoch.7,
                after_epoch.8,
                after_epoch.9,
                after_epoch.10,
            ),
            "finish publication changed original directory identity/protection",
        )?;
        let successor_flags = flags(self.origin.descriptor()?)?;
        let result = Published {
            original: self,
            predecessor,
            before_epoch,
            after_epoch,
            others,
            successor_flags,
        };
        result.recheck_owned(authorize)?;
        result
            .original
            .references
            .verify_finished_origin(&result, authorize)?;
        result.recheck_owned(authorize)?;
        Ok(result)
    }
}
impl Published<'_> {
    pub(crate) fn require_source(&self, guard: &Guard, lock: &files::Lock) -> Result<()> {
        require(
            std::ptr::eq(self.original.guard, guard) && std::ptr::eq(self.original.lock, lock),
            "finish belongs to another original guard/lock",
        )
    }
    pub(crate) fn folder(&self) -> &str {
        self.original.selection.folder
    }
    pub(crate) fn id(&self) -> &str {
        &self.original.selection.id
    }
    pub(crate) fn before(&self) -> &Value {
        &self.original.selection.before
    }
    pub(crate) fn next(&self) -> &Value {
        &self.original.selection.next
    }
    pub(crate) fn require_original_directory(
        &self,
        parent: &File,
        before: files::FileIdentity,
    ) -> Result<()> {
        require(
            before == self.before_epoch
                && files::identity(&parent.metadata()?) == self.after_epoch
                && flags(parent)? == self.original.parent_flags
                && mount_identity::id(parent.as_fd(), true)?
                    == self.original.guard.control_mount_id(),
            "finish producer differs from original registry directory",
        )
    }
    pub(crate) fn require_original_member(
        &self,
        old: &crate::control_record::Retained,
    ) -> Result<()> {
        match &self.predecessor {
            Some(previous) => previous.require_original_retained(old),
            None => {
                let entry = enzimos_platform::directory_entry::Entry::observe(
                    &self.original.parent,
                    Path::new(&format!("{}.json", self.id())),
                )?;
                old.matches_entry(&entry)?;
                entry.matches(self.original.origin.descriptor()?)?;
                require(
                    old.value()? == self.before(),
                    "unchanged retired origin differs",
                )?;
                old.recheck()
            }
        }
    }
    pub(crate) fn recheck_owned(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_owned_inner(None, authorize)
    }
    pub(crate) fn recheck_completed(
        &self,
        receipt: &crate::root_retirement_online_journal::Completed<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_source(self.original.guard, self.original.lock)?;
        self.recheck_owned_inner(Some(receipt), authorize)
    }
    fn recheck_owned_inner(
        &self,
        completed: Option<&crate::root_retirement_online_journal::Completed<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        let original = &self.original;
        original.guard.recheck()?;
        original.lock.recheck()?;
        match completed {
            Some(receipt) => {
                receipt.require_original_observation(&original.receipt)?;
                require(
                    receipt.before()? == &original.record,
                    "finish completion predecessor differs",
                )?;
                original.inventory.require_completed(receipt, authorize)?;
            }
            None => {
                original.receipt.recheck()?;
                original
                    .inventory
                    .require_deleted_record(&original.receipt, authorize)?;
                require(
                    original.receipt.value()? == &original.record,
                    "finish deleted receipt changed",
                )?;
            }
        }
        let named =
            files::directory_relative(original.guard.control(), Path::new(self.folder()), Some(0))?;
        require(
            files::identity(&original.parent.metadata()?) == self.after_epoch
                && files::identity(&named.metadata()?) == self.after_epoch
                && flags(&original.parent)? == original.parent_flags
                && mount_identity::id(named.as_fd(), true)? == original.guard.control_mount_id()
                && mount_identity::id(original.parent.as_fd(), true)?
                    == original.guard.control_mount_id()
                && files::directory_names(&original.parent, original.selection.maximum)?
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    == original.names,
            "owned finish directory changed/replaced/covered",
        )?;
        if let Some(previous) = &self.predecessor {
            previous.recheck()?;
        }
        for row in self.others.values() {
            row.recheck()?;
        }
        original.origin.recheck()?;
        require(
            original.origin.value()? == self.next()
                && flags(original.origin.descriptor()?)? == self.successor_flags,
            "owned finish metadata successor changed",
        )?;
        original.inventory.recheck(authorize)?;
        authorize()
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_owned(authorize)?;
        self.original
            .references
            .verify_finished_origin(self, authorize)?;
        self.recheck_owned(authorize)
    }
}

/// Online completion consumes all original mutation actors. Errors retain their
/// durable state and never replay a publication, reconstruct a proof or roll back.
pub fn finish<'a>(
    original: Original<'a>,
    journal: Journal<'a>,
    cleanup: Option<crate::boot_retirement_context::finish::Cleanup<'a, 'a>>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    original.recheck(authorize)?;
    journal.require_original_source(original.guard, original.lock)?;
    require(
        journal.record()? == &original.record,
        "finish journal differs from original deleted selection",
    )?;
    require(
        original.record.get("coordinator").is_some() == cleanup.is_some(),
        "finish requires actual coordinator cleanup iff receipt contains coordinator",
    )?;
    if let Some(actor) = &cleanup {
        actor.require_source(original.guard, original.lock, &original.record, authorize)?;
    }
    let origin = original.publish(authorize)?;
    if let Some(actor) = &cleanup {
        actor.recheck_after_origin(&origin, authorize)?;
    }
    origin.recheck(authorize)?;
    let receipt = journal.publish_complete(&mut || {
        origin
            .original
            .references
            .completion_publication_barrier(&origin, authorize)
    })?;
    origin
        .original
        .references
        .verify_finished_completion(&origin, &receipt, authorize)?;
    origin.recheck_completed(&receipt, authorize)?;
    if let Some(actor) = &cleanup {
        actor.recheck_completed(&origin, &receipt, authorize)?;
    }
    origin
        .original
        .inventory
        .require_completed(&receipt, authorize)?;
    authorize()?;
    receipt.recheck()?;
    Ok(value!({"id":receipt.record()?["id"],"status":"root-retirement-complete"}))
}

/// Root CLI uses complete standalone backend references, with no job exemption.
pub fn finish_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    let journal = Journal::observe(
        guard,
        lock,
        id,
        crate::root_retirement_online_journal::Phase::Deleted,
    )?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let references = Observation::observe_journal(guard, lock, &journal, authorize)?;
        let inventory = Inventory::observe(guard, &top, lock, authorize)?;
        let origin = Original::observe(
            guard,
            &top,
            lock,
            &references,
            &inventory,
            &journal,
            authorize,
        )?;
        let cleanup = if journal.record()?.get("coordinator").is_some() {
            let boot = crate::root_retirement_online_boot::Boot::observe_journal(
                guard,
                lock,
                &references,
                &journal,
                authorize,
            )?;
            let firmware = if crate::recovery_activation_runtime::efi_guard()? {
                Some(
                    crate::root_retirement_firmware_publication::finish::Original::observe(
                        guard, lock, &journal, &inventory, authorize,
                    )?
                    .clear(&inventory, authorize)?,
                )
            } else {
                None
            };
            Some(boot.finish_loaders(&journal, &inventory, firmware, authorize)?)
        } else {
            None
        };
        finish(origin, journal, cleanup, authorize)
    })();
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(mut value), Ok(())) => {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            value["source_snapshot_left_to_snapper"] = value!(true);
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root finish inspection cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}
