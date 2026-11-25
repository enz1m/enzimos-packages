// SPDX-License-Identifier: MIT
//! Original newly published credential and completion receipt; metadata only.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "original credential publication parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
/// Cannot be reconstructed by reading an existing credential or receipt.
/// The producer passes only handles from its own completed publication.
pub struct Published {
    source: crate::transition_idle::Snapshot,
    parent: File,
    parent_shape: Shape,
    file: File,
    identity: files::FileIdentity,
    receipt: File,
    receipt_identity: files::FileIdentity,
    bytes: Vec<u8>,
    owner: u32,
}
impl Published {
    pub(crate) fn new(
        source: crate::transition_idle::Snapshot,
        parent: File,
        file: File,
        identity: files::FileIdentity,
        receipt: File,
        bytes: Vec<u8>,
        owner: u32,
    ) -> Result<Self> {
        let this = Self {
            parent_shape: shape(&parent)?,
            receipt_identity: files::identity(&receipt.metadata()?),
            source,
            parent,
            file,
            identity,
            receipt,
            bytes,
            owner,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.source.recheck()?;
        let guard = &self.source.guard;
        crate::backup_publication_identity::recheck(
            &self.parent,
            "backup.password",
            &self.file,
            self.identity,
            guard.root_mount_id(),
            0,
        )?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new("backup.password"))?;
        let receipt = files::open_relative(guard.control(), Path::new("backup-secret-input.json"))?;
        let record = json::decode(&self.bytes, 32768)?;
        crate::backup_secret_persistence::validate(&record)?;
        require(
            record["phase"] == "complete"
                && record["owner_uid"] == self.owner
                && record["root_binding"] == guard.backup_root_binding()?
                && record["credential_identity"]
                    == crate::backup_secret_persistence::publication(
                        &self.file,
                        self.identity.2 as usize,
                        guard,
                    )?
                && shape(&parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == guard.root_mount_id()
                && mount_identity::id(self.parent.as_fd(), true)? == guard.root_mount_id()
                && mount_identity::id(named.as_fd(), true)? == guard.root_mount_id()
                && mount_identity::id(self.file.as_fd(), true)? == guard.root_mount_id()
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.receipt.metadata()?) == self.receipt_identity
                && files::identity(&receipt.metadata()?) == self.receipt_identity
                && mount_identity::id(receipt.as_fd(), true)? == guard.control_mount_id()
                && mount_identity::id(self.receipt.as_fd(), true)? == guard.control_mount_id()
                && files::read_file(&self.receipt, 32768, Some(0), true)? == self.bytes,
            "original newly published credential/receipt changed or replaced",
        )
    }
    pub(crate) fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.file.as_fd())
    }
    pub fn public_result(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"credential_stored":true,"repository_enrolled":false,"recovery_key_exported":false,"automatic_backup_enabled":false}),
        )
    }
    pub(crate) fn source(&self) -> &crate::storage_runtime::Guard {
        &self.source.guard
    }
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
    /// Failure rollback of an incomplete setup: remove exactly this run's
    /// credential and its completion receipt. The caller proves that no
    /// repository was created and no pin was published.
    pub fn retract(&self, lock: &files::Lock) -> Result<()> {
        lock.recheck()?;
        self.recheck()?;
        crate::backup_publication_identity::retract(&self.parent, c"backup.password")?;
        crate::backup_publication_identity::retract(
            self.source.guard.control(),
            c"backup-secret-input.json",
        )?;
        lock.recheck()
    }
    pub fn binding(&self) -> Result<Value> {
        self.recheck()?;
        crate::backup_secret_persistence::publication(
            &self.file,
            self.identity.2 as usize,
            &self.source.guard,
        )
    }
}
