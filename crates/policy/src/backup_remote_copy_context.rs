// SPDX-License-Identifier: MIT
//! Original local and remote copy inputs, retained together under one Root lock.
use crate::{
    backup_admission::Repository, backup_credential::Credential, backup_destination::Destination,
    backup_remote_context, backup_repository_header::Header, storage_runtime::Guard,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::fd::{AsFd, BorrowedFd},
    sync::Arc,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Replicate,
    Retrieve,
}
impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Replicate => "replicate",
            Self::Retrieve => "retrieve",
        }
    }
}
pub struct Context<'a, 'g> {
    guard: &'g Guard,
    lock: &'a files::Lock,
    destination: &'a Destination<'g>,
    remote: backup_remote_context::Context<'a>,
    credential: Credential,
    password: File,
    repository: File,
    header: Header,
    pin: Repository<'a, 'g>,
    direction: Direction,
    snapshot: String,
    receipt_id: Option<String>,
    id: String,
    actor: Arc<()>,
    original: Value,
}
impl<'a, 'g: 'a> Context<'a, 'g> {
    pub fn observe(
        guard: &'g Guard,
        lock: &'a files::Lock,
        destination: &'a Destination<'g>,
        direction: Direction,
        snapshot: &str,
        id: &str,
        receipt_id: Option<&str>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::sha(snapshot)?;
        crate::backup_worker_request::id(id)?;
        if direction == Direction::Retrieve {
            crate::identity::safe_id(receipt_id.unwrap_or(""))?;
        } else {
            require(
                receipt_id.is_none(),
                "replication has no retrieval receipt ID",
            )?;
        }
        authorize()?;
        lock.recheck()?;
        // Best effort under the held lock: the registries' own bounds decide.
        let _ =
            crate::restore_history::retire_launches(guard, lock, crate::restore_history::REMOTE);
        let _ = crate::restore_history::retire_retrievals(guard, lock);
        require(
            std::ptr::eq(destination.storage(), guard),
            "remote copy local storage actor differs",
        )?;
        destination.require_writable()?;
        let remote = backup_remote_context::Context::observe(guard, lock, authorize)?;
        let credential = Credential::open()?;
        credential.binding(guard)?;
        let password = File::from(credential.descriptor()?.try_clone_to_owned()?);
        let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
        let header = Header::observe(&repository)?;
        let pin = Repository::open(destination)?;
        let mut this = Self {
            guard,
            lock,
            destination,
            remote,
            credential,
            password,
            repository,
            header,
            pin,
            direction,
            snapshot: snapshot.into(),
            id: id.into(),
            receipt_id: receipt_id.map(str::to_owned),
            actor: Arc::new(()),
            original: Value::Null,
        };
        this.original = this.current(authorize)?;
        crate::backup_remote_request::context(&this.original)?;
        require(
            enzimos_platform::json::canonical(&this.original)?.len() <= 65536,
            "remote copy context bound",
        )?;
        this.descriptors(authorize)?;
        Ok(this)
    }
    fn current(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.destination.require_writable()?;
        self.pin.recheck()?;
        self.header.recheck(&self.repository)?;
        self.credential.binding(self.guard)?;
        let file = |f: &File| -> Result<Value> {
            Ok(
                value!({"inode":files::identity(&f.metadata()?),"mount":mount_identity::id(f.as_fd(),true)?}),
            )
        };
        let credential = File::from(self.credential.descriptor()?.try_clone_to_owned()?);
        require(
            file(&credential)? == file(&self.password)?,
            "remote copy original local credential changed",
        )?;
        Ok(
            value!({"schema":1,"role":"remote-copy-context","id":self.id,"receipt_id":self.receipt_id,"direction":self.direction.name(),"snapshot":self.snapshot,
        "remote":self.remote.evidence(authorize)?,"source":self.guard.backup_root_binding()?,"destination":self.destination.evidence()?,
        "local_configuration":self.destination.configuration()?.evidence()?,"local_pin":self.pin.evidence()?,
        "local_root":crate::backup_worker_scope::directory(self.destination.root_descriptor()?)?,"local_repository":crate::backup_worker_scope::directory(&self.repository)?,
        "local_header":self.header.evidence(&self.repository)?,"local_credential":file(&self.password)?,"operation_lock":file(self.lock.as_file())?,
        "remote_authenticated":false,"copy_complete":false,"worker_closed":false,"receipt_complete":false,"scheduler_enabled":false,"automatic_retry":false}),
        )
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        require(
            self.current(authorize)? == self.original,
            "original remote copy context changed; no replacement adoption",
        )
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.original)
    }
    /// Fourteen actual input descriptions. A sealed request and original one-use
    /// intent add two descriptions at handoff; neither is fabricated here.
    pub fn descriptors(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BTreeMap<&'static str, BorrowedFd<'_>>> {
        self.recheck(authorize)?;
        let mut values = self.remote.descriptors(authorize)?;
        for (role, fd) in [
            ("local-root", self.destination.root_descriptor()?.as_fd()),
            ("local-repository", self.repository.as_fd()),
            ("local-credential", self.password.as_fd()),
            (
                "local-configuration",
                self.destination.configuration()?.descriptor()?.as_fd(),
            ),
            ("local-pin", self.pin.descriptor()?.as_fd()),
        ] {
            require(
                values.insert(role, fd).is_none(),
                "remote copy role collision",
            )?;
        }
        require(
            values.len() == 14,
            "exact original remote copy descriptor count",
        )?;
        let mut identities = std::collections::BTreeSet::new();
        for (role, fd) in &values {
            if *role == "caller-pidfd" {
                continue;
            }
            let file = File::from(fd.try_clone_to_owned()?);
            let epoch = files::identity(&file.metadata()?);
            require(
                identities.insert((epoch.0, epoch.1)),
                "remote copy descriptors alias one original inode",
            )?;
        }
        self.recheck(authorize)?;
        Ok(values)
    }
    pub(crate) fn legacy_binding(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.recheck(authorize)?;
        crate::backup_destination::legacy_binding(&self.destination.evidence()?, self.guard)
    }
    pub(crate) fn guard(&self) -> &'g Guard {
        self.guard
    }
    pub(crate) fn actor_identity(&self) -> Arc<()> {
        Arc::clone(&self.actor)
    }
    pub fn require_description(&self, fd: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.remote.require_description(fd, number)
    }
    /// Comparing original in-memory actors is intentionally distinct from
    /// comparing their JSON evidence or inode numbers.
    pub fn same_actor(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.actor, &other.actor)
    }
}
