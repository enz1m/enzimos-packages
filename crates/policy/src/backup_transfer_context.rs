// SPDX-License-Identifier: MIT
//! Original live transfer inputs. This observes no worker execution or cleanup.
use crate::{
    backup_admission::Repository, backup_archive_inputs::Inputs, backup_credential::Credential,
    backup_destination::Destination, backup_repository_header::Header,
    backup_restic_runtime::Image, backup_transfer_caller::Caller,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::fd::{AsFd, BorrowedFd},
};

pub struct Context<'a, 'b, 'c, 's, 'cfg, 'g> {
    inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
    lock: &'a files::Lock,
    destination: &'a Destination<'g>,
    pin: Repository<'a, 'g>,
    credential: Credential,
    caller: Caller,
    image: Image,
    repository: File,
    header: Header,
    original: Value,
}
impl<'a, 'b, 'c, 's, 'cfg, 'g> Context<'a, 'b, 'c, 's, 'cfg, 'g> {
    pub(crate) fn guard(&self) -> &crate::storage_runtime::Guard {
        self.inputs.guard()
    }
    pub(crate) fn require_description(&self, file: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.caller.require_description(file, number)
    }
    /// Retain the exact original backend caller for the separate source offer.
    pub fn caller(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Caller> {
        self.recheck(authorize)?;
        Ok(&self.caller)
    }
    /// Fence the one PID1 start before any service or transient socket exists.
    pub fn enter_launch(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Launch> {
        self.recheck(authorize)?;
        let guard = self.guard();
        let parent = files::ensure_directory_relative(
            guard.control(),
            std::path::Path::new("backup-transfer-launches"),
            0o700,
            0,
        )?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.control_mount_id() && files::directory_names(&parent, 256)?.len() < 256,
            "original transfer launch registry mount/capacity",
        )?;
        self.recheck(authorize)?;
        let value = value!({"schema":1,"kind":"captured-backup-transfer-launch","id":self.original["id"],
            "context_sha256":json::fingerprint(&self.original)?,"phase":"starting",
            "worker_started":false,"backup_complete":false});
        let record = crate::control_record::Retained::create(
            &parent,
            std::path::Path::new(&format!("{}.json", self.original["id"].as_str().unwrap())),
            &value,
            4096,
            mount,
        )?;
        self.recheck(authorize)?;
        Ok(Launch { record, value })
    }
    /// Current native backend plus actual original capture, operation lock and
    /// independently qualified existing repository. No setup-plan adoption.
    pub fn observe(
        inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
        lock: &'a files::Lock,
        destination: &'a Destination<'g>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        inputs.require_original_lock(lock)?;
        require(
            std::ptr::eq(inputs.guard(), destination.storage()),
            "transfer destination must retain original capture guard",
        )?;
        destination.require_free_space()?;
        let pin = Repository::open(destination)?;
        let credential = Credential::open()?;
        credential.binding(inputs.guard())?;
        authorize()?;
        let caller = Caller::current()?;
        let image = Image::open()?;
        let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
        let header = Header::observe(&repository)?;
        let mut this = Self {
            inputs,
            lock,
            destination,
            pin,
            credential,
            caller,
            image,
            repository,
            header,
            original: Value::Null,
        };
        authorize()?;
        this.original = this.current()?;
        crate::backup_transfer_request::context(&this.original)?;
        crate::backup_worker_request::id(this.original["id"].as_str().unwrap_or(""))?;
        this.recheck(authorize)?;
        Ok(this)
    }
    fn current(&self) -> Result<Value> {
        self.inputs.require_original_lock(self.lock)?;
        self.destination.require_free_space()?;
        self.pin.recheck()?;
        self.credential.binding(self.inputs.guard())?;
        self.caller.recheck()?;
        self.header.recheck(&self.repository)?;
        let input = self.inputs.evidence()?;
        let credential = File::from(self.credential.descriptor()?.try_clone_to_owned()?);
        Ok(value!({"schema":1,"role":"backup-transfer-context",
            "id":input["inventory"]["receipt"]["id"],"boot_id":crate::operation::boot_id()?,
            "caller":self.caller.evidence()?,"source":self.inputs.guard().backup_root_binding()?,
            "destination":self.destination.evidence()?,"pin":self.pin.evidence()?,
            "configuration":self.destination.configuration()?.evidence()?,
            "root_directory":crate::backup_worker_scope::directory(self.destination.root_descriptor()?)?,
            "repository_directory":crate::backup_worker_scope::directory(&self.repository)?,
            "operation_lock":{"inode":files::identity(&self.lock.as_file().metadata()?),
                "mount":mount_identity::id(self.lock.as_file().as_fd(), true)?},
            "header":self.header.evidence(&self.repository)?,
            "credential":{"inode":files::identity(&credential.metadata()?),
                "mount":mount_identity::id(credential.as_fd(), true)?},
            "restic":self.image.evidence()?,"input_sha256":json::fingerprint(&input)?,
            "arguments":self.inputs.arguments()?,"source_mounts_admitted":false,
            "transfer_complete":false,"worker_kernel_closed":false,"cleanup_complete":false,
            "backup_complete":false}))
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        require(
            self.current()? == self.original,
            "original transfer context changed; no replacement or replay",
        )
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.original)
    }
    /// Actual retained descriptions only. A worker still needs kernel-stamped
    /// admission, fresh authorization and its own original durable request.
    pub fn descriptors(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BTreeMap<&str, BorrowedFd<'_>>> {
        self.recheck(authorize)?;
        Ok(BTreeMap::from([
            ("caller-image", self.caller.image()?.as_fd()),
            ("caller-pidfd", self.caller.pidfd()?),
            ("repository", self.repository.as_fd()),
            ("root", self.destination.root_descriptor()?.as_fd()),
            (
                "configuration",
                self.destination.configuration()?.descriptor()?.as_fd(),
            ),
            ("pin", self.pin.descriptor()?.as_fd()),
            ("operation-lock", self.lock.as_file().as_fd()),
            ("credential", self.credential.descriptor()?),
            ("restic", self.image.descriptor()?.as_fd()),
        ]))
    }
}

/// Durable starting fence; it cannot be reopened or used to adopt a worker.
pub struct Launch {
    record: crate::control_record::Retained,
    value: Value,
}
impl Launch {
    pub fn recheck(&self) -> Result<()> {
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value,
            "original transfer launch fence changed",
        )
    }
}
