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

/// Where the transfer writes: the mounted backup drive with its pinned
/// repository, or the NAS share with its pinned repository (no drive).
#[allow(
    clippy::large_enum_variant,
    reason = "One value per transfer, never moved in bulk."
)]
enum Target<'a, 'g> {
    Drive {
        destination: &'a Destination<'g>,
        pin: Repository<'a, 'g>,
        credential: Credential,
        repository: File,
        header: Header,
        caller: Caller,
        image: Image,
    },
    /// The share context's own caller and Restic image serve the transfer.
    Share {
        remote: crate::backup_remote_context::Context<'a>,
    },
}
/// Inputs of one backup transfer: capture, lock, destination and caller.
pub struct Context<'a, 'b, 'c, 's, 'cfg, 'g> {
    inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
    lock: &'a files::Lock,
    target: Target<'a, 'g>,
    original: Value,
}
impl<'a, 'b, 'c, 's, 'cfg, 'g> Context<'a, 'b, 'c, 's, 'cfg, 'g> {
    pub(crate) fn guard(&self) -> &crate::storage_runtime::Guard {
        self.inputs.guard()
    }
    fn caller_actor(&self) -> &Caller {
        match &self.target {
            Target::Drive { caller, .. } => caller,
            Target::Share { remote } => remote.caller_actor(),
        }
    }
    fn image_actor(&self) -> &Image {
        match &self.target {
            Target::Drive { image, .. } => image,
            Target::Share { remote } => remote.image_actor(),
        }
    }
    pub(crate) fn require_description(&self, file: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.caller_actor().require_description(file, number)
    }
    /// Retain the exact original backend caller for the separate source offer.
    ///
    /// # Errors
    ///
    /// Fails when the context changed or `authorize` fails.
    pub fn caller(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Caller> {
        self.recheck(authorize)?;
        Ok(self.caller_actor())
    }
    /// Fence the one PID1 start before any service or transient socket exists.
    ///
    /// # Errors
    ///
    /// Fails when the launch registry is unsafe or full, or the context changed.
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
            std::path::Path::new(&format!(
                "{}.json",
                enzimos_platform::json::string(&self.original["id"])?
            )),
            &value,
            4096,
            mount,
        )?;
        self.recheck(authorize)?;
        Ok(Launch { record, value })
    }
    /// Current native backend plus actual original capture, operation lock and
    /// independently qualified existing repository. No setup-plan adoption.
    ///
    /// # Errors
    ///
    /// Fails when the destination does not retain the capture guard, or `authorize` fails.
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
        Self::seal(
            inputs,
            lock,
            Target::Drive {
                destination,
                pin,
                credential,
                repository,
                header,
                caller,
                image,
            },
            authorize,
        )
    }
    /// The same transfer into the pinned NAS share repository, for setups
    /// without a backup drive. The share inputs are the retained originals the
    /// NAS copy uses; an unfinished share rotation is refused.
    ///
    /// # Errors
    /// Changed capture inputs or lock, or share inputs the NAS copy would
    /// also refuse.
    pub fn observe_share(
        inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        inputs.require_original_lock(lock)?;
        let remote =
            crate::backup_remote_context::Context::observe(inputs.guard(), lock, authorize)?;
        Self::seal(inputs, lock, Target::Share { remote }, authorize)
    }
    fn seal(
        inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
        lock: &'a files::Lock,
        target: Target<'a, 'g>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        let mut this = Self {
            inputs,
            lock,
            target,
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
        let (destination, pin, credential, repository, header, caller, image) = match &self.target {
            Target::Drive {
                destination,
                pin,
                credential,
                repository,
                header,
                caller,
                image,
            } => (
                destination,
                pin,
                credential,
                repository,
                header,
                caller,
                image,
            ),
            Target::Share { remote } => return self.current_share(remote),
        };
        destination.require_free_space()?;
        pin.recheck()?;
        credential.binding(self.inputs.guard())?;
        caller.recheck()?;
        header.recheck(repository)?;
        let input = self.inputs.evidence()?;
        let credential = File::from(credential.descriptor()?.try_clone_to_owned()?);
        Ok(value!({"schema":1,"role":"backup-transfer-context",
            "id":input["inventory"]["receipt"]["id"],"boot_id":crate::operation::boot_id()?,
            "caller":caller.evidence()?,"source":self.inputs.guard().backup_root_binding()?,
            "destination":destination.evidence()?,"pin":pin.evidence()?,
            "configuration":destination.configuration()?.evidence()?,
            "root_directory":crate::backup_worker_scope::directory(destination.root_descriptor()?)?,
            "repository_directory":crate::backup_worker_scope::directory(repository)?,
            "operation_lock":{"inode":files::identity(&self.lock.as_file().metadata()?),
                "mount":mount_identity::id(self.lock.as_file().as_fd(), true)?},
            "header":header.evidence(repository)?,
            "credential":{"inode":files::identity(&credential.metadata()?),
                "mount":mount_identity::id(credential.as_fd(), true)?},
            "restic":image.evidence()?,"input_sha256":json::fingerprint(&input)?,
            "arguments":self.inputs.arguments()?,"source_mounts_admitted":false,
            "transfer_complete":false,"worker_kernel_closed":false,"cleanup_complete":false,
            "backup_complete":false}))
    }
    fn current_share(&self, remote: &crate::backup_remote_context::Context<'a>) -> Result<Value> {
        let share = remote.evidence(&mut || Ok(()))?.clone();
        let input = self.inputs.evidence()?;
        let guard = self.inputs.guard();
        Ok(value!({"schema":1,"role":"backup-transfer-share-context",
            "id":input["inventory"]["receipt"]["id"],"boot_id":crate::operation::boot_id()?,
            "caller":share["caller"],"source":guard.backup_root_binding()?,
            "share":share,"root_control":crate::backup_worker_scope::directory(guard.control())?,
            "operation_lock":{"inode":files::identity(&self.lock.as_file().metadata()?),
                "mount":mount_identity::id(self.lock.as_file().as_fd(), true)?},
            "restic":share["restic"],"input_sha256":json::fingerprint(&input)?,
            "arguments":self.inputs.arguments()?,"source_mounts_admitted":false,
            "transfer_complete":false,"worker_kernel_closed":false,"cleanup_complete":false,
            "backup_complete":false}))
    }
    /// Verify the inputs are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when they changed or `authorize` fails.
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        enzimos_platform::recheck_scope::evaluation(|| {
            authorize()?;
            require(
                self.current()? == self.original,
                "original transfer context changed; no replacement or replay",
            )
        })
    }
    /// JSON evidence for the transfer context.
    ///
    /// # Errors
    ///
    /// Fails when the context changed or `authorize` fails.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        enzimos_platform::recheck_scope::evaluation(|| {
            self.recheck(authorize)?;
            Ok(&self.original)
        })
    }
    /// Actual retained descriptions only. A worker still needs kernel-stamped
    /// admission, fresh authorization and its own original durable request.
    pub(crate) fn descriptors(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BTreeMap<&str, BorrowedFd<'_>>> {
        enzimos_platform::recheck_scope::evaluation(|| {
            self.recheck(authorize)?;
            let common = [
                ("caller-image", self.caller_actor().image()?.as_fd()),
                ("caller-pidfd", self.caller_actor().pidfd()?),
                ("operation-lock", self.lock.as_file().as_fd()),
                ("restic", self.image_actor().descriptor()?.as_fd()),
            ];
            let mut map = BTreeMap::from(common);
            match &self.target {
                Target::Drive {
                    destination,
                    pin,
                    credential,
                    repository,
                    ..
                } => map.extend([
                    ("repository", repository.as_fd()),
                    ("root", destination.root_descriptor()?.as_fd()),
                    (
                        "configuration",
                        destination.configuration()?.descriptor()?.as_fd(),
                    ),
                    ("pin", pin.descriptor()?.as_fd()),
                    ("credential", credential.descriptor()?),
                ]),
                Target::Share { remote } => {
                    let share = remote.descriptors(&mut || Ok(()))?;
                    for role in [
                        "remote-configuration",
                        "remote-password",
                        "remote-share-password",
                        "remote-pin",
                        "root-control",
                    ] {
                        map.insert(role, share[role]);
                    }
                }
            }
            Ok(map)
        })
    }
}

/// Durable starting fence; it cannot be reopened or used to adopt a worker.
pub struct Launch {
    record: crate::control_record::Retained,
    value: Value,
}
impl Launch {
    /// Verify the launch fence is unchanged.
    ///
    /// # Errors
    ///
    /// Fails when it changed.
    pub fn recheck(&self) -> Result<()> {
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value,
            "original transfer launch fence changed",
        )
    }
}
