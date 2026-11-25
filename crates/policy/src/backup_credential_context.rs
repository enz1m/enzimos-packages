// SPDX-License-Identifier: MIT
//! Original existing-repository credential review inputs; no execution authority.
use crate::{
    backup_admission::Repository, backup_credential_candidate::Candidate,
    backup_credential_journal::Enrollment, backup_credential_record,
    backup_destination::Destination, backup_repository_header::Header,
    backup_restic_runtime::Image, backup_transfer_caller::Caller, control_record::Retained,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const FOLDER: &str = "credential-review-launches";
/// Inputs of one credential review of an existing repository.
pub struct Context<'a, 'g> {
    guard: &'g Guard,
    lock: &'a files::Lock,
    enrollment: &'a Enrollment<'g>,
    candidate: &'a Candidate<'g>,
    destination: &'a Destination<'g>,
    pin: Repository<'a, 'g>,
    caller: Caller,
    image: Image,
    repository: File,
    current: File,
    next: File,
    header: Header,
    original: Value,
    id: String,
}
impl<'a, 'g> Context<'a, 'g> {
    pub(crate) fn guard(&self) -> &'g Guard {
        self.guard
    }
    pub(crate) fn require_description(&self, file: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.caller.require_description(file, number)
    }

    /// Observe the review inputs.
    ///
    /// # Errors
    ///
    /// Fails when the destination storage differs, a bound is exceeded, or `authorize` fails.
    pub fn observe(
        guard: &'g Guard,
        lock: &'a files::Lock,
        enrollment: &'a Enrollment<'g>,
        candidate: &'a Candidate<'g>,
        destination: &'a Destination<'g>,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::backup_worker_request::id(id)?;
        authorize()?;
        enrollment.require_original(guard, lock)?;
        enrollment.require_input(candidate)?;
        require(
            std::ptr::eq(destination.storage(), guard),
            "credential destination storage actor differs",
        )?;
        destination.require_writable()?;
        let pin = Repository::open(destination)?;
        let caller = Caller::current()?;
        let image = Image::open()?;
        let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
        let header = Header::observe(&repository)?;
        let (current, next) = candidate.descriptors(guard)?;
        let current = File::from(current.try_clone_to_owned()?);
        let next = File::from(next.try_clone_to_owned()?);
        let mut this = Self {
            guard,
            lock,
            enrollment,
            candidate,
            destination,
            pin,
            caller,
            image,
            repository,
            current,
            next,
            header,
            original: Value::Null,
            id: id.into(),
        };
        authorize()?;
        this.original = this.current()?;
        crate::backup_credential_request::context(&this.original)?;
        require(
            json::canonical(&this.original)?.len() <= 65536,
            "credential review context bound",
        )?;
        this.recheck(authorize)?;
        Ok(this)
    }
    fn current(&self) -> Result<Value> {
        self.enrollment.require_original(self.guard, self.lock)?;
        self.enrollment.require_input(self.candidate)?;
        self.destination.require_writable()?;
        self.pin.recheck()?;
        self.caller.recheck()?;
        self.header.recheck(&self.repository)?;
        let enrollment = self.enrollment.evidence()?;
        let candidate = self.candidate.evidence()?;
        let pin = self.destination.expected_pin()?;
        let selected = self.enrollment.record()?;
        let stable = backup_credential_record::stable_binding(&selected["repository_binding"])?;
        require(
            stable
                == value!({"filesystem_uuid":pin["filesystem_uuid"],"repository_sha256":pin["repository_sha256"]}),
            "credential review repository differs from original enrollment",
        )?;
        let file = |f: &File| -> Result<Value> {
            Ok(
                value!({"inode":files::identity(&f.metadata()?),"mount":mount_identity::id(f.as_fd(),true)?}),
            )
        };
        require(
            file(&self.current)?["inode"] == candidate["current_file"]
                && file(&self.next)?["inode"] == candidate["next_file"],
            "credential context lost original input epochs",
        )?;
        Ok(
            value!({"schema":1,"role":"credential-review-context","id":self.id,"boot_id":crate::operation::boot_id()?,
            "caller":self.caller.evidence()?,"source":self.guard.backup_root_binding()?,
            "enrollment":{"id":selected["id"],"file":enrollment["file"],"bytes_sha256":enrollment["bytes_sha256"],
                "directory":enrollment["directory"],"mount":enrollment["mount"]},
            "input_identity":candidate["input_identity"],"destination":self.destination.evidence()?,
            "configuration":self.destination.configuration()?.evidence()?,"pin":self.pin.evidence()?,
            "root_directory":crate::backup_worker_scope::directory(self.destination.root_descriptor()?)?,
            "repository_directory":crate::backup_worker_scope::directory(&self.repository)?,
            "current_credential":file(&self.current)?,"next_credential":file(&self.next)?,
            "restic":self.image.evidence()?,"header":self.header.evidence(&self.repository)?,
            "operation_lock":file(self.lock.as_file())?,"worker_closed":false,"review_complete":false,
            "key_creation_replayed":false,"old_access_revoked":false,"credential_exported":false}),
        )
    }
    pub(crate) fn enrollment_record(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&Value> {
        self.recheck(authorize)?;
        self.enrollment.record()
    }
    pub(crate) fn enrollment_actor(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<std::sync::Arc<()>> {
        self.recheck(authorize)?;
        self.enrollment.actor_identity()
    }
    /// Verify the inputs are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when they changed or `authorize` fails.
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        require(
            self.current()? == self.original,
            "original credential review context changed; no adoption/replay",
        )
    }
    /// JSON evidence for the review context.
    ///
    /// # Errors
    ///
    /// Fails on [`Context::recheck`].
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.original)
    }
    /// Only actual retained descriptions; a future worker reservation must still
    /// prove each sender OFD and durably enter send before handing them off.
    pub(crate) fn descriptors(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BTreeMap<&str, BorrowedFd<'_>>> {
        self.recheck(authorize)?;
        let values = BTreeMap::from([
            ("caller-image", self.caller.image()?.as_fd()),
            ("caller-pidfd", self.caller.pidfd()?),
            ("root", self.destination.root_descriptor()?.as_fd()),
            ("repository", self.repository.as_fd()),
            ("current-credential", self.current.as_fd()),
            ("next-credential", self.next.as_fd()),
            ("restic", self.image.descriptor()?.as_fd()),
            (
                "configuration",
                self.destination.configuration()?.descriptor()?.as_fd(),
            ),
            ("pin", self.pin.descriptor()?.as_fd()),
            ("operation-lock", self.lock.as_file().as_fd()),
            ("enrollment", self.enrollment.descriptor()?.as_fd()),
        ]);
        // Role separation is independent of the sender's numeric FD table.
        let mut objects = std::collections::BTreeSet::new();
        for (role, fd) in &values {
            if *role == "caller-pidfd" {
                continue;
            }
            let f = File::from(fd.try_clone_to_owned()?);
            let epoch = files::identity(&f.metadata()?);
            require(
                objects.insert((epoch.0, epoch.1)),
                "credential descriptor roles alias one inode",
            )?;
        }
        self.recheck(authorize)?;
        Ok(values)
    }
    /// Fence one original PID1 start before sockets or worker creation. It grants
    /// neither a credential read result nor authority to complete the enrollment.
    ///
    /// # Errors
    ///
    /// Fails when the launch registry is unsafe or full, or the context changed.
    pub fn enter_launch(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Launch<'g>> {
        self.recheck(authorize)?;
        let parent =
            files::ensure_directory_relative(self.guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == self.guard.control_mount_id()
                && files::directory_names(&parent, 32)?.len() < 32,
            "credential launch registry mount/capacity",
        )?;
        let value = value!({"schema":1,"id":self.id,"phase":"starting","context_sha256":json::fingerprint(&self.original)?,
            "boot_id":crate::operation::boot_id()?,"worker_closed":false,"review_complete":false});
        let record = Retained::create(
            &parent,
            Path::new(&format!("{}.json", self.id)),
            &value,
            4096,
            mount,
        )?;
        self.recheck(authorize)?;
        let shape = launch_shape(&parent)?;
        let launch = Launch {
            guard: self.guard,
            parent,
            shape,
            mount,
            record,
            value,
        };
        launch.recheck()?;
        Ok(launch)
    }
}
type LaunchShape = (u64, u64, u32, u32, u32);
fn launch_shape(file: &File) -> Result<LaunchShape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original Root-private credential launch registry required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
/// A recorded launch intent of one credential review worker.
pub struct Launch<'g> {
    guard: &'g Guard,
    parent: File,
    shape: LaunchShape,
    mount: u64,
    record: Retained,
    value: Value,
}
impl Launch<'_> {
    /// Verify the launch intent is unchanged.
    ///
    /// # Errors
    ///
    /// Fails when the registry or intent changed.
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            launch_shape(&self.parent)? == self.shape
                && launch_shape(&named)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && self.mount == self.guard.control_mount_id(),
            "original credential launch registry replaced/covered",
        )?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value && self.value["phase"] == "starting",
            "original credential launch intent changed; no replay",
        )
    }
}
