// SPDX-License-Identifier: MIT
//! Original existing-repository selective export inputs; no execution authority.
use crate::{
    backup_admission::Repository, backup_credential::Credential, backup_destination::Destination,
    backup_repository_header::Header, backup_restic_runtime::Image, backup_transfer_caller::Caller,
    control_record::Retained, storage_runtime::Guard,
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
const FOLDER: &str = "selective-export-launches";
/// Inputs of one selective export from an existing repository.
pub struct Context<'a, 'g> {
    guard: &'g Guard,
    actor: std::sync::Arc<()>,
    kind: crate::backup_selective_request::Kind,
    lock: &'a files::Lock,
    credential: Credential,
    selection: Value,
    destination: &'a Destination<'g>,
    pin: Repository<'a, 'g>,
    caller: Caller,
    image: Image,
    repository: File,
    current: File,
    header: Header,
    original: Value,
    id: String,
}
impl<'a, 'g> Context<'a, 'g> {
    pub(crate) fn kind(&self) -> crate::backup_selective_request::Kind {
        self.kind
    }
    pub(crate) fn actor_identity(&self) -> std::sync::Arc<()> {
        std::sync::Arc::clone(&self.actor)
    }
    pub(crate) fn guard(&self) -> &'g Guard {
        self.guard
    }
    pub(crate) fn require_description(&self, file: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.caller.require_description(file, number)
    }

    /// Observe the inputs of file export `id`.
    ///
    /// # Errors
    ///
    /// Fails when the selection, destination or storage is invalid or changes, or `authorize`
    /// fails.
    pub fn observe(
        guard: &'g Guard,
        lock: &'a files::Lock,
        selection: &Value,
        destination: &'a Destination<'g>,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_kind(
            guard,
            lock,
            selection,
            destination,
            id,
            authorize,
            crate::backup_selective_request::Kind::File,
        )
    }
    /// Observe the inputs of tree export `id`.
    ///
    /// # Errors
    ///
    /// Fails when the selection, destination or storage is invalid or changes, or `authorize`
    /// fails.
    pub fn observe_tree(
        guard: &'g Guard,
        lock: &'a files::Lock,
        selection: &Value,
        destination: &'a Destination<'g>,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_kind(
            guard,
            lock,
            selection,
            destination,
            id,
            authorize,
            crate::backup_selective_request::Kind::Tree,
        )
    }
    fn observe_kind(
        guard: &'g Guard,
        lock: &'a files::Lock,
        selection: &Value,
        destination: &'a Destination<'g>,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
        kind: crate::backup_selective_request::Kind,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::backup_worker_request::id(id)?;
        authorize()?;
        crate::backup_selective_request::selection(selection)?;
        guard.recheck()?;
        lock.recheck()?;
        // Best effort under the held lock: the registries' own bounds decide.
        let _ =
            crate::restore_history::retire_launches(guard, lock, crate::restore_history::SELECTIVE);
        let _ = crate::restore_history::retire_exports(guard, lock);
        require(
            std::ptr::eq(destination.storage(), guard),
            "selective destination storage actor differs",
        )?;
        destination.require_writable()?;
        let pin = Repository::open(destination)?;
        let caller = Caller::current()?;
        let image = Image::open()?;
        let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
        let header = Header::observe(&repository)?;
        let credential = Credential::open()?;
        credential.binding(guard)?;
        let current = File::from(credential.descriptor()?.try_clone_to_owned()?);
        let mut this = Self {
            guard,
            actor: std::sync::Arc::new(()),
            kind,
            lock,
            credential,
            selection: selection.clone(),
            destination,
            pin,
            caller,
            image,
            repository,
            current,
            header,
            original: Value::Null,
            id: id.into(),
        };
        authorize()?;
        this.original = this.current()?;
        crate::backup_selective_request::context_kind(&this.original, this.kind)?;
        require(
            json::canonical(&this.original)?.len() <= 65536,
            "selective export context bound",
        )?;
        this.recheck(authorize)?;
        Ok(this)
    }
    fn current(&self) -> Result<Value> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.destination.require_writable()?;
        self.pin.recheck()?;
        self.caller.recheck()?;
        self.header.recheck(&self.repository)?;
        self.credential.binding(self.guard)?;
        let file = |f: &File| -> Result<Value> {
            Ok(
                value!({"inode":files::identity(&f.metadata()?),"mount":mount_identity::id(f.as_fd(),true)?}),
            )
        };
        let credential_file = File::from(self.credential.descriptor()?.try_clone_to_owned()?);
        require(
            file(&credential_file)? == file(&self.current)?,
            "selective context lost original credential epoch",
        )?;
        Ok(
            value!({"schema":1,"role":self.kind.context(),"id":self.id,"boot_id":crate::operation::boot_id()?,
            "caller":self.caller.evidence()?,"source":self.guard.backup_root_binding()?,
            "selection":self.selection,"destination":self.destination.evidence()?,
            "configuration":self.destination.configuration()?.evidence()?,"pin":self.pin.evidence()?,
            "root_directory":crate::backup_worker_scope::directory(self.destination.root_descriptor()?)?,
            "repository_directory":crate::backup_worker_scope::directory(&self.repository)?,
            "credential":file(&self.current)?,"restic":self.image.evidence()?,"header":self.header.evidence(&self.repository)?,
            "operation_lock":file(self.lock.as_file())?,"worker_closed":false,"export_complete":false,
            "live_home_written":false,"metadata_restored":false,"per_user_authorized":false}),
        )
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
            "original selective export context changed; no adoption/replay",
        )
    }
    /// Authenticated metadata planning uses original descriptions and an existing
    /// Root-private tmpfs directory. It creates neither an export nor a receipt.
    pub(crate) fn query_tree(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        use enzimos_platform::local_restic::{self, SelectedFile, SelectiveTask};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        require(
            self.kind == crate::backup_selective_request::Kind::Tree,
            "tree planning requires original tree context",
        )?;
        self.recheck(authorize)?;
        let scratch = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let epoch = files::identity(&scratch.metadata()?);
        let mount = mount_identity::id(scratch.as_fd(), true)?;
        let descriptors = self.descriptors(authorize)?;
        let image = File::from(descriptors["restic"].try_clone_to_owned()?);
        let repository = File::from(descriptors["repository"].try_clone_to_owned()?);
        let credential = File::from(descriptors["credential"].try_clone_to_owned()?);
        let snapshot = enzimos_platform::json::string(&self.selection["snapshot"])?;
        let path = enzimos_platform::json::string(&self.selection["path"])?;
        let selected = SelectedFile::new(snapshot, path)?;
        let mut boundary = || {
            self.recheck(authorize)?;
            let named = files::directory(Path::new("/run/enzimos"), Some(0))?;
            require(
                files::identity(&scratch.metadata()?) == epoch
                    && files::identity(&named.metadata()?) == epoch
                    && mount_identity::id(scratch.as_fd(), true)? == mount
                    && mount_identity::id(named.as_fd(), true)? == mount,
                "original metadata planning directory changed",
            )
        };
        let mut query = |task| {
            boundary()?;
            let output = local_restic::selective_plan(
                &selected,
                task,
                &image,
                &repository,
                &credential,
                &scratch,
                &mut boundary,
            )?;
            boundary()?;
            require(
                output.status.code() == Some(0),
                "tree plan query failed; no replay",
            )?;
            Ok::<_, enzimos_platform::Error>(output.stdout)
        };
        let snapshots = query(SelectiveTask::Snapshot)?;
        crate::backup_selective_result::snapshot_scope(Some(0), &snapshots, snapshot)?;
        let listing = query(SelectiveTask::TreeListing)?;
        let details =
            crate::backup_tree_result::metadata(Some(0), &listing, snapshot, path)?.details;
        boundary()?;
        Ok(details)
    }
    /// JSON evidence for the export context.
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
            ("credential", self.current.as_fd()),
            ("restic", self.image.descriptor()?.as_fd()),
            (
                "configuration",
                self.destination.configuration()?.descriptor()?.as_fd(),
            ),
            ("pin", self.pin.descriptor()?.as_fd()),
            ("operation-lock", self.lock.as_file().as_fd()),
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
                "selective descriptor roles alias one inode",
            )?;
        }
        self.recheck(authorize)?;
        Ok(values)
    }
    /// Fence one original PID1 start before sockets or worker creation. It grants
    /// neither an observed file result nor authority to publish an export.
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
            "selective launch registry mount/capacity",
        )?;
        let value = value!({"schema":1,"id":self.id,"phase":"starting","context_sha256":json::fingerprint(&self.original)?,
            "boot_id":crate::operation::boot_id()?,"worker_closed":false,"export_complete":false});
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
        "original Root-private selective launch registry required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
/// A recorded launch intent of one selective export worker.
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
            "original selective launch registry replaced/covered",
        )?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value && self.value["phase"] == "starting",
            "original selective launch intent changed; no replay",
        )
    }
}
