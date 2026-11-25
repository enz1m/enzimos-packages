// SPDX-License-Identifier: MIT
//! Standalone local initialization enters one durable original attempt before
//! the fixed Restic consumer. Existing/nonempty repositories cannot be adopted.
use super::*;
use crate::{
    backup_credential::Credential,
    backup_restic_runtime::{Observed, Runtime},
    operation,
};
use enzimos_platform::{local_restic::Task, receipt_registry::Registry};
use std::os::fd::AsFd;
struct Empty<'a> {
    config: Configuration,
    source: &'a storage_runtime::Guard,
    root: File,
    repository: File,
    root_epoch: files::FileIdentity,
    repository_epoch: files::FileIdentity,
    root_flags: i32,
    repository_flags: i32,
    unique: u64,
    normal: u64,
    filesystem: Value,
    mounted: mountinfo::Row,
    topology: topology::Graph,
    source_topology: topology::Graph,
    credential: Credential,
    credential_binding: Value,
    image: crate::backup_restic_runtime::Image,
}
fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original initialization read-only descriptor required",
    )?;
    Ok(value)
}
impl<'a> Empty<'a> {
    fn observe(source: &'a storage_runtime::Guard) -> Result<Self> {
        source.recheck()?;
        let config = Configuration::open()?;
        let uuid = enzimos_platform::json::string(&config.value()["destination_uuid"])?;
        require(
            source.configuration["filesystem_uuid"] != uuid,
            "initial repository must be independent of system filesystem",
        )?;
        let root = files::directory(Path::new(MOUNT), Some(0))?;
        let unique = mount_identity::id(root.as_fd(), true)?;
        let normal = mount_identity::id(root.as_fd(), false)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == uuid,
            "initial repository filesystem differs from configured destination",
        )?;
        let mounted = mount(&storage_runtime::rows()?, normal)?;
        writable(&mounted)?;
        let topology = topology::mounted_btrfs(uuid)?;
        let source_topology = topology::mounted_btrfs(enzimos_platform::json::string(
            &source.configuration["filesystem_uuid"],
        )?)?;
        independent(&topology.json(), &source_topology.json())?;
        let repository = files::directory_relative(&root, Path::new("restic"), Some(0))?;
        let root_epoch = files::identity(&root.metadata()?);
        let repository_epoch = files::identity(&repository.metadata()?);
        shape(&root)?;
        shape(&repository)?;
        require(
            repository.metadata()?.gid() == 0
                && mount_identity::id(repository.as_fd(), true)? == unique,
            "initial repository protection/mount required",
        )?;
        let root_flags = flags(&root)?;
        let repository_flags = flags(&repository)?;
        let credential = Credential::open()?;
        let credential_binding = credential.binding(source)?;
        let image = crate::backup_restic_runtime::Image::open()?;
        let result = Self {
            config,
            source,
            root,
            repository,
            root_epoch,
            repository_epoch,
            root_flags,
            repository_flags,
            unique,
            normal,
            filesystem,
            mounted,
            topology,
            source_topology,
            credential,
            credential_binding,
            image,
        };
        result.recheck_empty()?;
        Ok(result)
    }
    fn barrier(&self) -> Result<()> {
        self.source.recheck()?;
        self.config.recheck()?;
        self.credential.recheck()?;
        require(
            self.credential.binding(self.source)? == self.credential_binding,
            "original initialization credential binding changed",
        )?;
        self.image.evidence()?;
        require(
            topology::mounted_btrfs(enzimos_platform::json::string(
                &self.config.value()["destination_uuid"],
            )?)?
            .json()
                == self.topology.json()
                && topology::mounted_btrfs(enzimos_platform::json::string(
                    &self.source.configuration["filesystem_uuid"],
                )?)?
                .json()
                    == self.source_topology.json(),
            "original initialization topology changed",
        )?;
        independent(&self.topology.json(), &self.source_topology.json())?;
        let named_root = files::directory(Path::new(MOUNT), Some(0))?;
        let named_repository =
            files::directory_relative(&named_root, Path::new("restic"), Some(0))?;
        let a = files::identity(&self.repository.metadata()?);
        let b = files::identity(&named_repository.metadata()?);
        let original = self.repository_epoch;
        require(
            files::identity(&self.root.metadata()?) == self.root_epoch
                && files::identity(&named_root.metadata()?) == self.root_epoch
                && (a.0, a.1, a.7, a.8, a.9)
                    == (original.0, original.1, original.7, original.8, original.9)
                && (b.0, b.1, b.7, b.8, b.9) == (a.0, a.1, a.7, a.8, a.9)
                && flags(&self.root)? == self.root_flags
                && flags(&self.repository)? == self.repository_flags
                && [&self.root, &self.repository, &named_root, &named_repository]
                    .iter()
                    .all(|file| mount_identity::id(file.as_fd(), true).ok() == Some(self.unique))
                && filesystem::observe(self.root.as_fd())? == self.filesystem
                && mount(&storage_runtime::rows()?, self.normal)? == self.mounted,
            "original empty repository/configuration/mount/description changed",
        )?;
        writable(&self.mounted)?;
        self.source.recheck()
    }
    fn recheck_empty(&self) -> Result<()> {
        self.barrier()?;
        require(
            files::identity(&self.repository.metadata()?) == self.repository_epoch
                && files::directory_is_empty(&self.repository)?,
            "existing/nonempty repository cannot be initialized/adopted",
        )?;
        self.barrier()
    }
}
/// Unknown outcomes leave the original durable attempt and refuse another call.
/// This standalone entry does not enable backup scheduling or publish an opt-in.
///
/// # Errors
///
/// Fails when a destination is already bound, `authorize` fails, or initialization fails.
pub fn initialize_locked(
    source: &storage_runtime::Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    lock.recheck()?;
    let pin_name = Path::new("backup-destination.json");
    require(
        files::optional_relative(source.control(), pin_name)?.is_none(),
        "backup destination already bound; no automatic replacement",
    )?;
    let empty = Empty::observe(source)?;
    let runtime_id = files::random_hex(16)?;
    let directory = files::ensure_directory_relative(
        source.control(),
        Path::new("backup-local-initialization"),
        0o700,
        0,
    )?;
    require(
        mount_identity::id(directory.as_fd(), true)? == source.control_mount_id(),
        "initialization receipt crossed control mount",
    )?;
    let path = Path::new(operation::CONTROL).join("backup-local-initialization");
    let mut registry = Registry::observe(&path, &directory, "attempt.json", 0)?;
    empty.recheck_empty()?;
    let record = value!({"schema":1,"phase":"entered","boot_id":operation::boot_id()?,"runtime":runtime_id,
        "filesystem_uuid":empty.filesystem["filesystem_uuid"],"configuration_sha256":json::fingerprint(empty.config.value())?,
        "repository_epoch":empty.repository_epoch,"credential":empty.credential.binding(source)?,"scheduler_enabled":false});
    let mut bytes = json::canonical(&record)?;
    bytes.push(b'\n');
    registry.publish(&bytes, &mut || {
        authorize()?;
        lock.recheck()?;
        empty.recheck_empty()
    })?;
    let runtime = Runtime::create(&runtime_id, &mut || {
        authorize()?;
        lock.recheck()?;
        empty.recheck_empty()?;
        registry.recheck()
    })?;
    empty.recheck_empty()?;
    registry.recheck()?;
    require(
        runtime.image_evidence()? == empty.image.evidence()?,
        "original initialization vendor image changed",
    )?;
    let credential = File::from(empty.credential.descriptor()?.try_clone_to_owned()?);
    let observed = runtime.run(
        Task::Initialize,
        &empty.repository,
        &credential,
        &mut || {
            authorize()?;
            lock.recheck()?;
            empty.barrier()?;
            require(
                runtime.image_evidence()? == empty.image.evidence()?,
                "original initialization vendor image changed during execution",
            )?;
            registry.recheck()
        },
    )?;
    require(
        observed == Observed::Initialized,
        "initialization result unknown; original receipt retained, no replay",
    )?;
    let header = crate::backup_repository_header::Header::observe(&empty.repository)?;
    header.recheck(&empty.repository)?;
    empty.barrier()?;
    registry.recheck()?;
    // Legacy standalone init also binds the new repository to protected control
    // storage. A public header receipt alone leaves subsequent manual backup
    // unavailable. Publish only this original completed initialization's pin;
    // existing pins cannot be adopted or replaced.
    let destination = Destination::open(&empty.config, source)?;
    require(
        destination.unique == empty.unique
            && destination.root_shape == shape(&empty.root)?
            && destination.repository_shape == shape(&empty.repository)?,
        "initialized repository observer differs from original descriptors",
    )?;
    let pin = destination.expected_pin()?;
    require(
        pin["repository_sha256"] == header.evidence(&empty.repository)?["sha256"],
        "initialized pin differs from the original encrypted header",
    )?;
    let mut pin_bytes = json::canonical(&pin)?;
    pin_bytes.push(b'\n');
    authorize()?;
    lock.recheck()?;
    empty.barrier()?;
    header.recheck(&empty.repository)?;
    let pin_file = files::atomic_relative_retained(
        source.control(),
        pin_name,
        &pin_bytes,
        0o600,
        Some(0),
        false,
        crate::backup_configuration::LIMIT,
    )?;
    let pin_identity = files::identity(&pin_file.metadata()?);
    let recheck_pin = || -> Result<()> {
        source.recheck()?;
        let named = files::open_relative(source.control(), pin_name)?;
        require(
            files::identity(&pin_file.metadata()?) == pin_identity
                && files::identity(&named.metadata()?) == pin_identity
                && mount_identity::id(pin_file.as_fd(), true)? == source.control_mount_id()
                && files::read_file(&pin_file, crate::backup_configuration::LIMIT, Some(0), true)?
                    == pin_bytes,
            "original initialization destination pin changed or replaced",
        )?;
        destination.recheck()?;
        header.recheck(&empty.repository)
    };
    recheck_pin()?;
    let mut complete = record;
    complete["phase"] = value!("complete");
    complete["header"] = header.evidence(&empty.repository)?;
    complete["destination_pin_sha256"] = value!(json::sha256(&pin_bytes));
    let mut bytes = json::canonical(&complete)?;
    bytes.push(b'\n');
    registry.publish(&bytes, &mut || {
        authorize()?;
        lock.recheck()?;
        empty.barrier()?;
        header.recheck(&empty.repository)?;
        recheck_pin()
    })?;
    registry.recheck()?;
    recheck_pin()?;
    header.recheck(&empty.repository)?;
    empty.barrier()?;
    authorize()?;
    lock.recheck()?;
    Ok(value!({"status":"repository-initialized","scheduler_enabled":false}))
}
