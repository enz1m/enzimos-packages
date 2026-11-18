// SPDX-License-Identifier: MIT
//! Original capture inventory documents, entered once on the protected control mount.
//! Staging these files does not grant a source mount, transfer or completed backup.
use crate::{
    backup_boot_capture::Captured as BootCapture,
    backup_capture_scope,
    backup_database_export::{self, Completed},
    backup_database_sources::Configuration,
    backup_source_capture::Released,
    control_record::Retained,
    identity, operation,
    settings_command::Command,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const FOLDER: &str = "backup-inventory-stages";
const DOCUMENTS: &[&str] = &[
    "exclusions.json",
    "mounts.txt",
    "packages.txt",
    "scope.json",
    "skipped.txt",
];
const MAX: usize = 2 * 1024 * 1024;
const RECORD_MAX: usize = 8 * 1024 * 1024;
fn members() -> BTreeSet<std::ffi::OsString> {
    DOCUMENTS
        .iter()
        .copied()
        .chain(std::iter::once("databases"))
        .map(std::ffi::OsString::from)
        .collect()
}
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(directory: &File) -> Result<Shape> {
    let m = directory.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original private inventory staging directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(directory.as_fd(), true)?,
    ))
}
struct Document {
    file: File,
    epoch: files::FileIdentity,
    bytes: Vec<u8>,
}
impl Document {
    fn publish(parent: &File, name: &str, bytes: Vec<u8>, owner: u32) -> Result<Self> {
        require(
            DOCUMENTS.contains(&name) && !bytes.is_empty() && bytes.len() <= MAX,
            "fixed inventory document bounds",
        )?;
        let file = files::atomic_relative_retained(
            parent,
            Path::new(name),
            &bytes,
            0o600,
            Some(owner),
            false,
            MAX,
        )?;
        let epoch = files::identity(&file.metadata()?);
        let this = Self { file, epoch, bytes };
        this.recheck(parent, name, owner)?;
        Ok(this)
    }
    fn recheck(&self, parent: &File, name: &str, owner: u32) -> Result<()> {
        let named = files::open_relative(parent, Path::new(name))?;
        require(
            files::identity(&named.metadata()?) == self.epoch
                && files::identity(&self.file.metadata()?) == self.epoch
                && mount_identity::id(named.as_fd(), true)?
                    == mount_identity::id(parent.as_fd(), true)?
                && mount_identity::id(self.file.as_fd(), true)?
                    == mount_identity::id(parent.as_fd(), true)?
                && self.epoch.8 == owner
                && self.epoch.10 == 1
                && self.epoch.7 & 0o7777 == 0o600
                && files::read_file(&self.file, MAX, Some(owner), true)? == self.bytes,
            "original inventory document changed or covered",
        )?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch,
            "original inventory document changed during its read",
        )
    }
    fn evidence(&self) -> Value {
        value!({"inode":self.epoch,"bytes":self.bytes.len(),"sha256":json::sha256(&self.bytes)})
    }
}
pub struct Staged<'c, 's, 'cfg, 'g> {
    capture: &'c Released<'s, 'cfg, 'g>,
    id: String,
    registry: File,
    registry_shape: Shape,
    directory: File,
    directory_shape: Shape,
    documents: BTreeMap<String, Document>,
    databases: File,
    databases_shape: Shape,
    database_configuration: Configuration<'g>,
    database_exports: Vec<Completed<'s, 'g>>,
    boot: &'c BootCapture<'s, 'g>,
    record: Retained,
    value: Value,
}
impl<'c, 's, 'cfg, 'g> Staged<'c, 's, 'cfg, 'g> {
    pub(crate) fn original_root(&self) -> Result<Value> {
        self.recheck()?;
        self.capture.guard().backup_root_binding()
    }
    /// Consume this actual stage only after original worker/source retirement.
    /// Per-role receipts enter before mutation; failed partial stages never retry.
    pub fn retire(
        mut self,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Retired<'s, 'g>> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck()?;
        closed.require_inventory_stage(&self)?;
        let guard = self.capture.guard();
        let lock = self.capture.lock();
        self.value["phase"] = value!("retirement-entered");
        self.value["closed_transfer"] = closed.evidence()?;
        self.record.replace(&self.value)?;
        let mut boundary = || {
            authorize()?;
            crate::namespaces::initial()?;
            closed.recheck()?;
            guard.recheck()?;
            lock.recheck()?;
            let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
            require(
                shape(&self.registry)? == self.registry_shape
                    && shape(&named)? == self.registry_shape,
                "original stage retirement registry changed",
            )?;
            self.record.recheck()
        };
        let mut documents = Vec::new();
        for (name, document) in self.documents {
            boundary()?;
            document.recheck(&self.directory, &name, 0)?;
            documents.push(
                enzimos_platform::named_retirement::Quarantined::enter_bounded(
                    &self.directory,
                    &document.file,
                    Path::new(&name),
                    0,
                    MAX as u64,
                    &mut boundary,
                )?
                .unlink(&mut boundary)?,
            );
        }
        let mut exports = Vec::new();
        for export in self.database_exports {
            boundary()?;
            exports.push(export.retire(&mut boundary)?);
        }
        boundary()?;
        require(
            files::directory_is_empty(&self.databases)?,
            "original staged database directory has unknown members",
        )?;
        let databases = enzimos_platform::named_retirement::Quarantined::enter(
            &self.directory,
            &self.databases,
            Path::new("databases"),
            0,
            &mut boundary,
        )?
        .unlink(&mut boundary)?;
        boundary()?;
        require(
            files::directory_is_empty(&self.directory)?,
            "original inventory stage has unknown members",
        )?;
        let directory = enzimos_platform::named_retirement::Quarantined::enter(
            &self.registry,
            &self.directory,
            Path::new(&self.id),
            0,
            &mut boundary,
        )?
        .unlink(&mut boundary)?;
        boundary()?;
        self.value["phase"] = value!("retired");
        self.value["inventory_stage_removed"] = value!(true);
        self.record.replace(&self.value)?;
        let retired = Retired {
            guard,
            lock,
            id: self.id,
            registry: self.registry,
            registry_shape: self.registry_shape,
            record: self.record,
            value: self.value,
            documents,
            exports,
            databases,
            directory,
        };
        retired.evidence()?;
        Ok(retired)
    }
    pub fn recheck(&self) -> Result<()> {
        self.capture.recheck()?;
        self.boot.require_original(self.capture)?;
        require(
            self.value["boot_capture"] == self.boot.evidence()?
                && self.value["boot_staged"] == true,
            "original staged boot copy differs from receipt",
        )?;
        let named_registry =
            files::directory_relative(self.capture.guard().control(), Path::new(FOLDER), Some(0))?;
        let named = files::directory_relative(&self.registry, Path::new(&self.id), Some(0))?;
        require(
            shape(&self.registry)? == self.registry_shape
                && shape(&named_registry)? == self.registry_shape
                && shape(&self.directory)? == self.directory_shape
                && shape(&named)? == self.directory_shape,
            "original inventory stage or registry changed or covered",
        )?;
        let names = files::directory_names(&self.directory, 8)?;
        require(
            names.into_iter().collect::<BTreeSet<_>>() == members(),
            "original inventory document membership changed",
        )?;
        self.database_configuration.recheck()?;
        let named_databases =
            files::directory_relative(&self.directory, Path::new("databases"), Some(0))?;
        require(
            shape(&self.databases)? == self.databases_shape
                && shape(&named_databases)? == self.databases_shape,
            "original database export directory changed or covered",
        )?;
        let expected = self
            .database_exports
            .iter()
            .map(|export| Ok(std::ffi::OsString::from(export.file_name()?)))
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            files::directory_names(&self.databases, 8)?
                .into_iter()
                .collect::<BTreeSet<_>>()
                == expected,
            "original configured database export membership changed",
        )?;
        let exports = self
            .database_exports
            .iter()
            .map(Completed::evidence)
            .collect::<Result<Vec<_>>>()?;
        require(
            self.value["database_configuration"] == self.database_configuration.evidence()?
                && self.value["database_exports"] == value!(exports)
                && self.value["database_exports_staged"] == true,
            "original configured database exports differ from stage receipt",
        )?;
        for (name, document) in &self.documents {
            document.recheck(&self.directory, name, 0)?;
        }
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value
                && self.value["phase"] == "documents-ready"
                && self.value["capture"] == self.capture.evidence()?,
            "original inventory stage receipt changed",
        )
    }
    pub(crate) fn require_original(&self, capture: &Released<'_, '_, '_>) -> Result<()> {
        self.recheck()?;
        require(
            std::ptr::from_ref(self.capture).cast::<()>()
                == std::ptr::from_ref(capture).cast::<()>(),
            "original inventory/source capture pair required",
        )
    }
    pub(crate) fn original_directory(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.directory)
    }
    /// Fixed documents only. A retained descriptor is review/staging data, not
    /// permission to mount this directory or pass caller-selected Restic options.
    pub fn descriptor(&self, name: &str) -> Result<&File> {
        self.recheck()?;
        self.documents
            .get(name)
            .map(|d| &d.file)
            .ok_or_else(|| Error("unknown inventory document".into()))
    }
    /// Actual staged tree retained from this same original capture. Data only;
    /// consumers must separately admit their own readonly mount/transfer role.
    pub fn boot_directory(&self) -> Result<&File> {
        self.recheck()?;
        self.boot.descriptor()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}
fn database_scope(configuration: &Value, exports: &[Completed<'_, '_>]) -> Result<Value> {
    if configuration["configured"] == false {
        require(
            exports.is_empty(),
            "absent database configuration cannot carry exports",
        )?;
        return Ok(value!({"configured":false,"exports":[],"raw_databases":"crash-consistent"}));
    }
    let rows = configuration["rows"]
        .as_array()
        .ok_or_else(|| Error("original database selection shape".into()))?;
    require(
        !rows.is_empty() && rows.len() == exports.len(),
        "configured database export count differs",
    )?;
    let mut summaries = Vec::new();
    for (row, export) in rows.iter().zip(exports) {
        let evidence = export.evidence()?;
        let source = &evidence["receipt"]["source"];
        require(
            source["name"] == row["name"] && source["path"] == row["path"],
            "completed database export belongs to another configured source",
        )?;
        let output = &evidence["receipt"]["output"];
        summaries.push(value!({"name":row["name"],"source":row["path"],
            "identity":{"device":source["main"]["file"][0],"inode":source["main"]["file"][1],"unique_mount_id":source["main"]["mount"]},
            "bytes":output["bytes"],"sha256":output["sha256"],"method":"sqlite-online-backup"}));
    }
    Ok(
        value!({"configured":true,"configuration_sha256":configuration["configuration"]["sha256"],
        "exports":summaries,"raw_databases":"crash-consistent","global_atomicity":false}),
    )
}
/// Folders this backup skips by rule (build output, caches, game files, the
/// Trash and people's exclusions), found in the read-only home snapshot it
/// captured. Any problem yields an empty list: the backup then keeps them.
fn skipped_document(capture: &Released<'_, '_, '_>) -> Result<Vec<u8>> {
    use enzimos_platform::{backup_rules, fsview};
    use std::os::unix::fs::MetadataExt;
    let mut homes = Vec::new();
    for captured in capture.snapshots()? {
        let dataset = captured.dataset()?;
        if dataset.archive != "home" {
            continue;
        }
        let number = captured.snapshot()?.evidence()?["number"]
            .as_u64()
            .ok_or_else(|| Error("home snapshot number".into()))?;
        let path = Path::new(&dataset.path).join(format!(".snapshots/{number}/snapshot"));
        let Ok(root) = fsview::open_directory(&path) else {
            continue;
        };
        let Ok(listing) = fsview::entries(&root, 10_000) else {
            continue;
        };
        for entry in listing {
            let Some(name) = entry
                .name
                .to_str()
                .filter(|n| entry.kind.is_dir() && *n != ".snapshots")
            else {
                continue;
            };
            let Ok(Some(home)) = fsview::child_directory(&root, &entry.name) else {
                continue;
            };
            let Ok(uid) = home.metadata().map(|m| m.uid()) else {
                continue;
            };
            let Ok(account) = enzimos_platform::accounts::lookup_uid(uid) else {
                continue;
            };
            if uid < 1000
                || account.home != format!("{}/{name}", dataset.path.trim_end_matches('/'))
            {
                continue;
            }
            homes.push((
                name.to_owned(),
                home,
                backup_rules::read_rules(Path::new(backup_rules::STATE), uid),
            ));
        }
    }
    Ok(backup_rules::exclude_file("/backup-source/home", &homes))
}
fn inventory_scope(
    capture: &Released<'_, '_, '_>,
    review: &Value,
    sqlite: &Value,
    boot: &BootCapture<'_, '_>,
) -> Result<Value> {
    capture.recheck()?;
    boot.require_original(capture)?;
    let mut sources = Vec::new();
    let mut snapshots = Vec::new();
    let mut bindings = Vec::new();
    for captured in capture.snapshots()? {
        let dataset = captured.dataset()?;
        let snapshot = captured.snapshot()?.evidence()?;
        sources.push(value!([dataset.name, dataset.path, dataset.archive]));
        snapshots.push(value!([dataset.name, snapshot["number"]]));
        bindings.push(value!({"config":dataset.name,"number":snapshot["number"],
            "source":snapshot["source"],"snapshot":snapshot["object"]}));
    }
    let evidence = capture.evidence()?;
    capture.recheck()?;
    Ok(
        value!({"schema":1,"source_snapshots":snapshots,"source_bindings":bindings,"sources":sources,
        "archive_paths":review["sources"],"capture":evidence,
        "authority_restore":"current control/keyring state must be preserved; never replay from backup",
        "native_package_capture":"libalpm transaction lock plus coordinator operation lock",
        "application_consistency":"sequential crash-consistent datasets, not atomic app or user Flatpak transactions",
        "system_flatpak_capture":evidence["receipt"]["flatpak_capture"],"sqlite_exports":sqlite,
        "inactive_swap_excluded":true,"backup_worker_activation_restored":false,
        "database_exports_staged":true,"boot_staged":true,"boot_capture":boot.evidence()?,"source_mounts_admitted":false,
        "transfer_complete":false,"backup_complete":false}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (mkdirat).")]
pub fn stage<'c, 's, 'cfg, 'g>(
    capture: &'c Released<'s, 'cfg, 'g>,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Staged<'c, 's, 'cfg, 'g>> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    identity::safe_id(id)?;
    require(id.len() <= 64, "inventory stage ID bound")?;
    capture.require_original(lock)?;
    authorize()?;
    let guard = capture.guard();
    let database_configuration = Configuration::observe(guard)?;
    let registry = files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
    let registry_shape = shape(&registry)?;
    require(
        registry_shape.5 == guard.control_mount_id(),
        "inventory stage left original control mount",
    )?;
    let record_name = format!("{id}.json");
    require(
        files::directory_names(&registry, 256)?.len() < 256
            && files::optional_directory_relative(&registry, Path::new(id), Some(0))?.is_none()
            && files::optional_relative(&registry, Path::new(&record_name))?.is_none(),
        "inventory stage already entered or registry full; no replay",
    )?;
    let mut body = value!({"schema":1,"id":id,"role":"backup-inventory-stage","phase":"entered",
        "boot_id":operation::boot_id()?,"capture":capture.evidence()?,"documents":null,"mount_inventory_provider":null,
        "database_configuration":database_configuration.evidence()?,"database_exports":null,"boot_capture":null,
        "database_exports_staged":false,"boot_staged":false,"source_mounts_admitted":false,
        "transfer_complete":false,"backup_complete":false});
    let mut record = Retained::create(
        &registry,
        Path::new(&record_name),
        &body,
        RECORD_MAX,
        registry_shape.5,
    )?;
    let boundary = |record: &Retained| -> Result<()> {
        capture.require_original(lock)?;
        record.recheck()?;
        let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&registry)? == registry_shape && shape(&named)? == registry_shape,
            "original inventory registry changed",
        )
    };
    authorize()?;
    boundary(&record)?;
    let component =
        std::ffi::CString::new(id).map_err(|_| Error("inventory stage component".into()))?;
    require(
        unsafe { libc::mkdirat(registry.as_raw_fd(), component.as_ptr(), 0o700) } == 0,
        "exclusive inventory stage creation failed; intent retained",
    )?;
    registry.sync_all()?;
    let directory = files::directory_relative(&registry, Path::new(id), Some(0))?;
    let directory_shape = shape(&directory)?;
    require(
        directory_shape.5 == registry_shape.5 && files::directory_is_empty(&directory)?,
        "new inventory stage changed before publication",
    )?;
    authorize()?;
    boundary(&record)?;
    require(
        unsafe { libc::mkdirat(directory.as_raw_fd(), c"databases".as_ptr(), 0o700) } == 0,
        "exclusive database export directory creation failed; stage intent retained",
    )?;
    directory.sync_all()?;
    let databases = files::directory_relative(&directory, Path::new("databases"), Some(0))?;
    let databases_shape = shape(&databases)?;
    require(
        databases_shape.5 == directory_shape.5 && files::directory_is_empty(&databases)?,
        "new database output directory changed before export",
    )?;
    let database_exports = {
        let sources = database_configuration.sources()?;
        let mut exports = Vec::new();
        for (index, source) in sources.iter().enumerate() {
            let export_id = format!("db-{}-{index}", &json::sha256(id.as_bytes())[..48]);
            let mut checkpoint = || {
                authorize()?;
                boundary(&record)?;
                database_configuration.recheck()?;
                let named_stage = files::directory_relative(&registry, Path::new(id), Some(0))?;
                let named_outputs =
                    files::directory_relative(&directory, Path::new("databases"), Some(0))?;
                require(
                    shape(&directory)? == directory_shape
                        && shape(&named_stage)? == directory_shape
                        && shape(&databases)? == databases_shape
                        && shape(&named_outputs)? == databases_shape,
                    "original database stage changed during export",
                )
            };
            exports.push(backup_database_export::export(
                source,
                capture.attempt(),
                capture.lock(),
                &databases,
                &export_id,
                &mut checkpoint,
            )?);
        }
        exports
    };
    database_configuration.recheck()?;
    let sqlite = database_scope(&database_configuration.evidence()?, &database_exports)?;
    // Reuse the actual copy made while the original cooperating barriers were held.
    // No later live boot refresh or reconstruction from the receipt is permitted.
    let boot = capture.boot()?;
    boot.require_original(capture)?;
    let command = Command::open("/usr/bin/findmnt")?;
    let mut mounts = command.run(&["--json"], &[0], MAX - 1)?;
    json::decode(&mounts, MAX - 1)?;
    mounts.push(b'\n');
    authorize()?;
    boundary(&record)?;
    let scope = backup_capture_scope::review(capture)?;
    let packages = capture.installed_packages()?;
    let mut text = String::new();
    for (name, version) in packages {
        text.push_str(&format!("{name} {version}\n"));
    }
    let skipped = skipped_document(capture)?;
    authorize()?;
    boundary(&record)?;
    let rows = BTreeMap::from([
        ("skipped.txt", skipped),
        ("packages.txt", text.into_bytes()),
        ("mounts.txt", mounts),
        ("exclusions.json", json::canonical(&scope["excludes"])?),
        (
            "scope.json",
            json::canonical(&inventory_scope(capture, &scope, &sqlite, boot)?)?,
        ),
    ]);
    let mut documents = BTreeMap::new();
    for (name, bytes) in rows {
        authorize()?;
        boundary(&record)?;
        let named = files::directory_relative(&registry, Path::new(id), Some(0))?;
        require(
            shape(&directory)? == directory_shape && shape(&named)? == directory_shape,
            "original inventory stage changed before document publication",
        )?;
        documents.insert(
            name.to_owned(),
            Document::publish(&directory, name, bytes, 0)?,
        );
    }
    directory.sync_all()?;
    authorize()?;
    boundary(&record)?;
    let named = files::directory_relative(&registry, Path::new(id), Some(0))?;
    require(
        shape(&directory)? == directory_shape && shape(&named)? == directory_shape,
        "original inventory stage changed before ready publication",
    )?;
    require(
        files::directory_names(&directory, 8)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            == members(),
        "inventory stage has unknown members before ready publication",
    )?;
    for (name, document) in &documents {
        document.recheck(&directory, name, 0)?;
    }
    command.recheck()?;
    body["mount_inventory_provider"] = command.evidence()?;
    database_configuration.recheck()?;
    require(
        shape(&databases)? == databases_shape
            && shape(&files::directory_relative(
                &directory,
                Path::new("databases"),
                Some(0),
            )?)? == databases_shape,
        "original database stage changed before ready publication",
    )?;
    let expected = database_exports
        .iter()
        .map(|export| Ok(std::ffi::OsString::from(export.file_name()?)))
        .collect::<Result<BTreeSet<_>>>()?;
    require(
        files::directory_names(&databases, 8)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            == expected,
        "configured database exports have unknown members",
    )?;
    body["database_exports"] = value!(
        database_exports
            .iter()
            .map(Completed::evidence)
            .collect::<Result<Vec<_>>>()?
    );
    boot.require_original(capture)?;
    body["boot_capture"] = boot.evidence()?;
    body["boot_staged"] = value!(true);
    body["database_exports_staged"] = value!(true);
    body["phase"] = value!("documents-ready");
    body["documents"] = value!(
        documents
            .iter()
            .map(|(name, d)| (name, d.evidence()))
            .collect::<BTreeMap<_, _>>()
    );
    record.replace(&body)?;
    let staged = Staged {
        capture,
        id: id.into(),
        registry,
        registry_shape,
        directory,
        directory_shape,
        documents,
        databases,
        databases_shape,
        database_configuration,
        database_exports,
        boot,
        record,
        value: body,
    };
    staged.recheck()?;
    authorize()?;
    staged.recheck()?;
    Ok(staged)
}

/// Actual original inventory documents, SQLite outputs and empty stage retired.
/// No live capture borrow prevents its subsequent separately gated retirement.
pub struct Retired<'s, 'g> {
    guard: &'g crate::storage_runtime::Guard,
    lock: &'s files::Lock,
    id: String,
    registry: File,
    registry_shape: Shape,
    record: Retained,
    value: Value,
    documents: Vec<enzimos_platform::named_retirement::Removed>,
    exports: Vec<backup_database_export::Retired<'s, 'g>>,
    databases: enzimos_platform::named_retirement::Removed,
    directory: enzimos_platform::named_retirement::Removed,
}
impl Retired<'_, '_> {
    pub(crate) fn require_pair(
        &self,
        guard: &crate::storage_runtime::Guard,
        lock: &files::Lock,
    ) -> Result<()> {
        self.evidence()?;
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "retired inventory guard/lock differs from original source cleanup",
        )
    }
    pub(crate) fn require_original(
        &self,
        capture: &Released<'_, '_, '_>,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
    ) -> Result<()> {
        self.evidence()?;
        capture.recheck()?;
        closed.recheck()?;
        require(
            std::ptr::eq(self.guard, capture.guard())
                && std::ptr::eq(self.lock, capture.lock())
                && self.value["capture"] == capture.evidence()?
                && self.value["closed_transfer"] == closed.evidence()?,
            "retired stage does not belong to original live capture/closed transfer",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.record.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&named)? == self.registry_shape
                && shape(&self.registry)? == self.registry_shape
                && self.record.value()? == &self.value
                && self.value["phase"] == "retired"
                && self.value["id"] == self.id,
            "original inventory retirement receipt changed",
        )?;
        for document in &self.documents {
            document.recheck()?;
        }
        for export in &self.exports {
            export.evidence()?;
        }
        self.databases.recheck()?;
        self.directory.recheck()?;
        Ok(value!({"receipt":self.value,"inventory_stage_removed":true,
            "source_cleanup_complete":false,"backup_complete":false}))
    }
}
