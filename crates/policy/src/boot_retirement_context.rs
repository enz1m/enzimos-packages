// SPDX-License-Identifier: MIT
//! Retained Root boot inventory for retirement. No decoded data can create this actor.
use crate::{
    boot_entries, boot_retirement_plan as plan,
    boot_volume::{Artifact, RetiredArtifact, Volume},
    catalog::{self, Transaction},
    generation_pins, identity, operation, root_rebind_boot,
    storage_runtime::Guard,
    transition_idle,
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
#[path = "root_retirement_finish_loaders.rs"]
pub mod finish;
#[path = "boot_retirement_runtime.rs"]
pub mod runtime;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original ESP directory",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
struct Directory {
    relative: String,
    file: File,
    shape: Shape,
    names: BTreeSet<String>,
}
fn names(file: &File, maximum: usize) -> Result<BTreeSet<String>> {
    files::directory_names(file, maximum)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| Error("boot inventory filename encoding".into()))?;
            identity::safe_id(&name)?;
            Ok(name)
        })
        .collect()
}
impl Directory {
    fn observe(volume: &Volume, relative: &str, maximum: usize) -> Result<Self> {
        let file = volume.directory(Path::new(relative))?;
        Ok(Self {
            relative: relative.into(),
            shape: shape(&file)?,
            names: names(&file, maximum)?,
            file,
        })
    }
    fn recheck(&self, volume: &Volume) -> Result<()> {
        let named = volume.directory(Path::new(&self.relative))?;
        require(
            shape(&self.file)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.file.as_fd(), true)? == volume.unique
                && mount_identity::id(named.as_fd(), true)? == volume.unique
                && names(&self.file, self.names.len().max(1))? == self.names
                && names(&named, self.names.len().max(1))? == self.names,
            "original ESP directory membership/replacement changed",
        )
    }
}
const GENERATIONS: &str = "enzimos/generations";
/// Whether the ESP generations folder must exist: always once present, and
/// required whenever the catalog names a generation. Only an empty catalog
/// admits its exact absence (a fresh install before its first publication).
pub(crate) fn generations_folder_required(path: &Path, generations: &Value) -> Result<bool> {
    let absent = crate::root_retirement_signed_namespace::absent(path)?;
    generations_folder_layout(absent, generations)
}
fn generations_folder_layout(absent: bool, generations: &Value) -> Result<bool> {
    let empty = generations
        .as_object()
        .ok_or_else(|| Error("generation catalog map required".into()))?
        .is_empty();
    require(
        !absent || empty,
        "registered generations require the ESP generations folder",
    )?;
    Ok(!absent)
}
pub(crate) fn firmware() -> Result<Value> {
    let observable = crate::recovery_activation_runtime::efi_guard()?;
    let mut variables = value!({});
    if observable {
        let folder = Path::new(crate::recovery_activation_runtime::EFI);
        for key in ["LoaderEntrySelected", "LoaderEntryLastBooted"] {
            let path = folder.join(format!(
                "{key}-{}",
                crate::recovery_activation_runtime::GUID
            ));
            match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
                Ok(m) => {
                    require(
                        m.is_file(),
                        "EFI loader variable must be original regular kernel object",
                    )?;
                    variables[key] =
                        value!(boot_entries::efi_string(&files::read_kernel(&path, 8192)?)?);
                }
            }
        }
    }
    Ok(value!({"observable":observable,"variables":variables}))
}
pub(crate) fn command_line() -> Result<String> {
    String::from_utf8(files::read_kernel(Path::new("/proc/cmdline"), 65536)?)
        .map_err(|_| Error("actual boot command line encoding".into()))
}
fn selected(texts: &BTreeMap<String, String>, firmware: &Value) -> Result<BTreeSet<String>> {
    let loader = boot_entries::fields(
        texts
            .get("loader/loader.conf")
            .ok_or_else(|| Error("original loader configuration required".into()))?,
        false,
    )?;
    let default = loader
        .get("default")
        .ok_or_else(|| Error("explicit original UEFI default required".into()))?;
    // Ambiguous glob/saved/one-shot defaults require review before destructive
    // support. This inventory never guesses which missing entry would be selected.
    identity::safe_id(default)?;
    require(
        default.ends_with(".conf") && texts.contains_key(&format!("loader/entries/{default}")),
        "one actual UEFI default entry required",
    )?;
    let menu = boot_entries::menu(&texts["limine/limine.conf"])?;
    let mut result = BTreeSet::from([
        default.clone(),
        menu.entries[menu.selected - 1].title.clone(),
    ]);
    for v in enzimos_platform::json::object(&firmware["variables"])?.values() {
        result.insert(enzimos_platform::json::string(v)?.into());
    }
    Ok(result)
}
pub(crate) struct SignedInventory {
    directory: Option<Directory>,
    autodiscovery: Option<Directory>,
    images: BTreeMap<String, Artifact>,
    verified: Vec<crate::signed_entry::Verification>,
    entries: BTreeMap<String, String>,
}
impl SignedInventory {
    pub(crate) fn observe(
        volume: &Volume,
        texts: &BTreeMap<String, String>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        let path = volume.path(Path::new("enzimos/secure-boot"))?;
        let directory = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
            Ok(_) => Some(Directory::observe(volume, "enzimos/secure-boot", 128)?),
        };
        let automatic = volume.path(Path::new("EFI/Linux"))?;
        let autodiscovery = match std::fs::symlink_metadata(&automatic) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
            Ok(_) => Some(Directory::observe(volume, "EFI/Linux", 128)?),
        };
        if let Some(d) = &autodiscovery {
            crate::boot_retirement_references::external_autodiscovery(&d.names)?;
        }
        let mut this = Self {
            directory,
            autodiscovery,
            images: BTreeMap::new(),
            verified: Vec::new(),
            entries: BTreeMap::new(),
        };
        if let Some(directory) = &this.directory {
            for name in &directory.names {
                authorize()?;
                let digest = name.strip_suffix(".efi").ok_or_else(|| {
                    Error("unknown/interrupted owner UKI member protects retirement".into())
                })?;
                identity::sha(digest)?;
                let relative = format!("/enzimos/secure-boot/{name}");
                this.images.insert(
                    relative,
                    volume.artifact(
                        Path::new(&format!("enzimos/secure-boot/{name}")),
                        256 * 1024 * 1024,
                    )?,
                );
            }
        }
        for (name, body) in texts
            .iter()
            .filter(|(name, _)| name.starts_with("loader/entries/"))
        {
            authorize()?;
            let fields = boot_entries::fields(body, false)?;
            if let Some(relative) = fields.get("uki") {
                if relative.starts_with("/enzimos/secure-boot/") {
                    let verification = crate::signed_entry::retain(&fields)?.ok_or_else(|| {
                        Error("actual original signed UKI verification required".into())
                    })?;
                    let image = this.images.get(relative).ok_or_else(|| {
                        Error("signed entry output absent from original UKI inventory".into())
                    })?;
                    require(
                        verification.relative() == relative
                            && files::identity(&verification.descriptor()?.metadata()?)
                                == files::identity(&image.file.metadata()?),
                        "signed entry verification differs from retained original UKI",
                    )?;
                    this.verified.push(verification);
                    this.entries.insert(name.clone(), relative.clone());
                } else {
                    // Unowned UKIs may still refer to this generation through an
                    // embedded command line. A destructive planner must refuse.
                    return Err(Error(
                        "unowned UKI prevents complete boot retirement references".into(),
                    ));
                }
            }
        }
        this.recheck(volume, authorize)?;
        Ok(this)
    }
    pub(crate) fn recheck(
        &self,
        volume: &Volume,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        match &self.directory {
            Some(d) => d.recheck(volume)?,
            None => require(
                matches!(std::fs::symlink_metadata(volume.path(Path::new("enzimos/secure-boot"))?),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "originally absent UKI directory appeared",
            )?,
        }
        self.recheck_original_members(volume, authorize)
    }
    fn recheck_original_members(
        &self,
        volume: &Volume,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        match &self.autodiscovery {
            Some(d) => {
                d.recheck(volume)?;
                crate::boot_retirement_references::external_autodiscovery(&d.names)?;
            }
            None => require(
                matches!(std::fs::symlink_metadata(volume.path(Path::new("EFI/Linux"))?),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "originally absent automatic UKI directory appeared",
            )?,
        }
        for image in self.images.values() {
            authorize()?;
            image.recheck()?;
        }
        for verified in &self.verified {
            authorize()?;
            verified.recheck()?;
        }
        authorize()
    }
    pub(crate) fn retire_original_image(
        &mut self,
        volume: &Volume,
        relative: &str,
        retired: &RetiredArtifact,
    ) -> Result<()> {
        let original = self
            .images
            .get(relative)
            .ok_or_else(|| Error("original signed continuation image missing".into()))?;
        retired.require_original(original)?;
        let leaf = Path::new(relative)
            .file_name()
            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?;
        let directory = self
            .directory
            .as_mut()
            .ok_or_else(|| Error("original signed continuation directory missing".into()))?;
        require(
            directory.names.remove(leaf),
            "actual signed continuation member missing",
        )?;
        directory.recheck(volume)?;
        self.images.remove(relative);
        self.entries.retain(|_, p| p != relative);
        retired.recheck()
    }
    pub(crate) fn recheck_owned(
        &self,
        volume: &Volume,
        retired: &BTreeMap<std::path::PathBuf, RetiredArtifact>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        match &self.directory {
            Some(directory) => directory.recheck(volume)?,
            None => require(
                matches!(std::fs::symlink_metadata(volume.path(Path::new("enzimos/secure-boot"))?),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "originally absent owned signed directory appeared",
            )?,
        }
        match &self.autodiscovery {
            Some(directory) => {
                directory.recheck(volume)?;
                crate::boot_retirement_references::external_autodiscovery(&directory.names)?;
            }
            None => require(
                matches!(std::fs::symlink_metadata(volume.path(Path::new("EFI/Linux"))?),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "originally absent automatic signed directory appeared",
            )?,
        }
        for image in self.images.values() {
            image.recheck()?;
        }
        for verifier in &self.verified {
            verifier.recheck_owned_retirements(retired)?;
        }
        for removed in retired.values() {
            removed.recheck()?;
        }
        authorize()
    }
    pub(crate) fn evidence(
        &self,
        volume: &Volume,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.recheck(volume, authorize)?;
        Ok(
            value!({"entries":self.entries,"images":self.images.iter().map(|(name,a)| Ok((name.clone(),value!({"inode":files::identity(&a.file.metadata()?),"sha256":a.sha,"bytes":a.bytes})))).collect::<Result<BTreeMap<_,_>>>()?,"directory":self.directory.as_ref().map(|d|value!({"shape":d.shape,"names":d.names}))}),
        )
    }
}
fn root_loaders_unmentioned(texts: &BTreeMap<String, String>, targets: &Value) -> Result<()> {
    let mut roots = BTreeSet::new();
    for (name, text) in texts {
        if name.starts_with("loader/entries/")
            && let Some(root) = crate::root_retirement_offline_loaders::root_reference(text, false)?
        {
            roots.insert(root);
        }
    }
    for entry in boot_entries::menu(&texts["limine/limine.conf"])?.entries {
        if let Some(root) =
            crate::root_retirement_offline_loaders::root_reference(&entry.text, true)?
        {
            roots.insert(root);
        }
    }
    crate::root_retirement_offline_loaders::unmentioned(&roots, targets)?;
    Ok(())
}
enum TransactionActor {
    Owned(Transaction),
    Shared(std::sync::Arc<Transaction>),
}
impl TransactionActor {
    fn owned_mut(&mut self) -> Result<&mut Transaction> {
        match self {
            TransactionActor::Owned(original) => Ok(original),
            TransactionActor::Shared(_) => {
                Err(Error("shared original Root catalog is read-only".into()))
            }
        }
    }
}
impl std::ops::Deref for TransactionActor {
    type Target = Transaction;
    fn deref(&self) -> &Transaction {
        match self {
            Self::Owned(actor) => actor,
            Self::Shared(actor) => actor,
        }
    }
}
pub struct Context<'a, 'g> {
    guard: &'g Guard,
    lock: &'a files::Lock,
    generation: String,
    volume: Volume,
    transaction: TransactionActor,
    idle: transition_idle::Snapshot,
    reference_registries: Vec<crate::control_registry::Snapshot<'g>>,
    reference_journals: Vec<crate::recovery_journal::Journal>,
    signed_inventory: SignedInventory,
    pins: generation_pins::Snapshot<'g>,
    directories: Vec<Directory>,
    artifacts: BTreeMap<String, Artifact>,
    texts: BTreeMap<String, String>,
    firmware: Value,
    command_line: String,
    original: Value,
    root_registry_absent: bool,
    root_loader_directory: Option<(files::FileIdentity, i32)>,
}
impl<'a, 'g: 'a> Context<'a, 'g> {
    pub fn observe(
        guard: &'g Guard,
        lock: &'a files::Lock,
        generation: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_inner(guard, lock, generation, None, None, authorize)
    }
    pub(crate) fn observe_shared_catalog(
        guard: &'g Guard,
        lock: &'a files::Lock,
        catalog: std::sync::Arc<Transaction>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_inner(
            guard,
            lock,
            "root-retirement-observation",
            Some(catalog),
            None,
            authorize,
        )
    }
    pub(crate) fn observe_shared_journal(
        guard: &'g Guard,
        lock: &'a files::Lock,
        catalog: std::sync::Arc<Transaction>,
        journal: &crate::root_retirement_online_journal::Journal<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        journal.recheck()?;
        Self::observe_inner(
            guard,
            lock,
            "root-retirement-observation",
            Some(catalog),
            Some(journal),
            authorize,
        )
    }
    fn observe_inner(
        guard: &'g Guard,
        lock: &'a files::Lock,
        generation: &str,
        catalog: Option<std::sync::Arc<Transaction>>,
        journal: Option<&crate::root_retirement_online_journal::Journal<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        identity::safe_id(generation)?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let transaction = match catalog {
            Some(original) => TransactionActor::Shared(original),
            None => TransactionActor::Owned(Transaction::begin()?),
        };
        require(
            transaction.config == guard.configuration,
            "boot retirement original configured source changed",
        )?;
        let idle = match journal {
            Some(original) => transition_idle::Snapshot::root_retirement(original)?,
            None => transition_idle::Snapshot::online()?,
        };
        require(
            idle.guard.backup_root_binding()? == guard.backup_root_binding()?,
            "retirement original transition source differs",
        )?;
        let mut reference_registries = Vec::new();
        for (folder, key) in [
            ("boot-publications", "boot_publications"),
            ("update-workers", "update_workers"),
            ("module-views", "module_views"),
            ("authority-refresh", "authority_refresh"),
            ("root-births", "births"),
            ("root-rebind-journal", "rebinds"),
            ("retirement-journals", "retirement"),
            ("boot-retirements", "boot_retirement"),
            ("root-retirements", "root_retirement"),
        ] {
            authorize()?;
            reference_registries.push(crate::control_registry::Snapshot::observe(
                guard,
                folder,
                &idle.records[key],
            )?);
        }
        use crate::recovery_journal::{Journal, Kind};
        let mut reference_journals = Vec::new();
        for (kind, key) in [
            (Kind::Jobs, "jobs"),
            (Kind::Runs, "runs"),
            (Kind::Activations, "activations"),
            (Kind::Workflows, "workflows"),
            (Kind::Images, "images"),
            (Kind::Publications, "publications"),
            (Kind::Media, "media"),
        ] {
            authorize()?;
            let journal = Journal::open(kind, false)?;
            require(
                value!(journal.records) == idle.records[key],
                "original recovery references changed before retention",
            )?;
            journal.unchanged()?;
            reference_journals.push(journal);
        }
        let pins = generation_pins::Snapshot::observe(guard)?;
        let volume = Volume::observe()?;
        volume.writable()?;
        root_rebind_boot::generations(&volume, &transaction.data)?;
        let texts = root_rebind_boot::texts(&volume)?;
        let uefi = texts
            .iter()
            .filter_map(|(name, body)| {
                name.strip_prefix("loader/entries/")
                    .map(|name| (name.to_owned(), body.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        for row in enzimos_platform::json::object(&transaction.data["generations"])?.values() {
            authorize()?;
            require(
                boot_entries::fingerprint_entries(row, &uefi, &texts["limine/limine.conf"])?
                    == row["entry_fingerprints"],
                "original publisher loader entry drift",
            )?;
        }
        let mut directories = vec![Directory::observe(&volume, "loader/entries", 126)?];
        // A fresh install has published no generation and has no generations
        // folder yet; its absence is then part of the original context.
        if generations_folder_required(
            &volume.path(Path::new(GENERATIONS))?,
            &transaction.data["generations"],
        )? {
            directories.push(Directory::observe(&volume, GENERATIONS, 64)?);
        }
        let mut artifacts = BTreeMap::new();
        for (name, body) in &texts {
            authorize()?;
            let artifact = volume.artifact(Path::new(name), boot_entries::MAX_TEXT as u64)?;
            require(
                files::read_file(&artifact.file, boot_entries::MAX_TEXT, Some(0), true)?
                    == body.as_bytes(),
                "original boot text changed during retention",
            )?;
            artifacts.insert(name.clone(), artifact);
        }
        for (id, row) in enzimos_platform::json::object(&transaction.data["generations"])? {
            authorize()?;
            let path = format!("enzimos/generations/{id}");
            let directory = Directory::observe(&volume, &path, 6)?;
            require(
                directory.names == plan::MEMBERS.iter().map(|n| (*n).into()).collect(),
                "unknown or missing publisher generation members",
            )?;
            for name in plan::MEMBERS {
                authorize()?;
                let relative = format!("{path}/{name}");
                let limit = if name.ends_with(".json") {
                    catalog::MAX_CATALOG as u64
                } else {
                    128 * 1024 * 1024
                };
                let artifact = volume.artifact(Path::new(&relative), limit)?;
                if let Some(expected) = enzimos_platform::json::array(&row["material"]["files"])?
                    .iter()
                    .find(|r| r["name"] == name)
                {
                    require(
                        artifact.bytes == enzimos_platform::json::unsigned(&expected["bytes"])?
                            && artifact.sha == expected["sha256"],
                        "original registered ESP artifact differs",
                    )?;
                }
                if name == "READY.json" {
                    let ready = json::decode(
                        &files::read_file(&artifact.file, catalog::MAX_CATALOG, Some(0), true)?,
                        catalog::MAX_CATALOG,
                    )?;
                    require(
                        ready
                            == value!({"generation":id,"kernels":row["material"]["kernels"],"files":row["material"]["files"]}),
                        "original retained generation manifest changed",
                    )?;
                }
                if name == "PUBLISHED.json" {
                    let published = json::decode(
                        &files::read_file(&artifact.file, catalog::MAX_CATALOG, Some(0), true)?,
                        catalog::MAX_CATALOG,
                    )?;
                    json::fields(&published, "generation bios_first_entry flavors")?;
                    require(
                        published["generation"] == *id
                            && published["flavors"] == value!(["linux", "linux-lts"])
                            && published["bios_first_entry"]
                                .as_u64()
                                .is_some_and(|n| (1..=255).contains(&n)),
                        "original publication marker invalid",
                    )?;
                }
                artifacts.insert(relative, artifact);
            }
            directories.push(directory);
        }
        let signed_inventory = SignedInventory::observe(&volume, &texts, authorize)?;
        let firmware = firmware()?;
        let command_line = command_line()?;
        let root_registry_absent = reference_registries
            .iter()
            .find(|r| r.folder() == "root-retirements")
            .ok_or_else(|| Error("original Root reference registry missing".into()))?
            .originally_absent()?;
        let root_loader_directory = if matches!(&transaction, TransactionActor::Shared(_)) {
            let directory = directories
                .iter()
                .find(|d| d.relative == "loader/entries")
                .ok_or_else(|| Error("original Root loader directory missing".into()))?;
            let flags = enzimos_platform::files::status_flags(&directory.file);
            require(
                flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
                "original Root loader directory read-only description required",
            )?;
            Some((files::identity(&directory.file.metadata()?), flags))
        } else {
            None
        };
        let mut this = Self {
            guard,
            lock,
            generation: generation.into(),
            volume,
            transaction,
            idle,
            reference_registries,
            reference_journals,
            signed_inventory,
            pins,
            directories,
            artifacts,
            texts,
            firmware,
            command_line,
            original: Value::Null,
            root_registry_absent,
            root_loader_directory,
        };
        this.original = this.current(authorize)?;
        this.recheck(authorize)?;
        Ok(this)
    }
    fn recheck_root_loader_directory(&self) -> Result<()> {
        if let Some((epoch, flags)) = self.root_loader_directory {
            let original = self
                .directories
                .iter()
                .find(|d| d.relative == "loader/entries")
                .ok_or_else(|| Error("retained original Root loader directory missing".into()))?;
            let named = self.volume.directory(Path::new("loader/entries"))?;
            require(
                files::identity(&original.file.metadata()?) == epoch
                    && files::identity(&named.metadata()?) == epoch
                    && enzimos_platform::files::status_flags(&original.file) == flags
                    && mount_identity::id(original.file.as_fd(), true)? == self.volume.unique
                    && mount_identity::id(named.as_fd(), true)? == self.volume.unique,
                "original Root loader directory epoch/description changed",
            )?;
        }
        Ok(())
    }
    fn current(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.transaction.recheck()?;
        self.idle.recheck()?;
        let reference_epochs = self
            .reference_registries
            .iter()
            .map(|r| {
                authorize()?;
                r.evidence()
            })
            .collect::<Result<Vec<_>>>()?;
        let recovery_epochs = self
            .reference_journals
            .iter()
            .map(|j| {
                authorize()?;
                j.unchanged()?;
                j.evidence()
            })
            .collect::<Result<Vec<_>>>()?;
        self.pins.recheck()?;
        self.volume.writable()?;
        require(
            firmware()? == self.firmware && command_line()? == self.command_line,
            "actual firmware/current boot state changed",
        )?;
        for d in &self.directories {
            authorize()?;
            d.recheck(&self.volume)?;
        }
        let mut artifacts = value!({});
        for (name, a) in &self.artifacts {
            authorize()?;
            a.recheck()?;
            artifacts[name] = value!({"inode":files::identity(&a.file.metadata()?),"mount":mount_identity::id(a.file.as_fd(),true)?,"bytes":a.bytes,"sha256":a.sha});
        }
        self.recheck_root_loader_directory()?;
        let generations_folder = generations_folder_required(
            &self.volume.path(Path::new(GENERATIONS))?,
            &self.transaction.data["generations"],
        )?;
        require(
            generations_folder == self.directories.iter().any(|d| d.relative == GENERATIONS),
            "original ESP generations folder appeared or disappeared",
        )?;
        let selected = selected(&self.texts, &self.firmware)?;
        let mut result = value!({"schema":1,"role":"boot-retirement-original-context","generation":self.generation,
            "source":self.guard.backup_root_binding()?,"boot_id":operation::boot_id()?,
            "boot_uuid":self.volume.uuid,"boot_mount":self.volume.unique,
            "catalog":self.transaction.data,"catalog_epoch":self.transaction.evidence()?,
            "references":self.idle.records,"reference_epochs":reference_epochs,"recovery_epochs":recovery_epochs,"concrete_boot_references":match &self.transaction {TransactionActor::Owned(_)=>value!(crate::boot_retirement_references::protection(&self.idle.records,&self.generation)?),TransactionActor::Shared(_)=>Value::Null},"pins":self.pins.evidence()?,"artifacts":artifacts,
            "texts":self.texts,"signed_inventory":self.signed_inventory.evidence(&self.volume,authorize)?,"selected":selected,"firmware":self.firmware,
            "command_line":self.command_line,"backend_references_complete":false,
            "retirement_authorized":false,"root_subvolume_retained":true});
        if let Some(original) = self.root_loader_directory {
            result["root_loader_directory"] = value!(original);
        }
        Ok(result)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        require(
            self.current(authorize)? == self.original,
            "original boot retirement context changed; no adoption",
        )
    }
}

mod retirement;
