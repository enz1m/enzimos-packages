// SPDX-License-Identifier: MIT
//! One locked publication copies, signs, observes, registers and selects both loaders.
use crate::{
    boot_entries,
    boot_volume::Volume,
    catalog::{self, Transaction},
    control_record, generation_publication as journal,
    generation_stage::Stage,
    operation, recovery_boot, root_rebind_boot, signed_entry,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, publication, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
struct Runtime<'a> {
    source: &'a Stage,
    authorize: &'a mut dyn FnMut() -> Result<()>,
    snapshot: Snapshot,
    registry: Transaction,
    volume: Volume,
    record: Value,
    receipt: PathBuf,
    receipt_directory: File,
    receipt_shape: (u64, u64, u32, u32, u32),
    metadata: BTreeMap<String, String>,
    original_metadata: BTreeMap<String, crate::boot_volume::Artifact>,
    published_metadata: BTreeMap<String, publication::Committed>,
    receipt_registry: enzimos_platform::receipt_registry::Registry,
    output: Option<crate::generation_destination::Destination>,
    authority: crate::authority_mount::Authority,
    authority_hashes: Value,
    owner: crate::secure_owner_source::Owner,
}
impl Runtime<'_> {
    fn verify(&mut self) -> Result<()> {
        (self.authorize)()?;
        self.source.recheck()?;
        self.owner.recheck()?;
        self.snapshot.recheck()?;
        self.registry.recheck()?;
        self.volume.writable()?;
        self.authority.recheck(&self.snapshot.guard)?;
        require(
            self.authority.hashes()? == self.authority_hashes,
            "original independent package authority changed during boot publication",
        )?;
        if let Some(output) = &self.output {
            output.recheck(&self.volume)?;
        }
        require(
            self.source.material == self.record["material"],
            "generation publication source material changed",
        )?;
        for artifact in self.original_metadata.values() {
            artifact.recheck()?;
        }
        for published in self.published_metadata.values() {
            published.recheck()?;
        }
        require(
            root_rebind_boot::texts(&self.volume)? == self.metadata,
            "original or published boot metadata membership or bytes drifted",
        )?;
        let parent = files::directory(
            self.receipt
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        for directory in [&self.receipt_directory, &parent] {
            let m = directory.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()) == self.receipt_shape
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o700
                    && mount_identity::id(directory.as_fd(), true)?
                        == self.snapshot.guard.control_mount_id(),
                "original generation receipt directory changed/covered",
            )?;
        }
        self.receipt_registry.recheck()?;
        if self.snapshot.records["boot_publications"]
            .get(enzimos_platform::json::string(&self.record["generation"])?)
            .is_some()
        {
            require(
                files::read_file(
                    self.receipt_registry.descriptor()?,
                    catalog::MAX_CATALOG,
                    Some(0),
                    true,
                )? == json::canonical(&self.record)?,
                "original generation receipt publication changed",
            )?;
        }
        if self.snapshot.records["boot_publications"]
            .get(enzimos_platform::json::string(&self.record["generation"])?)
            .is_some()
        {
            let parent = files::directory(
                self.receipt
                    .parent()
                    .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
                Some(0),
            )?;
            require(
                control_record::read(
                    &parent,
                    Path::new(
                        self.receipt
                            .file_name()
                            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
                    ),
                    catalog::MAX_CATALOG,
                    self.snapshot.guard.control_mount_id(),
                )? == self.record,
                "original durable generation publication receipt changed",
            )?;
        }
        Ok(())
    }
    fn checkpoint(&mut self, phase: &str) -> Result<()> {
        self.verify()?;
        let before = self.snapshot.records["boot_publications"]
            .get(enzimos_platform::json::string(&self.record["generation"])?)
            .cloned();
        self.record["phase"] = value!(phase);
        self.record = journal::seal(self.record.clone())?;
        journal::transition(
            before.as_ref(),
            &self.record,
            enzimos_platform::json::string(&self.record["generation"])?,
        )?;
        let bytes = json::canonical(&self.record)?;
        self.receipt_registry.publish(&bytes, self.authorize)?;
        self.snapshot.boot_checkpoint(&self.record)?;
        self.verify()
    }
    fn write(&mut self, name: &str, text: String, replace: bool) -> Result<()> {
        self.verify()?;
        let path = self.volume.path(Path::new(name))?;
        let parent = self.volume.directory(
            Path::new(name)
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        )?;
        require(
            mount_identity::id(parent.as_fd(), true)? == self.volume.unique,
            "generation metadata destination crosses another mount",
        )?;
        if !replace {
            require(
                matches!(std::fs::symlink_metadata(&path),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "existing generation entry cannot be adopted",
            )?;
        }
        let original = if replace {
            Some(if let Some(published) = self.published_metadata.get(name) {
                published.file()?.try_clone()?
            } else {
                self.original_metadata
                    .get(name)
                    .ok_or_else(|| Error("original metadata description missing".into()))?
                    .file
                    .try_clone()?
            })
        } else {
            None
        };
        let prepared =
            publication::Prepared::write_authorized(&path, text.as_bytes(), 0, self.authorize)?;
        if let Some(original) = &original {
            prepared.require_original(original)?;
        }
        let published = prepared.commit_retained_authorized(replace, self.authorize)?;
        self.original_metadata.remove(name);
        self.published_metadata.insert(name.into(), published);
        self.metadata.insert(name.into(), text);
        self.verify()
    }
    fn artifacts(&mut self, directory: &File) -> Result<()> {
        for row in enzimos_platform::json::array(&self.source.material["files"])? {
            let file = files::open_relative(
                directory,
                Path::new(enzimos_platform::json::string(&row["name"])?),
            )?;
            require(
                mount_identity::id(file.as_fd(), true)? == self.volume.unique
                    && enzimos_platform::stream_copy::hash_borrowed(
                        &file,
                        128 * 1024 * 1024,
                        Some(0),
                    )? == (
                        enzimos_platform::json::unsigned(&row["bytes"])?,
                        enzimos_platform::json::string(&row["sha256"])?.into(),
                    ),
                "published generation artifact bytes or mount differ",
            )?;
        }
        self.verify()
    }
}
pub fn publish_locked(source: &Stage, generation: &str, lock: &files::Lock) -> Result<Value> {
    publish_authorized(source, generation, lock, &mut || lock.recheck())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn publish_authorized(
    source: &Stage,
    generation: &str,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    authorize()?;
    lock.recheck()?;
    operation::root_only()?;
    crate::identity::safe_id(generation)?;
    catalog::material(&source.material, generation)?;
    let snapshot = Snapshot::boot_publication(generation)?;
    let authority = crate::authority_mount::Authority::observe(&snapshot.guard)?;
    let authority_hashes = authority.hashes()?;
    require(
        *source.filesystem_uuid() == snapshot.guard.configuration["filesystem_uuid"],
        "generation source filesystem differs from original installed guard",
    )?;
    let registry = Transaction::begin()?;
    require(
        registry.data["generations"].get(generation).is_none()
            && registry
                .data
                .get("retired")
                .and_then(|r| r.get(generation))
                .is_none(),
        "registered or retired generation name cannot be adopted",
    )?;
    let volume = Volume::observe()?;
    volume.writable()?;
    root_rebind_boot::generations(&volume, &registry.data)?;
    let metadata = root_rebind_boot::texts(&volume)?;
    require(
        metadata.len() <= 126,
        "both new loader entries must fit before publication intent",
    )?;
    let mut original_metadata = BTreeMap::new();
    for (name, text) in &metadata {
        authorize()?;
        let artifact = volume.artifact(Path::new(name), boot_entries::MAX_TEXT as u64)?;
        require(
            files::read_file(&artifact.file, boot_entries::MAX_TEXT, Some(0), true)?
                == text.as_bytes(),
            "original initial generation metadata changed",
        )?;
        original_metadata.insert(name.clone(), artifact);
    }
    let directory_name = format!("enzimos/generations/{generation}");
    let destination = volume.path(Path::new(&directory_name))?;
    require(
        matches!(std::fs::symlink_metadata(&destination),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "existing or partial generation directory cannot be adopted",
    )?;
    let owner = crate::secure_owner_source::Owner::observe()?;
    let certificate = owner.certificate_hash();
    let record = journal::seal(
        value!({"schema":1,"generation":generation,"phase":"intent","created_boot":operation::boot_id()?,"filesystem_uuid":snapshot.guard.configuration["filesystem_uuid"],"material":source.material,
        "bios_before":metadata["limine/limine.conf"],"defaults_before":metadata["loader/loader.conf"],"certificate_sha256":certificate}),
    )?;
    let entries = journal::entries(generation, &source.material, certificate.as_deref())?;
    for name in entries.keys() {
        require(
            !metadata.contains_key(name)
                && matches!(std::fs::symlink_metadata(volume.path(Path::new(name))?),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "existing or partial generation loader entry cannot be adopted",
        )?;
    }
    let artifact_bytes = enzimos_platform::json::array(&source.material["files"])?
        .iter()
        .try_fold(0u64, |sum, row| {
            sum.checked_add(enzimos_platform::json::unsigned(&row["bytes"])?)
                .ok_or_else(|| Error("generation ESP reservation overflow".into()))
        })?;
    let needed =
        crate::update_resources::publication_required(artifact_bytes, certificate.is_some())?;
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `info` is a writable `libc::statvfs` and `volume.directory` keeps the descriptor
        // open.
        unsafe { libc::fstatvfs(volume.directory.as_raw_fd(), &mut info) } == 0
            && (info.f_bavail as u64)
                .checked_mul(info.f_frsize as u64)
                .is_some_and(|free| free >= needed),
        "generation publication ESP headroom",
    )?;
    let receipts = Path::new(operation::CONTROL).join("boot-publications");
    authorize()?;
    lock.recheck()?;
    let receipt_directory = files::ensure_directory(&receipts, 0o700, 0)?;
    require(
        mount_identity::id(receipt_directory.as_fd(), true)? == snapshot.guard.control_mount_id(),
        "publication receipt cannot cross another mount",
    )?;
    let receipt_registry = enzimos_platform::receipt_registry::Registry::observe(
        &receipts,
        &receipt_directory,
        &format!("{generation}.json"),
        0,
    )?;
    let m = receipt_directory.metadata()?;
    let receipt_shape = (m.dev(), m.ino(), m.mode(), m.uid(), m.gid());
    let mut runtime = Runtime {
        source,
        authorize,
        snapshot,
        registry,
        volume,
        record,
        receipt: receipts.join(format!("{generation}.json")),
        receipt_directory,
        receipt_shape,
        metadata,
        original_metadata,
        published_metadata: BTreeMap::new(),
        receipt_registry,
        output: None,
        authority,
        authority_hashes,
        owner,
    };
    runtime.checkpoint("intent")?;
    crate::secure_loader_refresh::refresh_authorized(&runtime.volume, lock, runtime.authorize)?;
    runtime.verify()?;
    runtime.registry.data = catalog::reserve_document(
        &runtime.registry.data,
        generation,
        &source.material,
        &operation::boot_id()?,
    )?;
    runtime.verify()?;
    runtime.registry.commit()?;
    runtime.verify()?;
    let directory_mode = files::public_directory_mode(&runtime.volume.directory)?;
    let parent = files::ensure_directory(
        &runtime.volume.path(Path::new("enzimos/generations"))?,
        directory_mode,
        0,
    )?;
    require(
        mount_identity::id(parent.as_fd(), true)? == runtime.volume.unique,
        "generation parent crosses another mount",
    )?;
    runtime.verify()?;
    let directory = files::create_directory(&destination, directory_mode, 0)?;
    require(
        mount_identity::id(directory.as_fd(), true)? == runtime.volume.unique,
        "new generation crosses another mount",
    )?;
    source.copy_authorized(&directory, runtime.authorize)?;
    runtime.verify()?;
    runtime.output = Some(crate::generation_destination::Destination::capture(
        &directory,
        generation,
        &runtime.volume,
    )?);
    runtime.artifacts(&directory)?;
    runtime.checkpoint("artifacts")?;
    let ready = value!({"generation":generation,"kernels":source.material["kernels"],"files":source.material["files"]});
    runtime.verify()?;
    let ready_publication = publication::Prepared::write_authorized(
        &destination.join("READY.json"),
        &json::canonical(&ready)?,
        0,
        runtime.authorize,
    )?
    .commit_retained_authorized(false, runtime.authorize)?;
    runtime
        .output
        .as_mut()
        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
        .add_published("READY.json", &runtime.volume, ready_publication)?;
    require(
        json::decode(
            &root_rebind_boot::body(
                &runtime.volume,
                &format!("{directory_name}/READY.json"),
                catalog::MAX_CATALOG,
            )?,
            catalog::MAX_CATALOG,
        )? == ready,
        "generation READY readback differs",
    )?;
    runtime.checkpoint("ready")?;
    let unsigned = journal::entries(generation, &source.material, None)?;
    for (flavor, phase) in [("linux", "linux-entry"), ("linux-lts", "lts-entry")] {
        let name = format!("loader/entries/enzimos-{generation}-{flavor}.conf");
        runtime.verify()?;
        let signed = signed_entry::wrap_locked(&unsigned[&name], lock)?;
        require(
            signed == entries[&name],
            "original owner authority changed while building generation entry",
        )?;
        runtime.write(&name, signed, false)?;
        runtime.checkpoint(phase)?;
    }
    let bios = journal::bios(
        generation,
        &source.material,
        enzimos_platform::json::string(&runtime.record["bios_before"])?,
    )?;
    runtime.write("limine/limine.conf", bios.clone(), true)?;
    runtime.checkpoint("bios")?;
    let published = value!({"generation":generation,"bios_first_entry":boot_entries::menu(enzimos_platform::json::string(&runtime.record["bios_before"])?)?.entries.len()+1,"flavors":["linux","linux-lts"]});
    runtime.verify()?;
    let published_publication = publication::Prepared::write_authorized(
        &destination.join("PUBLISHED.json"),
        &json::canonical(&published)?,
        0,
        runtime.authorize,
    )?
    .commit_retained_authorized(false, runtime.authorize)?;
    runtime
        .output
        .as_mut()
        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
        .add_published("PUBLISHED.json", &runtime.volume, published_publication)?;
    require(
        json::decode(
            &root_rebind_boot::body(
                &runtime.volume,
                &format!("{directory_name}/PUBLISHED.json"),
                catalog::MAX_CATALOG,
            )?,
            catalog::MAX_CATALOG,
        )? == published,
        "generation PUBLISHED readback differs",
    )?;
    runtime.checkpoint("published")?;
    let observed = entries
        .iter()
        .map(|(name, text)| {
            (
                name.strip_prefix("loader/entries/")
                    .expect("journal entries are all named under loader/entries/")
                    .to_owned(),
                text.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for text in observed.values() {
        signed_entry::verify(&boot_entries::fields(text, false)?)?;
    }
    let fingerprints = boot_entries::fingerprint_entries(
        &runtime.registry.data["generations"][generation],
        &observed,
        &bios,
    )?;
    runtime.artifacts(&directory)?;
    runtime.registry.data =
        catalog::publish_document(&runtime.registry.data, generation, &fingerprints)?;
    runtime.verify()?;
    runtime.registry.commit()?;
    runtime.checkpoint("registry")?;
    runtime.write(
        "loader/loader.conf",
        recovery_boot::replace_default(
            enzimos_platform::json::string(&runtime.record["defaults_before"])?,
            "default ",
            &format!("enzimos-{generation}-linux.conf"),
        )?,
        true,
    )?;
    runtime.checkpoint("uefi-selected")?;
    let number = boot_entries::number(&bios, &format!("enzimOS {generation} linux"))?;
    runtime.write(
        "limine/limine.conf",
        recovery_boot::replace_default(&bios, "default_entry: ", &number.to_string())?,
        true,
    )?;
    runtime.checkpoint("bios-selected")?;
    runtime.artifacts(&directory)?;
    root_rebind_boot::generations(&runtime.volume, &runtime.registry.data)?;
    for text in observed.values() {
        signed_entry::verify(&boot_entries::fields(text, false)?)?;
    }
    runtime.checkpoint("complete")?;
    Ok(
        value!({"generation":generation,"files":source.material["files"],"selected":"linux","status":"prepared-not-rebooted","installed_qualification":false}),
    )
}
