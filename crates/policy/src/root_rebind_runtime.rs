// SPDX-License-Identifier: MIT
//! Fresh Root preparation or explicit boot-only recovery; package bodies never replay.
use crate::{
    authority_identity, boot_entries,
    boot_volume::Volume,
    catalog::{self, Transaction},
    control_record, control_registry, identity, operation,
    root_rebind_apply::{self, Adapter},
    root_rebind_boot,
    root_rebind_plan::{self, RecoveryOwners, Texts},
    root_rebind_record, root_rebind_verify, signed_entry,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
fn seal(mut record: Value) -> Result<Value> {
    record
        .as_object_mut()
        .ok_or_else(|| Error("rebind record object missing".into()))?
        .remove("journal_sha256");
    let digest = json::fingerprint(&record)?;
    record["journal_sha256"] = value!(digest);
    Ok(record)
}
fn kernels() -> Result<Value> {
    let mut result = value!({});
    for flavor in ["linux", "linux-lts"] {
        let body = operation::query(
            "/usr/bin/pacman",
            &["-Qlq", flavor],
            Duration::from_secs(30),
            2 * 1024 * 1024,
            &[0],
        )?;
        let body = std::str::from_utf8(&body)
            .map_err(|_| Error("rebind kernel package listing encoding".into()))?;
        let versions = body
            .lines()
            .filter_map(|line| {
                line.strip_prefix("/usr/lib/modules/")
                    .and_then(|tail| tail.strip_suffix("/vmlinuz"))
            })
            .collect::<Vec<_>>();
        require(
            versions.len() == 1,
            "rebind installed kernel identity is ambiguous",
        )?;
        identity::safe_id(versions[0])?;
        result[flavor] = value!(versions[0]);
    }
    require(
        result["linux"] != result["linux-lts"],
        "rebind installed flavors overlap",
    )?;
    Ok(result)
}
fn auxiliary(snapshot: &Snapshot) -> Result<RecoveryOwners> {
    let images: BTreeMap<String, Value> =
        serde_json::from_value(snapshot.records["images"].clone())?;
    let activations: BTreeMap<String, Value> =
        serde_json::from_value(snapshot.records["activations"].clone())?;
    RecoveryOwners::from_records(&images, &activations)
}
struct Runtime<'a> {
    authorize: &'a mut dyn FnMut() -> Result<()>,
    snapshot: Snapshot,
    registry: Transaction,
    volume: Volume,
    journal: Value,
    path: PathBuf,
}
impl Runtime<'_> {
    fn durable(&self) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(0))?;
        require(
            control_record::read(
                &parent,
                Path::new(self.path.file_name().unwrap()),
                catalog::MAX_CATALOG,
                self.snapshot.guard.control_mount_id(),
            )? == self.journal,
            "rebind durable journal changed",
        )
    }
    fn lineage(&self) -> Result<()> {
        let id = self.journal["id"].as_str().unwrap();
        let birth = self.snapshot.records["births"]
            .get(id)
            .ok_or_else(|| Error("rebind has no retained publisher birth".into()))?;
        require(
            birth["phase"] == "ready"
                && birth["source"] == self.journal["source"]
                && birth["root"]["path"] == self.journal["target"]["path"]
                && birth["root"]["id"] == self.journal["target"]["id"]
                && birth["root"]["uuid"] == self.journal["target"]["uuid"]
                && birth["snapshot"]["number"] == self.journal["snapshot"]["number"]
                && birth["snapshot"]["object"]["uuid"] == self.journal["snapshot"]["uuid"]
                && birth["inventory_sha256"] == self.journal["inventory_sha256"],
            "rebind differs from durable fallback birth",
        )
    }
}
impl Adapter for Runtime<'_> {
    fn verify(&mut self, journal: &Value) -> Result<()> {
        (self.authorize)()?;
        require(*journal == self.journal, "rebind engine intent changed")?;
        self.snapshot.recheck()?;
        self.durable()?;
        self.registry.recheck()?;
        self.volume.recheck()?;
        self.lineage()?;
        root_rebind_verify::roots(journal, &self.snapshot.guard)?;
        root_rebind_boot::generations(&self.volume, &journal["before_catalog"])?;
        root_rebind_boot::auxiliary(
            &self.volume,
            &self.snapshot.records["images"],
            &self.snapshot.records["activations"],
        )?;
        let original: Texts = serde_json::from_value(journal["before_files"].clone())?;
        let owners = auxiliary(&self.snapshot)?;
        let declaration = self
            .snapshot
            .guard
            .configuration
            .get("legacy_boot_entries")
            .filter(|v| !v.is_null());
        let planned = root_rebind_plan::redirect(
            &journal["before_catalog"],
            &journal["source"],
            &journal["target"],
            &original,
            declaration,
            &owners,
            signed_entry::render_existing,
        )?;
        require(
            planned.catalog == journal["after_catalog"]
                && value!(planned.replacements) == journal["replacements"]
                && value!(planned.affected) == journal["affected"],
            "rebind journal differs from current owned boot plan",
        )?;
        self.snapshot.recheck()
    }
    fn files(&mut self) -> Result<Texts> {
        (self.authorize)()?;
        self.snapshot.recheck()?;
        self.volume.recheck()?;
        root_rebind_boot::texts(&self.volume)
    }
    fn catalog(&mut self) -> Result<Value> {
        (self.authorize)()?;
        self.registry.recheck()?;
        Ok(self.registry.data.clone())
    }
    fn write_file(&mut self, name: &str, body: &str) -> Result<()> {
        (self.authorize)()?;
        self.snapshot.recheck()?;
        self.durable()?;
        self.registry.recheck()?;
        self.volume.writable()?;
        require(
            self.journal["replacements"][name] == body,
            "rebind write not declared by immutable journal",
        )?;
        let original = root_rebind_boot::body(&self.volume, name, boot_entries::MAX_TEXT)?;
        let current = String::from_utf8(original)
            .map_err(|_| Error("rebind current text encoding".into()))?;
        crate::recovery_publication::classify(
            &value!(current),
            &self.journal["before_files"][name],
            &self.journal["replacements"][name],
        )?;
        (self.authorize)()?;
        files::atomic(
            &self.volume.path(Path::new(name))?,
            body.as_bytes(),
            files::public_file_mode(&self.volume.directory)?,
            Some(0),
            true,
        )?;
        require(
            root_rebind_boot::body(&self.volume, name, boot_entries::MAX_TEXT)? == body.as_bytes(),
            "rebind boot write readback changed",
        )?;
        self.snapshot.recheck()?;
        self.volume.recheck()
    }
    fn write_catalog(&mut self, body: &Value) -> Result<()> {
        (self.authorize)()?;
        self.snapshot.recheck()?;
        self.durable()?;
        require(
            *body == self.journal["after_catalog"],
            "rebind undeclared catalog write",
        )?;
        self.registry.data = body.clone();
        (self.authorize)()?;
        self.registry.commit()
    }
    fn finish(&mut self, journal: &Value) -> Result<()> {
        (self.authorize)()?;
        self.snapshot.recheck()?;
        self.durable()?;
        self.registry.recheck()?;
        self.volume.recheck()?;
        let mut complete = journal.clone();
        complete["phase"] = value!("complete");
        let complete = seal(complete)?;
        root_rebind_record::validate(&complete, complete["id"].as_str().unwrap())?;
        (self.authorize)()?;
        files::atomic_bounded(
            &self.path,
            &json::canonical(&complete)?,
            0o600,
            Some(0),
            true,
            catalog::MAX_CATALOG,
        )?;
        self.snapshot.rebind_checkpoint(&complete)?;
        self.journal = complete;
        self.durable()
    }
}
pub fn prepare_locked(id: &str, lock: &files::Lock) -> Result<Value> {
    prepare_authorized(id, lock, &mut || lock.recheck())
}
pub fn prepare_authorized(
    id: &str,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    authorize()?;
    lock.recheck()?;
    crate::namespaces::initial()?;
    identity::safe_id(id)?;
    let mut snapshot = Snapshot::online()?;
    let registry = Transaction::begin()?;
    let volume = Volume::observe()?;
    volume.writable()?;
    let birth = snapshot.records["births"]
        .get(id)
        .ok_or_else(|| Error("fresh rebind fallback birth missing".into()))?
        .clone();
    require(
        birth["phase"] == "ready" && birth["created_boot"] == operation::boot_id()?,
        "fresh rebind requires current completed birth",
    )?;
    let source = birth["source"].clone();
    require(
        source["path"] == snapshot.guard.configuration["root_subvol"],
        "fresh rebind live source changed",
    )?;
    let target = value!({"path":birth["root"]["path"],"id":birth["root"]["id"],"uuid":birth["root"]["uuid"],"ownership":"not-established"});
    let files = root_rebind_boot::texts(&volume)?;
    root_rebind_boot::generations(&volume, &registry.data)?;
    root_rebind_boot::auxiliary(
        &volume,
        &snapshot.records["images"],
        &snapshot.records["activations"],
    )?;
    let old = format!("old-{id}");
    identity::safe_id(&old)?;
    let fallback = registry.data["generations"]
        .get(&old)
        .ok_or_else(|| Error("retained fallback boot publication missing".into()))?;
    require(
        fallback["state"] == "ready" && fallback["material"]["root_identity"] == target,
        "retained fallback publication identity changed",
    )?;
    let defaults = boot_entries::fields(&files["loader/loader.conf"], false)?;
    let menu = boot_entries::menu(&files["limine/limine.conf"])?;
    require(
        defaults.get("default") == Some(&format!("enzimos-{old}-linux.conf"))
            && menu.entries[menu.selected - 1].title == format!("enzimOS {old} linux"),
        "retained fallback is not selected in both loaders",
    )?;
    let kernels = kernels()?;
    for record in registry.data["generations"].as_object().unwrap().values() {
        if record["material"]["root_identity"]["uuid"] == source["uuid"] {
            require(
                record["material"]["inventory_sha256"] == birth["inventory_sha256"]
                    && record["material"]["kernels"] == kernels,
                "registered live source is no longer coherent",
            )?;
        }
    }
    let owners = auxiliary(&snapshot)?;
    let declaration = snapshot
        .guard
        .configuration
        .get("legacy_boot_entries")
        .filter(|v| !v.is_null());
    let planned = root_rebind_plan::redirect(
        &registry.data,
        &source,
        &target,
        &files,
        declaration,
        &owners,
        |text| signed_entry::wrap_locked(text, lock),
    )?;
    let mut hashes = value!({});
    for flavor in ["linux", "linux-lts"] {
        let version = kernels[flavor].as_str().unwrap();
        hashes[flavor] = value!(json::sha256(&files::read(
            Path::new(&format!("/usr/lib/modules/{version}/vmlinuz")),
            128 * 1024 * 1024,
            Some(0),
            true
        )?));
    }
    let journal = seal(
        value!({"schema":1,"id":id,"phase":"prepared","filesystem_uuid":snapshot.guard.configuration["filesystem_uuid"],
        "source":source,"target":target,"snapshot":{"number":birth["snapshot"]["number"],"uuid":birth["snapshot"]["object"]["uuid"]},
        "inventory_sha256":birth["inventory_sha256"],"kernels":kernels,"kernel_hashes":hashes,"authority":authority_identity::observe(&snapshot.guard)?,
        "before_files":files,"replacements":planned.replacements,"before_catalog":registry.data,"after_catalog":planned.catalog,"affected":planned.affected}),
    )?;
    root_rebind_record::validate(&journal, id)?;
    root_rebind_verify::roots(&journal, &snapshot.guard)?;
    authorize()?;
    lock.recheck()?;
    snapshot.prepare_rebind(id)?;
    let folder = Path::new(operation::CONTROL).join("root-rebind-journal");
    files::ensure_directory(&folder, 0o700, 0)?;
    let path = folder.join(format!("{id}.json"));
    authorize()?;
    lock.recheck()?;
    files::atomic_bounded(
        &path,
        &json::canonical(&journal)?,
        0o600,
        Some(0),
        false,
        catalog::MAX_CATALOG,
    )?;
    snapshot.rebind_checkpoint(&journal)?;
    let mut runtime = Runtime {
        authorize,
        snapshot,
        registry,
        volume,
        journal: journal.clone(),
        path,
    };
    root_rebind_apply::apply(&journal, &mut runtime)
}
pub fn resume_locked(id: &str, _lock: &files::Lock) -> Result<Value> {
    let mut authorize = || _lock.recheck();
    crate::namespaces::initial()?;
    identity::safe_id(id)?;
    let guard = crate::storage_runtime::Guard::observe()?;
    let records = control_registry::read(
        &guard,
        "root-rebind-journal",
        32,
        root_rebind_record::validate,
    )?;
    let journal = records
        .get(id)
        .ok_or_else(|| Error("explicit rebind record missing".into()))?
        .clone();
    require(
        records
            .iter()
            .all(|(name, record)| name == id || record["phase"] == "complete"),
        "another rebind requires review",
    )?;
    if journal["phase"] == "complete" {
        return Ok(value!({"status":"already-complete","id":id,"packages_replayed":false}));
    }
    let snapshot = Snapshot::rebind_existing(&journal)?;
    let registry = Transaction::begin()?;
    let volume = Volume::observe()?;
    let path = Path::new(operation::CONTROL)
        .join("root-rebind-journal")
        .join(format!("{id}.json"));
    let mut runtime = Runtime {
        authorize: &mut authorize,
        snapshot,
        registry,
        volume,
        journal: journal.clone(),
        path,
    };
    root_rebind_apply::apply(&journal, &mut runtime)
}
pub fn status() -> Result<Value> {
    crate::namespaces::initial()?;
    let guard = crate::storage_runtime::Guard::observe()?;
    let records = control_registry::read(
        &guard,
        "root-rebind-journal",
        32,
        root_rebind_record::validate,
    )?;
    require(
        records
            .values()
            .all(|record| record["filesystem_uuid"] == guard.configuration["filesystem_uuid"]),
        "foreign root rebind requires review",
    )?;
    let pending = records
        .iter()
        .filter(|(_, record)| record["phase"] != "complete")
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    Ok(value!({"pending":pending,"retirement_enabled":false}))
}
