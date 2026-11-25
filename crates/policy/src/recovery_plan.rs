// SPDX-License-Identifier: MIT
//! Online preparation records a fresh exact source before the independent boot.
use crate::{
    birth_runtime,
    boot_volume::Volume,
    catalog, identity, native_policy_files, operation, recovery_context,
    recovery_journal::{Journal, Kind},
    recovery_records as records,
    storage_runtime::TopMount,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{os::fd::AsFd, path::Path};
pub struct Review {
    idle: Snapshot,
    ledger: catalog::Transaction,
    volume: Volume,
    births: birth_runtime::Store,
    live: std::fs::File,
    actual: Value,
    birth_id: String,
    generation: String,
}
impl Review {
    pub fn open(birth_id: &str, generation: &str) -> Result<Self> {
        identity::safe_id(birth_id)?;
        identity::safe_id(generation)?;
        let idle = Snapshot::online()?;
        let config = &idle.guard.configuration;
        let filesystem = records::text(config, "filesystem_uuid")?;
        require(
            matches!(std::fs::symlink_metadata("/var/lib/pacman/db.lck"),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "package transaction prevents recovery planning",
        )?;
        let ledger = catalog::Transaction::begin()?;
        let generation_record = &ledger.data["generations"][generation];
        require(
            generation_record["state"] == "ready",
            "ready registered recovery generation required",
        )?;
        let volume = Volume::observe()?;
        require(
            recovery_context::fingerprint_entries(&volume, generation_record)?
                == generation_record["entry_fingerprints"],
            "recovery generation boot bindings changed",
        )?;
        let births = birth_runtime::Store::open(false)?;
        require(
            births.configuration() == config
                && births.control_mount_id() == idle.guard.control_mount_id(),
            "recovery birth registry storage differs",
        )?;
        births.recheck()?;
        let source = births
            .records
            .get(birth_id)
            .ok_or_else(|| Error("recorded recovery birth missing".into()))?;
        require(
            source["phase"] == "ready" && source["source"]["path"] == config["root_subvol"],
            "completed birth from current configured root required",
        )?;
        let source_name = records::text(config, "root_subvol")?;
        let (live, actual, readonly) =
            birth_runtime::observe(Path::new("/"), source_name, filesystem)?;
        require(
            !readonly
                && ["id", "uuid"]
                    .iter()
                    .all(|key| actual[*key] == source["source"][*key]),
            "actual configured source root changed",
        )?;
        let rows = crate::storage_runtime::rows()?;
        let roots = rows
            .iter()
            .filter(|row| row.target == "/")
            .collect::<Vec<_>>();
        require(
            roots.len() == 1 && roots[0].root == format!("/{source_name}"),
            "configured live root mount differs",
        )?;
        let this = Self {
            idle,
            ledger,
            volume,
            births,
            live,
            actual,
            birth_id: birth_id.into(),
            generation: generation.into(),
        };
        this.view()?;
        Ok(this)
    }
    pub fn view(&self) -> Result<Value> {
        self.idle.recheck()?;
        self.ledger.recheck()?;
        self.volume.recheck()?;
        self.births.recheck()?;
        let name = records::text(&self.idle.guard.configuration, "root_subvol")?;
        require(
            crate::subvolume::observe(self.live.as_fd(), name)? == (self.actual.clone(), false),
            "original recovery live source changed",
        )?;
        let source = &self.births.records[&self.birth_id];
        let generation = &self.ledger.data["generations"][&self.generation];
        require(
            source["phase"] == "ready" && generation["state"] == "ready",
            "recovery selection ceased to be ready",
        )?;
        let jobs = Journal::open(Kind::Jobs, false)?;
        let view = value!({"storage":self.idle.guard.configuration,"boot_id":operation::boot_id()?,
            "birth":source,"generation":generation,"live_root":self.actual,
            "catalog_epoch":self.ledger.evidence()?,"birth_epochs":self.births.evidence()?,
            "jobs_epoch":jobs.evidence()?,"idle":self.idle.records,
            "boot_uuid":self.volume.uuid,"boot_mount":self.volume.unique,
            "boot_entries":recovery_context::fingerprint_entries(&self.volume,generation)?});
        jobs.unchanged()?;
        self.idle.recheck()?;
        self.ledger.recheck()?;
        self.births.recheck()?;
        self.volume.recheck()?;
        require(
            crate::subvolume::observe(self.live.as_fd(), name)? == (self.actual.clone(), false),
            "original recovery source changed during review",
        )?;
        Ok(view)
    }
}
pub fn prepare_locked(
    id: &str,
    birth_id: &str,
    generation: &str,
    lock: &files::Lock,
) -> Result<Value> {
    prepare_authorized(id, birth_id, generation, lock, &mut || lock.recheck())
}
/// Fresh checks surround temporary mounts and original durable job publication.
pub(crate) fn prepare_authorized<F: FnMut() -> Result<()>>(
    id: &str,
    birth_id: &str,
    generation: &str,
    lock: &files::Lock,
    authorize: &mut F,
) -> Result<Value> {
    prepare_checked(id, birth_id, generation, lock, None, authorize)
}
pub(crate) fn prepare_reviewed<F: FnMut() -> Result<()>>(
    id: &str,
    birth_id: &str,
    generation: &str,
    lock: &files::Lock,
    expected: &Value,
    authorize: &mut F,
) -> Result<Value> {
    prepare_checked(id, birth_id, generation, lock, Some(expected), authorize)
}
fn prepare_checked<F: FnMut() -> Result<()>>(
    id: &str,
    birth_id: &str,
    generation: &str,
    lock: &files::Lock,
    expected: Option<&Value>,
    authorize: &mut F,
) -> Result<Value> {
    records::job_id(id)?;
    identity::safe_id(birth_id)?;
    identity::safe_id(generation)?;
    authorize()?;
    lock.recheck()?;
    let review = Review::open(birth_id, generation)?;
    if let Some(expected) = expected {
        require(
            review.view()? == *expected,
            "recovery preparation review changed",
        )?;
    }
    let Review {
        idle,
        ledger,
        volume,
        births,
        live,
        actual,
        ..
    } = review;
    let config = &idle.guard.configuration;
    let filesystem = records::text(config, "filesystem_uuid")?;
    let generation_record = &ledger.data["generations"][generation];
    let source = &births.records[birth_id];
    let source_name = records::text(config, "root_subvol")?;
    let inventory = recovery_context::subvolumes(Path::new("/"))?;
    let target = format!("enzimos-recovered-{id}");
    require(
        !inventory.contains_key(&target),
        "existing recovery destination cannot be adopted",
    )?;
    authorize()?;
    lock.recheck()?;
    idle.recheck()?;
    ledger.recheck()?;
    births.recheck()?;
    let mut top = TopMount::open(&idle.guard)?;
    let mut held = Vec::new();
    for role in ["root", "history"] {
        let object = &source[role];
        let path = records::text(object, "path")?;
        let (file, current, readonly) =
            birth_runtime::observe(&top.path().join(path), path, filesystem)?;
        require(
            inventory.get(path) == Some(object) && current == *object && !readonly,
            "recorded fallback material changed",
        )?;
        held.push((path.to_owned(), object.clone(), file));
    }
    let snapshot_object = &source["snapshot"]["object"];
    let relative = records::text(snapshot_object, "path")?;
    let snapshot_path = top.path().join(relative);
    let (snapshot, current, readonly) =
        birth_runtime::observe(&snapshot_path, relative, filesystem)?;
    require(
        current == *snapshot_object && readonly && inventory.get(relative) == Some(snapshot_object),
        "recovery source snapshot changed or writable",
    )?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == native_policy_files::observe(&snapshot_path.join("usr/lib/enzimos-native"))?,
        "snapshot native policy is incompatible; no injection permitted",
    )?;
    let mut protected = serde_json::Map::new();
    for (role, mount) in [
        ("home", "/home"),
        ("authority", "/etc/pacman.d/gnupg"),
        ("control", operation::CONTROL),
    ] {
        let path = records::text(config, &format!("{role}_subvol"))?;
        let expected = inventory
            .get(path)
            .ok_or_else(|| Error("protected recovery subvolume missing".into()))?;
        let (file, current, readonly) = birth_runtime::observe(Path::new(mount), path, filesystem)?;
        require(
            current == *expected && !readonly,
            "protected recovery storage identity changed",
        )?;
        held.push((path.to_owned(), expected.clone(), file));
        protected.insert(role.into(), expected.clone());
    }
    let mut plan = value!({"schema":1,"id":id,"created_boot":operation::boot_id()?,"filesystem_uuid":filesystem,"boot_uuid":volume.uuid,"storage":config,"protected":protected,"source_birth":source,"generation":generation,"target_name":target,"material":generation_record["material"]});
    plan["plan_sha256"] = value!(json::fingerprint(&plan)?);
    records::plan(&plan)?;
    recovery_context::contents(&plan, &snapshot_path, &volume)?;
    authorize()?;
    lock.recheck()?;
    births.recheck()?;
    let mut jobs = Journal::open(Kind::Jobs, true)?;
    require(
        !jobs.records.contains_key(id),
        "recovery job already recorded; no replay",
    )?;
    idle.recheck()?;
    ledger.recheck()?;
    jobs.unchanged()?;
    volume.recheck()?;
    top.recheck()?;
    require(
        crate::subvolume::observe(live.as_fd(), source_name)? == (actual, false)
            && crate::subvolume::observe(snapshot.as_fd(), relative)?
                == (snapshot_object.clone(), true),
        "retained recovery planning source changed",
    )?;
    for (relative, expected, file) in held {
        require(
            crate::subvolume::observe(file.as_fd(), &relative)? == (expected, false),
            "retained recovery planning identity changed",
        )?;
    }
    // Normal unmount before publication; a failed cleanup cannot produce a usable plan.
    drop(snapshot);
    top.close()?;
    idle.recheck()?;
    ledger.recheck()?;
    let job = value!({"plan":plan,"phase":"planned","stage_boot":null,"root":null,"history":null});
    authorize()?;
    lock.recheck()?;
    idle.recheck()?;
    ledger.recheck()?;
    births.recheck()?;
    jobs.unchanged()?;
    jobs.save(id, job, None, lock)?;
    Ok(
        value!({"status":"recovery-plan-prepared","id":id,"plan_sha256":plan["plan_sha256"],"target_name":target,"activation_available":false,"retirement_enabled":false}),
    )
}
