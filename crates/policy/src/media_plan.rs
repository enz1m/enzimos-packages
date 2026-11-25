// SPDX-License-Identifier: MIT
//! Native media creates a fresh sealed plan before a one-attempt restore workflow.
use crate::{
    birth, birth_runtime,
    boot_volume::Volume,
    catalog, control_record, filesystem, identity, media_origin, native_policy_files, operation,
    recovery_context::{self, Context},
    recovery_journal::{Journal, Kind},
    recovery_records as records, storage,
    storage_runtime::IndependentGuard,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
#[expect(
    clippy::too_many_arguments,
    reason = "Each argument is one independently reviewed plan input."
)]
pub(crate) fn document(
    id: &str,
    config: &Value,
    origin: &Value,
    boot: &str,
    source: &Value,
    generation: &str,
    record: &Value,
    inventory: &std::collections::BTreeMap<String, Value>,
) -> Result<Value> {
    records::job_id(id)?;
    identity::safe_id(generation)?;
    storage::validate(config)?;
    records::media_origin(origin)?;
    records::fat_uuid(boot)?;
    let filesystem = records::text(config, "filesystem_uuid")?;
    birth::validate(source, records::text(source, "transaction")?, filesystem)?;
    require(
        source["phase"] == "ready"
            && source["source"]["path"] == config["root_subvol"]
            && record["state"] == "ready"
            && record["generation"] == generation,
        "completed source birth and generation required",
    )?;
    for role in ["root", "history"] {
        let object = &source[role];
        let name = records::text(object, "path")?;
        require(
            inventory.get(name) == Some(object),
            "media source ownership changed",
        )?;
    }
    let snapshot = &source["snapshot"]["object"];
    require(
        inventory.get(records::text(snapshot, "path")?) == Some(snapshot),
        "media snapshot ownership changed",
    )?;
    let mut protected = serde_json::Map::new();
    for role in ["home", "authority", "control"] {
        let name = records::text(config, &format!("{role}_subvol"))?;
        protected.insert(
            role.into(),
            inventory
                .get(name)
                .ok_or_else(|| Error("protected media root missing".into()))?
                .clone(),
        );
    }
    let target = format!("enzimos-recovered-{id}");
    require(
        !inventory.contains_key(&target),
        "existing media destination cannot be adopted",
    )?;
    let mut plan = value!({"schema":2,"id":id,"created_boot":origin["boot_id"],"media_origin":origin,"filesystem_uuid":filesystem,
        "boot_uuid":boot,"storage":config,"protected":protected,"source_birth":source,"generation":generation,"target_name":target,"material":record["material"]});
    plan["plan_sha256"] = value!(json::fingerprint(&plan)?);
    records::plan(&plan)?;
    Ok(plan)
}
fn record(folder: &str, name: &str, mount: u64) -> Result<Value> {
    let parent = files::directory(&Path::new(operation::CONTROL).join(folder), Some(0))?;
    control_record::read(&parent, Path::new(name), catalog::MAX_CATALOG, mount)
}
pub(crate) fn prepare_locked(
    config: &Value,
    birth_id: &str,
    generation: &str,
    lock: &files::Lock,
) -> Result<Value> {
    identity::safe_id(birth_id)?;
    identity::safe_id(generation)?;
    storage::validate(config)?;
    let origin = media_origin::current()?;
    crate::recovery_bootstrap::quiet()?;
    let top = files::directory(Path::new(IndependentGuard::TOP), Some(0))?;
    let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
    require(
        filesystem::observe(top.as_fd())?["filesystem_uuid"] == config["filesystem_uuid"]
            && filesystem::observe(control.as_fd())?["filesystem_uuid"]
                == config["filesystem_uuid"]
            && control.metadata()?.uid() == 0
            && control.metadata()?.mode() & 0o7777 == 0o700,
        "media control and top storage binding refused",
    )?;
    let mount = mount_identity::id(control.as_fd(), true)?;
    let source = record("root-births", &format!("{birth_id}.json"), mount)?;
    let catalog = record("generation-registry", "catalog.json", mount)?;
    crate::catalog::validate(&catalog, records::text(config, "filesystem_uuid")?)?;
    let inventory = recovery_context::subvolumes(Path::new(IndependentGuard::TOP))?;
    let volume = Volume::observe()?;
    let id = format!("media-{}", files::random_hex(12)?);
    let plan = document(
        &id,
        config,
        &origin,
        &volume.uuid,
        &source,
        generation,
        &catalog["generations"][generation],
        &inventory,
    )?;
    let context = Context::observe(&plan)?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == native_policy_files::observe(&context.source_path.join("usr/lib/enzimos-native"))?,
        "snapshot native policy differs from installer media; use matching media",
    )?;
    require(
        recovery_context::private_records(
            &context.guard,
            "root-births",
            birth_runtime::MAX_RECORDS,
            |v, id| birth::validate(v, id, records::text(config, "filesystem_uuid")?),
        )?
        .get(birth_id)
            == Some(&source),
        "media birth changed during planning",
    )?;
    let mut jobs = Journal::open_independent(Kind::Jobs, true, &plan)?;
    require(
        jobs.records.len() < records::MAX_JOBS
            && jobs.records.values().all(|v| v["phase"] == "staged"),
        "unfinished recovery plan prevents a new media attempt",
    )?;
    for (kind, key, phase) in [
        (Kind::Runs, "phase", "complete"),
        (Kind::Workflows, "state", "complete"),
        (Kind::Activations, "phase", "adopted"),
        (Kind::Media, "phase", "complete"),
    ] {
        let journal = Journal::open_independent(kind, false, &plan)?;
        require(
            journal.records.values().all(|v| v[key] == phase),
            "unfinished recovery prevents a new media attempt",
        )?;
        journal.unchanged()?;
    }
    require(
        record("generation-registry", "catalog.json", mount)? == catalog
            && recovery_context::subvolumes(Path::new(IndependentGuard::TOP))? == inventory,
        "media catalog or inventory changed during planning",
    )?;
    context.recheck()?;
    jobs.unchanged()?;
    volume.recheck()?;
    let job = value!({"plan":plan,"phase":"planned","stage_boot":null,"root":null,"history":null});
    jobs.save(&id, job, None, lock)?;
    Ok(plan)
}
pub(crate) fn execute_locked<F: FnMut(&str, &Value) -> Result<()>>(
    plan: &Value,
    lock: &files::Lock,
    observer: F,
) -> Result<Value> {
    records::plan(plan)?;
    require(
        plan["schema"] == 2 && media_origin::current()? == plan["media_origin"],
        "current direct native media plan required",
    )?;
    let id = records::text(plan, "id")?;
    let jobs = Journal::open_independent(Kind::Jobs, false, plan)?;
    require(
        jobs.records
            .get(id)
            .is_some_and(|j| j["phase"] == "planned" && j["plan"] == *plan),
        "exact unstarted media job required",
    )?;
    let mut media = Journal::open_independent(Kind::Media, true, plan)?;
    require(
        !media.records.contains_key(id) && media.records.values().all(|v| v["phase"] == "complete"),
        "media attempt already exists or is uncertain; no replay",
    )?;
    let context = Context::observe(plan)?;
    context.recheck()?;
    jobs.unchanged()?;
    media.unchanged()?;
    let running = value!({"schema":1,"id":id,"phase":"running","plan_sha256":plan["plan_sha256"],"media_origin":plan["media_origin"]});
    media.save(id, running.clone(), None, lock)?;
    let result = crate::recovery_workflow::execute_locked(
        id,
        records::text(plan, "plan_sha256")?,
        "linux",
        lock,
        observer,
    );
    let mut terminal = running.clone();
    terminal["phase"] = value!(if result.is_ok() { "executed" } else { "failed" });
    media.unchanged()?;
    media.save(id, terminal, Some(&running), lock)?;
    result
}
/// Retained snapshots that a media restore may target: ready births of the
/// configured root matched to ready catalog generations with the same root UUID.
pub(crate) fn choices(config: &Value) -> Result<Vec<Value>> {
    storage::validate(config)?;
    let filesystem = records::text(config, "filesystem_uuid")?;
    media_origin::current()?;
    let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
    let mount = mount_identity::id(control.as_fd(), true)?;
    let catalog = record("generation-registry", "catalog.json", mount)?;
    crate::catalog::validate(&catalog, filesystem)?;
    let folder = Path::new(operation::CONTROL).join("root-births");
    let directory = files::directory(&folder, Some(0))?;
    require(
        mount_identity::id(directory.as_fd(), true)? == mount,
        "root birth registry crosses a mount",
    )?;
    let mut names = std::fs::read_dir(&folder)?
        .take(birth_runtime::MAX_RECORDS + 1)
        .map(|row| {
            row?.file_name()
                .into_string()
                .map_err(|_| Error("root birth filename encoding".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    require(
        names.len() <= birth_runtime::MAX_RECORDS,
        "root birth registry count bound",
    )?;
    names.sort();
    let mut result = Vec::new();
    for name in names {
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| Error("unknown or interrupted root birth write".into()))?;
        identity::safe_id(id)?;
        let source =
            control_record::read(&directory, Path::new(&name), catalog::MAX_CATALOG, mount)?;
        birth::validate(&source, id, filesystem)?;
        if source["phase"] != "ready" || source["source"]["path"] != config["root_subvol"] {
            continue;
        }
        let Some(generations) = catalog["generations"].as_object() else {
            continue;
        };
        for (generation, record) in generations {
            if record["state"] == "ready"
                && record["material"]["root_identity"]["uuid"] == source["root"]["uuid"]
            {
                result.push(value!({"birth":id,"generation":generation,
                    "kernels":record["material"]["kernels"],
                    "snapshot":source["snapshot"]["object"]["path"]}));
                require(result.len() <= 64, "snapshot list bound")?;
            }
        }
    }
    Ok(result)
}
