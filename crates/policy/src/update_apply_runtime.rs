// SPDX-License-Identifier: MIT
//! One original operation lock spans fallback, isolated packages and publication.
use crate::{
    authority_identity, birth, boot_options, catalog, control_record, fallback,
    generation_publish_runtime, generation_stage,
    module_view::ModuleView,
    operation, root_rebind_runtime,
    storage_runtime::TopMount,
    subvolume,
    update_apply_store::Store,
    update_boot_stage,
    update_plan::{self, Plan},
    update_resolution, update_worker_launch,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
fn independent(plan: &Plan, folder: &str, id: &str) -> Result<Value> {
    let guard = plan.admitted().guard();
    let parent = files::directory(&Path::new(operation::CONTROL).join(folder), Some(0))?;
    control_record::read(
        &parent,
        Path::new(&format!("{id}.json")),
        catalog::MAX_CATALOG,
        guard.control_mount_id(),
    )
}
fn durable(name: &str, document: &Value, replace: bool) -> Result<()> {
    crate::identity::safe_id(name)?;
    let parent = files::directory(Path::new(operation::STATE), Some(0))?;
    let m = parent.metadata()?;
    require(
        m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original update receipt directory required",
    )?;
    let shape = (m.dev(), m.ino(), m.uid(), m.gid(), m.mode());
    let mount = enzimos_platform::mount_identity::id(parent.as_fd(), true)?;
    let bytes = json::canonical(document)?;
    let original = if replace {
        files::optional_relative(&parent, Path::new(name))?
    } else {
        None
    };
    if let Some(file) = &original {
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() <= catalog::MAX_CATALOG as u64
                && enzimos_platform::mount_identity::id(file.as_fd(), true)? == mount,
            "original update result receipt protection differs",
        )?;
        let epoch = files::identity(&m);
        files::read_file(file, catalog::MAX_CATALOG, Some(0), true)?;
        require(
            files::identity(&file.metadata()?) == epoch,
            "original update result receipt changed while validating",
        )?;
    }
    let written = match original {
        Some(original) => files::atomic_replace_original(
            &parent,
            Path::new(name),
            &bytes,
            0o600,
            Some(0),
            catalog::MAX_CATALOG,
            &original,
        )?,
        None => files::atomic_relative_retained(
            &parent,
            Path::new(name),
            &bytes,
            0o600,
            Some(0),
            false,
            catalog::MAX_CATALOG,
        )?,
    };
    let named = files::open_relative(&parent, Path::new(name))?;
    let now = files::directory(Path::new(operation::STATE), Some(0))?;
    let held = parent.metadata()?;
    let now_meta = now.metadata()?;
    require(
        (held.dev(), held.ino(), held.uid(), held.gid(), held.mode()) == shape
            && (
                now_meta.dev(),
                now_meta.ino(),
                now_meta.uid(),
                now_meta.gid(),
                now_meta.mode(),
            ) == shape
            && enzimos_platform::mount_identity::id(parent.as_fd(), true)? == mount
            && enzimos_platform::mount_identity::id(now.as_fd(), true)? == mount
            && files::identity(&written.metadata()?) == files::identity(&named.metadata()?)
            && enzimos_platform::mount_identity::id(written.as_fd(), true)? == mount
            && enzimos_platform::mount_identity::id(named.as_fd(), true)? == mount
            && files::read_file(&written, catalog::MAX_CATALOG, Some(0), true)? == bytes,
        "original update result receipt or directory changed during publication",
    )
}
fn safe_roots(plan: &Plan) -> Result<()> {
    plan.admitted().recheck()?;
    let root = files::directory(Path::new("/"), Some(0))?;
    let name = enzimos_platform::json::string(&plan.document()["storage"]["root_subvol"])?;
    let (object, readonly) = subvolume::observe(root.as_fd(), name)?;
    require(!readonly, "live package root became read-only")?;
    let transaction = catalog::Transaction::begin()?;
    require(
        enzimos_platform::json::object(&transaction.data["generations"])?
            .values()
            .all(|row| {
                row["state"] == "ready" && row["material"]["root"]["uuid"] != object["uuid"]
            }),
        "ready boot generation still aliases the mutable live root",
    )?;
    transaction.recheck()?;
    plan.admitted().recheck()
}
/// Apply the planned update while `lock` is held.
///
/// # Errors
///
/// As [`apply_locked_with_progress`].
pub fn apply_locked(lock: &files::Lock) -> Result<Value> {
    apply_locked_with_progress(lock, &mut |_| Ok(()))
}
/// Apply the planned update, reporting each phase to `progress`.
///
/// # Errors
///
/// Fails when the plan is stale or a step fails.
pub fn apply_locked_with_progress(
    lock: &files::Lock,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    apply_authorized(lock, progress, &mut || lock.recheck())
}
/// Checks at orchestration entry are additional to each subsystem's original resource checks.
/// Native routing still requires authorization propagation through nested worker/publication writes.
pub(crate) fn apply_authorized(
    lock: &files::Lock,
    progress: &mut dyn FnMut(&str) -> Result<()>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    apply_original(lock, None, None, progress, authorize)
}
/// The backend job owns this request ID and reviewed plan. Fresh observation
/// under the same original lock must match before durable apply intent is made.
///
/// # Errors
///
/// Fails when the plan is not the backend's reviewed plan, or as [`apply_locked_with_progress`].
pub fn apply_reviewed_backend(
    lock: &files::Lock,
    expected: &Value,
    request_id: &str,
    progress: &mut dyn FnMut(&str) -> Result<()>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::backup_worker_request::id(request_id)?;
    require(
        expected["schema"] == 2 && expected["implementation_image"] == crate::update_actor::BACKEND,
        "reviewed update requires original backend plan",
    )?;
    apply_original(lock, Some(expected), Some(request_id), progress, authorize)
}
fn apply_original(
    lock: &files::Lock,
    expected: Option<&Value>,
    request_id: Option<&str>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    authorize()?;
    lock.recheck()?;
    crate::namespaces::initial()?;
    // Best effort: the daily retention timer may not have run yet. It reuses
    // this held lock; a refusal leaves the plan's own bound to decide.
    crate::generation_retention::before_update_locked(lock, authorize);
    authorize()?;
    lock.recheck()?;
    let plan = Plan::observe_locked(lock)?;
    if let Some(expected) = expected {
        require(plan.document() == expected, "job-plan-changed")?;
    }

    crate::update_apply_record::plan(plan.document())?;
    authorize()?;
    lock.recheck()?;
    plan.recheck_before_mutation()?;
    let mut store =
        Store::create_authorized(plan.document(), plan.image(), lock, request_id, authorize)?;
    progress("capturing")?;
    // Until the fallback snapshot exists nothing on the system has changed: a
    // failure here ends the record instead of blocking every later operation.
    let fail_unchanged = |store: &mut Store, error: Error| -> Error {
        let reason = error.0.chars().take(160).collect::<String>();
        let _ = store.checkpoint(
            crate::update_apply_record::FAILED,
            &value!({"reason":reason}),
            Some("failed-no-change"),
        );
        error
    };
    let candidates = match (|| {
        authorize()?;
        lock.recheck()?;
        update_resolution::resolve(&plan)
    })() {
        Ok(candidates) => candidates,
        Err(error) => return Err(fail_unchanged(&mut store, error)),
    };
    store.checkpoint("resolved", &value!({"candidates":candidates}), None)?;
    if candidates.is_empty() {
        plan.recheck_before_mutation()?;
        store.checkpoint(
            "complete",
            &value!({"candidates":candidates}),
            Some("up-to-date-no-new-generation"),
        )?;
        return Ok(
            value!({"generation":store.id(),"status":"up-to-date-no-new-generation","reboot_requested":false}),
        );
    }
    let id = store.id().to_owned();
    let stage = match (|| {
        authorize()?;
        lock.recheck()?;
        update_boot_stage::Stage::capture_authorized(&plan, &id, lock, authorize)
    })() {
        Ok(stage) => stage,
        Err(error) => return Err(fail_unchanged(&mut store, error)),
    };
    store.checkpoint("stage-recorded", &stage.evidence(), None)?;
    authorize()?;
    lock.recheck()?;
    let created = fallback::create_locked(&id, lock, |_, _| {
        authorize()?;
        lock.recheck()?;
        store.recheck()?;
        plan.admitted().recheck()?;
        stage.recheck_original()
    })?;
    let birth = independent(&plan, "root-births", &id)?;
    birth::validate(
        &birth,
        &id,
        enzimos_platform::json::string(&plan.document()["storage"]["filesystem_uuid"])?,
    )?;
    require(
        birth["phase"] == "ready"
            && birth["created_boot"] == plan.document()["boot_id"]
            && birth["inventory_sha256"] == plan.document()["inventory_sha256"]
            && created["subvolume"] == birth["root"]["path"]
            && created["snapshot"] == birth["snapshot"]["number"],
        "created fallback differs from original plan",
    )?;
    store.checkpoint("fallback-born", &birth, None)?;
    let old = format!("old-{id}");
    let name = created["subvolume"]
        .as_str()
        .ok_or_else(|| Error("created fallback name missing".into()))?;
    let options = boot_options::root_options(
        enzimos_platform::json::string(&plan.document()["options"])?,
        name,
    )?;
    authorize()?;
    lock.recheck()?;
    let mut top = TopMount::open(plan.admitted().guard())?;
    let target = files::directory_relative(top.directory()?, Path::new(name), Some(0))?;
    let expected_root = value!({"path":name,"id":birth["root"]["id"],"uuid":birth["root"]["uuid"],"ownership":"not-established"});
    let source = generation_stage::Stage::observe(
        &stage.path,
        &old,
        &plan.document()["current_kernels"],
        &options,
        &target,
        &top.path().join(name),
        &expected_root,
    )?;
    store.recheck()?;
    plan.admitted().recheck()?;
    stage.recheck_original()?;
    authorize()?;
    lock.recheck()?;
    let fallback_publication =
        generation_publish_runtime::publish_authorized(&source, &old, lock, authorize)?;
    source.recheck()?;
    store.recheck()?;
    plan.admitted().recheck()?;
    // Inspection descriptors must leave the top-level mount before normal close.
    drop(source);
    drop(target);
    top.close()?;
    let fallback = value!({"snapshot":created["snapshot"],"subvolume":created["subvolume"],"generation":old,"kernels":plan.document()["current_kernels"]});
    authorize()?;
    lock.recheck()?;
    durable(&format!("{id}-fallback.json"), &fallback, false)?;
    store.checkpoint(
        "fallback-published",
        &value!({"fallback":fallback,"publication":fallback_publication}),
        None,
    )?;
    stage.recheck_original()?;
    plan.admitted().recheck()?;
    authorize()?;
    lock.recheck()?;
    let rebound = root_rebind_runtime::prepare_authorized(&id, lock, authorize)?;
    store.checkpoint("rebound", &rebound, None)?;
    safe_roots(&plan)?;
    authorize()?;
    lock.recheck()?;
    let mut view = ModuleView::enter_authorized(&id, lock, authorize)?;
    let view_record = independent(&plan, "module-views", &id)?;
    crate::module_view_record::validate(&view_record, &id)?;
    require(
        view_record["phase"] == "active",
        "module view did not enter exact active state",
    )?;
    store.checkpoint("view-entered", &view_record, None)?;
    stage.recheck_original()?;
    plan.admitted().recheck()?;
    progress("transferring")?;
    store.checkpoint(
        "worker-starting",
        &value!({"stage":stage.evidence(),"module_view":view_record}),
        None,
    )?;
    authorize()?;
    lock.recheck()?;
    let worker =
        update_worker_launch::run_authorized(&id, &mut view, stage.directory(), lock, authorize)?;
    // Only successful original service exit and an empty retained cgroup permit
    // restoration. Any unknown worker outcome keeps the view and pending intent.
    store.checkpoint("worker-complete", &worker, None)?;
    authorize()?;
    lock.recheck()?;
    view.leave_authorized(lock, authorize)?;
    let restored = independent(&plan, "module-views", &id)?;
    crate::module_view_record::validate(&restored, &id)?;
    require(
        restored["phase"] == "complete",
        "module view restoration incomplete",
    )?;
    store.checkpoint("view-restored", &restored, None)?;
    progress("finishing")?;
    plan.admitted().recheck()?;
    stage.recheck_directory()?;
    let root = files::directory(Path::new("/"), Some(0))?;
    let inventory = generation_stage::inventory(&root)?;
    require(
        update_plan::installed_kernels()? == plan.document()["target_kernels"],
        "installed update kernels differ from admitted cohort",
    )?;
    let authority = authority_identity::observe(plan.admitted().guard())?;
    require(
        authority == plan.document()["authority"],
        "independent authority changed across package transaction",
    )?;
    let completed = value!({"generation":id,"kernels":plan.document()["target_kernels"],"options":plan.document()["options"],
        "inventory":inventory,"authority":authority,"boot_id":operation::boot_id()?});
    authorize()?;
    lock.recheck()?;
    durable(
        &format!("{id}-transaction-complete.json"),
        &completed,
        false,
    )?;
    let (object, readonly) = subvolume::observe(
        root.as_fd(),
        enzimos_platform::json::string(&plan.document()["storage"]["root_subvol"])?,
    )?;
    require(!readonly, "completed update root is read-only")?;
    let expected_root = value!({"path":object["path"],"id":object["id"],"uuid":object["uuid"],"ownership":"not-established"});
    let source = generation_stage::Stage::observe(
        &stage.path,
        &id,
        &completed["kernels"],
        enzimos_platform::json::string(&completed["options"])?,
        &root,
        Path::new("/"),
        &expected_root,
    )?;
    store.checkpoint(
        "transaction-recorded",
        &value!({"transaction":completed,"material":source.material}),
        None,
    )?;
    source.recheck()?;
    plan.admitted().recheck()?;
    authorize()?;
    lock.recheck()?;
    let publication =
        generation_publish_runtime::publish_authorized(&source, &id, lock, authorize)?;
    source.recheck()?;
    plan.admitted().recheck()?;
    require(
        generation_stage::inventory(&root)? == completed["inventory"],
        "inventory changed before final update receipt",
    )?;
    store.checkpoint("new-published", &publication, None)?;
    let last = value!({"generation":id,"kernels":completed["kernels"],"artifacts":publication["files"],"status":"prepared-not-rebooted"});
    authorize()?;
    lock.recheck()?;
    durable("last-update.json", &last, true)?;
    source.recheck()?;
    plan.admitted().recheck()?;
    store.checkpoint("complete", &last, Some("prepared-not-rebooted"))?;
    Ok(
        value!({"generation":id,"status":"prepared-not-rebooted","reboot_requested":false,"installed_qualification":false}),
    )
}
