// SPDX-License-Identifier: MIT
//! Internal coordinator adapter: persist intent before requesting a fresh service.
use crate::{
    control_record, module_view::ModuleView, namespaces, operation, storage_runtime::Guard,
    update_worker_record as record,
};
use enzimos_platform::{
    Error, Result, files, json, memfile, mount_identity, process, process_identity, require,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
const COHORT: &str = "/var/lib/enzimos-update-cohort/admission.json";
fn directory(file: &File) -> Result<Value> {
    let metadata = file.metadata()?;
    require(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7022 == 0,
        "worker coordinator directory authority refused",
    )?;
    Ok(
        value!({"device":metadata.dev(),"inode":metadata.ino(),"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
fn input_directory(file: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    directory(file)?;
    let m = file.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
pub fn run_locked(
    id: &str,
    view: &mut ModuleView,
    boot_stage: &File,
    lock: &files::Lock,
) -> Result<Value> {
    run_authorized(id, view, boot_stage, lock, &mut || lock.recheck())
}
/// Fresh orchestration entry checks; original caller is one closed installed native coordinator role.
pub(crate) fn run_authorized(
    id: &str,
    view: &mut ModuleView,
    boot_stage: &File,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    authorize()?;
    lock.recheck()?;
    namespaces::initial()?;
    crate::identity::safe_id(id)?;
    let guard = Guard::observe()?;
    let metadata = files::read_kernel(
        &PathBuf::from(format!("/proc/{}/stat", std::process::id())),
        8192,
    )?;
    let task = process_identity::parse_stat(
        std::str::from_utf8(&metadata)
            .map_err(|_| Error("worker coordinator stat encoding".into()))?,
        std::process::id(),
    )?;
    let actor = crate::update_actor::Actor::current()?;
    let image = actor.image()?;
    let image_body = files::read_file(image, 32 * 1024 * 1024, Some(0), true)?;
    let caller = actor.process()?;
    let boot = directory(boot_stage)?;
    let named = files::directory(
        &Path::new(operation::STATE).join("boot-stage").join(id),
        Some(0),
    )?;
    require(
        directory(&named)? == boot,
        "worker coordinator boot stage changed",
    )?;
    let config_path = Path::new(record::CONFIG);
    let config_parent = files::directory(
        config_path
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    let config_file = files::open_relative(
        &config_parent,
        Path::new(
            config_path
                .file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )?;
    let config_epoch = files::identity(&config_file.metadata()?);
    let config = files::read_file(&config_file, 65536, Some(0), true)?;
    let cohort_path = Path::new(COHORT);
    let cohort_parent = files::directory(
        cohort_path
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    let cohort_file = files::open_relative(
        &cohort_parent,
        Path::new(
            cohort_path
                .file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )?;
    let cohort_epoch = files::identity(&cohort_file.metadata()?);
    let cohort_bytes = files::read_file(&cohort_file, 2 * 1024 * 1024, Some(0), true)?;
    let cohort = json::decode(&cohort_bytes, 2 * 1024 * 1024)?;
    let admission_record = control_record::Retained::open(
        guard.control(),
        Path::new("update-admission.json"),
        65536,
        guard.control_mount_id(),
    )?;
    let admission = admission_record.value()?.clone();
    let coordinator_path = Path::new(record::EXECUTABLE);
    let coordinator_parent = files::directory(
        coordinator_path
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    let coordinator = files::open_relative(
        &coordinator_parent,
        Path::new(
            coordinator_path
                .file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )?;
    let coordinator_epoch = files::identity(&coordinator.metadata()?);
    require(
        coordinator_epoch.7 & 0o7777 == 0o755
            && coordinator_epoch.8 == 0
            && coordinator_epoch.9 == 0
            && coordinator_epoch.10 == 1,
        "original fixed coordinator image required",
    )?;
    let config_directory = input_directory(&config_parent)?;
    let cohort_directory = input_directory(&cohort_parent)?;
    let coordinator_directory = input_directory(&coordinator_parent)?;
    let original_inputs = || -> Result<()> {
        namespaces::initial()?;
        lock.recheck()?;
        guard.recheck()?;
        actor.recheck()?;
        caller.recheck()?;
        admission_record.recheck()?;
        for (held, parent, path, epoch, parent_epoch) in [
            (
                &config_file,
                &config_parent,
                config_path,
                config_epoch,
                &config_directory,
            ),
            (
                &cohort_file,
                &cohort_parent,
                cohort_path,
                cohort_epoch,
                &cohort_directory,
            ),
            (
                &coordinator,
                &coordinator_parent,
                coordinator_path,
                coordinator_epoch,
                &coordinator_directory,
            ),
        ] {
            let current_parent = files::directory(
                path.parent()
                    .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
                Some(0),
            )?;
            require(
                input_directory(parent)? == *parent_epoch
                    && input_directory(&current_parent)? == *parent_epoch,
                "original worker coordinator input directory changed",
            )?;
            let named = files::open_relative(
                &current_parent,
                Path::new(
                    path.file_name()
                        .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
                ),
            )?;
            require(
                files::identity(&held.metadata()?) == epoch
                    && files::identity(&named.metadata()?) == epoch
                    && mount_identity::id(held.as_fd(), true)?
                        == mount_identity::id(named.as_fd(), true)?,
                "original worker coordinator input replaced or covered",
            )?;
        }
        require(
            files::read_file(&config_file, 65536, Some(0), true)? == config
                && files::read_file(&cohort_file, 2 * 1024 * 1024, Some(0), true)? == cohort_bytes
                && files::identity(&config_file.metadata()?) == config_epoch
                && files::identity(&cohort_file.metadata()?) == cohort_epoch,
            "original worker coordinator input bytes changed",
        )
    };
    let mut boundary = || -> Result<()> {
        authorize()?;
        original_inputs()
    };
    boundary()?;
    crate::update_admission::validate(&admission)?;
    let fingerprint = json::fingerprint(&cohort)?;
    require(
        admission["schema"] == 1
            && admission["phase"] == "complete"
            && admission["admission_sha256"] == fingerprint,
        "worker coordinator requires completed exact cohort admission",
    )?;
    let modules = view.transaction_directory()?.try_clone()?;
    boundary()?;
    let active = view.prepare_worker(id)?;
    let request = value!({"schema":3,"caller_image":actor.path(),"id":id,"boot_id":operation::boot_id()?,"filesystem_uuid":guard.configuration["filesystem_uuid"],
        "caller":{"pid":task.pid,"start_ticks":task.start_ticks,"executable_sha256":json::sha256(&image_body)},
        "module_view":active,"boot_stage":boot,"config_sha256":json::sha256(&config),"cohort_sha256":fingerprint,
        "descriptors":{"modules":modules.as_raw_fd(),"boot_stage":boot_stage.as_raw_fd(),"operation_lock":lock.as_file().as_raw_fd()}});
    record::execution_request(&request)?;
    let apply = crate::update_apply_lease::Lease::observe(&request)?;
    boundary()?;
    let journal_parent =
        files::ensure_directory_relative(guard.control(), Path::new("update-workers"), 0o700, 0)?;
    let journal_shape = directory(&journal_parent)?;
    require(
        mount_identity::id(journal_parent.as_fd(), true)? == guard.control_mount_id(),
        "worker intent left original control",
    )?;
    let journal_check = || -> Result<()> {
        let named =
            files::directory_relative(guard.control(), Path::new("update-workers"), Some(0))?;
        require(
            directory(&journal_parent)? == journal_shape && directory(&named)? == journal_shape,
            "original worker journal directory changed or covered",
        )
    };
    let mut current = value!({"schema":1,"id":id,"phase":"intent","request_sha256":json::fingerprint(&request)?,
        "request":request,"supervisor":null,"invocation":null,"exit_code":null});
    record::transition(None, &current, id)?;
    boundary()?;
    journal_check()?;
    let mut original = control_record::Retained::create(
        &journal_parent,
        Path::new(&format!("{id}.json")),
        &current,
        2 * 1024 * 1024,
        guard.control_mount_id(),
    )?;
    view.worker_checkpoint(&current)?;
    let intent = current.clone();
    current["phase"] = value!("starting");
    record::transition(Some(&intent), &current, id)?;
    boundary()?;
    journal_check()?;
    original.replace(&current)?;
    view.worker_checkpoint(&current)?;
    let sealed = memfile::sealed("update-worker-request", &json::canonical(&request)?)?;
    boundary()?;
    journal_check()?;
    original.recheck()?;
    let output = process::run_pinned(
        record::EXECUTABLE,
        &coordinator,
        &["launch", id, "@fd:0", "@fd:1", "@fd:2", "@fd:3", "@fd:4"],
        &[],
        Duration::from_secs(record::RUNTIME_SECONDS + record::STOP_SECONDS + 40),
        2 * 1024 * 1024,
        &[
            sealed.as_fd(),
            modules.as_fd(),
            boot_stage.as_fd(),
            lock.as_file().as_fd(),
            caller.pidfd(),
        ],
    )?;
    require(
        output.status.success(),
        "native worker failed; retain unfinished transaction resources",
    )?;
    let reply = json::decode(&output.stdout, 2 * 1024 * 1024)?;
    json::fields(&reply, "schema generation checkpoints")?;
    require(
        reply["schema"] == 1 && reply["generation"] == id,
        "worker coordinator reply changed",
    )?;
    let history = reply["checkpoints"]
        .as_array()
        .ok_or_else(|| Error("worker coordinator history missing".into()))?;
    record::history(&current, history, id)?;
    // Check factual completion against retained inputs before requesting permission
    // for the next mutation. Authorization failure leaves existing worker receipts.
    original_inputs()?;
    journal_check()?;
    boundary()?;
    view.worker_history(id, history)?;
    apply.recheck()?;
    Ok(reply)
}
