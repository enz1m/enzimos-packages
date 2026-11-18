// SPDX-License-Identifier: MIT
//! `enzimos-policy backup-setup reset-uncertain`: settle an interrupted local
//! backup setup after a failed or uncertain enrollment.
//!
//! Root only, under the operation lock, in the initial namespace. It only
//! touches what an unfinished setup attempt can have left behind:
//!   1. mounts at /backup-repository that are either the private area bind of
//!      the Root's own empty `backup-repository` directory or the destination
//!      Btrfs named by the unfinished setup (never anything else);
//!   2. unfinished setup-mount and private-area intents (marked rolled-back);
//!   3. the attempt's configuration, credential, credential receipt and setup
//!      intent, only while no destination pin or schedule opt-in exists, the
//!      intent never completed, and (for initialization) a read-only probe of
//!      that UUID shows no restic repository. An adopted repository is never
//!      written by setup, so its enrollment is retracted without a probe.
use crate::{backup_review_store::Store, filesystem, identity, operation, storage_runtime};
use enzimos_platform::{Error, Result, files, json, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    ffi::{CStr, CString},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
const TARGET: &str = "/backup-repository";
/// Root-private proof that a reset retracted one setup request's publications
/// after detaching its mounts and settling its intents. The backend reads it
/// on that request's next status and records the job `rolled-back`.
pub const RESET_PROOF: &str = "backup-setup-reset.json";
/// The proof for one retracted setup intent (`backup-initial-setup.json`).
pub fn reset_proof(intent: &Value) -> Result<Value> {
    let plan = &intent["plan"];
    let id = plan["id"]
        .as_str()
        .ok_or_else(|| Error("setup intent request ID required".into()))?;
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "setup intent request ID invalid",
    )?;
    Ok(value!({"schema":1,"request_id":id,"plan_sha256":json::fingerprint(plan)?,"retracted":true}))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mount {
    /// The private bind of the Root's own `backup-repository` stub.
    AreaBind,
    /// The destination filesystem named by the unfinished setup.
    Destination,
    Foreign(&'static str),
}
/// Decide whether a mount on /backup-repository may be detached.
pub(crate) fn classify(
    row: &mountinfo::Row,
    root: &mountinfo::Row,
    uuid: Option<&str>,
    destinations: &[String],
) -> Mount {
    if row.target != TARGET {
        return Mount::Foreign("not the fixed setup target");
    }
    if row.filesystem != "btrfs" {
        return Mount::Foreign("not Btrfs");
    }
    let stub = format!("{}/backup-repository", root.root.trim_end_matches('/'));
    if (row.major, row.minor) == (root.major, root.minor) && row.root == stub {
        return Mount::AreaBind;
    }
    match uuid {
        Some(uuid) if row.root == "/" && destinations.iter().any(|d| d == uuid) => {
            Mount::Destination
        }
        Some(_) => Mount::Foreign("filesystem is not the unfinished setup destination"),
        None => Mount::Foreign("filesystem identity unavailable"),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Repository {
    Absent,
    /// A `restic` directory without `config`: restic cannot open it, so no
    /// repository exists; a new initialization needs the directory removed.
    Incomplete,
    Present,
    DeviceMissing,
    NotChecked,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Publications {
    Retract,
    Keep(&'static str),
}
/// Decide whether the attempt's publications may be removed.
pub(crate) fn publications(
    intent: Option<&Value>,
    configuration: Option<&Value>,
    pin_present: bool,
    repository: Repository,
) -> Publications {
    let Some(intent) = intent else {
        return Publications::Keep(
            "no setup intent: configuration is not from an unfinished setup",
        );
    };
    if intent["phase"] != "prepared" {
        return Publications::Keep("setup intent completed");
    }
    if pin_present {
        return Publications::Keep("destination pin or schedule opt-in exists");
    }
    let destination = &intent["plan"]["destination"]["filesystem_uuid"];
    if let Some(configuration) = configuration
        && configuration["destination_uuid"] != *destination
    {
        return Publications::Keep("configuration names another destination");
    }
    match (intent["plan"]["mode"].as_str(), repository) {
        (Some("adopt"), _) => Publications::Retract,
        (Some("initialize"), Repository::Absent | Repository::Incomplete) => Publications::Retract,
        (Some("initialize"), Repository::Present) => {
            Publications::Keep("a restic repository exists on the destination")
        }
        (Some("initialize"), Repository::DeviceMissing) => {
            Publications::Keep("attach the reviewed destination drive and run again")
        }
        (Some("initialize"), Repository::NotChecked) => {
            Publications::Keep("destination repository was not checked")
        }
        _ => Publications::Keep("unknown setup mode"),
    }
}

/// Intent stores the reset settles, in settling order: (name, private area).
const INTENT_STORES: [(&str, bool); 2] =
    [("backup-setup-mounts", false), ("backup-setup-areas", true)];
/// Optional regular file (publications, pins, intent records).
fn optional(parent: &File, name: &str) -> Result<Option<File>> {
    files::optional_relative(parent, Path::new(name))
}
/// Optional directory (the intent stores). The regular-file helper refuses
/// directories, which made every reset on a system with intents fail.
fn optional_directory(parent: &File, name: &str, owner: u32) -> Result<Option<File>> {
    files::optional_directory_relative(parent, Path::new(name), Some(owner))
}
fn read_json(parent: &File, name: &str) -> Result<Option<Value>> {
    read_json_owned(parent, name, 0)
}
fn read_json_owned(parent: &File, name: &str, owner: u32) -> Result<Option<Value>> {
    let Some(file) = optional(parent, name)? else {
        return Ok(None);
    };
    let m = file.metadata()?;
    require(
        m.is_file() && m.uid() == owner && m.mode() & 0o077 == 0,
        "setup publication is not a Root-private file",
    )?;
    Ok(Some(json::decode(
        &files::read_file(&file, 65536, Some(owner), true)?,
        65536,
    )?))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn remove(parent: &File, name: &str, removed: &mut Vec<String>, label: &str) -> Result<()> {
    let Some(file) = optional(parent, name)? else {
        return Ok(());
    };
    let m = file.metadata()?;
    require(
        m.is_file() && m.uid() == 0 && m.nlink() <= 2,
        "setup publication is not a Root-owned regular file; not removed",
    )?;
    drop(file);
    let c = CString::new(name).unwrap();
    require(
        unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), 0) } == 0,
        "setup publication removal refused",
    )?;
    removed.push(format!("{label}/{name}"));
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fsync).")]
fn sync(parent: &File) -> Result<()> {
    require(
        unsafe { libc::fsync(parent.as_raw_fd()) } == 0,
        "setup reset durability unknown",
    )
}
fn top_uuid() -> Option<String> {
    let file = files::directory(Path::new(TARGET), Some(0)).ok()?;
    filesystem::observe(file.as_fd())
        .ok()?
        .get("filesystem_uuid")?
        .as_str()
        .map(str::to_owned)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
fn detach_mounts(destinations: &[String]) -> Result<Vec<String>> {
    let mut detached = Vec::new();
    for _ in 0..4 {
        let rows = storage_runtime::rows()?;
        require(
            !rows
                .iter()
                .any(|r| r.target.starts_with("/backup-repository/")),
            "mounts below /backup-repository exist; inspect manually",
        )?;
        let Some(top) = rows.iter().rfind(|r| r.target == TARGET) else {
            return Ok(detached);
        };
        let root = rows
            .iter()
            .rfind(|r| r.target == "/")
            .ok_or_else(|| Error("Root mount row missing".into()))?;
        let class = classify(top, root, top_uuid().as_deref(), destinations);
        match class {
            Mount::Foreign(reason) => {
                return Err(Error(format!(
                    "mount {} on /backup-repository not touched: {reason}",
                    top.id
                )));
            }
            Mount::AreaBind | Mount::Destination => {
                let target: &CStr = c"/backup-repository";
                require(
                    unsafe { libc::umount2(target.as_ptr(), 0) } == 0,
                    "/backup-repository is busy; stop its users and run again",
                )?;
                detached.push(format!("{class:?}:{}", top.id));
            }
        }
    }
    Err(Error(
        "too many stacked mounts on /backup-repository".into(),
    ))
}
/// What an interrupted setup left in the control directory: which intent
/// stores exist and the destinations their unfinished setup-mount intents name.
#[derive(Debug, Default, PartialEq, Eq)]
struct Discovery {
    stores: Vec<(&'static str, bool)>,
    destinations: Vec<String>,
}
fn discover(control: &File, owner: u32) -> Result<Discovery> {
    let mut found = Discovery::default();
    for (name, area) in INTENT_STORES {
        let Some(directory) = optional_directory(control, name, owner)? else {
            continue;
        };
        found.stores.push((name, area));
        if area {
            continue;
        }
        // Unfinished setup-mount intents name their destination UUID.
        for entry in files::directory_names(&directory, 64)? {
            let entry = entry
                .into_string()
                .map_err(|_| Error("setup intent filename encoding".into()))?;
            if let Some(v) = read_json_owned(&directory, &entry, owner)?
                && !crate::backup_review_store::terminal(&v["phase"])
                && let Some(uuid) = v["filesystem_uuid"].as_str()
            {
                found.destinations.push(uuid.to_owned());
            }
        }
    }
    Ok(found)
}
fn settle_intents(
    guard: &storage_runtime::Guard,
    lock: &files::Lock,
    stores: &[(&'static str, bool)],
) -> Result<Vec<String>> {
    let mut settled = Vec::new();
    for &(directory, area) in stores {
        let path = Path::new(operation::CONTROL).join(directory);
        let check = Box::new(move || {
            guard.recheck()?;
            lock.recheck()
        });
        let mut store = if area {
            Store::retained_area(&path, 0, guard.control_mount_id(), check)?
        } else {
            Store::retained_setup(&path, 0, guard.control_mount_id(), check)?
        };
        for id in store.unfinished()? {
            store.rolled_back(&id)?;
            settled.push(format!("{directory}/{id}"));
        }
    }
    Ok(settled)
}
/// Read-only, never-attached probe of the destination for a restic repository.
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
fn probe(uuid: &str, source_uuid: &str) -> Result<Repository> {
    identity::uuid(uuid)?;
    require(
        uuid != source_uuid,
        "destination equals the system filesystem",
    )?;
    let link = Path::new("/dev/disk/by-uuid").join(uuid);
    let device = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(&link)
    {
        Ok(device) => device,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Repository::DeviceMissing);
        }
        Err(error) => return Err(error.into()),
    };
    require(
        device.metadata()?.file_type().is_block_device(),
        "destination link is not a block device",
    )?;
    let raw = unsafe { libc::syscall(libc::SYS_fsopen, c"btrfs".as_ptr(), 1u32) };
    require(raw >= 0, "read-only destination probe refused")?;
    let context = unsafe { File::from_raw_fd(raw as i32) };
    let source = CString::new(format!("/proc/self/fd/{}", device.as_raw_fd())).unwrap();
    let configure = |command: u32, key: Option<&CStr>, val: Option<&CStr>| {
        let null = std::ptr::null::<libc::c_char>();
        require(
            unsafe {
                libc::syscall(
                    libc::SYS_fsconfig,
                    context.as_raw_fd(),
                    command,
                    key.map_or(null, CStr::as_ptr),
                    val.map_or(null, CStr::as_ptr),
                    0i32,
                )
            } == 0,
            "read-only destination probe configuration refused",
        )
    };
    configure(1, Some(c"source"), Some(&source))?;
    configure(0, Some(c"ro"), None)?;
    configure(1, Some(c"rescue"), Some(c"nologreplay"))?;
    configure(1, Some(c"subvolid"), Some(c"5"))?;
    // CREATE_EXCL: refuse to share a superblock that is still in use elsewhere.
    configure(8, None, None)?;
    // Detached: never attached to any path; released when the fd closes.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            context.as_raw_fd(),
            1u32,
            1u32 | 2 | 4 | 8,
        )
    };
    require(raw >= 0, "read-only destination probe mount refused")?;
    let mount = unsafe { File::from_raw_fd(raw as i32) };
    require(
        filesystem::observe(mount.as_fd())?["filesystem_uuid"] == uuid,
        "probed filesystem differs from the setup destination",
    )?;
    // `restic` is a directory; the optional *file* helper refused it.
    let found = match files::optional_directory_relative(&mount, Path::new("restic"), None)? {
        None => Repository::Absent,
        Some(directory) => {
            require(
                directory.metadata()?.is_dir(),
                "destination restic entry is not a directory",
            )?;
            if files::optional_relative(&directory, Path::new("config"))?.is_some() {
                Repository::Present
            } else if files::directory_is_empty(&directory)? {
                Repository::Absent
            } else {
                Repository::Incomplete
            }
        }
    };
    drop(mount);
    drop(context);
    Ok(found)
}
pub fn reset_locked(lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    let guard = storage_runtime::Guard::observe()?;
    let etc = files::directory(Path::new("/etc/enzimos"), Some(0))?;
    let intent = read_json(guard.control(), "backup-initial-setup.json")?;
    let configuration = read_json(&etc, "backup.json")?;
    // Only unfinished setup attempts name destinations this reset may detach;
    // a completed configuration's destination is never touched here.
    let discovery = discover(guard.control(), 0)?;
    let mut destinations = discovery.destinations.clone();
    if let Some(v) = &intent
        && v["phase"] == "prepared"
        && let Some(uuid) = v["plan"]["destination"]["filesystem_uuid"].as_str()
    {
        destinations.push(uuid.to_owned());
    }
    destinations.sort();
    destinations.dedup();
    let detached = detach_mounts(&destinations)?;
    lock.recheck()?;
    let settled = settle_intents(&guard, lock, &discovery.stores)?;
    let pin_present = optional(guard.control(), "backup-destination.json")?.is_some()
        || optional(guard.control(), "backup.enabled")?.is_some();
    let destination = intent
        .as_ref()
        .and_then(|v| v["plan"]["destination"]["filesystem_uuid"].as_str())
        .map(str::to_owned);
    let mut probe_note = Value::Null;
    let repository = match (&intent, &destination) {
        (Some(v), Some(uuid))
            if v["phase"] == "prepared" && v["plan"]["mode"] == "initialize" && !pin_present =>
        {
            let source = guard.configuration["filesystem_uuid"]
                .as_str()
                .unwrap_or("");
            probe(uuid, source).unwrap_or_else(|error| {
                probe_note = value!(crate::diagnostic::bounded(&error.0));
                Repository::NotChecked
            })
        }
        _ => Repository::NotChecked,
    };
    let decision = publications(
        intent.as_ref(),
        configuration.as_ref(),
        pin_present,
        repository,
    );
    let mut retracted = Vec::new();
    let mut setup_job = Value::Null;
    if decision == Publications::Retract {
        lock.recheck()?;
        for name in [
            "backup.json",
            ".backup-setup-config",
            "backup.password",
            ".backup-password-input",
        ] {
            remove(&etc, name, &mut retracted, "/etc/enzimos")?;
        }
        sync(&etc)?;
        for name in ["backup-secret-input.json", "backup-initial-setup.json"] {
            remove(guard.control(), name, &mut retracted, operation::CONTROL)?;
        }
        sync(guard.control())?;
        // The retraction is proven: mounts detached, intents settled, no pin,
        // publications removed. Record it for the backend's setup job.
        if let Some(v) = &intent
            && v["plan"]["operation"] == "backup-initial-setup"
            && let Ok(proof) = reset_proof(v)
        {
            let mut bytes = json::canonical(&proof)?;
            bytes.push(b'\n');
            files::atomic_relative(
                guard.control(),
                Path::new(RESET_PROOF),
                &bytes,
                0o600,
                Some(0),
                true,
                4096,
            )?;
            sync(guard.control())?;
            setup_job = proof["request_id"].clone();
        }
    }
    lock.recheck()?;
    Ok(value!({
        "mounts_detached": detached,
        "intents_settled": settled,
        "repository": format!("{repository:?}").to_lowercase(),
        "repository_probe_error": probe_note,
        "publications": match decision {
            Publications::Retract => "retracted".to_owned(),
            Publications::Keep(reason) => format!("kept: {reason}"),
        },
        "removed": retracted,
        "setup_job_rolled_back": setup_job,
    }))
}
