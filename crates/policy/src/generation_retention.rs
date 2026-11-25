// SPDX-License-Identifier: MIT
//! Automatic boot generation retention under the one operation lock.
//!
//! The newest update pair is always kept. Every older generation is offered,
//! oldest first, to the existing boot-retirement plan: its protections (current,
//! this-boot or unfinished generation, loader default, pins, last bootable entry
//! of a confirmed root, live recovery references) decide, never this module.
//! Afterwards, transient update staging (`boot-stage/<id>`, `module-views/<id>`)
//! is removed only for finished applies whose generations are both retired.
use crate::{
    boot_retirement_cli,
    boot_retirement_context::Context,
    catalog, control_registry, filesystem, operation,
    recovery_journal::Records,
    storage_runtime,
    storage_runtime::Guard,
    transition_idle, update_apply_record,
    update_resources::{BOOT_GENERATIONS, TRANSIENT_GENERATIONS},
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};
/// The newest update pair (`old-<id>` fallback and `<id>`) is never offered.
pub(crate) const KEEP_NEWEST: usize = 2;
/// A bounded number of destructive retirements per run.
pub(crate) const MAX_RETIREMENTS: usize = 4;
const TRANSIENT_FOLDERS: [&str; 2] = ["boot-stage", "module-views"];
const MAX_TREE_DEPTH: usize = 32;
const MAX_TREE_MEMBERS: u64 = 1_000_000;
/// Generation count after which the next update (two fresh generations) fits.
pub const fn target() -> usize {
    BOOT_GENERATIONS - 2
}
/// Retirement candidates in order: ready generations older than the newest
/// `keep` by ordinal, oldest first, excluding explicitly protected names.
pub fn candidates(
    generations: &Value,
    keep: usize,
    protected: &BTreeSet<String>,
) -> Result<Vec<String>> {
    let rows = generations
        .as_object()
        .ok_or_else(|| Error("generation catalog map required".into()))?;
    let mut ordered = rows
        .iter()
        .map(|(name, row)| {
            row["ordinal"]
                .as_u64()
                .map(|ordinal| (ordinal, name, row))
                .ok_or_else(|| Error("generation ordinal required".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by_key(|(ordinal, _, _)| *ordinal);
    let older = ordered.len().saturating_sub(keep);
    Ok(ordered[..older]
        .iter()
        .filter(|(_, name, row)| row["state"] == "ready" && !protected.contains(*name))
        .map(|(_, name, _)| (*name).clone())
        .collect())
}
/// Why transient staging for apply `id` must stay, or None when it is provably
/// unreferenced: the apply finished, its view and worker are complete or
/// absent, both of its generations are retired and it is not the last update.
pub(crate) fn transient_blocker(
    id: &str,
    applies: &Records,
    module_views: &Value,
    update_workers: &Value,
    live_generations: &BTreeSet<String>,
    last_update: Option<&str>,
) -> Option<&'static str> {
    let Some(apply) = applies.get(id) else {
        return Some("no-apply-record");
    };
    if !update_apply_record::finished(apply) {
        return Some("apply-unfinished");
    }
    if [module_views, update_workers].iter().any(|records| {
        records
            .get(id)
            .is_some_and(|row| row["phase"] != "complete")
    }) {
        return Some("view-or-worker-unfinished");
    }
    if live_generations.contains(id) || live_generations.contains(&format!("old-{id}")) {
        return Some("generation-retained");
    }
    if last_update == Some(id) {
        return Some("last-update-source");
    }
    None
}
fn last_update_generation() -> Result<Option<String>> {
    let state = files::directory(Path::new(operation::STATE), Some(0))?;
    let Some(file) = files::optional_relative(&state, Path::new("last-update.json"))? else {
        return Ok(None);
    };
    let last = json::decode(
        &files::read_file(&file, catalog::MAX_CATALOG, Some(0), true)?,
        catalog::MAX_CATALOG,
    )?;
    let generation = last["generation"]
        .as_str()
        .ok_or_else(|| Error("last update generation missing".into()))?;
    crate::identity::safe_id(generation)?;
    Ok(Some(generation.to_owned()))
}
fn catalog_generations() -> Result<Value> {
    let transaction = catalog::Transaction::begin()?;
    let generations = transaction.data["generations"].clone();
    transaction.recheck()?;
    Ok(generations)
}
fn transient_count(folder: &str) -> Result<usize> {
    let state = files::directory(Path::new(operation::STATE), Some(0))?;
    Ok(
        match files::optional_directory_relative(&state, Path::new(folder), Some(0))? {
            Some(directory) => files::directory_names(&directory, 256)?.len(),
            None => 0,
        },
    )
}
/// Whether the next update would be refused by a retention bound.
pub fn needed() -> Result<bool> {
    let generations = catalog_generations()?
        .as_object()
        .map_or(0, serde_json::Map::len);
    if generations + 2 > BOOT_GENERATIONS {
        return Ok(true);
    }
    for folder in TRANSIENT_FOLDERS {
        if transient_count(folder)? + 1 >= TRANSIENT_GENERATIONS {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Best-effort retention before an update plan or apply under the caller's
/// already held lock, only when the update would otherwise be refused. Errors
/// are ignored: the plan's own resource bounds still decide admission.
pub fn before_update_locked(lock: &files::Lock, authorize: &mut dyn FnMut() -> Result<()>) {
    let Ok(guard) = Guard::observe() else {
        return;
    };
    // Control registries first: a full one refuses the retention below too.
    if crate::control_retention::needed(&guard).unwrap_or(false) && authorize().is_ok() {
        let _ = retain_control(&guard, lock);
    }
    if !needed().unwrap_or(false) {
        return;
    }
    let _ = retain_locked(&guard, lock, &mut || {
        guard.recheck()?;
        authorize()
    });
}
/// Retire finished control registry rows whose generations and roots are gone.
pub(crate) fn retain_control(guard: &Guard, lock: &files::Lock) -> Value {
    let attempt = || -> Result<Value> {
        let generations = catalog_generations()?
            .as_object()
            .ok_or_else(|| Error("generation catalog map required".into()))?
            .keys()
            .cloned()
            .collect();
        crate::control_retention::retire_locked(guard, lock, generations, last_update_generation()?)
    };
    attempt().unwrap_or_else(|error| value!({"error":error.to_string()}))
}
fn unfinished_retirements(guard: &Guard) -> Result<usize> {
    Ok(crate::control_registry::read(
        guard,
        "boot-retirements",
        crate::retirement_journal::MAX_RECORDS,
        crate::retirement_journal::validate,
    )?
    .values()
    .filter(|row| row["phase"] != "complete")
    .count())
}
fn retire_one(
    guard: &Guard,
    lock: &files::Lock,
    generation: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<std::result::Result<Value, String>> {
    let plan = {
        let context = Context::observe(guard, lock, generation, &mut *authorize)?;
        context.preview_plan(&mut *authorize)?
    };
    if plan["retirable"] != true {
        let protection = plan["protection"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        return Ok(Err(if protection.is_empty() {
            "protected".into()
        } else {
            protection
        }));
    }
    let sha = plan["plan_sha256"]
        .as_str()
        .ok_or_else(|| Error("retirable plan digest missing".into()))?
        .to_owned();
    boot_retirement_cli::retire_locked(guard, lock, generation, &sha, authorize, &mut |_| Ok(()))
        .map(Ok)
}
/// Retire old boot generations and their transient staging. Only the caller's
/// already held operation lock is used; a retirement that fails after its
/// journal started stops the run so the journal stays for explicit review.
pub fn retain_locked(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    // Bounded control registries first: every retirement below observes them.
    let control_before = retain_control(guard, lock);
    authorize()?;
    let protected = last_update_generation()?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let generations = catalog_generations()?;
    let before = generations.as_object().map_or(0, serde_json::Map::len);
    let offered = candidates(&generations, KEEP_NEWEST, &protected)?;
    let mut remaining = before;
    let mut retired = Vec::new();
    let mut skipped = Vec::new();
    let mut stopped = Value::Null;
    for generation in &offered {
        if remaining <= target() || retired.len() >= MAX_RETIREMENTS {
            break;
        }
        authorize()?;
        lock.recheck()?;
        let journals_before = unfinished_retirements(guard)?;
        match retire_one(guard, lock, generation, authorize) {
            Ok(Ok(_)) => {
                retired.push(generation.clone());
                remaining = catalog_generations()?
                    .as_object()
                    .map_or(0, serde_json::Map::len);
            }
            Ok(Err(reason)) => {
                skipped.push(value!({"generation":generation,"reason":reason}));
            }
            // A refusal before the retirement journal started (for example a
            // backend row still naming the generation) only skips this
            // candidate; one that left a journal unfinished stops the run so
            // that journal stays for review.
            Err(error) if unfinished_retirements(guard)? <= journals_before => {
                skipped.push(value!({"generation":generation,"reason":error.to_string()}));
            }
            Err(error) => {
                stopped = value!({"generation":generation,"reason":error.to_string()});
                break;
            }
        }
    }
    authorize()?;
    lock.recheck()?;
    let transient = if stopped.is_null() {
        match cleanup_transient(guard, lock, authorize) {
            Ok(result) => result,
            Err(error) => value!({"error":error.to_string()}),
        }
    } else {
        value!({"skipped":"retirement-stopped"})
    };
    authorize()?;
    // Rows for the generations retired above are now history too.
    let control_after = retain_control(guard, lock);
    guard.recheck()?;
    lock.recheck()?;
    Ok(
        value!({"status":"generation-retention","control":[control_before,control_after],
        "generations_before":before,
        "generations_after":remaining,"target":target(),"kept_newest":KEEP_NEWEST,
        "retired":retired,"skipped":skipped,"stopped":stopped,"transient":transient,
        "root_subvolume_retained":true}),
    )
}
fn cleanup_transient(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    // Fresh idle admission: every module view, worker and publication is
    // complete, so no transient directory is held by a running operation.
    let idle = transition_idle::Snapshot::online()?;
    require(
        idle.guard.configuration == guard.configuration,
        "retention idle source differs",
    )?;
    let applies = control_registry::read(
        guard,
        "update-applies",
        update_apply_record::MAXIMUM,
        update_apply_record::validate,
    )?;
    let filesystem_uuid = guard.configuration["filesystem_uuid"].clone();
    let last = last_update_generation()?;
    let live = catalog_generations()?
        .as_object()
        .ok_or_else(|| Error("generation catalog map required".into()))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for folder in TRANSIENT_FOLDERS {
        let state = files::directory(Path::new(operation::STATE), Some(0))?;
        let Some(parent) = files::optional_directory_relative(&state, Path::new(folder), Some(0))?
        else {
            continue;
        };
        require(
            filesystem::observe(parent.as_fd())?["filesystem_uuid"] == filesystem_uuid,
            "update resource filesystem differs",
        )?;
        for name in files::directory_names(&parent, 256)? {
            let id = name
                .to_str()
                .ok_or_else(|| Error("update resource name encoding".into()))?
                .to_owned();
            crate::identity::safe_id(&id)?;
            if let Some(reason) = transient_blocker(
                &id,
                &applies,
                &idle.records["module_views"],
                &idle.records["update_workers"],
                &live,
                last.as_deref(),
            ) {
                kept.push(value!({"folder":folder,"id":id,"reason":reason}));
                continue;
            }
            let path = Path::new(operation::STATE).join(folder).join(&id);
            let prefix = format!("{}/", path.display());
            if storage_runtime::rows()?
                .iter()
                .any(|row| Path::new(&row.target) == path || row.target.starts_with(&prefix))
            {
                kept.push(value!({"folder":folder,"id":id,"reason":"mounted"}));
                continue;
            }
            authorize()?;
            lock.recheck()?;
            idle.recheck()?;
            let members = remove_tree(&parent, &id, authorize)?;
            removed.push(value!({"folder":folder,"id":id,"members":members}));
        }
    }
    idle.recheck()?;
    Ok(value!({"removed":removed,"kept":kept}))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open_directory(parent: &File, name: &CString) -> Result<File> {
    // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "transient member directory open failed")?;
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(raw) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn unlink(parent: &File, name: &CString, directory: bool) -> Result<()> {
    require(
        // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
        unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        } == 0,
        "transient member removal failed",
    )
}
/// Remove one private root-owned tree without following symlinks or leaving
/// the parent's filesystem and mount; any crossing aborts the removal.
fn remove_tree(
    parent: &File,
    name: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<u64> {
    remove_owned_tree(parent, name, 0, authorize)
}
/// [`remove_tree`] for a private (0700) tree of `owner`; backup history
/// removes failed backups' staging with it.
pub(crate) fn remove_owned_tree(
    parent: &File,
    name: &str,
    owner: u32,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<u64> {
    let device = parent.metadata()?.dev();
    let mount = mount_identity::id(parent.as_fd(), true)?;
    let name = CString::new(name).map_err(|_| Error("transient name encoding".into()))?;
    let top = open_directory(parent, &name)?;
    let m = top.metadata()?;
    require(
        m.uid() == owner
            && m.mode() & 0o7777 == 0o700
            && m.dev() == device
            && mount_identity::id(top.as_fd(), true)? == mount,
        "foreign or independently mounted update resource",
    )?;
    let mut members = 0;
    empty(&top, device, mount, 0, &mut members, authorize)?;
    drop(top);
    unlink(parent, &name, true)?;
    parent.sync_all()?;
    Ok(members)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
fn empty(
    directory: &File,
    device: u64,
    mount: u64,
    depth: usize,
    members: &mut u64,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    require(depth < MAX_TREE_DEPTH, "transient tree depth bound")?;
    for name in files::directory_names(directory, 131072)? {
        *members += 1;
        require(*members <= MAX_TREE_MEMBERS, "transient tree member bound")?;
        if (*members).is_multiple_of(1024) {
            authorize()?;
        }
        let name = CString::new(name.as_bytes())
            .map_err(|_| Error("transient member name encoding".into()))?;
        // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: The name is NUL-terminated, the stat buffer is writable, and `directory`
            // stays open.
            unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    &mut status,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0,
            "transient member status failed",
        )?;
        require(status.st_dev == device, "transient member left filesystem")?;
        if status.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = open_directory(directory, &name)?;
            require(
                child.metadata()?.dev() == device
                    && mount_identity::id(child.as_fd(), true)? == mount,
                "transient member directory is independently mounted",
            )?;
            empty(&child, device, mount, depth + 1, members, authorize)?;
            drop(child);
            unlink(directory, &name, true)?;
        } else {
            unlink(directory, &name, false)?;
        }
    }
    Ok(())
}
