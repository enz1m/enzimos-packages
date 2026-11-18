// SPDX-License-Identifier: MIT
//! Bounded history for restore, export, delivery and remote-copy registries.
//!
//! Each of these registries has a small lifetime capacity (16 or 32 records)
//! and refused forever once it filled. Records are retired here, oldest first
//! and always keeping the newest few, only when they are provably finished:
//! a worker whose kernel scope closed, a launch whose worker closed or whose
//! boot ended (no worker unit survives a reboot), a delivered, cancelled or
//! expired grant, a complete retrieval, and a private export copy that no live
//! grant can still deliver. All callers hold the operation lock and have not
//! yet observed the registry being retired.
use crate::{
    control_registry::{self, Folder, Row},
    storage_runtime::Guard,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
/// Recent records always kept in every registry handled here.
pub const KEEP: usize = 8;
const LIMIT: usize = 1024 * 1024;
const EXPORTS: &str = "restore-exports";
const GRANTS: &str = "restore-delivery-grants";
const RETRIEVALS: &str = "backup-retrievals";
/// Worker launch registries paired with their worker request registries.
pub const SELECTIVE: (&str, &str) = ("selective-export-launches", "selective-export-workers");
pub const REMOTE: (&str, &str) = ("backup-remote-launches", "backup-remote-workers");
fn identity(v: &Value, id: &str) -> Result<()> {
    require(v["id"] == id, "registry record identity")
}
/// A worker request is finished once its kernel scope closed, or when its
/// launch belongs to an earlier boot.
pub(crate) fn worker_finished(worker: &Value, launch: Option<&Value>, boot: &str) -> bool {
    worker["phase"] == "worker-kernel-closed"
        || launch.is_some_and(|l| l["boot_id"].as_str().is_some_and(|b| b != boot))
}
/// A launch never advances past `starting`; it is finished when its worker
/// closed or when it belongs to an earlier boot.
pub(crate) fn launch_finished(launch: &Value, worker: Option<&Value>, boot: &str) -> bool {
    launch["boot_id"].as_str().is_some_and(|b| b != boot)
        || worker.is_some_and(|w| w["phase"] == "worker-kernel-closed")
}
/// Delivered or cancelled grants are final; a granted one from an earlier boot
/// expired (delivery requires the granting boot). An entered delivery stays.
pub(crate) fn grant_finished(grant: &Value, boot: &str) -> bool {
    match grant["phase"].as_str() {
        Some("complete" | "cancelled") => true,
        Some("granted") => grant["boot_id"].as_str().is_some_and(|b| b != boot),
        _ => false,
    }
}
/// A copying retrieval from an earlier boot was interrupted with its worker.
pub(crate) fn retrieval_finished(receipt: &Value, boot: &str) -> bool {
    receipt["phase"] == "complete"
        || receipt["phase"] == "copying" && receipt["boot_id"].as_str().is_some_and(|b| b != boot)
}
/// A private export may be removed when it is complete and no grant can still
/// deliver it, or when its worker was interrupted in an earlier boot. A
/// directory without a record is an interrupted creation only when empty.
pub(crate) fn export_retirable(
    id: &str,
    record: Option<&Value>,
    members: usize,
    grants: &[&Value],
    boot: &str,
) -> bool {
    let Some(record) = record else {
        return members == 0;
    };
    if record["id"] != id {
        return false;
    }
    match record["phase"].as_str() {
        Some("complete") => {
            let mentioned = grants
                .iter()
                .filter(|g| g["export"]["export"] == id)
                .collect::<Vec<_>>();
            let active = mentioned.iter().any(|g| match g["phase"].as_str() {
                Some("granted") => g["boot_id"] == boot,
                Some("delivering") => true,
                _ => false,
            });
            // An export never delivered is kept for the boot that made it: the
            // user may still deliver it, and its snapshot may since have been
            // rotated away.
            let undelivered_this_boot =
                mentioned.is_empty() && record["created_boot"].as_str().is_none_or(|b| b == boot);
            !active && !undelivered_this_boot
        }
        Some("observing" | "copying") => record["created_boot"].as_str().is_some_and(|b| b != boot),
        _ => false,
    }
}
fn open(guard: &Guard, folder: &str) -> Result<Option<Folder>> {
    Folder::open(
        guard.control(),
        guard.control_mount_id(),
        0,
        folder,
        LIMIT,
        identity,
    )
}
fn retire_rows(folder: &mut Folder, rows: Vec<Row>, trigger: usize) -> Result<Vec<String>> {
    let mut retired = Vec::new();
    for id in control_registry::select(rows, KEEP, trigger) {
        if folder.retire(&id)? {
            retired.push(id);
        }
    }
    if !retired.is_empty() {
        folder.sync()?;
    }
    Ok(retired)
}
/// Retire finished launch/worker pairs (workers first, so a launch is never
/// removed while its worker record still needs it to prove its boot).
pub fn retire_launches(guard: &Guard, lock: &files::Lock, pair: (&str, &str)) -> Result<Value> {
    crate::operation::root_only()?;
    guard.recheck()?;
    lock.recheck()?;
    let boot = crate::operation::boot_id()?;
    let Some(mut launches) = open(guard, pair.0)? else {
        return Ok(json!({"launches":[],"workers":[]}));
    };
    let mut workers = open(guard, pair.1)?;
    // Decide launch completion from the workers as observed before retirement.
    let finished = launches
        .members
        .iter()
        .filter(|(id, m)| {
            m.value.as_ref().is_some_and(|l| {
                launch_finished(l, workers.as_ref().and_then(|w| w.value(id)), &boot)
            })
        })
        .map(|(id, _)| id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut workers_retired = Vec::new();
    if let Some(workers) = &mut workers {
        let rows = workers.rows(|id, w| worker_finished(w, launches.value(id), &boot));
        // Workers are retired alongside their launches (trigger on launch count).
        if launches.len() >= 24 {
            workers_retired = retire_rows(workers, rows, 0)?;
        }
    }
    let rows = launches.rows(|id, _| {
        finished.contains(id) && workers.as_ref().is_none_or(|w| !w.members.contains_key(id))
    });
    let launches_retired = retire_rows(&mut launches, rows, 24)?;
    guard.recheck()?;
    lock.recheck()?;
    Ok(json!({"launches":launches_retired,"workers":workers_retired}))
}
/// Retire delivered, cancelled and expired grants.
pub fn retire_grants(guard: &Guard, lock: &files::Lock) -> Result<Vec<String>> {
    crate::operation::root_only()?;
    lock.recheck()?;
    let boot = crate::operation::boot_id()?;
    let retired = control_registry::retire_terminal(
        guard,
        GRANTS,
        KEEP,
        12,
        LIMIT,
        crate::delivery_cancel::validate,
        |_, g| grant_finished(g, &boot),
    )?;
    lock.recheck()?;
    Ok(retired)
}
/// Retire complete and interrupted (earlier-boot) retrieval receipts.
pub fn retire_retrievals(guard: &Guard, lock: &files::Lock) -> Result<Vec<String>> {
    crate::operation::root_only()?;
    lock.recheck()?;
    let boot = crate::operation::boot_id()?;
    let retired = control_registry::retire_terminal(
        guard,
        RETRIEVALS,
        KEEP,
        12,
        LIMIT,
        |v, id| {
            crate::backup_remote_receipt::record(v)?;
            identity(v, id)
        },
        |_, r| retrieval_finished(r, &boot),
    )?;
    lock.recheck()?;
    Ok(retired)
}
struct ExportDirectory {
    order: (i64, i64),
    shape: (u64, u64, u32),
    record: Option<Value>,
    members: BTreeMap<String, files::FileIdentity>,
}
fn export_directory(parent: &File, id: &str, mount: u64) -> Result<Option<ExportDirectory>> {
    // An unexpected entry (non-directory, extra members) is skipped, never an
    // error: one odd directory must not stop every later retirement.
    let Ok(directory) = files::directory_relative(parent, Path::new(id), Some(0)) else {
        return Ok(None);
    };
    let m = directory.metadata()?;
    if m.mode() & 0o7777 != 0o700 || mount_identity::id(directory.as_fd(), true)? != mount {
        return Ok(None);
    }
    let mut members = BTreeMap::new();
    let mut record = None;
    let mut order = (m.mtime(), m.mtime_nsec());
    let Ok(names) = files::directory_names(&directory, 3) else {
        return Ok(None);
    };
    for name in names {
        let Some(name) = name
            .to_str()
            .filter(|n| matches!(*n, "record.json" | "content.bin"))
        else {
            return Ok(None);
        };
        let Some(file) = files::optional_relative(&directory, Path::new(name))? else {
            return Ok(None);
        };
        let fm = file.metadata()?;
        if !(fm.uid() == 0 && fm.nlink() == 1 && mount_identity::id(file.as_fd(), true)? == mount) {
            return Ok(None);
        }
        if name == "record.json" {
            let bytes = files::read_file(&file, 32768, Some(0), true)?;
            record = Some(enzimos_platform::json::decode(&bytes, 32768)?);
            order = (fm.mtime(), fm.mtime_nsec());
        }
        members.insert(name.to_owned(), files::identity(&fm));
    }
    Ok(Some(ExportDirectory {
        order,
        shape: (m.dev(), m.ino(), m.mode()),
        record,
        members,
    }))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn remove_export(parent: &File, id: &str, observed: &ExportDirectory) -> Result<()> {
    let directory = files::directory_relative(parent, Path::new(id), Some(0))?;
    let m = directory.metadata()?;
    require(
        (m.dev(), m.ino(), m.mode()) == observed.shape,
        "retired export directory changed",
    )?;
    // Content first and the record last: an interrupted removal leaves a
    // record (still retirable) or an empty directory (interrupted creation).
    for name in ["content.bin", "record.json"] {
        let Some(expected) = observed.members.get(name) else {
            continue;
        };
        let file = files::optional_relative(&directory, Path::new(name))?
            .ok_or_else(|| Error("retired export member disappeared".into()))?;
        require(
            files::identity(&file.metadata()?) == *expected,
            "retired export member changed",
        )?;
        let c = CString::new(name).map_err(|_| Error("export member name".into()))?;
        require(
            unsafe { libc::unlinkat(directory.as_raw_fd(), c.as_ptr(), 0) } == 0,
            "export member removal failed",
        )?;
    }
    require(
        files::directory_is_empty(&directory)?,
        "retired export directory gained members",
    )?;
    directory.sync_all()?;
    let c = CString::new(id).map_err(|_| Error("export name".into()))?;
    require(
        unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } == 0,
        "export directory removal failed",
    )?;
    Ok(())
}
/// Remove private export copies no grant can still deliver, oldest first,
/// once the export registry is nearly full. The data stays in the backup and
/// can be exported again.
pub fn retire_exports(guard: &Guard, lock: &files::Lock) -> Result<Vec<String>> {
    crate::operation::root_only()?;
    guard.recheck()?;
    lock.recheck()?;
    let boot = crate::operation::boot_id()?;
    let mount = guard.control_mount_id();
    let Some(parent) =
        files::optional_directory_relative(guard.control(), Path::new(EXPORTS), Some(0))?
    else {
        return Ok(Vec::new());
    };
    require(
        parent.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(parent.as_fd(), true)? == mount,
        "export registry protection/mount",
    )?;
    let names = files::directory_names(&parent, 64)?;
    if names.len() < 12 {
        return Ok(Vec::new());
    }
    let grants = open(guard, GRANTS)?;
    let grant_values = grants
        .as_ref()
        .map(|g| {
            g.members
                .values()
                .filter_map(|m| m.value.as_ref())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // A grant that failed validation could still reference an export: keep all.
    if grants
        .as_ref()
        .is_some_and(|g| g.foreign > 0 || g.members.values().any(|m| m.value.is_none()))
    {
        return Ok(Vec::new());
    }
    let mut observed = BTreeMap::new();
    let mut rows = Vec::new();
    for name in names {
        let Some(id) = name
            .to_str()
            .filter(|n| crate::identity::safe_id(n).is_ok())
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(export) = export_directory(&parent, &id, mount)? else {
            continue;
        };
        rows.push(Row {
            order: export.order,
            id: id.clone(),
            retirable: export_retirable(
                &id,
                export.record.as_ref(),
                export.members.len(),
                &grant_values,
                &boot,
            ),
        });
        observed.insert(id, export);
    }
    let mut retired = Vec::new();
    for id in control_registry::select(rows, KEEP, 0) {
        guard.recheck()?;
        lock.recheck()?;
        remove_export(&parent, &id, &observed[&id])?;
        retired.push(id);
    }
    if !retired.is_empty() {
        parent.sync_all()?;
    }
    Ok(retired)
}
