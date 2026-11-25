// SPDX-License-Identifier: MIT
//! Native inspection schema2. Original measurements are report data, never deletion authority.
use crate::{operation, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, process_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::Arc,
};
#[path = "boot_process_handles.rs"]
mod kernel_handles;
const MAX_PROCESSES: usize = 4096;
const MAX_HANDLES: usize = 32768;
const MAX_MAPS: usize = 16384;
const MAX_TOTAL_MAP_BYTES: usize = 32 * 1024 * 1024;
fn text(path: &Path, limit: usize, uid: u32) -> Result<String> {
    String::from_utf8(files::read_kernel_owned(path, limit, uid)?)
        .map_err(|_| Error("boot inspection kernel text encoding".into()))
}
fn stat(body: &str, pid: u32) -> Result<process_identity::Stat> {
    // Ordinary tasks keep the strict positive-start contract. Only the parser
    // requiring the actual PF_KTHREAD bit admits a legitimate boot-time zero.
    process_identity::parse_stat(body, pid)
        .or_else(|_| process_identity::parse_kernel_stat(body, pid))
}
fn pid_names() -> Result<BTreeSet<u32>> {
    let proc = files::directory(Path::new("/proc"), None)?;
    let mut pids = BTreeSet::new();
    for name in files::directory_names(&proc, 8192)? {
        let Some(name) = name.to_str() else { continue };
        if name.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty() {
            let pid = name
                .parse::<u32>()
                .map_err(|_| Error("kernel PID range".into()))?;
            require(
                pid > 0 && pid.to_string() == name && pids.len() < MAX_PROCESSES,
                "bounded canonical process census required",
            )?;
            pids.insert(pid);
        }
    }
    Ok(pids)
}
struct Process {
    pid: u32,
    start: u64,
    uid: u32,
    _pidfd: File,
    record: Value,
    map_bytes: usize,
    handles: usize,
}
impl Process {
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    fn alive(&self) -> Result<()> {
        let mut p = libc::pollfd {
            fd: self._pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(
            unsafe { libc::poll(&mut p, 1, 0) } == 0,
            "original process departed during inspection",
        )?;
        let stat = stat(
            &text(
                &PathBuf::from(format!("/proc/{}/stat", self.pid)),
                8192,
                self.uid,
            )?,
            self.pid,
        )?;
        require(
            stat.start_ticks == self.start
                && std::fs::metadata(format!("/proc/{}", self.pid))?.uid() == self.uid,
            "inspection process identity changed",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    fn observe(pid: u32) -> Result<Self> {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let uid = std::fs::metadata(&base)?.uid();
        let before = stat(&text(&base.join("stat"), 8192, uid)?, pid)?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let pidfd = unsafe { File::from_raw_fd(raw as i32) };
        let fd_parent = files::directory(&base.join("fd"), None)?;
        let names = files::directory_names(&fd_parent, MAX_HANDLES)?;
        let mut handles = Vec::new();
        for name in names {
            let name = name
                .to_str()
                .ok_or_else(|| Error("kernel descriptor name encoding".into()))?;
            let fd = name
                .parse::<u32>()
                .map_err(|_| Error("kernel descriptor number".into()))?;
            require(
                fd.to_string() == name,
                "canonical kernel descriptor number required",
            )?;
            let path = base.join("fd").join(name);
            // Explicit numeric kernel links only. Opening a target is forbidden:
            // descriptors are measured, not duplicated or adopted from another task.
            let link = std::fs::read_link(&path)?;
            let link = link
                .to_str()
                .ok_or_else(|| Error("kernel handle path encoding".into()))?;
            require(
                link.len() <= 4096 && !link.contains('\0'),
                "kernel handle path bound",
            )?;
            let metadata = std::fs::metadata(&path)?;
            let info = text(&base.join("fdinfo").join(name), 16384, uid)?;
            let mut mounts = Vec::new();
            for line in info.lines() {
                if let Some(id) = line.strip_prefix("mnt_id:") {
                    let id = id
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| Error("kernel handle mount ID".into()))?;
                    mounts.push(id);
                }
            }
            require(mounts.len() <= 1, "ambiguous handle mount identity")?;
            handles.push(value!({"fd":fd,"target":link,"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),"mount_id":mounts.first()}));
        }
        handles.sort_by_key(|r| r["fd"].as_u64().unwrap());
        let maps = text(&base.join("maps"), 2 * 1024 * 1024, uid)?;
        require(
            maps.lines().count() <= MAX_MAPS,
            "kernel mappings count bound",
        )?;
        let map_bytes = maps.len();
        let handle_count = handles.len();
        let record = value!({"pid":pid,"directory_owner_uid":uid,"start_ticks":before.start_ticks,"handles":handles,
            "maps":maps,"maps_sha256":json::sha256(maps.as_bytes())});
        let process = Self {
            pid,
            start: before.start_ticks,
            uid,
            _pidfd: pidfd,
            record,
            map_bytes,
            handles: handle_count,
        };
        process.alive()?;
        Ok(process)
    }
}
fn process_references() -> Result<Value> {
    let before = pid_names()?;
    let mut observed = Vec::new();
    let mut blockers = BTreeSet::new();
    let mut map_bytes = 0usize;
    let mut handles = 0usize;
    let mut legacy_references = Vec::new();
    let mut legacy_handles = 0usize;
    let mut legacy_mappings = 0usize;
    let mut legacy_bytes = 0usize;
    for pid in &before {
        match Process::observe(*pid) {
            Ok(process) => {
                map_bytes = map_bytes
                    .checked_add(process.map_bytes)
                    .ok_or_else(|| Error("process mapping census overflow".into()))?;
                handles = handles
                    .checked_add(process.handles)
                    .ok_or_else(|| Error("process handle census overflow".into()))?;
                require(
                    map_bytes <= MAX_TOTAL_MAP_BYTES && handles <= MAX_HANDLES,
                    "aggregate process census bound",
                )?;
                match kernel_handles::inspect(&process) {
                    Ok(measurement) => {
                        legacy_handles = legacy_handles
                            .checked_add(measurement.handles)
                            .ok_or_else(|| Error("kernel handle census overflow".into()))?;
                        legacy_mappings = legacy_mappings
                            .checked_add(measurement.mappings)
                            .ok_or_else(|| Error("kernel mapping count overflow".into()))?;
                        legacy_bytes = legacy_bytes
                            .checked_add(measurement.bytes)
                            .ok_or_else(|| Error("kernel census byte overflow".into()))?;
                        require(
                            legacy_handles <= MAX_HANDLES && legacy_bytes <= MAX_TOTAL_MAP_BYTES,
                            "aggregate kernel metadata census bound",
                        )?;
                        legacy_references.extend(measurement.references);
                        blockers.extend(measurement.blockers);
                    }
                    Err(_) => {
                        blockers.insert("process-handles-unreadable".into());
                    }
                }
                observed.push(process);
            }
            Err(error) => {
                blockers.insert(format!("process-{pid}-unavailable: {error}"));
            }
        }
    }
    if pid_names()? != before {
        blockers.insert("process-membership-changed-during-observation".into());
    }
    for p in &observed {
        if p.alive().is_err() {
            blockers.insert(format!("original-process-{}-departed", p.pid));
        }
    }
    blockers.insert("mapped-file-and-kernel-held-references-not-complete".into());
    let legacy = value!({"schema":1,"references":legacy_references,"handles_sampled":legacy_handles,"mappings_sampled":legacy_mappings,
        "blockers":blockers,"complete":false,"deletion_authorized":false});
    Ok(
        value!({"schema":2,"complete":false,"execution_authorized":false,"observed_processes":observed.iter().map(|p|&p.record).collect::<Vec<_>>(),
        "handle_count":handles,"mapping_bytes":map_bytes,"blockers":blockers,"legacy":legacy,
        "scope":"bounded leader descriptor and mapping inspection; not a global atomic or all-thread ownership census"}),
    )
}
pub fn collect() -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    let lock = operation::lock()?;
    let guard = Guard::observe()?;
    let permission = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()
    };
    permission()?;
    let mut blockers = BTreeSet::from([
        "inspection-data-does-not-authorize-retirement".to_owned(),
        "global-atomic-filesystem-and-all-thread-handle-inventory-unqualified".to_owned(),
    ]);
    let transaction = Arc::new(crate::catalog::Transaction::begin()?);
    require(
        transaction.config == guard.configuration,
        "boot inspection publisher source differs",
    )?;
    let context = match crate::boot_retirement_context::Context::observe_shared_catalog(
        &guard,
        &lock,
        std::sync::Arc::clone(&transaction),
        &mut || permission(),
    ) {
        Ok(context) => Some(context),
        Err(error) => {
            blockers.insert(format!("original-boot-context-unavailable: {error}"));
            None
        }
    };
    let namespaces = match crate::namespaces::observe() {
        Ok(observed) => Some(observed),
        Err(error) => {
            blockers.insert(format!(
                "complete-mount-namespace-observation-unavailable: {error}"
            ));
            None
        }
    };
    permission()?;
    let namespace_data = namespaces
        .as_ref()
        .map(crate::namespaces::Observation::json);
    let mut families = match crate::boot_inventory_families::Observation::observe(
        &guard,
        &lock,
        &transaction,
        namespace_data.as_ref(),
    ) {
        Ok(original) => Some(original),
        Err(error) => {
            blockers.insert(format!("original-reference-families-unavailable: {error}"));
            None
        }
    };
    let processes = process_references()?;
    for reason in enzimos_platform::json::array(&processes["blockers"])? {
        blockers.insert(enzimos_platform::json::string(reason)?.to_owned());
    }
    let original = context
        .as_ref()
        .map(|context| {
            let result = context.evidence(&mut || permission())?.clone();
            context.recheck(&mut || permission())?;
            Ok::<_, Error>(result)
        })
        .transpose()?;
    if let (Some(families), Some(boot)) = (&mut families, &original)
        && let Err(error) = families.complete_graph(&transaction, boot)
    {
        blockers.insert(format!("original-recovery-graph-unavailable: {error}"));
    }
    let family_data = families
        .as_ref()
        .map(super::boot_inventory_families::Observation::evidence)
        .transpose()?;
    if let Some(original) = &namespace_data {
        require(
            crate::namespaces::observe()?.json() == *original,
            "original namespace reference census changed during diagnostic collection",
        )?;
    }
    transaction.recheck()?;
    permission()?;
    let mut report = value!({"schema":2,"status":"OBSERVED-retirement-blocked","complete":false,"execution_available":false,
        "boot_id":operation::boot_id()?,"running_kernel":crate::namespaces::kernel_release()?,
        "source":guard.backup_root_binding()?,"publisher_catalog":transaction.data,"original_boot_context":original,
        "mount_namespaces":namespace_data,"reference_families":family_data,"process_references":processes,"blockers":blockers,
        "observation_scope":"fresh bounded native inspection; no serialized report constructs an execution actor"});
    report["observation_sha256"] = value!(json::fingerprint(&report)?);
    permission()?;
    Ok(report)
}
