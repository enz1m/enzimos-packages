// SPDX-License-Identifier: MIT
//! Kernel-origin namespace authority and complete bounded mount observations.
use crate::operation;
use enzimos_platform::{Error, Result, files, json, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
    time::{Duration, Instant},
};
pub const KINDS: &[&str] = &["mnt", "pid", "user", "net", "uts", "ipc", "cgroup"];
#[allow(unsafe_code, reason = "Linux syscall ABI (uname).")]
pub fn kernel_release() -> Result<String> {
    let mut data = std::mem::MaybeUninit::<libc::utsname>::uninit();
    require(
        unsafe { libc::uname(data.as_mut_ptr()) } == 0,
        "kernel identity unavailable",
    )?;
    let data = unsafe { data.assume_init() };
    let bytes = unsafe { std::ffi::CStr::from_ptr(data.release.as_ptr()) }.to_bytes();
    let release =
        std::str::from_utf8(bytes).map_err(|_| Error("kernel release encoding".into()))?;
    crate::identity::safe_id(release)?;
    Ok(release.into())
}
fn path(pid: u32, relative: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{relative}"))
}
pub fn identity(pid: u32, kind: &str) -> Result<(u64, u64)> {
    require(KINDS.contains(&kind), "unqualified kernel namespace kind")?;
    // Only fixed numeric kernel namespace links are followed here.
    let metadata = std::fs::metadata(path(pid, &format!("ns/{kind}")))
        .map_err(|error| sample_error(pid, kind, error))?;
    Ok((metadata.dev(), metadata.ino()))
}
pub(crate) fn kernel_thread(body: &str) -> Result<()> {
    ticks(body, 2)?;
    let start = body
        .find('(')
        .ok_or_else(|| Error("kernel thread stat header".into()))?;
    let end = body
        .rfind(')')
        .ok_or_else(|| Error("kernel thread stat header".into()))?;
    require(
        start < end && &body[start + 1..end] == "kthreadd",
        "initial PID namespace kernel thread unavailable",
    )?;
    let flags = body[end + 1..]
        .split_whitespace()
        .nth(6)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| Error("kernel thread flags unavailable".into()))?;
    require(
        flags & 0x00200000 != 0,
        "initial PID namespace kernel thread unavailable",
    )
}
fn ticks(body: &str, pid: u32) -> Result<u64> {
    require(
        body.len() <= 8192 && !body.contains('\0'),
        "namespace process stat bound",
    )?;
    let begin = body
        .find('(')
        .ok_or_else(|| Error("namespace process stat shape".into()))?;
    let end = body
        .rfind(')')
        .ok_or_else(|| Error("namespace process stat shape".into()))?;
    require(
        begin < end
            && body[..begin].trim().parse::<u32>().ok() == Some(pid)
            && pid > 0
            && pid < i32::MAX as u32,
        "namespace process stat PID mismatch",
    )?;
    let fields = body[end + 1..].split_whitespace().collect::<Vec<_>>();
    require(
        (20..=64).contains(&fields.len())
            && fields[0].len() == 1
            && "RSDZTtXxKWPI".contains(fields[0]),
        "namespace process stat fields",
    )?;
    // Initial PID1 and kernel threads may have started on tick zero. Observation
    // does not turn that value into a reusable process-termination authority.
    fields[19]
        .parse::<u64>()
        .map_err(|_| Error("namespace process start identity".into()))
}
pub fn initial() -> Result<Vec<(u64, u64)>> {
    operation::root_only()?;
    let own = std::process::id();
    let stat = files::read_kernel(&path(2, "stat"), 8192)?;
    kernel_thread(
        std::str::from_utf8(&stat).map_err(|_| Error("kernel thread stat encoding".into()))?,
    )?;
    let mut identities = Vec::new();
    for kind in KINDS {
        let current = identity(own, kind)?;
        require(
            current == identity(2, kind)?,
            "initial kernel namespaces required",
        )?;
        identities.push(current);
    }
    for name in ["uid_map", "gid_map"] {
        let body = files::read_kernel(&path(own, name), 8192)?;
        require(
            std::str::from_utf8(&body).ok().is_some_and(|s| {
                s.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"]
            }),
            "initial user namespace required",
        )?;
    }
    Ok(identities)
}
pub struct View {
    pub representative: u32,
    pub identity: (u64, u64),
    pub sha: String,
    pub mounts: Vec<mountinfo::Row>,
    // Retain the actual nsfs object: its inode cannot be recycled during use.
    _namespace: File,
}
pub struct Observation {
    pub views: Vec<View>,
}
impl Observation {
    pub fn json(&self) -> Value {
        value!({"departed_processes":[],"namespaces":self.views.iter().map(|v| value!({"namespace":format!("mnt:[{}]",v.identity.1),"representative_pid":v.representative,"sha256":v.sha,"mounts":v.mounts.iter().map(|r| value!({"id":r.id,"parent":r.parent,"major":r.major,"minor":r.minor,"root":r.root,"target":r.target,"fstype":r.filesystem,"options":r.options})).collect::<Vec<_>>()})).collect::<Vec<_>>()})
    }
    pub(crate) fn refuse_subtrees(
        &self,
        source: &str,
        target: &str,
        target_root: &str,
    ) -> Result<()> {
        for view in &self.views {
            for row in &view.mounts {
                require(
                    ![source, target].iter().any(|path| {
                        row.target == *path || row.target.starts_with(&format!("{path}/"))
                    }),
                    "mounted source or target subtree prevents recovery staging",
                )?;
                require(
                    !(row.filesystem == "btrfs"
                        && (row.root == target_root
                            || row.root.starts_with(&format!("{target_root}/")))),
                    "recovery destination mounted in a namespace",
                )?;
            }
        }
        Ok(())
    }
}
enum ScanError {
    Departed(&'static str),
    Refused(Error),
}
impl From<Error> for ScanError {
    fn from(error: Error) -> Self {
        Self::Refused(error)
    }
}
impl From<std::io::Error> for ScanError {
    fn from(error: std::io::Error) -> Self {
        Self::Refused(error.into())
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
fn exited(file: &File) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    require(
        result >= 0 && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
        "namespace original process exit observation unavailable",
    )?;
    Ok(result > 0 && poll.revents & libc::POLLIN != 0)
}
// Namespace links can disappear during exit before the pidfd becomes readable.
// A failed sample gets a bounded wait on its original kernel identity; a still
// live or unreadable actor keeps the original refusal, never a partial map.
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
fn exited_after_sample(file: &File, failed: bool) -> Result<bool> {
    if exited(file)? {
        return Ok(true);
    }
    if !failed {
        return Ok(false);
    }
    let deadline = Instant::now() + Duration::from_millis(25);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return exited(file);
        }
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = remaining.as_millis().clamp(1, 25) as i32;
        let result = unsafe { libc::poll(&mut poll, 1, timeout) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        require(
            result >= 0 && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "namespace original process exit settling unavailable",
        )?;
        if result > 0 && poll.revents & libc::POLLIN != 0 {
            return Ok(true);
        }
    }
}
struct OriginalProcess {
    pid: u32,
    file: File,
}
impl OriginalProcess {
    fn dead(&self) -> Result<bool> {
        dead_original(&self.file, self.pid)
    }
}
fn original(pid: u32) -> std::result::Result<OriginalProcess, ScanError> {
    original_kind(pid, 0)
}
fn original_thread(tid: u32) -> std::result::Result<OriginalProcess, ScanError> {
    // Linux 6.9 PIDFD_THREAD is O_EXCL in the public UAPI. Unsupported kernels
    // refuse; substituting a whole-group handle would lose thread-death proof.
    original_kind(tid, libc::O_EXCL)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, syscall).")]
fn original_kind(pid: u32, flags: i32) -> std::result::Result<OriginalProcess, ScanError> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) } as i32;
    if raw < 0 {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                ScanError::Departed("process vanished before original pidfd retention")
            } else {
                ScanError::Refused(sample_error(
                    pid,
                    "original pidfd retention",
                    std::io::Error::last_os_error(),
                ))
            },
        );
    }
    let file = unsafe { File::from_raw_fd(raw) };
    require(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "namespace process descriptor must be CLOEXEC",
    )?;
    Ok(OriginalProcess { pid, file })
}
// Busy hosts (package hooks forking on several CPUs) can cross a process exit
// in many consecutive whole scans; back off and keep sampling for a bounded
// window instead of failing after a few milliseconds.
const STABLE_ATTEMPTS: u32 = 48;
const STABLE_WINDOW: Duration = Duration::from_secs(4);
fn stable<T>(mut sample: impl FnMut() -> std::result::Result<T, ScanError>) -> Result<T> {
    let start = Instant::now();
    let mut last = "unavailable original process";
    for attempt in 0..STABLE_ATTEMPTS {
        match sample() {
            Ok(value) => return Ok(value),
            Err(ScanError::Refused(error)) => return Err(error),
            Err(ScanError::Departed(reason)) => last = reason,
        }
        if attempt + 1 == STABLE_ATTEMPTS || start.elapsed() >= STABLE_WINDOW {
            break;
        }
        std::thread::sleep(Duration::from_millis((5u64 << attempt.min(4)).min(80)));
    }
    Err(Error(format!(
        "complete namespace observation repeatedly crossed an original process exit: {last}"
    )))
}
pub fn observe() -> Result<Observation> {
    operation::root_only()?;
    // Retry only fresh read-only samples. Never retain a partial namespace map,
    // skip an unreadable process, or repeat the caller's storage operation.
    stable(|| observe_once(Sampling::Strict))
}
/// Mounted-target admission counts active actors, unlike retirement observations.
/// Only original thread-pidfd-confirmed death permits thread exclusion; whole
/// groups are excluded only after original group-pidfd death. An unknown
/// numeric PID occupant still discards the complete sample.
pub fn observe_active() -> Result<Observation> {
    operation::root_only()?;
    stable(|| observe_once(Sampling::Active))
}
#[derive(Clone, Copy)]
enum Sampling {
    Strict,
    Active,
}
fn sample_error(pid: u32, role: &str, error: impl std::fmt::Display) -> Error {
    Error(format!("namespace original process {pid} {role}: {error}"))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn namespace_file(pid: u32, expected: (u64, u64)) -> Result<File> {
    // This fixed kernel magic link is intentional; no caller-controlled path.
    let file =
        File::open(path(pid, "ns/mnt")).map_err(|error| sample_error(pid, "nsfs open", error))?;
    let metadata = file.metadata()?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } == 0,
        "namespace descriptor filesystem unavailable",
    )?;
    require(
        unsafe { filesystem.assume_init() }.f_type == 0x6e736673
            && (metadata.dev(), metadata.ino()) == expected,
        "namespace descriptor is not the original nsfs object",
    )?;
    Ok(file)
}
fn dead_original(process: &File, pid: u32) -> Result<bool> {
    if !exited(process)? {
        return Ok(false);
    }
    // A still-mapped dead group owns this PID, preventing numeric reuse. Once
    // reaped, absence must also be proven. A new occupant cannot be skipped.
    match enzimos_platform::process_identity::pidfd_mapping(process.as_fd())? {
        Some(mapped) => {
            require(mapped == pid, "dead original process mapping differs")?;
            Ok(true)
        }
        None => match std::fs::metadata(path(pid, "")) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(true),
            Ok(_) => Ok(false),
            Err(error) => Err(error.into()),
        },
    }
}
fn group_id(body: &[u8]) -> Result<u32> {
    let text =
        std::str::from_utf8(body).map_err(|_| Error("original task status encoding".into()))?;
    let rows = text
        .lines()
        .filter_map(|s| s.strip_prefix("Tgid:"))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "original task group identity shape")?;
    let id = rows[0]
        .trim()
        .parse::<u32>()
        .map_err(|_| Error("original task group identity bound".into()))?;
    require(
        id > 0 && id < i32::MAX as u32,
        "original task group identity bound",
    )?;
    Ok(id)
}
fn original_tasks(group: &OriginalProcess) -> std::result::Result<Vec<OriginalProcess>, ScanError> {
    require(
        enzimos_platform::process_identity::pidfd_target(group.file.as_fd())? == group.pid,
        "original group identity changed before task enumeration",
    )?;
    let mut tasks = Vec::new();
    for entry in std::fs::read_dir(path(group.pid, "task"))
        .map_err(|error| sample_error(group.pid, "task directory enumeration", error))?
    {
        let entry =
            entry.map_err(|error| sample_error(group.pid, "task directory entry", error))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| Error("original thread name encoding".into()))?;
        require(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) && tasks.len() < 16384,
            "original thread enumeration bound",
        )?;
        let tid = name
            .parse::<u32>()
            .map_err(|_| Error("original thread identity bound".into()))?;
        require(
            tid > 0 && tid < i32::MAX as u32 && tid.to_string() == name,
            "original thread identity shape",
        )?;
        let task = original_thread(tid)?;
        let observed = (|| -> Result<()> {
            require(
                enzimos_platform::process_identity::pidfd_target(task.file.as_fd())? == tid,
                "original thread descriptor mapping differs",
            )?;
            let owner = std::fs::metadata(path(tid, ""))
                .map_err(|error| sample_error(tid, "thread directory metadata", error))?
                .uid();
            let status = files::read_kernel_owned(&path(tid, "status"), 65536, owner)
                .map_err(|error| sample_error(tid, "thread group status", error))?;
            require(
                group_id(&status)? == group.pid,
                "enumerated original thread belongs to another group",
            )
        })();
        if exited_after_sample(&task.file, observed.is_err())? {
            return Err(ScanError::Departed(
                "original thread exited during retention",
            ));
        }
        observed?;
        tasks.push(task);
    }
    require(
        !tasks.is_empty()
            && enzimos_platform::process_identity::pidfd_target(group.file.as_fd())? == group.pid,
        "original group changed or has no readable threads",
    )?;
    Ok(tasks)
}
fn observe_once(sampling: Sampling) -> std::result::Result<Observation, ScanError> {
    let mut processes = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(name) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            let pid = name
                .parse::<u32>()
                .map_err(|_| Error("kernel process identity bound".into()))?;
            require(
                pid > 0 && processes.len() < 16384,
                "process namespace observation bound",
            )?;
            // Retain original kernel identities before slow namespace reads.
            // A later group exit can then be proven without opening its numeric
            // PID again. ESRCH here still discards the entire fresh sample.
            processes.push(original(pid)?);
        }
    }
    let mut threads = Vec::new();
    for group in processes {
        let sampled = original_tasks(&group);
        if exited_after_sample(&group.file, sampled.is_err())? {
            match sampling {
                Sampling::Active if group.dead()? => continue,
                _ => {
                    return Err(ScanError::Departed(
                        "original group exited during thread enumeration",
                    ));
                }
            }
        }
        let sampled = sampled?;
        require(
            threads.len() + sampled.len() <= 32768,
            "complete original thread count bound",
        )?;
        threads.extend(sampled);
    }
    threads.sort_unstable_by_key(|thread| thread.pid);
    let mut views = BTreeMap::new();
    let mut total = 0;
    for original in threads {
        let pid = original.pid;
        let process = &original.file;
        let observed = (|| -> Result<Option<(View, usize)>> {
            require(
                enzimos_platform::process_identity::pidfd_target(process.as_fd())? == pid,
                "namespace original process identity differs",
            )?;
            let owner = std::fs::metadata(path(pid, ""))
                .map_err(|error| sample_error(pid, "proc directory metadata", error))?
                .uid();
            let read = |name: &str, bound| {
                files::read_kernel_owned(&path(pid, name), bound, owner)
                    .map_err(|error| sample_error(pid, name, error))
            };
            let before = read("stat", 8192)?;
            let before = ticks(
                std::str::from_utf8(&before)
                    .map_err(|_| Error("process namespace stat encoding".into()))?,
                pid,
            )?;
            let namespace = identity(pid, "mnt")
                .map_err(|error| sample_error(pid, "initial mount identity", error))?;
            let candidate = if !views.contains_key(&namespace) {
                let descriptor = namespace_file(pid, namespace)?;
                let body = read("mountinfo", 2 * 1024 * 1024)?;
                require(
                    total + body.len() <= 8 * 1024 * 1024,
                    "mount namespace total byte bound",
                )?;
                let mounts = mountinfo::parse(
                    std::str::from_utf8(&body)
                        .map_err(|_| Error("mount namespace encoding".into()))?,
                )?;
                Some((
                    View {
                        representative: pid,
                        identity: namespace,
                        sha: json::sha256(&body),
                        mounts,
                        _namespace: descriptor,
                    },
                    body.len(),
                ))
            } else {
                None
            };
            let after = read("stat", 8192)?;
            let after = ticks(
                std::str::from_utf8(&after)
                    .map_err(|_| Error("process namespace stat encoding".into()))?,
                pid,
            )?;
            require(
                before == after
                    && identity(pid, "mnt")
                        .map_err(|error| sample_error(pid, "final mount identity", error))?
                        == namespace,
                "process or mount namespace changed during observation",
            )?;
            require(
                enzimos_platform::process_identity::pidfd_target(process.as_fd())? == pid,
                "namespace original process mapping changed",
            )?;
            Ok(candidate)
        })();
        if exited_after_sample(process, observed.is_err())? {
            match sampling {
                Sampling::Active if original.dead()? => continue,
                Sampling::Active => {
                    return Err(ScanError::Departed(
                        "dead original PID has another occupant",
                    ));
                }
                Sampling::Strict => {
                    return Err(ScanError::Departed(
                        "original group exited during strict sampling",
                    ));
                }
            }
        }
        if let Some((view, size)) = observed.map_err(ScanError::Refused)? {
            total += size;
            views.insert(view.identity, view);
        }
    }
    // Only validated, retained thread namespaces enter the map. Live unreadable tasks
    // always refuse; retirement also discards the map on any original exit.
    Ok(Observation {
        views: views.into_values().collect(),
    })
}

#[cfg(test)]
mod subtree_tests {
    use super::*;
    #[test]
    fn any_foreign_namespace_source_target_or_destination_root_mount_blocks_staging() {
        let row = "41 1 0:31 /root /run/enzimos/recovery-top rw - btrfs /dev/mapper/recover rw\n";
        let observation = |text| Observation {
            views: vec![View {
                representative: 1,
                identity: (4, 99),
                sha: "a".repeat(64),
                mounts: mountinfo::parse(text).unwrap(),
                _namespace: namespace_file(
                    std::process::id(),
                    identity(std::process::id(), "mnt").unwrap(),
                )
                .unwrap(),
            }],
        };
        observation(row)
            .refuse_subtrees(
                "/run/enzimos/recovery-top/root/.snapshots/1/snapshot",
                "/run/enzimos/recovery-top/enzimos-recovered-job1",
                "/enzimos-recovered-job1",
            )
            .unwrap();
        for row in [
            "41 1 0:31 /root /run/enzimos/recovery-top/root/.snapshots/1/snapshot/sub rw - btrfs /dev/mapper/recover rw\n",
            "41 1 0:31 /root /run/enzimos/recovery-top/enzimos-recovered-job1 rw - btrfs /dev/mapper/recover rw\n",
            "41 1 0:31 /enzimos-recovered-job1 /other-namespace/target rw - btrfs /dev/mapper/recover rw\n",
            "41 1 0:31 /enzimos-recovered-job1/nested /other-namespace/target rw - btrfs /dev/mapper/recover rw\n",
        ] {
            assert!(
                observation(row)
                    .refuse_subtrees(
                        "/run/enzimos/recovery-top/root/.snapshots/1/snapshot",
                        "/run/enzimos/recovery-top/enzimos-recovered-job1",
                        "/enzimos-recovered-job1"
                    )
                    .is_err()
            );
        }
        assert_eq!(
            observation(row).json()["departed_processes"],
            serde_json::json!([])
        );
    }
}
