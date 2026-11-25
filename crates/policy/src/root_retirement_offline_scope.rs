// SPDX-License-Identifier: MIT
//! Actual single-thread PID1 on a RAM root, with complete bounded proc census.
//! This is one offline observation prerequisite, not a deletion capability.
use crate::operation;
use enzimos_platform::{Error, Result, files, mount_identity, process_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};

const MAX_TASKS: usize = 4096;
const PF_KTHREAD: u64 = 0x0020_0000;
// Primary Linux sources: include/linux/sched.h and fs/proc/array.c.
// https://github.com/torvalds/linux/blob/master/include/linux/sched.h
// https://github.com/torvalds/linux/blob/master/fs/proc/array.c
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn kind(file: &File) -> Result<i64> {
    let mut data = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(
        // SAFETY: `data` is writable for one `libc::statfs` and `file` keeps the descriptor open.
        unsafe { libc::fstatfs(file.as_raw_fd(), data.as_mut_ptr()) } == 0,
        "offline scope filesystem observation",
    )?;
    // SAFETY: fstatfs returned 0, so it initialized `data`.
    Ok(unsafe { data.assume_init() }.f_type)
}
fn read(file: &File, limit: usize) -> Result<String> {
    let mut bytes = vec![0; limit + 1];
    let mut count = 0;
    while count < bytes.len() {
        let n = file.read_at(&mut bytes[count..], count as u64)?;
        if n == 0 {
            break;
        }
        count += n;
    }
    require(count <= limit, "bounded original offline proc observation")?;
    bytes.truncate(count);
    String::from_utf8(bytes).map_err(|_| Error("offline proc observation encoding".into()))
}
fn field<'a>(body: &'a str, name: &str) -> Result<&'a str> {
    let rows = body
        .lines()
        .filter_map(|line| line.strip_prefix(name))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "exact offline proc status field required")?;
    Ok(rows[0].trim())
}
fn classify(stat: &str, status: &str, pid: u32) -> Result<(u64, bool)> {
    let kernel_status = field(status, "Kthread:")?;
    let identity = if kernel_status == "1" {
        process_identity::parse_kernel_stat(stat, pid)?
    } else {
        process_identity::parse_stat(stat, pid)?
    };
    let suffix = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let flags = suffix[6]
        .parse::<u64>()
        .map_err(|_| Error("offline proc flags".into()))?;
    let kernel = match field(status, "Kthread:")? {
        "0" => false,
        "1" => true,
        _ => return Err(Error("offline kernel task classification".into())),
    };
    require(
        kernel == (flags & PF_KTHREAD != 0),
        "offline kernel task flags/status disagree",
    )?;
    if pid == 1 {
        require(
            !kernel
                && identity.parent == 0
                && field(status, "Threads:")? == "1"
                && suffix[17] == "1"
                && field(status, "TracerPid:")? == "0"
                && field(status, "NSpid:")? == "1"
                && process_identity::parse_uids(status)? == [0; 4],
            "single untraced original Root PID1 required",
        )?;
        let gids = field(status, "Gid:")?
            .split_whitespace()
            .collect::<Vec<_>>();
        require(
            gids == ["0", "0", "0", "0"],
            "offline PID1 Root group identities required",
        )?;
    } else {
        require(
            kernel,
            "another userspace process prevents offline retirement",
        )?;
    }
    Ok((identity.start_ticks, kernel))
}
fn names(proc: &File) -> Result<Vec<u32>> {
    let mut result = Vec::new();
    for name in files::directory_names(proc, 16384)? {
        let name = name
            .to_str()
            .ok_or_else(|| Error("offline proc name encoding".into()))?;
        if name.bytes().all(|c| c.is_ascii_digit()) && !name.is_empty() {
            let pid = name
                .parse::<u32>()
                .map_err(|_| Error("offline proc PID bound".into()))?;
            require(
                pid > 0 && pid < i32::MAX as u32 && result.len() < MAX_TASKS,
                "offline process census bound",
            )?;
            result.push(pid);
        }
    }
    result.sort_unstable();
    require(result.contains(&1), "offline PID1 absent")?;
    Ok(result)
}
fn census(proc: &File) -> Result<BTreeMap<u32, (u64, bool)>> {
    let before = names(proc)?;
    let mut observed = BTreeMap::new();
    for pid in &before {
        let name = pid.to_string();
        let directory = files::directory_relative(proc, Path::new(&name), Some(0))?;
        let original = files::identity(&directory.metadata()?);
        require(
            kind(&directory)? == 0x9fa0,
            "actual proc task directory required",
        )?;
        let stat = files::open_relative(&directory, Path::new("stat"))?;
        let status = files::open_relative(&directory, Path::new("status"))?;
        let first = classify(&read(&stat, 8192)?, &read(&status, 65536)?, *pid)?;
        if *pid == 1 {
            let tasks = files::directory_relative(&directory, Path::new("task"), Some(0))?;
            let tids = files::directory_names(&tasks, 2)?;
            require(
                tids.len() == 1 && tids[0] == "1",
                "offline PID1 has additional threads",
            )?;
        }
        let last = classify(&read(&stat, 8192)?, &read(&status, 65536)?, *pid)?;
        let named = files::directory_relative(proc, Path::new(&name), Some(0))?;
        require(
            first == last
                && files::identity(&directory.metadata()?) == original
                && files::identity(&named.metadata()?) == original,
            "offline task disappeared/reused/changed during observation",
        )?;
        observed.insert(*pid, first);
    }
    require(
        names(proc)? == before,
        "offline process set changed during observation",
    )?;
    Ok(observed)
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "original protected offline directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub struct Scope {
    root: File,
    proc: File,
    root_shape: Shape,
    proc_shape: Shape,
    root_mount: u64,
    proc_mount: u64,
    root_kind: i64,
    root_flags: i32,
    proc_flags: i32,
    boot: String,
    start: u64,
}
impl Scope {
    pub(crate) fn require_ram_member(&self, file: &File) -> Result<()> {
        self.recheck()?;
        require(
            kind(file)? == self.root_kind
                && mount_identity::id(file.as_fd(), true)? == self.root_mount,
            "original offline RAM root member required",
        )
    }
    pub(crate) fn original_start(&self) -> Result<u64> {
        self.recheck()?;
        Ok(self.start)
    }
    pub(crate) fn original_proc(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.proc)
    }
    pub fn observe() -> Result<Self> {
        operation::root_only()?;
        require(
            enzimos_platform::process_identity::current_pid() == 1,
            "offline retirement observation requires actual PID1",
        )?;
        crate::namespaces::initial()?;
        let root = files::directory(Path::new("/"), Some(0))?;
        let proc = files::directory(Path::new("/proc"), Some(0))?;
        let root_kind = kind(&root)?;
        require(
            matches!(root_kind, 0x858458f6 | 0x01021994) && kind(&proc)? == 0x9fa0,
            "offline RAM root and actual proc filesystem required",
        )?;
        let first = census(&proc)?;
        let last = census(&proc)?;
        require(
            first == last,
            "offline complete census changed between passes",
        )?;
        let this = Self {
            root_shape: shape(&root)?,
            proc_shape: shape(&proc)?,
            root_mount: mount_identity::id(root.as_fd(), true)?,
            proc_mount: mount_identity::id(proc.as_fd(), true)?,
            root_kind,
            root_flags: readonly_flags(&root)?,
            proc_flags: readonly_flags(&proc)?,
            boot: operation::boot_id()?,
            start: first[&1].0,
            root,
            proc,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        operation::root_only()?;
        require(
            enzimos_platform::process_identity::current_pid() == 1,
            "original offline PID1 lost",
        )?;
        crate::namespaces::initial()?;
        require(
            operation::boot_id()? == self.boot,
            "original offline boot changed",
        )?;
        let root = files::directory(Path::new("/"), Some(0))?;
        let proc = files::directory(Path::new("/proc"), Some(0))?;
        for (held, named, expected, mount, filesystem) in [
            (
                &self.root,
                &root,
                self.root_shape,
                self.root_mount,
                self.root_kind,
            ),
            (&self.proc, &proc, self.proc_shape, self.proc_mount, 0x9fa0),
        ] {
            require(
                shape(held)? == expected
                    && shape(named)? == expected
                    && kind(held)? == filesystem
                    && kind(named)? == filesystem
                    && mount_identity::id(held.as_fd(), true)? == mount
                    && mount_identity::id(named.as_fd(), true)? == mount,
                "original offline RAM/proc root replaced or covered",
            )?;
        }
        require(
            readonly_flags(&self.root)? == self.root_flags
                && readonly_flags(&self.proc)? == self.proc_flags,
            "original offline root/proc descriptor flags changed",
        )?;
        let first = census(&self.proc)?;
        let last = census(&self.proc)?;
        require(
            first == last && first[&1].0 == self.start,
            "offline census or original PID1 identity changed",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = value!({"boot":self.boot,"pid":1,"start_ticks":self.start,
            "root_mount":self.root_mount,"proc_mount":self.proc_mount,
            "userspace_processes":1,"userspace_threads":1,"root_ram_backed":true,
            "execution_authorized":false,"exclusive_block_device_verified":false});
        self.recheck()?;
        Ok(result)
    }
}

/// Actual fixed offline top-level mount observed through original PID1 mountinfo.
/// Other Btrfs mounts protect the operation regardless of device major/minor.
/// Exclusive device ownership and original coordinator image remain separate.
pub struct Mounts<'a> {
    scope: &'a Scope,
    top: File,
    top_shape: Shape,
    top_mount: u64,
    top_flags: i32,
    filesystem: Value,
    mountinfo: File,
    mountinfo_identity: (u64, u64),
    rows: Vec<enzimos_platform::mountinfo::Row>,
}
const OFFLINE_TOP: &str = "/run/enzimos/root-retirement-top";
fn readonly_flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline observation flags",
    )?;
    Ok(flags)
}
fn offline_mount_rows(
    body: &str,
    top_id: u64,
    root_id: u64,
) -> Result<Vec<enzimos_platform::mountinfo::Row>> {
    let rows = enzimos_platform::mountinfo::parse(body)?;
    let roots = rows
        .iter()
        .filter(|row| row.target == "/")
        .collect::<Vec<_>>();
    require(
        roots.len() == 1
            && roots[0].id == root_id
            && roots[0].root == "/"
            && matches!(roots[0].filesystem.as_str(), "ramfs" | "tmpfs"),
        "offline original RAM root mount record differs",
    )?;
    let btrfs = rows
        .iter()
        .filter(|row| row.filesystem == "btrfs")
        .collect::<Vec<_>>();
    require(
        btrfs.len() == 1
            && btrfs[0].id == top_id
            && btrfs[0].root == "/"
            && btrfs[0].target == OFFLINE_TOP
            && btrfs[0].options.split(',').any(|word| word == "rw"),
        "only actual owned writable offline top-level Btrfs mount allowed",
    )?;
    require(
        rows.iter().filter(|row| row.target == OFFLINE_TOP).count() == 1,
        "offline top-level mount hidden or ambiguous",
    )?;
    Ok(rows)
}
impl<'a> Mounts<'a> {
    pub(crate) fn require_original_scope(&self, scope: &Scope) -> Result<()> {
        require(
            std::ptr::eq(self.scope, scope),
            "original offline scope actor differs",
        )?;
        self.recheck()
    }
    pub(crate) fn original_top(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.top)
    }
    pub(crate) fn filesystem_binding(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.filesystem.clone())
    }
    pub fn observe(scope: &'a Scope, original_top: &File, filesystem_uuid: &str) -> Result<Self> {
        scope.recheck()?;
        crate::identity::uuid(filesystem_uuid)?;
        let top = original_top.try_clone()?;
        let top_mount = mount_identity::id(top.as_fd(), true)?;
        require(
            kind(&top)? == 0x9123683e,
            "original offline top must be actual Btrfs",
        )?;
        let filesystem = crate::filesystem::observe(top.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == filesystem_uuid && filesystem["members"] == 1,
            "single-member original offline filesystem required",
        )?;
        let pid1 = files::directory_relative(&scope.proc, Path::new("1"), Some(0))?;
        let mountinfo = files::open_relative(&pid1, Path::new("mountinfo"))?;
        require(
            kind(&mountinfo)? == 0x9fa0,
            "actual original PID1 mountinfo required",
        )?;
        let rows = offline_mount_rows(
            &read(&mountinfo, 2 * 1024 * 1024)?,
            mount_identity::id(top.as_fd(), false)?,
            mount_identity::id(scope.root.as_fd(), false)?,
        )?;
        let metadata = mountinfo.metadata()?;
        let this = Self {
            scope,
            top_shape: shape(&top)?,
            top_flags: readonly_flags(&top)?,
            top,
            top_mount,
            filesystem,
            mountinfo_identity: (metadata.dev(), metadata.ino()),
            mountinfo,
            rows,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        let named = files::directory(Path::new(OFFLINE_TOP), Some(0))?;
        require(
            shape(&self.top)? == self.top_shape
                && shape(&named)? == self.top_shape
                && readonly_flags(&self.top)? == self.top_flags
                && mount_identity::id(self.top.as_fd(), true)? == self.top_mount
                && mount_identity::id(named.as_fd(), true)? == self.top_mount
                && crate::filesystem::observe(self.top.as_fd())? == self.filesystem
                && crate::filesystem::observe(named.as_fd())? == self.filesystem,
            "original offline top filesystem/mount/description changed",
        )?;
        let pid1 = files::directory_relative(&self.scope.proc, Path::new("1"), Some(0))?;
        let current = files::open_relative(&pid1, Path::new("mountinfo"))?;
        for file in [&self.mountinfo, &current] {
            let m = file.metadata()?;
            require(
                (m.dev(), m.ino()) == self.mountinfo_identity && kind(file)? == 0x9fa0,
                "original offline PID1 mountinfo description replaced",
            )?;
            let rows = offline_mount_rows(
                &read(file, 2 * 1024 * 1024)?,
                mount_identity::id(self.top.as_fd(), false)?,
                mount_identity::id(self.scope.root.as_fd(), false)?,
            )?;
            require(
                rows == self.rows,
                "offline mounts changed since original observation",
            )?;
        }
        self.scope.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = value!({"scope":self.scope.evidence()?,"filesystem":self.filesystem,
            "top_mount":self.top_mount,"top_path":OFFLINE_TOP,"observed_mounts":self.rows.len(),
            "other_btrfs_mounts":0,"execution_authorized":false,
            "exclusive_block_device_verified":false});
        self.recheck()?;
        Ok(result)
    }
}
