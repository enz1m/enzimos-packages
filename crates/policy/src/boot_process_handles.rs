// SPDX-License-Identifier: MIT
//! Kernel metadata only: never open or duplicate a sampled task's target handles.
use super::*;
use enzimos_platform::mountinfo;
use std::{collections::BTreeMap, os::unix::ffi::OsStrExt};
const BTRFS_MAGIC: u64 = 0x9123683e;
const NSFS_MAGIC: u64 = 0x6e736673;
pub(super) struct Measurement {
    pub(super) references: Vec<Value>,
    pub(super) blockers: BTreeSet<String>,
    pub(super) handles: usize,
    pub(super) mappings: usize,
    pub(super) bytes: usize,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (statfs).")]
fn filesystem(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error("numeric kernel path encoding".into()))?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut info) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(info.f_type as u64)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (statx).")]
fn mount(path: &Path, unique: bool) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error("numeric kernel path encoding".into()))?;
    let requested = if unique { 0x4000 } else { 0x1000 };
    // SAFETY: `libc::statx` is a plain C struct, for which all-zero bytes are a valid value.
    let mut info: libc::statx = unsafe { std::mem::zeroed() };
    // Following a fixed kernel link obtains metadata. It never adopts its target
    // open-file description, enters its namespace, or grants a filesystem actor.
    if unsafe { libc::statx(libc::AT_FDCWD, path.as_ptr(), 0, requested, &mut info) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    require(
        info.stx_mask & requested == requested && info.stx_mnt_id > 0,
        "kernel handle mount identity unavailable",
    )?;
    Ok(info.stx_mnt_id)
}
fn range(name: &str) -> bool {
    let Some((start, end)) = name.split_once('-') else {
        return false;
    };
    let parse = |s: &str| {
        s.len() <= 16
            && !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    parse(start)
        && parse(end)
        && u64::from_str_radix(start, 16)
            .ok()
            .zip(u64::from_str_radix(end, 16).ok())
            .is_some_and(|(s, e)| s < e)
}
fn mapped_ranges(maps: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let mut previous = 0u64;
    let mut count = 0usize;
    let hex = |s: &str| {
        !s.is_empty()
            && s.len() <= 16
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    for line in maps.lines() {
        count += 1;
        require(count <= MAX_MAPS, "kernel mapping metadata count bound")?;
        let f: Vec<_> = line.split_whitespace().take(6).collect();
        require(
            f.len() >= 5 && range(f[0]) && f[1].len() == 4 && hex(f[2]),
            "kernel mapping metadata required",
        )?;
        let p = f[1].as_bytes();
        require(
            matches!(p[0], b'r' | b'-')
                && matches!(p[1], b'w' | b'-')
                && matches!(p[2], b'x' | b'-')
                && matches!(p[3], b'p' | b's'),
            "kernel mapping permissions required",
        )?;
        require(
            f[3].split_once(':').is_some_and(|(a, b)| hex(a) && hex(b))
                && f[4].bytes().all(|b| b.is_ascii_digit()),
            "kernel mapping device/inode required",
        )?;
        let (start, end) = f[0].split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16)
            .map_err(|_| Error("kernel mapping address range".into()))?;
        let end = u64::from_str_radix(end, 16)
            .map_err(|_| Error("kernel mapping address range".into()))?;
        require(
            previous <= start && start < end,
            "unordered or overlapping kernel mappings",
        )?;
        previous = end;
        let inode = f[4]
            .parse::<u64>()
            .map_err(|_| Error("kernel mapping inode range".into()))?;
        if inode != 0 {
            result.insert(f[0].into());
        }
    }
    Ok(result)
}
pub(super) fn inspect(process: &Process) -> Result<Measurement> {
    process.alive()?;
    let base = PathBuf::from(format!("/proc/{}", process.pid));
    let namespace = std::fs::read_link(base.join("ns/mnt"))?
        .into_os_string()
        .into_string()
        .map_err(|_| Error("kernel namespace label encoding".into()))?;
    let mount_text = text(&base.join("mountinfo"), 2 * 1024 * 1024, process.uid)?;
    let rows = mountinfo::parse(&mount_text)?;
    let mounts:BTreeMap<_,_>=rows.iter().map(|r|(r.id,value!({"device":format!("{}:{}",r.major,r.minor),"root":r.root,"target":r.target,"fstype":r.filesystem}))).collect();
    require(
        mounts.len() == rows.len(),
        "ambiguous kernel process mount IDs",
    )?;
    let maps = process.record["maps"]
        .as_str()
        .ok_or_else(|| Error("original process mappings missing".into()))?;
    let expected = mapped_ranges(maps)?;
    let mapping_directory = files::directory(&base.join("map_files"), None)?;
    let names = files::directory_names(&mapping_directory, MAX_MAPS)?;
    let mut mappings = BTreeSet::new();
    for name in names {
        let name = name
            .into_string()
            .map_err(|_| Error("kernel mapping range encoding".into()))?;
        require(range(&name), "canonical kernel mapping range required")?;
        mappings.insert(name);
    }
    let mut result = Measurement {
        references: Vec::new(),
        blockers: BTreeSet::new(),
        handles: 0,
        mappings: mappings.len(),
        bytes: mount_text
            .len()
            .checked_add(maps.len())
            .ok_or_else(|| Error("kernel census byte overflow".into()))?,
    };
    if !expected.is_subset(&mappings) {
        result
            .blockers
            .insert("file-mapping-handles-missing".into());
    }
    let mut paths: Vec<(String, PathBuf, Option<&Value>)> = Vec::new();
    for row in process.record["handles"].as_array().unwrap() {
        let fd = row["fd"]
            .as_u64()
            .ok_or_else(|| Error("original kernel descriptor number required".into()))?;
        paths.push((
            format!("fd:{fd}"),
            base.join("fd").join(fd.to_string()),
            Some(row),
        ));
    }
    for kind in ["root", "cwd", "exe"] {
        paths.push((kind.into(), base.join(kind), None));
    }
    for name in &mappings {
        paths.push((
            format!("map:{name}"),
            base.join("map_files").join(name),
            None,
        ));
    }
    require(paths.len() <= MAX_HANDLES, "kernel handle census bound")?;
    for (kind, path, original) in paths {
        process.alive()?;
        result.handles += 1;
        let observed = (|| -> Result<()> {
            let before = std::fs::metadata(&path)?;
            if let Some(original) = original {
                require(
                    original["device"] == before.dev()
                        && original["inode"] == before.ino()
                        && original["mode"] == before.mode(),
                    "original sampled descriptor changed",
                )?;
                let link = std::fs::read_link(&path)?
                    .into_os_string()
                    .into_string()
                    .map_err(|_| Error("kernel handle link encoding".into()))?;
                require(
                    original["target"] == link,
                    "original sampled descriptor link changed",
                )?;
                if link.starts_with("anon_inode:") {
                    let classification = if matches!(
                        link.as_str(),
                        "anon_inode:[io_uring]" | "anon_inode:io_uring"
                    ) {
                        "io-uring-registered-files-needs-review"
                    } else {
                        "anonymous-kernel-object-needs-review"
                    };
                    result.blockers.insert(classification.into());
                    result.references.push(value!({"pid":process.pid,"handle":kind,"kind":"kernel-object","namespace":namespace,"classification":classification}));
                }
            }
            match filesystem(&path)? {
                NSFS_MAGIC => {
                    result
                        .blockers
                        .insert("process-held-namespace-needs-review".into());
                    result.references.push(value!({"pid":process.pid,"handle":kind,"kind":"namespace-handle","namespace":namespace}));
                }
                BTRFS_MAGIC => {
                    let normal = mount(&path, false)?;
                    let unique = mount(&path, true)?;
                    let measured = mounts.get(&normal);
                    if measured.is_none() {
                        result
                            .blockers
                            .insert("detached-or-foreign-Btrfs-handle".into());
                    }
                    result.references.push(value!({"pid":process.pid,"handle":kind,"kind":"btrfs-handle","namespace":namespace,
                        "origin":if kind.starts_with("map:"){"mapping"}else{"descriptor"},"unique_mount_id":unique,"mount":measured}));
                }
                _ => {}
            }
            let after = std::fs::metadata(&path)?;
            require(
                files::identity(&before) == files::identity(&after),
                "kernel handle metadata changed during inspection",
            )?;
            Ok(())
        })();
        if observed.is_err() {
            result
                .blockers
                .insert("process-handle-disappeared-or-unavailable".into());
        }
        process.alive()?;
    }
    if text(&base.join("maps"), 2 * 1024 * 1024, process.uid)? != maps {
        result
            .blockers
            .insert("process-mappings-changed-during-observation".into());
    }
    let descriptors = files::directory(&base.join("fd"), None)?;
    let after: BTreeSet<_> = files::directory_names(&descriptors, MAX_HANDLES)?
        .into_iter()
        .map(|n| {
            n.into_string()
                .map_err(|_| Error("kernel descriptor encoding".into()))
        })
        .collect::<Result<_>>()?;
    let before: BTreeSet<_> = process.record["handles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["fd"].as_u64().unwrap().to_string())
        .collect();
    if after != before {
        result
            .blockers
            .insert("process-descriptors-changed-during-observation".into());
    }
    if text(&base.join("mountinfo"), 2 * 1024 * 1024, process.uid)? != mount_text
        || std::fs::read_link(base.join("ns/mnt"))?.as_os_str() != std::ffi::OsStr::new(&namespace)
    {
        result
            .blockers
            .insert("process-mounts-changed-during-handle-observation".into());
    }
    process.alive()?;
    Ok(result)
}
