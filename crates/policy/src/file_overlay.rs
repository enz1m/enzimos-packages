// SPDX-License-Identifier: MIT
//! Review a complete content-declared overlay before descriptor-bound extraction.
use enzimos_platform::{Error, Result, files, json, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Component, Path},
};
const EXPANDED: u64 = 8 * 1024 * 1024 * 1024;
struct Pread<'a> {
    file: &'a File,
    offset: u64,
    bytes: u64,
}
impl Read for Pread<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .bytes
            .saturating_sub(self.offset)
            .min(buffer.len() as u64) as usize;
        let count = self.file.read_at(&mut buffer[..remaining], self.offset)?;
        self.offset += count as u64;
        Ok(count)
    }
}
fn path_name(path: &Path) -> Result<String> {
    let parts = path
        .components()
        .filter(|p| !matches!(p, Component::CurDir))
        .collect::<Vec<_>>();
    require(
        parts.len() <= 64 && parts.iter().all(|p| matches!(p, Component::Normal(_))),
        "unsafe overlay member path",
    )?;
    let name = parts
        .iter()
        .map(|p| {
            p.as_os_str()
                .to_str()
                .ok_or_else(|| Error("overlay path encoding".into()))
        })
        .collect::<Result<Vec<_>>>()?
        .join("/");
    require(
        name.len() <= 4096
            && !name.chars().any(char::is_control)
            && (name.is_empty()
                || matches!(name.split('/').next(), Some("usr" | "etc" | "opt" | "var")))
            && ![
                "var/lib/enzimos-control",
                "etc/pacman.d/gnupg",
                "etc/passwd",
                "etc/shadow",
                "etc/enzimos/storage.json",
            ]
            .iter()
            .any(|protected| name == *protected || name.starts_with(&format!("{protected}/"))),
        "overlay enters protected installation authority or an unknown tree",
    )?;
    Ok(name)
}
fn link_target(name: &str, target: &str) -> Result<()> {
    require(
        !target.is_empty() && target.len() <= 4096 && !target.chars().any(char::is_control),
        "overlay link target bound",
    )?;
    if target == "/dev/null" {
        // These four existing console masks are symbolic metadata, never a
        // device to open or an exception for arbitrary external links.
        return require(
            [
                "etc/systemd/system/getty@tty3.service",
                "etc/systemd/system/getty@tty4.service",
                "etc/systemd/system/getty@tty5.service",
                "etc/systemd/system/getty@tty6.service",
            ]
            .contains(&name),
            "overlay device link is not an approved console mask",
        );
    }
    let mut parts = if target.starts_with('/') {
        Vec::<String>::new()
    } else {
        name.rsplit_once('/')
            .map(|(parent, _)| parent.split('/').map(str::to_owned).collect())
            .unwrap_or_default()
    };
    for part in Path::new(target).components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| Error("overlay link encoding".into()))?
                    .into(),
            ),
            Component::ParentDir => {
                require(parts.pop().is_some(), "overlay symlink escapes target root")?;
            }
            _ => return Err(Error("overlay link prefix refused".into())),
        }
    }
    require(!parts.is_empty(), "overlay link to root refused")?;
    path_name(Path::new(&parts.join("/")))?;
    Ok(())
}
fn scan(
    file: &File,
    mut visit: impl FnMut(&Value, &mut dyn Read) -> Result<()>,
) -> Result<BTreeMap<String, Value>> {
    let before = files::identity(&file.metadata()?);
    require(
        file.metadata()?.is_file()
            && before.10 == 1
            && before.7 & 0o022 == 0
            && before.2 > 0
            && before.2 <= 4 * 1024 * 1024 * 1024,
        "overlay compressed byte bound or protection",
    )?;
    let decoder = zstd::stream::read::Decoder::new(Pread {
        file,
        offset: 0,
        bytes: before.2,
    })?;
    let mut archive = tar::Archive::new(decoder.take(EXPANDED));
    archive.set_ignore_zeros(true);
    let mut rows = BTreeMap::new();
    let mut total = 0u64;
    let mut regular = 0;
    for (index, entry) in archive.entries()?.enumerate() {
        require(index < 16384, "overlay member count bound")?;
        let mut entry = entry?;
        let name = path_name(&entry.path()?)?;
        let header = entry.header();
        let kind = header.entry_type();
        let mode = header.mode()?;
        require(
            header.uid()? == 0 && header.gid()? == 0 && (kind.is_symlink() || mode & 0o7022 == 0),
            "overlay member ownership or mode differs",
        )?;
        if name.is_empty() {
            require(
                kind.is_dir() && entry.size() == 0,
                "overlay root entry must be a directory",
            )?;
            continue;
        }
        require(!rows.contains_key(&name), "duplicate overlay path")?;
        let row = if kind.is_dir() {
            require(
                entry.size() == 0 && matches!(mode, 0o700 | 0o755),
                "overlay directory has data or unsafe mode",
            )?;
            value!({"path":name,"kind":"directory","mode":mode})
        } else if kind.is_file() {
            regular += 1;
            require(
                regular <= 2048
                    && entry.size() <= 512 * 1024 * 1024
                    && matches!(mode, 0o400 | 0o440 | 0o444 | 0o600 | 0o644 | 0o755),
                "overlay regular member bound",
            )?;
            total = total
                .checked_add(entry.size())
                .ok_or_else(|| Error("overlay size overflow".into()))?;
            require(
                total <= 6 * 1024 * 1024 * 1024,
                "overlay payload total bound",
            )?;
            // First observation hashes every complete member before any target write.
            let mut hash = openssl::sha::Sha256::new();
            let mut bytes = 0u64;
            let mut buffer = vec![0; 256 * 1024];
            loop {
                let n = entry.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                bytes += n as u64;
                hash.update(&buffer[..n]);
            }
            require(bytes == entry.size(), "overlay member truncated")?;
            let sha = hash
                .finish()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            value!({"path":name,"kind":"file","mode":mode,"bytes":bytes,"sha256":sha})
        } else if kind.is_symlink() {
            require(entry.size() == 0, "overlay symbolic link has data")?;
            let target = entry
                .link_name()?
                .ok_or_else(|| Error("overlay symbolic link target absent".into()))?
                .to_str()
                .ok_or_else(|| Error("overlay symbolic link encoding".into()))?
                .to_owned();
            link_target(&name, &target)?;
            value!({"path":name,"kind":"symlink","target":target})
        } else {
            return Err(Error("overlay special file or hard link refused".into()));
        };
        // A fresh descriptor reader for each member is supplied by extract's
        // second pass; review never publishes bytes through this exhausted reader.
        visit(&row, &mut entry)?;
        rows.insert(name, row);
    }
    require(
        archive.into_inner().limit() > 0,
        "overlay expanded byte bound exhausted",
    )?;
    require(
        files::identity(&file.metadata()?) == before,
        "original overlay archive changed",
    )?;
    for (name, row) in &rows {
        for ancestor in Path::new(name).ancestors().skip(1) {
            if let Some(parent) = ancestor.to_str().and_then(|name| rows.get(name)) {
                require(
                    parent["kind"] == "directory",
                    "overlay member descends through a non-directory",
                )?;
            }
        }
        if row["kind"] == "symlink" {
            link_target(name, row["target"].as_str().unwrap())?;
        }
    }
    Ok(rows)
}
pub fn review(file: &File, declared: &Value) -> Result<Value> {
    let expected = declared
        .as_object()
        .ok_or_else(|| Error("overlay file manifest shape".into()))?;
    require(
        !expected.is_empty() && expected.len() <= 2048,
        "overlay declared file count bound",
    )?;
    for (name, sha) in expected {
        require(
            path_name(Path::new(name))? == *name,
            "noncanonical overlay manifest path",
        )?;
        crate::identity::sha(
            sha.as_str()
                .ok_or_else(|| Error("overlay manifest digest type".into()))?,
        )?;
    }
    let rows = scan(file, |_, _| Ok(()))?;
    let actual = rows
        .iter()
        .filter(|(_, row)| row["kind"] == "file")
        .map(|(name, row)| (name.clone(), row["sha256"].clone()))
        .collect::<serde_json::Map<_, _>>();
    require(
        Value::Object(actual) == *declared,
        "overlay regular files differ from declared contents",
    )?;
    Ok(value!({"schema":1,"members":rows}))
}
/// Refuse insufficient descriptor headroom before an origin intent or file write.
#[allow(unsafe_code, reason = "Linux syscall ABI (getrlimit).")]
pub fn resources(reviewed: &Value) -> Result<()> {
    json::fields(reviewed, "schema members")?;
    require(
        reviewed["schema"].as_u64() == Some(1),
        "overlay review resource schema",
    )?;
    let rows = reviewed["members"]
        .as_object()
        .ok_or_else(|| Error("overlay review members missing".into()))?;
    let needed = rows
        .values()
        .filter(|row| row["kind"] != "directory")
        .count();
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0,
        "overlay descriptor limit unavailable",
    )?;
    let current = std::fs::read_dir("/proc/self/fd")?.count();
    require(
        current
            .checked_add(needed)
            .and_then(|n| n.checked_add(64))
            .is_some_and(|n| n as u64 <= limit.rlim_cur),
        "overlay original-descriptor retention requires more headroom",
    )
}
/// The caller holds its independent lifetime throughout both passes and every write.
pub fn extract(
    file: &File,
    declared: &Value,
    reviewed: &Value,
    root: &File,
    owner: u32,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    guard()?;
    require(
        review(file, declared)? == *reviewed,
        "overlay review changed before extraction",
    )?;
    resources(reviewed)?;
    let original = files::identity(&file.metadata()?);
    let root_mount = enzimos_platform::mount_identity::id(root.as_fd(), true)?;
    let decoder = zstd::stream::read::Decoder::new(Pread {
        file,
        offset: 0,
        bytes: original.2,
    })?;
    let mut archive = tar::Archive::new(decoder.take(EXPANDED));
    archive.set_ignore_zeros(true);
    let mut names = BTreeSet::new();
    let mut outputs = Vec::new();
    let mut links = Vec::new();
    for (index, entry) in archive.entries()?.enumerate() {
        require(index < 16384, "overlay extraction member bound")?;
        let mut entry = entry?;
        let name = path_name(&entry.path()?)?;
        if name.is_empty() {
            continue;
        }
        require(
            names.insert(name.clone()),
            "duplicate overlay extraction member",
        )?;
        let row = reviewed["members"]
            .get(&name)
            .ok_or_else(|| Error("unreviewed overlay member".into()))?;
        guard()?;
        require(
            files::identity(&file.metadata()?) == original,
            "original reviewed archive changed",
        )?;
        let mode = entry.header().mode()?;
        require(
            entry.header().uid()? == 0 && entry.header().gid()? == 0,
            "overlay ownership changed after review",
        )?;
        let kind = entry.header().entry_type();
        match row["kind"].as_str() {
            Some("directory") => {
                require(
                    kind.is_dir()
                        && entry.size() == 0
                        && Some(u64::from(mode)) == row["mode"].as_u64(),
                    "reviewed overlay directory changed",
                )?;
                let directory =
                    files::ensure_directory_relative(root, Path::new(&name), mode, owner)?;
                require(
                    enzimos_platform::mount_identity::id(directory.as_fd(), true)? == root_mount,
                    "overlay directory crosses target mount",
                )?;
            }
            Some("file") => {
                require(
                    kind.is_file()
                        && Some(entry.size()) == row["bytes"].as_u64()
                        && Some(u64::from(mode)) == row["mode"].as_u64(),
                    "reviewed overlay file changed",
                )?;
                let path = Path::new(&name);
                let parent =
                    files::ensure_directory_relative(root, path.parent().unwrap(), 0o755, owner)?;
                require(
                    enzimos_platform::mount_identity::id(parent.as_fd(), true)? == root_mount,
                    "overlay file crosses target mount",
                )?;
                let output = stream_copy::verified_reader(
                    &mut entry,
                    &parent,
                    path.file_name().unwrap().to_str().unwrap(),
                    row["bytes"].as_u64().unwrap(),
                    row["sha256"].as_str().unwrap(),
                    mode,
                    owner,
                    true,
                )?;
                let identity = files::identity(&output.metadata()?);
                outputs.push((name, output, identity));
            }
            Some("symlink") => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| Error("reviewed overlay link disappeared".into()))?
                    .to_str()
                    .ok_or_else(|| Error("overlay link encoding".into()))?
                    .to_owned();
                require(
                    kind.is_symlink() && entry.size() == 0 && row["target"] == target,
                    "reviewed overlay link changed",
                )?;
                links.push((name, target));
            }
            _ => return Err(Error("unknown reviewed overlay member type".into())),
        }
    }
    require(
        archive.into_inner().limit() > 0
            && names
                == reviewed["members"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect(),
        "overlay extraction does not cover the complete reviewed archive",
    )?;
    let mut link_outputs = Vec::new();
    for (name, target) in &links {
        guard()?;
        let path = Path::new(name);
        let parent = files::ensure_directory_relative(root, path.parent().unwrap(), 0o755, owner)?;
        require(
            enzimos_platform::mount_identity::id(parent.as_fd(), true)? == root_mount,
            "overlay link crosses target mount",
        )?;
        files::symlink_member(&parent, Path::new(path.file_name().unwrap()), target, owner)?;
        let (file, row) = capture(root, name, owner)?;
        require(
            row["kind"] == "symlink" && row["target"] == *target,
            "published overlay link differs",
        )?;
        link_outputs.push((file, row));
    }
    let mut receipts = serde_json::Map::new();
    for (name, file, identity) in outputs {
        guard()?;
        let named = files::open_relative(root, Path::new(&name))?;
        require(
            files::identity(&file.metadata()?) == identity
                && files::identity(&named.metadata()?) == identity
                && enzimos_platform::mount_identity::id(named.as_fd(), true)? == root_mount,
            "original published overlay file changed",
        )?;
        receipts.insert(name, value!(identity));
    }
    require(
        files::identity(&file.metadata()?) == original,
        "original archive changed during extraction",
    )?;
    guard()?;
    let mut link_receipts = Vec::new();
    for (file, row) in link_outputs {
        let (_, actual) = capture(root, row["path"].as_str().unwrap(), owner)?;
        require(
            actual == row && value!(files::identity(&file.metadata()?)) == row["inode"],
            "original published overlay link changed",
        )?;
        link_receipts.push(row);
    }
    Ok(
        value!({"schema":2,"files":receipts,"links":link_receipts,"review_sha256":json::fingerprint(reviewed)?}),
    )
}
/// Read an exact regular/link inode without following its destination. This
/// observer permits protected configuration paths; extraction still applies
/// the stricter archive write registry in path_name before any publication.
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub fn capture(root: &File, name: &str, owner: u32) -> Result<(File, Value)> {
    require(
        !name.is_empty()
            && name.len() <= 4096
            && !name.chars().any(char::is_control)
            && !name
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            && name.split('/').count() <= 64
            && matches!(name.split('/').next(), Some("usr" | "etc" | "opt" | "var"))
            && Path::new(name)
                .components()
                .all(|p| matches!(p, Component::Normal(_))),
        "capture requires canonical installation member",
    )?;
    let path = Path::new(name);
    let parent = files::directory_relative(root, path.parent().unwrap(), Some(owner))?;
    let leaf = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes())
        .map_err(|_| Error("overlay capture name encoding".into()))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "published overlay member absent")?;
    let file = unsafe { File::from_raw_fd(raw) };
    let m = file.metadata()?;
    let mount = enzimos_platform::mount_identity::id(file.as_fd(), true)?;
    require(
        m.uid() == owner
            && m.nlink() == 1
            && mount == enzimos_platform::mount_identity::id(root.as_fd(), true)?
            && (m.file_type().is_symlink() || (m.is_file() && m.mode() & 0o022 == 0)),
        "published overlay member type, ownership or mount differs",
    )?;
    let row = if m.file_type().is_symlink() {
        let target = std::fs::read_link(format!(
            "/proc/self/fd/{}/{}",
            parent.as_raw_fd(),
            path.file_name().unwrap().to_str().unwrap()
        ))?;
        let target = target
            .to_str()
            .ok_or_else(|| Error("published overlay link encoding".into()))?;
        require(
            target.len() <= 4096 && !target.is_empty() && !target.chars().any(char::is_control),
            "published overlay link target encoding",
        )?;
        value!({"path":name,"kind":"symlink","target":target,"inode":files::identity(&m),"mount":mount})
    } else {
        value!({"path":name,"kind":"file","inode":files::identity(&m),"mount":mount})
    };
    let named_raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(
        named_raw >= 0,
        "published overlay member disappeared during observation",
    )?;
    let named = unsafe { File::from_raw_fd(named_raw) };
    require(
        files::identity(&file.metadata()?) == files::identity(&m)
            && files::identity(&named.metadata()?) == files::identity(&m)
            && enzimos_platform::mount_identity::id(named.as_fd(), true)? == mount,
        "published overlay member replaced during observation",
    )?;
    Ok((file, row))
}
