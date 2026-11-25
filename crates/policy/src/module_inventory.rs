// SPDX-License-Identifier: MIT
//! Kernel trees may legitimately contain hardlinks, but never followed symlinks or nested mounts.
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const MAX_FILES: usize = 131072;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open(parent: &File, name: &str, flags: i32) -> Result<File> {
    let name = CString::new(name).map_err(|_| Error("module filename refused".into()))?;
    // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    require(raw >= 0, "retained module tree member unavailable")?;
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn authority(m: &std::fs::Metadata, owner: u32) -> Result<()> {
    require(
        m.uid() == owner && m.mode() & 0o7022 == 0,
        "module tree owner or mode refused",
    )
}
fn hash(file: &mut File) -> Result<(u64, String)> {
    let before = file.metadata()?;
    require(
        before.is_file() && before.nlink() > 0 && before.len() <= 512 * 1024 * 1024,
        "module file size or links refused",
    )?;
    let mut sum = openssl::sha::Sha256::new();
    let mut buffer = vec![0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Error("module file size overflow".into()))?;
        require(total <= before.len(), "module file grew while hashing")?;
        sum.update(&buffer[..count]);
    }
    require(
        total == before.len() && files::identity(&file.metadata()?) == files::identity(&before),
        "module file changed while hashing",
    )?;
    Ok((
        total,
        sum.finish().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}
struct Scan {
    owner: u32,
    mount: u64,
    bytes: u64,
    rows: BTreeMap<String, Value>,
}
impl Scan {
    #[allow(unsafe_code, reason = "Linux syscall ABI (readlinkat).")]
    fn visit(&mut self, parent: &File, prefix: &str, depth: usize) -> Result<()> {
        require(depth <= 64, "module tree depth bound")?;
        let before = parent.metadata()?;
        authority(&before, self.owner)?;
        require(
            mount_identity::id(parent.as_fd(), true)? == self.mount,
            "nested module directory mount refused",
        )?;
        let path = format!("/proc/self/fd/{}", parent.as_raw_fd());
        let mut names = Vec::new();
        for entry in std::fs::read_dir(path)? {
            require(
                names.len() + self.rows.len() < MAX_FILES,
                "module tree count bound",
            )?;
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| Error("module filename encoding".into()))?;
            require(
                !name.is_empty()
                    && name.len() <= 255
                    && !matches!(name.as_str(), "." | "..")
                    && !name.contains('/')
                    && !name.chars().any(char::is_control),
                "module filename refused",
            )?;
            names.push(name);
        }
        names.sort();
        for name in names {
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            require(
                relative.len() <= 4096 && self.rows.len() < MAX_FILES,
                "module tree path or count bound",
            )?;
            let held = open(parent, &name, libc::O_PATH)?;
            let metadata = held.metadata()?;
            require(
                mount_identity::id(held.as_fd(), true)? == self.mount,
                "nested module member mount refused",
            )?;
            let row = if metadata.file_type().is_symlink() {
                require(metadata.uid() == self.owner, "module symlink owner refused")?;
                let cname = CString::new(name.as_str())
                    .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
                let mut body = [0u8; 4097];
                // SAFETY: The name is NUL-terminated, the buffer pointer and length describe
                // `body`, and `parent` stays open.
                let length = unsafe {
                    libc::readlinkat(
                        parent.as_raw_fd(),
                        cname.as_ptr(),
                        body.as_mut_ptr().cast(),
                        body.len(),
                    )
                };
                require(length > 0 && length <= 4096, "module symlink length bound")?;
                let target = std::str::from_utf8(&body[..length as usize])
                    .map_err(|_| Error("module symlink encoding".into()))?;
                require(
                    !target.chars().any(char::is_control),
                    "module symlink target refused",
                )?;
                value!({"kind":"symlink","target":target,"gid":metadata.gid()})
            } else if metadata.is_dir() {
                authority(&metadata, self.owner)?;
                self.rows.insert(
                    relative.clone(),
                    value!({"kind":"directory","mode":metadata.mode()&0o7777,"gid":metadata.gid()}),
                );
                let directory = open(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                require(
                    files::identity(&directory.metadata()?) == files::identity(&metadata),
                    "module directory replaced",
                )?;
                self.visit(&directory, &relative, depth + 1)?;
                let named = open(parent, &name, libc::O_PATH)?;
                require(
                    files::identity(&named.metadata()?) == files::identity(&metadata)
                        && mount_identity::id(named.as_fd(), true)? == self.mount,
                    "module directory path or mount changed",
                )?;
                require(
                    files::identity(&held.metadata()?) == files::identity(&metadata),
                    "module directory changed",
                )?;
                continue;
            } else {
                authority(&metadata, self.owner)?;
                require(metadata.is_file(), "special module tree member refused")?;
                let mut file = open(parent, &name, libc::O_RDONLY)?;
                require(
                    files::identity(&file.metadata()?) == files::identity(&metadata),
                    "module file replaced before hashing",
                )?;
                let (bytes, sha) = hash(&mut file)?;
                self.bytes = self
                    .bytes
                    .checked_add(bytes)
                    .ok_or_else(|| Error("module tree byte overflow".into()))?;
                require(self.bytes <= MAX_BYTES, "module tree total byte bound")?;
                value!({"kind":"file","mode":metadata.mode()&0o7777,"bytes":bytes,"sha256":sha,"gid":metadata.gid()})
            };
            let named = open(parent, &name, libc::O_PATH)?;
            require(
                files::identity(&named.metadata()?) == files::identity(&metadata)
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && files::identity(&held.metadata()?) == files::identity(&metadata),
                "module member changed during inventory",
            )?;
            self.rows.insert(relative, row);
        }
        require(
            files::identity(&parent.metadata()?) == files::identity(&before),
            "module directory contents changed during inventory",
        )
    }
}
pub(crate) fn observe(directory: &File, owner: u32) -> Result<Value> {
    let mut scan = Scan {
        owner,
        mount: mount_identity::id(directory.as_fd(), true)?,
        bytes: 0,
        rows: BTreeMap::new(),
    };
    scan.visit(directory, "", 0)?;
    let root = directory.metadata()?;
    Ok(
        value!({"schema":1,"root":{"mode":root.mode()&0o7777,"uid":root.uid(),"gid":root.gid()},"bytes":scan.bytes,"members":scan.rows}),
    )
}
pub(crate) fn running(inventory: &Value, kernel: &str) -> Result<()> {
    crate::identity::safe_id(kernel)?;
    require(
        inventory["schema"] == 1 && inventory["members"].is_object(),
        "module inventory shape refused",
    )?;
    for name in ["modules.dep.bin", "vmlinuz"] {
        let row = &inventory["members"][format!("{kernel}/{name}")];
        require(
            row["kind"] == "file" && row["bytes"].as_u64().is_some_and(|n| n > 0),
            "running kernel modules or image unavailable",
        )?;
    }
    Ok(())
}
pub(crate) fn generation(inventory: &Value, kernel: &str) -> Result<Value> {
    running(inventory, kernel)?;
    let prefix = format!("{kernel}/");
    let rows = enzimos_platform::json::object(&inventory["members"])?
        .iter()
        .filter(|(name, _)| name.starts_with(&prefix))
        .map(|(name, row)| (name.clone(), row.clone()))
        .collect::<BTreeMap<_, _>>();
    Ok(value!(rows))
}
pub(crate) fn digest(inventory: &Value) -> Result<String> {
    json::fingerprint(inventory)
}
pub fn directory(path: &Path, owner: u32) -> Result<File> {
    files::directory(path, Some(owner))
}
