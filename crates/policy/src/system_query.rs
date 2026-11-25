// SPDX-License-Identifier: MIT
//! Read-only System1 status: retained public files and private control records.
use crate::{catalog, identity, recovery_image, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};

struct Record {
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    mount: u64,
}
impl Record {
    fn open(parent: &File, name: &Path, maximum: usize, private: bool) -> Result<Self> {
        let file = files::open_relative(parent, name)?;
        let m = file.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && if private {
                    m.mode() & 0o7777 == 0o600
                } else {
                    m.mode() & 0o022 == 0
                },
            "status source protection differs",
        )?;
        let identity = files::identity(&m);
        let bytes = files::read_file(&file, maximum, Some(0), private)?;
        let this = Self {
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            identity,
            bytes,
        };
        this.recheck(parent, name)?;
        Ok(this)
    }
    fn recheck(&self, parent: &File, name: &Path) -> Result<()> {
        let named = files::open_relative(parent, name)?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "original status source changed",
        )
    }
}
struct Folder {
    name: &'static str,
    directory: Option<File>,
    inode: Option<files::FileIdentity>,
    records: BTreeMap<String, Record>,
}
fn names(dir: &File, maximum: usize) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in files::directory_names(dir, maximum)? {
        require(names.len() < maximum, "status record inventory bound")?;
        names.push(
            item.into_string()
                .map_err(|_| Error("status filename encoding".into()))?,
        );
    }
    names.sort();
    Ok(names)
}
impl Folder {
    fn open(guard: &Guard, name: &'static str) -> Result<Self> {
        require(
            matches!(name, "generation-registry" | "recovery-images"),
            "status folder outside registry",
        )?;
        let directory =
            files::optional_directory_relative(guard.control(), Path::new(name), Some(0))?;
        let mut records = BTreeMap::new();
        let mut inode = None;
        if let Some(dir) = &directory {
            let m = dir.metadata()?;
            require(
                m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o700
                    && mount_identity::id(dir.as_fd(), true)? == guard.control_mount_id(),
                "status records left original private control storage",
            )?;
            inode = Some(files::identity(&m));
            let maximum = if name == "generation-registry" {
                2
            } else {
                recovery_image::MAX_IMAGES
            };
            for member in names(dir, maximum)? {
                if name == "generation-registry" {
                    require(
                        matches!(member.as_str(), "catalog.json" | "lock"),
                        "unfinished generation registry publication",
                    )?;
                } else {
                    recovery_image::identifier(
                        member
                            .strip_suffix(".json")
                            .ok_or_else(|| Error("unknown recovery image record".into()))?,
                    )?;
                }
                let record = Record::open(dir, Path::new(&member), catalog::MAX_CATALOG, true)?;
                require(
                    record.mount == guard.control_mount_id(),
                    "status record crosses control mount",
                )?;
                if member == "lock" {
                    require(
                        record.bytes.is_empty(),
                        "unexpected generation lock content",
                    )?;
                }
                records.insert(member, record);
            }
        }
        let this = Self {
            name,
            directory,
            inode,
            records,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let named =
            files::optional_directory_relative(guard.control(), Path::new(self.name), Some(0))?;
        match (&self.directory, named) {
            (None, None) => Ok(()),
            (Some(dir), Some(named)) => {
                require(
                    Some(files::identity(&dir.metadata()?)) == self.inode
                        && Some(files::identity(&named.metadata()?)) == self.inode
                        && mount_identity::id(dir.as_fd(), true)? == guard.control_mount_id()
                        && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
                        && names(dir, self.records.len() + 1)?
                            == self.records.keys().cloned().collect::<Vec<_>>(),
                    "original status inventory changed",
                )?;
                for (name, record) in &self.records {
                    record.recheck(dir, Path::new(name))?;
                }
                Ok(())
            }
            _ => Err(Error("status registry appeared or disappeared".into())),
        }
    }
}

/// OS release is data, never shell input. Only the five legacy public keys escape.
pub(crate) fn os_release(bytes: &[u8]) -> Result<Value> {
    require(
        bytes.len() <= 16384 && !bytes.contains(&0),
        "OS release byte bound",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|_| Error("OS release encoding".into()))?;
    let mut out = serde_json::Map::new();
    for line in text.lines() {
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        if !matches!(
            key,
            "NAME" | "PRETTY_NAME" | "ID" | "VERSION_ID" | "BUILD_ID"
        ) {
            continue;
        }
        require(
            !out.contains_key(&key.to_ascii_lowercase()),
            "duplicate public OS release field",
        )?;
        let text = raw.trim_matches('"');
        require(
            text.len() <= 1024 && !text.chars().any(char::is_control),
            "OS release public value bound",
        )?;
        out.insert(key.to_ascii_lowercase(), value!(text));
    }
    Ok(Value::Object(out))
}
pub(crate) fn marker(cmdline: &[u8]) -> Result<Option<String>> {
    require(
        cmdline.len() <= 65536 && !cmdline.contains(&0),
        "kernel command line bound",
    )?;
    let text =
        std::str::from_utf8(cmdline).map_err(|_| Error("kernel command line encoding".into()))?;
    let mut marker = None;
    for word in text.split_whitespace() {
        if let Some(name) = word.strip_prefix("enzimos.generation=") {
            require(marker.is_none(), "ambiguous actual running generation")?;
            marker = Some(identity::safe_id(name)?.to_owned());
        }
    }
    Ok(marker)
}
pub(crate) fn package_version(bytes: &[u8], name: &str) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error("package status encoding".into()))?;
    let words = text.split_whitespace().collect::<Vec<_>>();
    if words.is_empty() {
        return Ok(Value::Null);
    }
    require(
        words.len() == 2
            && words[0] == name
            && words[1].len() <= 256
            && words[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@+_.:-".contains(&b)),
        "package status name or version differs",
    )?;
    Ok(value!(words[1]))
}
const PACKAGES: [&str; 4] = [
    "enzimos-native-policy",
    "enzimos-system-backend",
    "linux",
    "linux-lts",
];
pub(crate) fn package_rows(bytes: &[u8]) -> Result<Value> {
    require(bytes.len() <= 16384, "package status output bound")?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error("package inventory encoding".into()))?;
    let mut result = PACKAGES
        .into_iter()
        .map(|name| (name.to_owned(), Value::Null))
        .collect::<serde_json::Map<_, _>>();
    let mut seen = std::collections::BTreeSet::new();
    for row in text.lines() {
        let name = row
            .split_whitespace()
            .next()
            .ok_or_else(|| Error("empty package status row".into()))?;
        require(
            PACKAGES.contains(&name) && seen.insert(name),
            "foreign or duplicate status package",
        )?;
        result.insert(name.to_owned(), package_version(row.as_bytes(), name)?);
    }
    Ok(Value::Object(result))
}
/// Generations of the registry `data` with their kernels.
///
/// # Errors
///
/// Fails when the registry is invalid.
///
/// # Panics
///
/// Never for a registry that passes validation, which requires integer ordinals and kernel objects.
pub fn generations(data: &Value) -> Result<Value> {
    catalog::validate(data, data["filesystem_uuid"].as_str().unwrap_or(""))?;
    let mut rows = enzimos_platform::json::object(&data["generations"])?
        .iter()
        .collect::<Vec<_>>();
    rows.sort_by_key(|(_, row)| {
        row["ordinal"]
            .as_u64()
            .expect("catalog validation requires integer ordinals")
    });
    Ok(Value::Array(
        rows.into_iter()
            .map(|(name, row)| {
                let mut kernels = row["material"]["kernels"]
                    .as_object()
                    .expect("catalog validation requires a kernels object")
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>();
                kernels.sort();
                value!({"name":name,"state":row["state"],"ordinal":row["ordinal"],"kernels":kernels,
            "confirmed":!row["first_confirmation"].is_null()})
            })
            .collect(),
    ))
}
/// System overview: OS release, generations and recovery images.
///
/// # Errors
///
/// Fails when a registry or record cannot be read.
pub fn system() -> Result<Value> {
    crate::namespaces::initial()?;
    crate::operation::root_only()?;
    let guard = Guard::observe()?;
    let catalog_folder = Folder::open(&guard, "generation-registry")?;
    let recovery = Folder::open(&guard, "recovery-images")?;
    let data = match catalog_folder.records.get("catalog.json") {
        Some(record) => json::decode(&record.bytes, catalog::MAX_CATALOG)?,
        None => catalog::empty(enzimos_platform::json::string(
            &guard.configuration["filesystem_uuid"],
        )?)?,
    };
    catalog::validate(
        &data,
        enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?,
    )?;
    let mut ready = 0;
    for (name, record) in &recovery.records {
        let body = json::decode(&record.bytes, catalog::MAX_CATALOG)?;
        recovery_image::validate(
            &body,
            name.strip_suffix(".json")
                .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?,
        )?;
        ready += usize::from(body["phase"] == "ready");
    }
    let etc = files::directory(Path::new("/etc"), Some(0))?;
    let alias_path = Path::new("/etc/os-release");
    let alias = std::fs::symlink_metadata(alias_path)?;
    let alias_inode = files::identity(&alias);
    let destination = if alias.file_type().is_symlink() {
        let target = std::fs::read_link(alias_path)?;
        require(
            matches!(
                target.to_str(),
                Some("../usr/lib/os-release" | "/usr/lib/os-release")
            ),
            "OS release alias outside exact vendor target",
        )?;
        Some(target)
    } else {
        None
    };
    let parent_path = if destination.is_some() {
        Path::new("/usr/lib")
    } else {
        Path::new("/etc")
    };
    let parent = if destination.is_some() {
        files::directory(parent_path, Some(0))?
    } else {
        etc
    };
    let parent_inode = files::identity(&parent.metadata()?);
    let parent_mount = mount_identity::id(parent.as_fd(), true)?;
    let release = Record::open(&parent, Path::new("os-release"), 16384, false)?;
    let pacman = crate::settings_command::Command::open("/usr/bin/pacman")?;
    let mut args = vec!["-Q"];
    args.extend(PACKAGES);
    let packages = package_rows(&pacman.run(&args, &[0, 1], 16384)?)?;
    let cmdline = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    let current = marker(&cmdline)?;
    let kernel = files::read_kernel(Path::new("/proc/sys/kernel/osrelease"), 4096)?;
    let kernel = std::str::from_utf8(&kernel)
        .map_err(|_| Error("kernel release encoding".into()))?
        .trim();
    require(
        !kernel.is_empty() && kernel.len() <= 256 && !kernel.chars().any(char::is_control),
        "kernel release bound",
    )?;
    let uefi = match std::fs::symlink_metadata("/sys/firmware/efi") {
        Ok(m) => {
            require(
                m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0,
                "firmware status type differs",
            )?;
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let result = value!({"os":os_release(&release.bytes)?,"kernel":kernel,"firmware":if uefi {"uefi"} else {"bios"},
        "packages":packages,"generations":generations(&data)?,"current_generation":current,"recovery_images_ready":ready});
    catalog_folder.recheck(&guard)?;
    recovery.recheck(&guard)?;
    release.recheck(&parent, Path::new("os-release"))?;
    let named_parent = files::directory(parent_path, Some(0))?;
    require(
        files::identity(&parent.metadata()?) == parent_inode
            && files::identity(&named_parent.metadata()?) == parent_inode
            && mount_identity::id(named_parent.as_fd(), true)? == parent_mount,
        "original public status directory changed",
    )?;
    require(
        files::identity(&std::fs::symlink_metadata(alias_path)?) == alias_inode
            && (if let Some(target) = destination {
                std::fs::read_link(alias_path)? == target
            } else {
                true
            })
            && files::read_kernel(Path::new("/proc/cmdline"), 65536)? == cmdline,
        "OS release alias or actual running generation changed",
    )?;
    pacman.recheck()?;
    guard.recheck()?;
    Ok(result)
}
