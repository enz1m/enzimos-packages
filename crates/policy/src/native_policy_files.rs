// SPDX-License-Identifier: MIT
//! Measured native recovery executables are never substituted into old snapshots.
use crate::recovery_activation;
use enzimos_platform::{Error, Result, files, require, stream_copy};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt, path::Path};
pub const FILES: &[&str] = &[
    "enzimos-policy",
    "enzimos-recovery-image-init",
    "enzimos-recovery-run-init",
    "recovery-pacman.conf",
];
pub fn observe(directory: &Path) -> Result<Value> {
    let held = files::directory(directory, Some(0))?;
    let directory_identity = files::identity(&held.metadata()?);
    require(
        held.metadata()?.mode() & 0o022 == 0,
        "unsafe native policy directory",
    )?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory)?.take(130) {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error("native policy filename encoding".into()))?;
        if name == "recovery-image.json" {
            continue;
        }
        require(
            names.len() < 128 && (name.starts_with("enzimos-") || name.ends_with(".conf")),
            "unknown or excess native policy member",
        )?;
        crate::identity::safe_id(&name)?;
        names.push(name);
    }
    require(
        FILES.iter().all(|name| names.iter().any(|s| s == name)),
        "incomplete native recovery policy",
    )?;
    names.sort();
    let mut result = BTreeMap::new();
    for name in &names {
        let mut file = files::open_relative(&held, Path::new(name))?;
        let before = files::identity(&file.metadata()?);
        if name.starts_with("enzimos-") {
            let header = files::read_file(&file, 128 * 1024 * 1024, Some(0), true)?;
            require(
                header.starts_with(b"\x7fELF") && file.metadata()?.mode() & 0o111 == 0o111,
                "native recovery executable required",
            )?;
        }
        let (_, sha) = stream_copy::hash(&mut file, 128 * 1024 * 1024, Some(0))?;
        require(
            files::identity(&files::open_relative(&held, Path::new(name))?.metadata()?) == before,
            "native policy member replaced",
        )?;
        result.insert(name.to_owned(), sha);
    }
    let current = files::directory(directory, Some(0))?;
    let a = held.metadata()?;
    let b = current.metadata()?;
    require(
        files::identity(&a) == directory_identity && files::identity(&b) == directory_identity,
        "native policy directory replaced",
    )?;
    let value = json!(result);
    recovery_activation::policy_files(&value, true, true)
        .map_err(|e| Error(format!("native recovery identity refused: {e}")))?;
    Ok(value)
}

/// Original installed native runtime descriptions for coordinator staging.
/// Hashes are comparisons only; decoded image metadata cannot create this actor.
pub struct Original {
    directory: std::fs::File,
    epoch: files::FileIdentity,
    directory_flags: i32,
    mount: u64,
    members: std::collections::BTreeSet<String>,
    files: BTreeMap<String, (std::fs::File, files::FileIdentity, i32, String)>,
    hashes: Value,
}
impl Original {
    pub fn retain() -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        use std::os::fd::{AsFd, AsRawFd};
        let path = Path::new("/usr/lib/enzimos-native");
        let directory = files::directory(path, Some(0))?;
        let epoch = files::identity(&directory.metadata()?);
        let directory_flags = enzimos_platform::files::status_flags(&directory);
        require(
            directory_flags >= 0 && directory_flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original installed runtime directory read-only description required",
        )?;
        require(
            directory.metadata()?.gid() == 0 && directory.metadata()?.mode() & 0o022 == 0,
            "original installed native policy directory protection",
        )?;
        let mount = enzimos_platform::mount_identity::id(directory.as_fd(), true)?;
        let members = files::directory_names(&directory, 129)?
            .into_iter()
            .map(|name| {
                name.into_string()
                    .map_err(|_| Error("native runtime member encoding".into()))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        require(
            members.len() <= 129 && FILES.iter().all(|name| members.contains(*name)),
            "complete bounded installed native runtime required",
        )?;
        let mut retained = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        let mut total = 0usize;
        for name in members
            .iter()
            .filter(|name| name.as_str() != "recovery-image.json")
        {
            crate::identity::safe_id(name)?;
            require(
                name.starts_with("enzimos-") || name.ends_with(".conf"),
                "unknown installed native runtime member",
            )?;
            let file = files::open_relative(&directory, Path::new(name))?;
            let epoch = files::identity(&file.metadata()?);
            let body = files::read_file(&file, 128 * 1024 * 1024, Some(0), true)?;
            total = total
                .checked_add(body.len())
                .ok_or_else(|| Error("native runtime byte overflow".into()))?;
            require(
                total <= 512 * 1024 * 1024
                    && file.metadata()?.gid() == 0
                    && enzimos_platform::mount_identity::id(file.as_fd(), true)? == mount,
                "installed runtime byte/mount/owner bound",
            )?;
            if name.starts_with("enzimos-") {
                require(
                    body.len() >= 20
                        && body.starts_with(b"\x7fELF")
                        && body[4] == 2
                        && body[5] == 1
                        && u16::from_le_bytes(body[18..20].try_into().unwrap()) == 62
                        && file.metadata()?.mode() & 0o111 == 0o111,
                    "installed x86_64 native runtime ELF required",
                )?;
            }
            let flags = enzimos_platform::files::status_flags(&file);
            require(
                flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
                "installed native runtime read-only description required",
            )?;
            let sha = enzimos_platform::json::sha256(&body);
            hashes.insert(name.clone(), sha.clone());
            retained.insert(name.clone(), (file, epoch, flags, sha));
        }
        let hashes = json!(hashes);
        recovery_activation::policy_files(&hashes, true, true)?;
        let this = Self {
            directory,
            epoch,
            directory_flags,
            mount,
            members,
            files: retained,
            hashes,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        use std::os::fd::{AsFd, AsRawFd};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        require(
            enzimos_platform::files::status_flags(&self.directory) == self.directory_flags,
            "original installed runtime directory description flags changed",
        )?;
        let named = files::directory(Path::new("/usr/lib/enzimos-native"), Some(0))?;
        for directory in [&self.directory, &named] {
            require(
                files::identity(&directory.metadata()?) == self.epoch
                    && enzimos_platform::mount_identity::id(directory.as_fd(), true)? == self.mount
                    && files::directory_names(directory, 129)?
                        .into_iter()
                        .map(|name| {
                            name.into_string()
                                .map_err(|_| Error("native runtime member encoding".into()))
                        })
                        .collect::<Result<std::collections::BTreeSet<_>>>()?
                        == self.members,
                "original installed runtime directory changed/replaced/covered",
            )?;
        }
        for (name, (original, epoch, flags, sha)) in &self.files {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&original.metadata()?) == *epoch
                    && files::identity(&named.metadata()?) == *epoch
                    && enzimos_platform::files::status_flags(&original) == *flags
                    && enzimos_platform::mount_identity::id(original.as_fd(), true)? == self.mount
                    && enzimos_platform::mount_identity::id(named.as_fd(), true)? == self.mount
                    && enzimos_platform::json::sha256(&files::read_file(
                        original,
                        128 * 1024 * 1024,
                        Some(0),
                        true,
                    )?) == *sha
                    && files::identity(&original.metadata()?) == *epoch,
                "original installed runtime member changed/replaced",
            )?;
        }
        Ok(())
    }
    pub fn hashes(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.hashes)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"directory_epoch":self.epoch,"directory_flags":self.directory_flags,"mount":self.mount,"hashes":self.hashes,
            "members":self.files.iter().map(|(name,(_,epoch,flags,sha))|(name.clone(),json!({"epoch":epoch,"flags":flags,"sha256":sha}))).collect::<BTreeMap<_,_>>(),
            "execution_authorized":false}),
        )
    }
}
