// SPDX-License-Identifier: MIT
//! The home dataset and its Snapper configuration retain their original identity.
use crate::{filesystem, storage_runtime::Guard, subvolume};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const CONFIG: &str = "/etc/snapper/configs/home";
pub(crate) fn validate(v: &Value) -> Result<()> {
    json::fields(
        v,
        "filesystem_uuid configuration_sha256 configuration_inode configuration_mount object home_shape home_mount snapshots_shape snapshots_mount",
    )?;
    crate::identity::uuid(
        v["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| Error("history filesystem receipt".into()))?,
    )?;
    crate::identity::sha(
        v["configuration_sha256"]
            .as_str()
            .ok_or_else(|| Error("history configuration digest".into()))?,
    )?;
    crate::birth::object(&v["object"], "/home", v["object"]["parent_uuid"].as_str())?;
    for key in ["configuration_mount", "home_mount", "snapshots_mount"] {
        require(
            v[key].as_u64().is_some_and(|n| n > 0),
            "history mount receipt identity",
        )?;
    }
    for key in ["home_shape", "snapshots_shape"] {
        let a = v[key]
            .as_array()
            .ok_or_else(|| Error("history directory receipt".into()))?;
        require(
            a.len() == 5
                && a[0].as_u64().is_some_and(|n| n > 0)
                && a[1].as_u64().is_some_and(|n| n > 0)
                && a[2] == 0
                && a[3] == 0
                && a[4].as_u64().is_some_and(|n| {
                    n <= u64::from(u32::MAX)
                        && n as u32 & libc::S_IFMT == libc::S_IFDIR
                        && n & 0o022 == 0
                }),
            "history directory receipt protection",
        )?;
    }
    let a = v["configuration_inode"]
        .as_array()
        .ok_or_else(|| Error("history configuration inode".into()))?;
    require(
        a.len() == 11
            && a.iter().all(|n| n.is_u64() || n.is_i64())
            && a[0].as_u64().is_some_and(|n| n > 0)
            && a[1].as_u64().is_some_and(|n| n > 0)
            && a[2].as_u64().is_some_and(|n| n > 0 && n <= 65536)
            && a[7].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFREG
                    && n & 0o022 == 0
            })
            && a[8] == 0
            && a[9] == 0
            && a[10] == 1,
        "history configuration receipt protection",
    )
}
pub(crate) fn configuration(bytes: &[u8]) -> Result<()> {
    configuration_for(bytes, "/home")
}
pub(crate) fn configuration_for(bytes: &[u8], expected: &str) -> Result<()> {
    require(
        bytes.len() <= 65536 && !bytes.contains(&0),
        "home Snapper configuration bound",
    )?;
    let body = std::str::from_utf8(bytes)
        .map_err(|_| Error("home Snapper configuration encoding".into()))?;
    let mut found = std::collections::BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, contents) = line
            .split_once('=')
            .ok_or_else(|| Error("home Snapper configuration line".into()))?;
        require(
            !key.is_empty()
                && key.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                && contents.starts_with('"')
                && contents.ends_with('"')
                && contents.len() >= 2,
            "home Snapper configuration grammar",
        )?;
        let contents = contents
            .strip_prefix('"')
            .and_then(|c| c.strip_suffix('"'))
            .ok_or_else(|| Error("home Snapper configuration grammar".into()))?;
        require(
            !contents.contains('"')
                && !contents.chars().any(char::is_control)
                && found.insert(key, contents).is_none(),
            "home Snapper duplicate or ambiguous configuration",
        )?;
    }
    require(
        found.get("SUBVOLUME") == Some(&expected) && found.get("FSTYPE") == Some(&"btrfs"),
        "home Snapper source binding differs",
    )
}
fn shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected home history directory required",
    )?;
    Ok(value!([m.dev(), m.ino(), m.uid(), m.gid(), m.mode()]))
}
pub(crate) struct Source {
    pub guard: Guard,
    home: File,
    snapshots: File,
    config: File,
    config_parent: File,
    config_parent_shape: Value,
    config_parent_mount: u64,
    config_identity: files::FileIdentity,
    config_mount: u64,
    config_bytes: Vec<u8>,
    home_shape: Value,
    snapshots_shape: Value,
    home_mount: u64,
    snapshots_mount: u64,
    object: Value,
}
impl Source {
    pub(crate) fn observe() -> Result<Self> {
        let guard = Guard::observe()?;
        let home = files::directory(Path::new("/home"), Some(0))?;
        let snapshots = files::directory_relative(&home, Path::new(".snapshots"), Some(0))?;
        let directory = files::directory(
            Path::new(CONFIG)
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let config = files::open_relative(&directory, Path::new("home"))?;
        let config_bytes = files::read_file(&config, 65536, Some(0), true)?;
        configuration(&config_bytes)?;
        require(
            config.metadata()?.gid() == 0,
            "Root home Snapper configuration group required",
        )?;
        let (object, readonly) = subvolume::observe(home.as_fd(), "/home")?;
        require(
            !readonly,
            "home history requires the writable live home dataset",
        )?;
        for file in [&home, &snapshots] {
            require(
                filesystem::observe(file.as_fd())?["filesystem_uuid"]
                    == guard.configuration["filesystem_uuid"],
                "home history filesystem differs",
            )?;
        }
        let this = Self {
            guard,
            home_shape: shape(&home)?,
            snapshots_shape: shape(&snapshots)?,
            config_identity: files::identity(&config.metadata()?),
            config_mount: mount_identity::id(config.as_fd(), true)?,
            config_parent_shape: shape(&directory)?,
            config_parent_mount: mount_identity::id(directory.as_fd(), true)?,
            home_mount: mount_identity::id(home.as_fd(), true)?,
            snapshots_mount: mount_identity::id(snapshots.as_fd(), true)?,
            home,
            snapshots,
            config,
            config_parent: directory,
            config_bytes,
            object,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let home = files::directory(Path::new("/home"), Some(0))?;
        let snapshots = files::directory_relative(&home, Path::new(".snapshots"), Some(0))?;
        let directory = files::directory(
            Path::new(CONFIG)
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let config = files::open_relative(&directory, Path::new("home"))?;
        require(
            shape(&home)? == self.home_shape
                && shape(&self.home)? == self.home_shape
                && shape(&snapshots)? == self.snapshots_shape
                && shape(&self.snapshots)? == self.snapshots_shape
                && mount_identity::id(home.as_fd(), true)? == self.home_mount
                && mount_identity::id(self.home.as_fd(), true)? == self.home_mount
                && mount_identity::id(snapshots.as_fd(), true)? == self.snapshots_mount
                && mount_identity::id(self.snapshots.as_fd(), true)? == self.snapshots_mount
                && files::identity(&config.metadata()?) == self.config_identity
                && shape(&directory)? == self.config_parent_shape
                && shape(&self.config_parent)? == self.config_parent_shape
                && mount_identity::id(directory.as_fd(), true)? == self.config_parent_mount
                && mount_identity::id(self.config_parent.as_fd(), true)?
                    == self.config_parent_mount
                && files::identity(&self.config.metadata()?) == self.config_identity
                && mount_identity::id(config.as_fd(), true)? == self.config_mount
                && mount_identity::id(self.config.as_fd(), true)? == self.config_mount
                && files::read_file(&self.config, 65536, Some(0), true)? == self.config_bytes
                && subvolume::observe(home.as_fd(), "/home")? == (self.object.clone(), false),
            "original home history source changed or replaced",
        )?;
        let rows = crate::storage_runtime::rows()?;
        let expected = format!(
            "/{}",
            self.guard.configuration["home_subvol"]
                .as_str()
                .ok_or_else(|| Error("home subvolume configuration".into()))?
        );
        crate::storage_runtime::mount_row(
            &rows,
            "/home",
            Some(&expected),
            mount_identity::id(home.as_fd(), false)?,
        )?;
        Ok(())
    }
    pub(crate) fn configuration_bytes(&self) -> Result<&[u8]> {
        self.recheck()?;
        Ok(&self.config_bytes)
    }
    pub(crate) fn configuration_context(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"parent":self.config_parent_shape,"mount":self.config_parent_mount}))
    }
    /// Advance only a Rust-authored replacement from this retained epoch.
    pub(crate) fn publish_configuration(&mut self, bytes: &[u8]) -> Result<()> {
        self.recheck()?;
        configuration(bytes)?;
        let file = files::atomic_replace_original(
            &self.config_parent,
            Path::new("home"),
            bytes,
            self.config_identity.7 & 0o7777,
            Some(0),
            65536,
            &self.config,
        )?;
        self.config_identity = files::identity(&file.metadata()?);
        self.config_mount = mount_identity::id(file.as_fd(), true)?;
        self.config_bytes = bytes.into();
        self.config = file;
        self.recheck()
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let v = value!({"filesystem_uuid":self.guard.configuration["filesystem_uuid"],"configuration_sha256":json::sha256(&self.config_bytes),
            "configuration_inode":self.config_identity,"configuration_mount":self.config_mount,"object":self.object,
            "home_shape":self.home_shape,"home_mount":self.home_mount,"snapshots_shape":self.snapshots_shape,"snapshots_mount":self.snapshots_mount});
        validate(&v)?;
        Ok(v)
    }
    pub(crate) fn snapshot(&self, number: u64) -> Result<(File, Value)> {
        require(number > 0 && number < 1 << 63, "home snapshot number bound")?;
        self.recheck()?;
        let relative = format!("{number}/snapshot");
        let file = files::directory_relative(&self.snapshots, Path::new(&relative), Some(0))?;
        let path = format!("/home/.snapshots/{relative}");
        let (object, readonly) = subvolume::observe(file.as_fd(), &path)?;
        require(
            readonly
                && object["id"] != self.object["id"]
                && object["uuid"] != self.object["uuid"]
                && object["parent_uuid"] == self.object["uuid"]
                && filesystem::observe(file.as_fd())?["filesystem_uuid"]
                    == self.guard.configuration["filesystem_uuid"],
            "home snapshot lineage or read-only state differs",
        )?;
        self.recheck()?;
        Ok((
            file,
            value!({"number":number,"object":object,"readonly":true}),
        ))
    }
}
