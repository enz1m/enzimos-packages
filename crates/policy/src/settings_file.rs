// SPDX-License-Identifier: MIT
//! A settings write advances only the caller's original reviewed file epoch.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
pub(crate) struct Config {
    path: PathBuf,
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32),
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    parent_mount: u64,
    limit: usize,
    pub body: Vec<u8>,
}
fn shape(f: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = f.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected settings parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Config {
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub(crate) fn open(path: &str, limit: usize) -> Result<Self> {
        require(
            matches!(
                path,
                "/etc/enzimos/memory-pressure.json"
                    | "/etc/enzimos/tmp-storage.conf"
                    | "/etc/UPower/UPower.conf"
                    | "/etc/enzimos/backup.json"
                    | "/etc/enzimos/backup-retention.json"
            ),
            "settings configuration outside registry",
        )?;
        let path = Path::new(path);
        let parent = files::directory(path.parent().unwrap(), Some(0))?;
        let file = files::open_relative(&parent, Path::new(path.file_name().unwrap()))?;
        Self::from_file(path, &parent, file, limit)
    }
    pub(crate) fn optional_database_configuration(parent: &File) -> Result<Option<Self>> {
        let path = Path::new("/etc/enzimos/backup-databases.json");
        shape(parent)?;
        files::optional_relative(parent, Path::new("backup-databases.json"))?
            .map(|file| Self::from_file(path, parent, file, 32768))
            .transpose()
    }
    fn from_file(path: &Path, parent: &File, file: File, limit: usize) -> Result<Self> {
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && if path == Path::new("/etc/enzimos/backup-databases.json") {
                    matches!(
                        m.mode() & 0o7777,
                        0o400 | 0o440 | 0o444 | 0o600 | 0o640 | 0o644
                    )
                } else {
                    matches!(m.mode() & 0o7777, 0o600 | 0o644)
                }
                && m.nlink() == 1,
            "settings configuration protected regular inode required",
        )?;
        let this = Self {
            path: path.into(),
            parent_shape: shape(parent)?,
            identity: files::identity(&m),
            mount: mount_identity::id(file.as_fd(), true)?,
            parent_mount: mount_identity::id(parent.as_fd(), true)?,
            body: files::read_file(&file, limit, Some(0), true)?,
            parent: parent.try_clone()?,
            file,
            limit,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            shape(&parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::read_file(&self.file, self.limit, Some(0), true)? == self.body
                && files::identity(&self.file.metadata()?) == self.identity,
            "original settings configuration epoch changed or replaced",
        )
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"path":self.path,"inode":self.identity,"mount":self.mount,"sha256":json::sha256(&self.body)}),
        )
    }
    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<()> {
        self.recheck()?;
        let file = files::atomic_replace_original(
            &self.parent,
            Path::new(self.path.file_name().unwrap()),
            bytes,
            self.identity.7 & 0o7777,
            Some(0),
            self.limit,
            &self.file,
        )?;
        self.identity = files::identity(&file.metadata()?);
        self.file = file;
        self.body = bytes.into();
        self.recheck()
    }
}
