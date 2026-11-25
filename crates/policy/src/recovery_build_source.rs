// SPDX-License-Identifier: MIT
//! Root build inputs retain both filesystem identity and measured content.
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    fs::File,
    os::fd::AsFd,
    path::{Path, PathBuf},
};
pub(crate) struct Source {
    pub file: File,
    pub body: Vec<u8>,
    path: PathBuf,
    identity: files::FileIdentity,
    unique: u64,
    limit: usize,
}
impl Source {
    pub(crate) fn observe(path: &Path, limit: usize) -> Result<Self> {
        let parent = files::directory(
            path.parent()
                .ok_or_else(|| Error("build source parent".into()))?,
            Some(0),
        )?;
        let file = files::open_relative(
            &parent,
            Path::new(
                path.file_name()
                    .ok_or_else(|| Error("build source name".into()))?,
            ),
        )?;
        let identity = files::identity(&file.metadata()?);
        let unique = mount_identity::id(file.as_fd(), true)?;
        let body = files::read_file(&file, limit, Some(0), true)?;
        let source = Self {
            file,
            body,
            path: path.into(),
            identity,
            unique,
            limit,
        };
        source.recheck()?;
        Ok(source)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(0))?;
        let named = files::open_relative(&parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && mount_identity::id(self.file.as_fd(), true)? == self.unique
                && files::read_file(&self.file, self.limit, Some(0), true)? == self.body,
            "build source replaced, remounted or changed",
        )
    }
}
