// SPDX-License-Identifier: MIT
//! Opt-out admission precedes any home or snapshot observation.
use crate::{home_history_create, operation};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
struct Gate {
    directory: File,
    path: PathBuf,
    owner: u32,
    shape: (u64, u64, u32, u32, u32),
    mount: u64,
}
fn shape(file: &File, owner: u32) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o022 == 0,
        "automatic history control protection",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Gate {
    fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        operation::root_only()?;
        Self::retained(Path::new(operation::CONTROL), 0)
    }
    fn retained(path: &Path, owner: u32) -> Result<Self> {
        let directory = files::directory(path, Some(owner))?;
        Ok(Self {
            shape: shape(&directory, owner)?,
            path: path.into(),
            owner,
            mount: mount_identity::id(directory.as_fd(), true)?,
            directory,
        })
    }
    fn admit<F: FnOnce() -> Result<Value>>(&self, body: F) -> Result<Value> {
        if self.disabled()? {
            Ok(json!({"status":"disabled-no-source-scan"}))
        } else {
            body()
        }
    }
    fn disabled(&self) -> Result<bool> {
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.directory, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount,
            "original automatic history control changed",
        )?;
        let marker = files::optional_relative(&self.directory, Path::new("home-history.disabled"))?;
        if let Some(file) = marker {
            let m = file.metadata()?;
            require(
                m.is_file()
                    && m.uid() == self.owner
                    && m.gid() == self.owner
                    && m.nlink() == 1
                    && m.mode() & 0o022 == 0
                    && mount_identity::id(file.as_fd(), true)? == self.mount,
                "unsafe automatic history disable marker",
            )?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
pub fn create() -> Result<Value> {
    let gate = Gate::open()?;
    gate.admit(|| {
        let lock = operation::lock()?;
        if gate.disabled()? {
            return Ok(json!({"status":"disabled-no-source-scan"}));
        }
        home_history_create::create_locked(&lock, None, || {
            require(
                !gate.disabled()?,
                "automatic history disabled before mutation",
            )?;
            lock.recheck()
        })
    })
}
