// SPDX-License-Identifier: MIT
//! Original public encrypted header. Credential bytes are never read or hashed.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::AsFd, path::Path};
pub(crate) struct Header {
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    mount: u64,
    owner: u32,
}
pub(crate) fn validate(v: &Value) -> Result<()> {
    validate_for(v, 0)
}
fn validate_for(v: &Value, owner: u32) -> Result<()> {
    json::fields(v, "identity sha256")?;
    crate::backup_worker_request::file(&v["identity"])?;
    let m = &v["identity"];
    require(
        m[7].as_u64()
            .is_some_and(|n| n as u32 & libc::S_IFMT == libc::S_IFREG && n & 0o022 == 0)
            && m[8] == owner
            && m[9].as_u64().is_some()
            && (owner != 0 || m[9] == 0)
            && m[10] == 1
            && m[2]
                .as_u64()
                .is_some_and(|n| (1..=1024 * 1024).contains(&n)),
        "protected encrypted header identity required",
    )?;
    crate::identity::sha(v["sha256"].as_str().unwrap_or("")).map(|_| ())
}
impl Header {
    pub(crate) fn descriptor(&self) -> &File {
        &self.file
    }
    pub(crate) fn observe(repository: &File) -> Result<Self> {
        Self::observe_for(repository, 0)
    }
    fn observe_for(repository: &File, owner: u32) -> Result<Self> {
        let file = files::open_relative(repository, Path::new("config"))?;
        Self::retain(repository, file, owner)
    }
    pub(crate) fn received(repository: &File, file: File) -> Result<Self> {
        crate::backup_worker_handoff::readonly(&file)?;
        Self::retain(repository, file, 0)
    }
    fn retain(repository: &File, file: File, owner: u32) -> Result<Self> {
        let identity = files::identity(&file.metadata()?);
        let mount = mount_identity::id(repository.as_fd(), true)?;
        require(
            mount_identity::id(file.as_fd(), true)? == mount,
            "encrypted header crossed repository mount",
        )?;
        let bytes = files::read_file(&file, 1024 * 1024, Some(owner), true)?;
        let this = Self {
            file,
            identity,
            bytes,
            mount,
            owner,
        };
        validate_for(&this.value(), owner)?;
        this.recheck(repository)?;
        Ok(this)
    }
    fn value(&self) -> Value {
        value!({"identity":self.identity,"sha256":json::sha256(&self.bytes)})
    }
    pub(crate) fn recheck(&self, repository: &File) -> Result<()> {
        let named = files::open_relative(repository, Path::new("config"))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(repository.as_fd(), true)? == self.mount
                && files::read_file(&self.file, 1024 * 1024, Some(self.owner), true)? == self.bytes,
            "original encrypted header replaced, changed or remounted",
        )
    }
    pub(crate) fn evidence(&self, repository: &File) -> Result<Value> {
        self.recheck(repository)?;
        Ok(self.value())
    }
}
