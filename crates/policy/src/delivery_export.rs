// SPDX-License-Identifier: MIT
//! Completed private export bytes remain paired with their original receipt and directories.
use crate::{control_record::Retained, identity, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) const MAX_FILE: u64 = crate::backup_selective_result::MAX_FILE;
const LIMIT: usize = 32768;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("export text required".into()))
}
fn size(record: &Value, id: &str) -> Result<u64> {
    json::fields(
        record,
        "schema id snapshot file phase created_boot destination_binding content_sha256 metadata_restored per_user_authorized",
    )?;
    json::fields(&record["file"], "path size node_sha256")?;
    require(
        record["schema"] == 1
            && record["id"] == id
            && record["phase"] == "complete"
            && record["metadata_restored"] == false
            && record["per_user_authorized"] == false,
        "completed private single-file export required",
    )?;
    identity::sha(text(record, "snapshot")?)?;
    identity::sha(text(record, "content_sha256")?)?;
    identity::sha(text(&record["file"], "node_sha256")?)?;
    identity::uuid(text(record, "created_boot")?)?;
    let path = text(&record["file"], "path")?;
    crate::backup_selective_result::file_path(path)?;
    record["file"]["size"]
        .as_u64()
        .filter(|n| *n <= MAX_FILE)
        .ok_or_else(|| Error("private delivery size bound".into()))
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private original export directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn ns(seconds: i64, nanos: i64) -> Result<i64> {
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or_else(|| Error("export timestamp bound".into()))
}
pub(crate) struct Export {
    id: String,
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32),
    directory: File,
    shape: (u64, u64, u32, u32, u32),
    record: Retained,
    content: File,
    identity: files::FileIdentity,
    mount: u64,
    bytes: u64,
    sha: String,
}
impl Export {
    pub(crate) fn source<'a>(&'a self, guard: &Guard) -> Result<&'a File> {
        self.recheck(guard)?;
        Ok(&self.content)
    }
    pub(crate) fn open(guard: &Guard, id: &str) -> Result<Self> {
        identity::safe_id(id)?;
        guard.recheck()?;
        let parent =
            files::directory_relative(guard.control(), Path::new("restore-exports"), Some(0))?;
        let directory = files::directory_relative(&parent, Path::new(id), Some(0))?;
        let parent_shape = shape(&parent)?;
        let shape = shape(&directory)?;
        let mount = guard.control_mount_id();
        require(
            mount_identity::id(parent.as_fd(), true)? == mount
                && mount_identity::id(directory.as_fd(), true)? == mount,
            "private export left original control mount",
        )?;
        let record = Retained::open(&directory, Path::new("record.json"), LIMIT, mount)?;
        let bytes = size(record.value()?, id)?;
        let content = files::open_relative(&directory, Path::new("content.bin"))?;
        let metadata = content.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() == bytes,
            "unsafe original export content",
        )?;
        let identity = files::identity(&metadata);
        let (length, sha) = stream_copy::hash_borrowed(&content, MAX_FILE, Some(0))?;
        require(
            length == bytes && record.value()?["content_sha256"] == sha,
            "private export bytes differ",
        )?;
        let this = Self {
            id: id.into(),
            parent,
            parent_shape,
            directory,
            shape,
            record,
            content,
            identity,
            mount,
            bytes,
            sha,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let parent =
            files::directory_relative(guard.control(), Path::new("restore-exports"), Some(0))?;
        let directory = files::directory_relative(&parent, Path::new(&self.id), Some(0))?;
        require(
            shape(&self.parent)? == self.parent_shape
                && shape(&parent)? == self.parent_shape
                && shape(&self.directory)? == self.shape
                && shape(&directory)? == self.shape
                && [
                    self.parent.as_fd(),
                    parent.as_fd(),
                    self.directory.as_fd(),
                    directory.as_fd(),
                ]
                .iter()
                .all(|fd| mount_identity::id(*fd, true).ok() == Some(self.mount)),
            "original export directory changed or covered",
        )?;
        self.record.recheck()?;
        let named = files::open_relative(&directory, Path::new("content.bin"))?;
        require(
            files::identity(&self.content.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.content.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original export content changed or covered",
        )?;
        require(
            size(self.record.value()?, &self.id)? == self.bytes
                && self.record.value()?["content_sha256"] == self.sha,
            "original export record changed",
        )?;
        guard.recheck()
    }
    pub(crate) fn binding(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        let m = self.content.metadata()?;
        Ok(
            value!({"export":self.id,"record_sha256":json::fingerprint(self.record.value()?)?,"sha256":self.sha,"bytes":self.bytes,
            "device":m.dev(),"inode":m.ino(),"mtime_ns":ns(m.mtime(),m.mtime_nsec())?,"ctime_ns":ns(m.ctime(),m.ctime_nsec())?}),
        )
    }
    pub(crate) fn evidence(&self, guard: &Guard) -> Result<Value> {
        Ok(
            value!({"binding":self.binding(guard)?,"record_epoch":self.record.evidence()?,"file":self.identity,"mount":self.mount,"directory":self.shape,"parent":self.parent_shape}),
        )
    }
}
