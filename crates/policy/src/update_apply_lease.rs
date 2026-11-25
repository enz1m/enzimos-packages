// SPDX-License-Identifier: MIT
//! A worker retains the exact apply intent through its complete owned lifetime.
use crate::{operation, storage_runtime::Guard, update_apply_record};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
fn shape(directory: &File) -> Result<Value> {
    let m = directory.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private apply lease directory required",
    )?;
    Ok(
        value!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"mount":mount_identity::id(directory.as_fd(),true)?}),
    )
}
/// An update worker's lease on its apply intent.
pub struct Lease {
    guard: Guard,
    path: PathBuf,
    directory: File,
    shape: Value,
    file: File,
    identity: files::FileIdentity,
    document: Value,
    request: Value,
}
impl Lease {
    /// Retain the apply intent named by `request`.
    ///
    /// # Errors
    ///
    /// Fails when the registry is unsafe or on another mount, or the intent is missing or invalid.
    pub fn observe(request: &Value) -> Result<Self> {
        crate::update_worker_record::execution_request(request)?;
        let id = enzimos_platform::json::string(&request["id"])?;
        let guard = Guard::observe()?;
        let path = Path::new(operation::CONTROL)
            .join("update-applies")
            .join(format!("{id}.json"));
        let directory = files::directory(
            path.parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let shape = shape(&directory)?;
        require(
            shape["mount"] == guard.control_mount_id(),
            "apply lease registry independently mounted",
        )?;
        let file = files::open_relative(
            &directory,
            Path::new(
                path.file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let identity = files::identity(&file.metadata()?);
        require(
            file.metadata()?.mode() & 0o7777 == 0o600
                && mount_identity::id(file.as_fd(), true)? == guard.control_mount_id(),
            "apply lease file authority or mount changed",
        )?;
        let document = json::decode(
            &files::read_file(&file, crate::catalog::MAX_CATALOG, Some(0), true)?,
            crate::catalog::MAX_CATALOG,
        )?;
        update_apply_record::worker_binding(&document, request)?;
        require(
            document["boot_id"] == operation::boot_id()?
                && document["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "apply lease belongs to another boot or filesystem",
        )?;
        let lease = Self {
            guard,
            path,
            directory,
            shape,
            file,
            identity,
            document,
            request: request.clone(),
        };
        lease.recheck()?;
        Ok(lease)
    }
    /// The apply intent document.
    pub fn document(&self) -> &Value {
        &self.document
    }
    /// Verify the intent and its directory are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when either changed.
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let directory = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        require(
            shape(&directory)? == self.shape && shape(&self.directory)? == self.shape,
            "original apply lease directory replaced",
        )?;
        let named = files::open_relative(
            &self.directory,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        for file in [&named, &self.file] {
            require(
                files::identity(&file.metadata()?) == self.identity
                    && mount_identity::id(file.as_fd(), true)? == self.guard.control_mount_id(),
                "original apply lease replaced or changed",
            )?;
        }
        require(
            json::decode(
                &files::read_file(&self.file, crate::catalog::MAX_CATALOG, Some(0), true)?,
                crate::catalog::MAX_CATALOG,
            )? == self.document,
            "original apply lease body changed",
        )?;
        update_apply_record::worker_binding(&self.document, &self.request)
    }
}
