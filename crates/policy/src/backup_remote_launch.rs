// SPDX-License-Identifier: MIT
//! One original durable launch before PID1 start; never a replayable worker grant.
use crate::{
    backup_remote_copy_context::Context, control_record::Retained, storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "backup-remote-launches";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original protected remote launch directory",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub struct Launch<'g> {
    guard: &'g Guard,
    parent: File,
    shape: Shape,
    mount: u64,
    record: Retained,
    value: Value,
}
impl<'g> Launch<'g> {
    pub fn enter(
        context: &Context<'_, 'g>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        context.recheck(authorize)?;
        let original = context.evidence(authorize)?;
        let guard = context.guard();
        let parent =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.control_mount_id() && files::directory_names(&parent, 32)?.len() < 32,
            "remote original launch capacity/mount",
        )?;
        context.recheck(authorize)?;
        let value = value!({"schema":1,"id":original["id"],"phase":"starting","context_sha256":json::fingerprint(original)?,"boot_id":original["remote"]["boot_id"],"worker_closed":false,"receipt_complete":false});
        let record = Retained::create(
            &parent,
            Path::new(&format!("{}.json", original["id"].as_str().unwrap())),
            &value,
            4096,
            mount,
        )?;
        let shape = shape(&parent)?;
        let this = Self {
            guard,
            parent,
            shape,
            mount,
            record,
            value,
        };
        this.recheck()?;
        context.recheck(authorize)?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.parent)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && self.mount == self.guard.control_mount_id(),
            "original remote launch directory replaced/covered",
        )?;
        require(
            self.record.value()? == &self.value && self.value["phase"] == "starting",
            "original remote launch intent changed; no replay",
        )
    }
}
