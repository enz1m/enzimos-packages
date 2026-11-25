// SPDX-License-Identifier: MIT
//! Original exclusive private stage and typed worker closure precede legacy completion.
use crate::{
    backup_selective_context::Context, backup_selective_report::Closed, control_record::Retained,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const FOLDER: &str = "restore-exports";
const CAPACITY: usize = 16;
const LIMIT: usize = 32768;
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original Root-private export directory",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
fn space(guard: &Guard) -> Result<()> {
    guard.recheck()?;
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatvfs(guard.control().as_raw_fd(), &mut status) } == 0
            && u128::from(status.f_bavail) * u128::from(status.f_frsize)
                >= u128::from(crate::backup_selective_result::MAX_FILE + 32 * 1024 * 1024),
        "selective private export space admission",
    )
}
/// Read-only admission; an existing ID or unsafe/crowded registry always refuses.
pub fn preflight(guard: &Guard, id: &str) -> Result<()> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    space(guard)?;
    if let Some(parent) =
        files::optional_directory_relative(guard.control(), Path::new(FOLDER), Some(0))?
    {
        let before = shape(&parent)?;
        require(
            before.5 == guard.control_mount_id(),
            "export registry left original control mount",
        )?;
        let members = files::directory_names(&parent, CAPACITY)?;
        require(
            members.len() < CAPACITY,
            "private export capacity; explicit review required",
        )?;
        for name in &members {
            let text = name
                .to_str()
                .ok_or_else(|| enzimos_platform::Error("export member encoding".into()))?;
            crate::identity::safe_id(text)?;
            let member = files::directory_relative(&parent, Path::new(name), Some(0))?;
            require(
                shape(&member)?.5 == before.5,
                "private export member changed/covered",
            )?;
        }
        require(
            files::optional_relative(&parent, Path::new(id))?.is_none()
                && files::directory_names(&parent, CAPACITY)? == members
                && shape(&parent)? == before,
            "private export ID already used or registry changed; no replay/adoption",
        )?;
        let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&named)? == before,
            "original export registry replaced/covered",
        )?;
    }
    guard.recheck()
}
pub struct Staging<'r, 'a, 'g> {
    context: &'r Context<'a, 'g>,
    original: Value,
    parent: File,
    parent_shape: Shape,
    directory: File,
    directory_shape: Shape,
    record: Retained,
    value: Value,
}
impl<'r, 'a, 'g> Staging<'r, 'a, 'g> {
    /// Durable selected ID fence exists before starting the worker. An observing
    /// record has no metadata/bytes or completion authority and is never adopted.
    pub fn enter(
        context: &'r Context<'a, 'g>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        context.recheck(authorize)?;
        let original = context.evidence(authorize)?.clone();
        let guard = context.guard();
        let id = original["selection"]["id"].as_str().unwrap();
        preflight(guard, id)?;
        context.recheck(authorize)?;
        let parent =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let parent_shape = shape(&parent)?;
        require(
            parent_shape.5 == guard.control_mount_id(),
            "original export registry mount",
        )?;
        context.recheck(authorize)?;
        preflight(guard, id)?;
        let directory = files::create_directory_relative(&parent, Path::new(id), 0o700, 0)?;
        let directory_shape = shape(&directory)?;
        require(
            directory_shape.5 == parent_shape.5 && files::directory_is_empty(&directory)?,
            "new original private export stage",
        )?;
        let mut value = value!({"schema":1,"id":id,"snapshot":original["selection"]["snapshot"],
            "file":null,"phase":"observing","created_boot":original["boot_id"],
            "destination_binding":original["destination"],"content_sha256":null,"metadata_restored":false,"per_user_authorized":false});
        if context.kind() == crate::backup_selective_request::Kind::Tree {
            value["kind"] = value!("tree-tar");
        }
        let record = Retained::create(
            &directory,
            Path::new("record.json"),
            &value,
            LIMIT,
            parent_shape.5,
        )?;
        let this = Self {
            context,
            original,
            parent,
            parent_shape,
            directory,
            directory_shape,
            record,
            value,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.context.recheck(authorize)?;
        require(
            *self.context.evidence(authorize)? == self.original,
            "original selected context changed",
        )?;
        let parent =
            files::directory_relative(self.context.guard().control(), Path::new(FOLDER), Some(0))?;
        let directory = files::directory_relative(
            &parent,
            Path::new(self.original["selection"]["id"].as_str().unwrap()),
            Some(0),
        )?;
        require(
            shape(&self.parent)? == self.parent_shape
                && shape(&parent)? == self.parent_shape
                && shape(&self.directory)? == self.directory_shape
                && shape(&directory)? == self.directory_shape
                && self.directory_shape.5 == self.parent_shape.5
                && self.parent_shape.5 == self.context.guard().control_mount_id()
                && *self.record.value()? == self.value,
            "original selected stage/record replaced, changed or covered",
        )?;
        let names = files::directory_names(&self.directory, 2)?;
        require(
            names
                .iter()
                .all(|n| matches!(n.to_str(), Some("record.json" | "content.bin")))
                && names.iter().any(|n| n == "record.json")
                && (self.value["phase"] != "observing" || names.len() == 1),
            "unexpected private export stage membership",
        )
    }
    pub fn publish(
        mut self,
        closed: Closed<'g>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Completed<'r, 'a, 'g>> {
        self.recheck(authorize)?;
        closed.require_context(self.context, authorize)?;
        let (header, data) = closed.observed_data()?;
        require(
            self.value["phase"] == "observing"
                && header["snapshot"] == self.original["selection"]["snapshot"],
            "original export stage already advanced",
        )?;
        let mut next = self.value.clone();
        next["phase"] = value!("copying");
        next["file"] = header["file"].clone();
        self.recheck(authorize)?;
        closed.require_context(self.context, authorize)?;
        self.record.replace(&next)?;
        self.value = next;
        self.recheck(authorize)?;
        let content = crate::backup_selective_copy::write(
            &self.directory,
            &data,
            header["content_sha256"].as_str().unwrap(),
            0,
            &mut || {
                self.recheck(authorize)?;
                closed.require_context(self.context, authorize)
            },
        )?;
        let epoch = files::identity(&content.metadata()?);
        self.recheck(authorize)?;
        closed.require_context(self.context, authorize)?;
        let named = files::open_relative(&self.directory, Path::new("content.bin"))?;
        require(
            files::identity(&named.metadata()?) == epoch,
            "original export content changed before completion",
        )?;
        let mut next = self.value.clone();
        next["phase"] = value!("complete");
        next["content_sha256"] = header["content_sha256"].clone();
        self.record.replace(&next)?;
        self.value = next;
        let completed = Completed {
            stage: self,
            closed,
            content,
            epoch,
        };
        completed.recheck(authorize)?;
        Ok(completed)
    }
}
/// No constructor from decoded receipts or a digest. Completion retains the
/// original stage, original content and original actual whole-worker closure.
pub struct Completed<'r, 'a, 'g> {
    stage: Staging<'r, 'a, 'g>,
    closed: Closed<'g>,
    content: File,
    epoch: files::FileIdentity,
}
impl Completed<'_, '_, '_> {
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.stage.recheck(authorize)?;
        self.closed.require_context(self.stage.context, authorize)?;
        let named = files::open_relative(&self.stage.directory, Path::new("content.bin"))?;
        require(
            files::identity(&self.content.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && self.epoch.7 & 0o7777 == 0o600
                && self.epoch.8 == 0
                && self.epoch.9 == 0
                && self.epoch.10 == 1
                && mount_identity::id(self.content.as_fd(), true)? == self.stage.directory_shape.5
                && mount_identity::id(named.as_fd(), true)? == self.stage.directory_shape.5
                && self.stage.value["phase"] == "complete"
                && self.stage.value["file"]["size"].as_u64() == Some(self.epoch.2),
            "original completed private export changed",
        )?;
        let (bytes, sha) = stream_copy::hash_borrowed(
            &self.content,
            crate::backup_selective_result::MAX_FILE,
            Some(0),
        )?;
        require(
            bytes == self.epoch.2 && self.stage.value["content_sha256"] == sha,
            "original completed private export bytes changed",
        )?;
        self.stage.recheck(authorize)
    }
    pub fn result(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let r = &self.stage.value;
        let mut result = value!({"status":if self.stage.context.kind()==crate::backup_selective_request::Kind::Tree {"private-tree-export-complete"}else{"private-file-export-complete"},"id":r["id"],"snapshot":r["snapshot"],"bytes":r["file"]["size"],"sha256":r["content_sha256"],"live_home_written":false,"metadata_restored":false,"per_user_authorized":false});
        if self.stage.context.kind() == crate::backup_selective_request::Kind::Tree {
            result["entries"] = r["file"]["entries"].clone();
        }
        Ok(result)
    }
    pub(crate) fn original_export(
        &self,
        guard: &Guard,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::delivery_export::Export> {
        self.recheck(authorize)?;
        require(
            std::ptr::eq(self.stage.context.guard(), guard),
            "delivery requires original export storage actor",
        )?;
        let export =
            crate::delivery_export::Export::open(guard, self.stage.value["id"].as_str().unwrap())?;
        let evidence = export.evidence(guard)?;
        require(
            evidence["file"] == serde_json::to_value(self.epoch)?
                && evidence["record_epoch"] == self.stage.record.evidence()?,
            "delivery export differs from original completed files",
        )?;
        self.recheck(authorize)?;
        Ok(export)
    }
    pub fn system_result(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        let result = self.result(authorize)?;
        let mut projected = value!({"id":result["id"],"status":result["status"],"bytes":result["bytes"],"sha256":result["sha256"]});
        if self.stage.context.kind() == crate::backup_selective_request::Kind::Tree {
            projected["entries"] = result["entries"].clone();
        }
        Ok(projected)
    }
}
