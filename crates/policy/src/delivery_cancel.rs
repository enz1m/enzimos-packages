// SPDX-License-Identifier: MIT
//! Cancellation changes only an unused original grant; it never authorizes delivery.
use crate::{control_record::Retained, identity, operation, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "restore-delivery-grants";
const LIMIT: usize = 32768;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("delivery grant text required".into()))
}
fn selection(v: &Value) -> Result<(&str, &str)> {
    json::fields(v, "id grant_sha256")?;
    Ok((
        identity::safe_id(text(v, "id")?)?,
        identity::sha(text(v, "grant_sha256")?)?,
    ))
}
pub(crate) fn filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_. ()-".contains(&b))
}
pub(crate) fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase boot_id account export filename metadata_restored grant_sha256",
    )?;
    require(
        v["id"] == id
            && matches!(v["schema"].as_u64(), Some(1 | 2))
            && matches!(
                v["phase"].as_str(),
                Some("granted" | "delivering" | "complete" | "cancelled")
            )
            && v["metadata_restored"] == false,
        "invalid delivery grant",
    )?;
    let name = text(v, "filename")?;
    require(
        if v["schema"] == 1 {
            name == format!("enzimos-restored-{id}.bin")
        } else {
            filename(name)
        },
        "invalid delivery grant filename",
    )?;
    identity::sha(text(v, "grant_sha256")?)?;
    let mut original = v.clone();
    original["phase"] = value!("granted");
    enzimos_platform::json::object_mut(&mut original)?.remove("grant_sha256");
    require(
        json::fingerprint(&original)? == v["grant_sha256"],
        "delivery grant material changed",
    )
}
fn cancelled(v: &Value, id: &str, expected: &str) -> Result<Value> {
    validate(v, id)?;
    require(
        v["grant_sha256"] == expected,
        "stale delivery cancellation digest",
    )?;
    require(
        matches!(v["phase"].as_str(), Some("granted" | "cancelled")),
        "delivery entered; cancellation cannot undo output",
    )?;
    let mut next = v.clone();
    next["phase"] = value!("cancelled");
    Ok(next)
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private grant directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
struct Scope {
    guard: Guard,
    directory: File,
    shape: (u64, u64, u32, u32, u32),
    record: Retained,
}
impl Scope {
    fn open(id: &str) -> Result<Self> {
        crate::namespaces::initial()?;
        let guard = Guard::observe()?;
        let directory =
            files::optional_directory_relative(guard.control(), Path::new(FOLDER), Some(0))?
                .ok_or_else(|| Error("delivery grant missing".into()))?;
        let original = shape(&directory)?;
        let record = Retained::open(
            &directory,
            Path::new(&format!("{id}.json")),
            LIMIT,
            guard.control_mount_id(),
        )?;
        let this = Self {
            guard,
            directory,
            shape: original,
            record,
        };
        this.recheck()?;
        validate(this.record.value()?, id)?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named =
            files::optional_directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?
                .ok_or_else(|| Error("original delivery directory disappeared".into()))?;
        require(
            shape(&self.directory)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.directory.as_fd(), true)?
                    == self.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == self.guard.control_mount_id(),
            "original delivery directory replaced or covered",
        )?;
        self.record.recheck()?;
        self.guard.recheck()
    }
    fn view(&self, id: &str, digest: &str) -> Result<Value> {
        self.recheck()?;
        let original = self.record.value()?;
        cancelled(original, id, digest)?;
        let result = value!({"grant":original,"record_epoch":self.record.evidence()?,"directory":self.shape,"mount":self.guard.control_mount_id(),"storage":self.guard.configuration});
        self.recheck()?;
        Ok(result)
    }
}
pub fn observation(body: &Value) -> Result<Value> {
    let (id, digest) = selection(body)?;
    Scope::open(id)?.view(id, digest)
}
pub fn cancel<F: FnMut() -> Result<()>>(
    body: &Value,
    expected: &Value,
    authorize: &mut F,
) -> Result<Value> {
    let (id, digest) = selection(body)?;
    let lock = operation::lock()?;
    let mut scope = Scope::open(id)?;
    require(
        scope.view(id, digest)? == *expected,
        "delivery cancellation review changed",
    )?;
    authorize()?;
    lock.recheck()?;
    require(
        scope.view(id, digest)? == *expected,
        "delivery cancellation review changed",
    )?;
    let next = cancelled(scope.record.value()?, id, digest)?;
    if scope.record.value()?["phase"] == "granted" {
        scope.record.replace(&next)?;
    }
    scope.recheck()?;
    require(
        scope.record.value()? == &next,
        "delivery cancellation publication changed",
    )?;
    lock.recheck()?;
    completion(id)
}
/// Root CLI status retains the original record without resolving private account/export data.
pub fn status(id: &str) -> Result<Value> {
    identity::safe_id(id)?;
    let lock = operation::lock()?;
    let scope = Scope::open(id)?;
    scope.recheck()?;
    let view = status_value(scope.record.value()?, id, &operation::boot_id()?)?;
    scope.recheck()?;
    lock.recheck()?;
    Ok(view)
}
fn status_value(record: &Value, id: &str, boot: &str) -> Result<Value> {
    validate(record, id)?;
    let phase = text(record, "phase")?;
    let state = if phase == "delivering" {
        "uncertain"
    } else if phase == "granted" && record["boot_id"] != boot {
        "expired"
    } else {
        phase
    };
    Ok(
        value!({"status":state,"id":id,"copy_may_exist":matches!(phase,"delivering"|"complete"),
        "automatic_retry":false,"cancellable":matches!(phase,"granted"|"cancelled")}),
    )
}
/// Closed System1 result; a value alone grants no cancellation authority.
pub fn completion(id: &str) -> Result<Value> {
    identity::safe_id(id)?;
    Ok(
        value!({"status":"delivery-grant-cancelled","grant_id":id,"output_removed":false,"copy_replayed":false}),
    )
}
