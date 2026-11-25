// SPDX-License-Identifier: MIT
//! Fresh authorized review, durable before filesystem creation; never enrollment.
use crate::{
    backup_candidates::Selection, backup_review_mount::Mount, backup_review_store::Store, identity,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{os::fd::AsFd, path::Path};
const OPTIONS: &str = "ro,rescue=nologreplay,nodev,nosuid,noexec,subvolid=5";
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error(format!("review {key} required")))
}
fn result(v: &Value, uuid: &str) -> Result<()> {
    json::fields(
        v,
        "schema readonly_mount_reviewed filesystem_uuid filesystem_verified credential_enrolled automatic_backup_enabled repository",
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["readonly_mount_reviewed"] == true
            && v["filesystem_uuid"] == uuid
            && v["filesystem_verified"] == false
            && v["credential_enrolled"] == false
            && v["automatic_backup_enabled"] == false,
        "review cannot claim health, enrollment or automatic backup",
    )?;
    json::fields(&v["repository"], "state configuration_sha256")?;
    require(
        match v["repository"]["state"].as_str() {
            Some("absent" | "empty") => v["repository"]["configuration_sha256"].is_null(),
            Some("existing") => v["repository"]["configuration_sha256"]
                .as_str()
                .is_some_and(|s| identity::sha(s).is_ok()),
            _ => false,
        },
        "review repository metadata state invalid",
    )
}
pub(crate) fn validate_receipt(v: &Value, id: &str) -> Result<()> {
    identity::safe_id(id)?;
    let phase = text(v, "phase")?;
    require(
        matches!(phase, "prepared" | "complete"),
        "review phase invalid",
    )?;
    match v["schema"].as_u64() {
        Some(2) => {
            json::fields(
                v,
                "schema phase id selection_id boot_id filesystem_uuid device mount_scope mount_options descriptor_scope_closed result",
            )?;
            require(
                v["mount_scope"] == "detached-file-descriptor"
                    && v["descriptor_scope_closed"] == (phase == "complete"),
                "native review descriptor scope not closed",
            )?;
            if phase == "prepared" {
                require(v["result"].is_null(), "prepared review cannot claim result")?;
            }
        }
        Some(1) => {
            // Historical completed Python receipts remain readable/countable, but
            // never grant a new native mount or substitute for its own fresh review.
            json::fields(
                v,
                if phase == "complete" {
                    "schema phase id selection_id boot_id filesystem_uuid device mount_path mount_options result"
                } else {
                    "schema phase id selection_id boot_id filesystem_uuid device mount_path mount_options"
                },
            )?;
            require(
                v["mount_path"] == format!("/run/enzimos/backup-device-review/{id}"),
                "legacy review mount path mismatch",
            )?;
        }
        _ => return Err(Error("review receipt schema unsupported".into())),
    }
    require(
        v["id"] == id && v["mount_options"] == OPTIONS,
        "review identity/options changed",
    )?;
    identity::sha(text(v, "selection_id")?)?;
    identity::uuid(text(v, "boot_id")?)?;
    identity::uuid(text(v, "filesystem_uuid")?)?;
    let d = &v["device"];
    json::fields(
        d,
        "major minor device_inode device_filesystem disk_sequence bytes read_only",
    )?;
    require(
        d["major"].as_u64().is_some_and(|n| n < 1 << 12)
            && d["minor"].as_u64().is_some_and(|n| n < 1 << 20)
            && ["device_inode", "disk_sequence", "bytes"]
                .iter()
                .all(|k| d[*k].as_u64().is_some_and(|n| n > 0 && n < i64::MAX as u64))
            && d["device_filesystem"].as_u64().is_some()
            && d["read_only"] == false,
        "review original block identity required",
    )?;
    if phase == "complete" {
        result(&v["result"], text(v, "filesystem_uuid")?)?;
    }
    Ok(())
}
/// Retains the exact completed native receipt, not an interchangeable JSON copy.
pub struct Review<'a, 'd> {
    store: Store<'a>,
    id: String,
    selection: &'a Selection<'d>,
    original: Value,
}
impl<'a, 'd> Review<'a, 'd> {
    pub fn open(
        selection: &'a Selection<'d>,
        id: &str,
        lock: &'a files::Lock,
        authorize: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        selection.recheck()?;
        identity::safe_id(id)?;
        let guard = selection.guard();
        let store = Store::retained(
            &Path::new(crate::operation::CONTROL).join("backup-device-reviews"),
            0,
            guard.control_mount_id(),
            Box::new(move || {
                guard.recheck()?;
                lock.recheck()?;
                authorize()
            }),
        )?;
        let original = store.completed(id)?;
        matching(
            &original,
            &selection.token()?,
            &crate::operation::boot_id()?,
            selection.uuid_hint(),
            &selection.evidence()?["device"],
        )?;
        let this = Self {
            store,
            id: id.into(),
            selection,
            original,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.selection.recheck()?;
        self.document_recheck()
    }
    pub(crate) fn document_recheck(&self) -> Result<()> {
        require(
            self.store.completed(&self.id)? == self.original,
            "original native review changed",
        )
    }
    pub(crate) fn repository(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.original["result"]["repository"].clone())
    }
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn original(&self) -> &Value {
        &self.original
    }
    pub(crate) fn selection(&self) -> &Selection<'d> {
        self.selection
    }
}
fn matching(v: &Value, token: &str, boot: &str, uuid: &str, device: &Value) -> Result<()> {
    validate_receipt(v, text(v, "id")?)?;
    require(
        v["schema"].as_u64() == Some(2)
            && v["phase"] == "complete"
            && v["descriptor_scope_closed"] == true
            && v["selection_id"] == token
            && v["boot_id"] == boot
            && v["filesystem_uuid"] == uuid
            && &v["device"] == device,
        "fresh exact native readonly review required",
    )
}
fn prepared(selection: &Selection<'_>, id: &str) -> Result<Value> {
    let v = value!({"schema":2,"phase":"prepared","id":id,"selection_id":selection.token()?,
        "boot_id":crate::operation::boot_id()?,"filesystem_uuid":selection.uuid_hint(),
        "device":selection.evidence()?["device"],"mount_scope":"detached-file-descriptor",
        "mount_options":OPTIONS,"descriptor_scope_closed":false,"result":null});
    validate_receipt(&v, id)?;
    Ok(v)
}
/// `authorize` must revalidate the caller's original fresh grant and session.
/// This primitive is not advertised as installed/qualified by the native frontend.
pub fn review(
    selection: &Selection<'_>,
    id: &str,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    crate::storage_runtime::initial_namespace()?;
    identity::safe_id(id)?;
    let recheck = || {
        lock.recheck()?;
        selection.recheck()?;
        authorize()
    };
    recheck()?;
    // Signature probing runs before creating any filesystem context/mount.
    let signature = crate::backup_signature::observe(selection)?;
    require(
        signature["filesystem_uuid"] == selection.uuid_hint(),
        "review signature changed",
    )?;
    let guard = selection.guard();
    let directory = files::ensure_directory_relative(
        guard.control(),
        Path::new("backup-device-reviews"),
        0o700,
        0,
    )?;
    require(
        mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
        "review journal outside original control mount",
    )?;
    let mut store = Store::retained(
        &Path::new(crate::operation::CONTROL).join("backup-device-reviews"),
        0,
        guard.control_mount_id(),
        Box::new(recheck),
    )?;
    store.prepare(prepared(selection, id)?)?;
    store.recheck()?; // original intent + fresh authorization immediately before mount
    let mount = Mount::create(selection, &|| store.recheck())?;
    mount.recheck(selection)?;
    store.recheck()?;
    let repository = mount.repository()?;
    mount.recheck(selection)?;
    store.recheck()?;
    let response = value!({"schema":1,"readonly_mount_reviewed":true,"filesystem_uuid":selection.uuid_hint(),
        "filesystem_verified":false,"credential_enrolled":false,"automatic_backup_enabled":false,"repository":repository});
    result(&response, selection.uuid_hint())?;
    mount.close()?;
    store.recheck()?;
    require(
        crate::backup_signature::observe(selection)? == signature,
        "review signature changed after closure",
    )?;
    store.recheck()?;
    store.complete(id, response.clone())?;
    Ok(response)
}
