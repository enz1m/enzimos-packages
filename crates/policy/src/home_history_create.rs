// SPDX-License-Identifier: MIT
//! Actual Snapper creation has durable intent and an observed read-only lineage.
use crate::{home_history_source::Source, identity, operation, settings_command::Command};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
/// Finished receipts always kept; older ones are retired once the registry
/// holds `RETIRE_AT` receipts, so hourly history never reaches its bound.
const RETAINED: usize = 168;
const RETIRE_AT: usize = 512;
pub fn validate(body: &Value) -> Result<()> {
    json::fields(
        body,
        "schema operation id boot_id phase source provider snapshot",
    )?;
    require(
        body["schema"] == 1 && body["operation"] == "home-history-create",
        "home history receipt role",
    )?;
    let id = body["id"]
        .as_str()
        .ok_or_else(|| Error("home history receipt ID".into()))?;
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "home history receipt ID shape",
    )?;
    identity::uuid(
        body["boot_id"]
            .as_str()
            .ok_or_else(|| Error("home history boot ID".into()))?,
    )?;
    crate::home_history_source::validate(&body["source"])?;
    crate::settings_command::validate(&body["provider"])?;
    require(
        body["provider"]["path"] == "/usr/bin/snapper",
        "home history provider role differs",
    )?;
    if body["phase"] == "complete" {
        json::fields(&body["snapshot"], "number object readonly")?;
        let number = body["snapshot"]["number"]
            .as_u64()
            .ok_or_else(|| Error("history snapshot number".into()))?;
        let path = format!("/home/.snapshots/{number}/snapshot");
        let parent = body["source"]["object"]["uuid"]
            .as_str()
            .ok_or_else(|| Error("history parent UUID".into()))?;
        crate::birth::object(&body["snapshot"]["object"], &path, Some(parent))?;
        require(
            body["snapshot"]["object"]["uuid"] != body["source"]["object"]["uuid"]
                && body["snapshot"]["object"]["id"] != body["source"]["object"]["id"],
            "history snapshot source alias refused",
        )?;
    }
    require(
        match body["phase"].as_str() {
            Some("creating" | "abandoned") => body["snapshot"].is_null(),
            Some("complete") => {
                body["snapshot"]["readonly"] == true
                    && body["snapshot"]["number"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n < 1 << 63)
                    && body["snapshot"]["object"]["parent_uuid"] == body["source"]["object"]["uuid"]
            }
            _ => false,
        },
        "home history receipt phase or snapshot proof",
    )
}
pub fn plan() -> Result<Value> {
    let lock = operation::lock()?;
    let source = Source::observe()?;
    let command = Command::open("/usr/bin/snapper")?;
    lock.recheck()?;
    Ok(value!({"source":source.evidence()?,"provider":command.evidence()?}))
}
/// A manual snapshot: Snapper's number cleanup applies the "manual" limit.
pub fn create<F: FnMut() -> Result<()>>(
    expected: Option<&Value>,
    authorization: F,
) -> Result<Value> {
    let lock = operation::lock()?;
    create_kind(&lock, expected, "number", authorization)
}
/// An automatic (hourly) snapshot, retained by the timeline limits.
pub(crate) fn create_locked<F: FnMut() -> Result<()>>(
    lock: &files::Lock,
    expected: Option<&Value>,
    authorization: F,
) -> Result<Value> {
    create_kind(lock, expected, "timeline", authorization)
}
/// Whether an existing receipt is finished history. A `creating` receipt
/// seen under the operation lock belongs to an earlier attempt that failed or
/// was interrupted; it is published `abandoned` (creation only adds a
/// snapshot that Snapper's own cleanup manages, so nothing needs undoing).
fn finished(body: &Value) -> bool {
    matches!(body["phase"].as_str(), Some("complete" | "abandoned"))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn create_kind<F: FnMut() -> Result<()>>(
    lock: &files::Lock,
    expected: Option<&Value>,
    cleanup: &str,
    mut authorization: F,
) -> Result<Value> {
    require(
        matches!(cleanup, "number" | "timeline"),
        "home history cleanup algorithm",
    )?;
    lock.recheck()?;
    let source = Source::observe()?;
    let command = Command::open("/usr/bin/snapper")?;
    let observed = value!({"source":source.evidence()?,"provider":command.evidence()?});
    if let Some(expected) = expected {
        require(*expected == observed, "home history plan changed")?;
    }
    let directory = files::ensure_directory_relative(
        source.guard.control(),
        Path::new("home-history-attempts"),
        0o700,
        0,
    )?;
    require(
        mount_identity::id(directory.as_fd(), true)? == source.guard.control_mount_id(),
        "history receipt left retained control filesystem",
    )?;
    let root = Path::new(operation::CONTROL).join("home-history-attempts");
    let directory_shape = |f: &std::fs::File| -> Result<(u64, u64, u32, u32, u32)> {
        let m = f.metadata()?;
        require(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
            "private history receipt directory protection",
        )?;
        Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
    };
    let original_shape = directory_shape(&directory)?;
    let check_directory = || -> Result<()> {
        let named = files::directory(&root, Some(0))?;
        require(
            directory_shape(&directory)? == original_shape
                && directory_shape(&named)? == original_shape
                && mount_identity::id(directory.as_fd(), true)? == source.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == source.guard.control_mount_id(),
            "original private history receipt directory replaced",
        )
    };
    check_directory()?;
    let mut rows = Vec::new();
    let mut receipt_identities = std::collections::BTreeMap::new();
    for name in files::directory_names(&directory, 4095)? {
        let file = files::open_relative(&directory, Path::new(&name))?;
        let m = file.metadata()?;
        require(
            m.gid() == 0
                && m.mode() & 0o7777 == 0o600
                && mount_identity::id(file.as_fd(), true)? == source.guard.control_mount_id(),
            "private historical receipt protection",
        )?;
        let bytes = files::read_file(&file, 16384, Some(0), true)?;
        let mut body = json::decode(&bytes, 16384)?;
        validate(&body)?;
        let id = body["id"].as_str().unwrap().to_owned();
        require(
            name.to_str() == Some(&format!("{id}.json")),
            "home history receipt name differs; review required",
        )?;
        let mut identity = files::identity(&m);
        if body["phase"] == "creating" {
            body["phase"] = value!("abandoned");
            validate(&body)?;
            lock.recheck()?;
            check_directory()?;
            let replaced = files::atomic_replace_original(
                &directory,
                Path::new(&name),
                &json::canonical(&body)?,
                0o600,
                Some(0),
                16384,
                &file,
            )?;
            identity = files::identity(&replaced.metadata()?);
        }
        require(finished(&body), "home history receipt phase")?;
        rows.push(crate::control_registry::Row {
            order: (m.mtime(), m.mtime_nsec()),
            id: id.clone(),
            retirable: true,
        });
        receipt_identities.insert(id, identity);
    }
    for id in retired(rows) {
        lock.recheck()?;
        check_directory()?;
        let name = format!("{id}.json");
        let file = files::open_relative(&directory, Path::new(&name))?;
        require(
            files::identity(&file.metadata()?) == receipt_identities[&id],
            "retired home history receipt changed",
        )?;
        let c =
            std::ffi::CString::new(name).map_err(|_| Error("home history receipt name".into()))?;
        require(
            unsafe { libc::unlinkat(directory.as_raw_fd(), c.as_ptr(), 0) } == 0,
            "home history receipt retirement failed",
        )?;
    }
    directory.sync_all()?;
    let id = files::random_hex(16)?;
    let name = format!("{id}.json");
    let mut body = value!({"schema":1,"operation":"home-history-create","id":id,"boot_id":operation::boot_id()?,
        "phase":"creating","source":observed["source"],"provider":observed["provider"],"snapshot":null});
    validate(&body)?;
    authorization()?;
    source.recheck()?;
    command.recheck()?;
    lock.recheck()?;
    check_directory()?;
    let intent_bytes = json::canonical(&body)?;
    let intent = files::atomic_relative_retained(
        &directory,
        Path::new(&name),
        &intent_bytes,
        0o600,
        Some(0),
        false,
        16384,
    )?;
    let intent_identity = files::identity(&intent.metadata()?);
    source.recheck()?;
    command.recheck()?;
    authorization()?;
    lock.recheck()?;
    check_directory()?;
    let named_intent = files::open_relative(&directory, Path::new(&name))?;
    require(
        files::identity(&named_intent.metadata()?) == intent_identity
            && files::identity(&intent.metadata()?) == intent_identity
            && files::read_file(&intent, 16384, Some(0), true)? == intent_bytes,
        "original history creation intent changed before snapshot mutation",
    )?;
    let output = command.run(
        &[
            "--no-dbus",
            "-c",
            "home",
            "create",
            "--type",
            "single",
            "--description",
            "enzimOS home history",
            "--cleanup-algorithm",
            cleanup,
            "--print-number",
        ],
        &[0],
        4096,
    )?;
    let number = std::str::from_utf8(&output)
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0 && *n < 1 << 63)
        .ok_or_else(|| Error("Snapper creation result uncertain; no automatic retry".into()))?;
    let (snapshot, proof) = source.snapshot(number)?;
    command.recheck()?;
    source.recheck()?;
    check_directory()?;
    let named_directory = files::directory(&root, Some(0))?;
    require(
        files::identity(&named_directory.metadata()?).0
            == files::identity(&directory.metadata()?).0
            && files::identity(&named_directory.metadata()?).1
                == files::identity(&directory.metadata()?).1
            && mount_identity::id(named_directory.as_fd(), true)?
                == source.guard.control_mount_id(),
        "original home history receipt directory replaced",
    )?;
    body["phase"] = value!("complete");
    body["snapshot"] = proof;
    validate(&body)?;
    let (named_snapshot, named_proof) = source.snapshot(number)?;
    require(
        named_proof == body["snapshot"]
            && files::identity(&named_snapshot.metadata()?)
                == files::identity(&snapshot.metadata()?),
        "original read-only history snapshot replaced before completion",
    )?;
    lock.recheck()?;
    require(
        files::identity(&intent.metadata()?) == intent_identity
            && files::read_file(&intent, 16384, Some(0), true)? == intent_bytes,
        "original history intent epoch changed before completion",
    )?;
    let completed = files::atomic_replace_original(
        &directory,
        Path::new(&name),
        &json::canonical(&body)?,
        0o600,
        Some(0),
        16384,
        &intent,
    )?;
    require(
        json::decode(&files::read_file(&completed, 16384, Some(0), true)?, 16384)? == body,
        "home history completion readback differs",
    )?;
    lock.recheck()?;
    Ok(value!({"snapshot":number}))
}

/// Oldest finished receipts to retire so the newest `RETAINED` remain.
fn retired(rows: Vec<crate::control_registry::Row>) -> Vec<String> {
    crate::control_registry::select(rows, RETAINED, RETIRE_AT)
}
