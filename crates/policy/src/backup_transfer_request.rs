// SPDX-License-Identifier: MIT
//! Closed transfer request syntax; never setup, execution or cleanup authority.
use enzimos_platform::{Error, Result, fd_packet::Credentials, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub const LIMIT: usize = 65536;
pub const DESCRIPTORS: usize = 11;
pub const ROLES: [&str; 9] = [
    "caller-pidfd",
    "caller-image",
    "root",
    "repository",
    "credential",
    "restic",
    "configuration",
    "pin",
    "operation-lock",
];
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("transfer request text field".into()))
}
pub fn context(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema role id boot_id caller source destination pin configuration root_directory repository_directory operation_lock header credential restic input_sha256 arguments source_mounts_admitted transfer_complete worker_kernel_closed cleanup_complete backup_complete",
    )?;
    require(
        v["schema"] == 1 && v["role"] == "backup-transfer-context",
        "closed actual transfer context role",
    )?;
    crate::backup_worker_request::id(text(v, "id")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    for key in [
        "source_mounts_admitted",
        "transfer_complete",
        "worker_kernel_closed",
        "cleanup_complete",
        "backup_complete",
    ] {
        require(
            v[key] == false,
            "transfer request cannot assert admission or completion",
        )?;
    }
    crate::backup_existing_repository_wire::validate(v)?;
    let caller = &v["caller"];
    json::fields(&v["credential"], "inode mount")?;
    crate::backup_worker_request::file(&v["credential"]["inode"])?;
    let credential = &v["credential"]["inode"];
    require(
        credential[7] == (libc::S_IFREG | 0o600)
            && credential[8] == 0
            && credential[9] == 0
            && credential[10] == 1
            && credential[2]
                .as_u64()
                .is_some_and(|n| (1..=4096).contains(&n))
            && v["credential"]["mount"].as_u64().is_some_and(|n| n > 0),
        "original private transfer credential",
    )?;
    crate::identity::sha(text(v, "input_sha256")?)?;
    let mut original_files = BTreeSet::new();
    for inode in [
        &caller["image_epoch"],
        &v["header"]["identity"],
        &v["credential"]["inode"],
        &v["configuration"]["inode"],
        &v["pin"]["inode"],
        &v["restic"]["inode"],
    ] {
        require(
            original_files.insert((inode[0].as_u64().unwrap(), inode[1].as_u64().unwrap())),
            "transfer original file roles alias an inode",
        )?;
    }
    let args = v["arguments"]
        .as_array()
        .ok_or_else(|| Error("transfer arguments missing".into()))?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error("transfer argument type".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut start = 6;
    while args.get(start).is_some_and(|s| s == "--exclude") {
        start += 2;
    }
    if args.get(start).is_some_and(|s| s == "--exclude-file") {
        start += 2;
    }
    let targets = args
        .get(start..)
        .ok_or_else(|| Error("transfer arguments incomplete".into()))?
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    enzimos_platform::backup_command::validate(&args, &targets)?;
    require(
        v["destination"].is_object() && json::canonical(v)?.len() <= LIMIT,
        "bounded transfer destination/context",
    )
}
pub fn request(v: &Value) -> Result<()> {
    json::fields(v, "schema kind id boot_id worker context")?;
    require(
        v["schema"] == 1 && v["kind"] == "captured-backup-transfer",
        "transfer request cannot substitute setup provisioning",
    )?;
    context(&v["context"])?;
    require(
        v["id"] == v["context"]["id"] && v["boot_id"] == v["context"]["boot_id"],
        "original transfer attempt/boot changed",
    )?;
    crate::backup_worker_intent::worker(&v["worker"], text(v, "id")?)?;
    require(
        json::canonical(v)?.len() <= LIMIT,
        "bounded sealed transfer request",
    )
}
pub fn frame(v: &Value, request_value: &Value, sender: &Credentials) -> Result<Vec<u32>> {
    request(request_value)?;
    json::fields(v, "schema kind id request_sha256 descriptor_numbers intent")?;
    require(
        v["schema"] == 1
            && v["kind"] == "captured-backup-transfer"
            && v["id"] == request_value["id"]
            && v["request_sha256"] == json::fingerprint(request_value)?
            && sender.uid == 0
            && sender.gid == 0
            && request_value["context"]["caller"]["pid"] == sender.pid,
        "transfer frame differs from actual original Root sender",
    )?;
    crate::backup_existing_repository_wire::intent(&v["intent"], LIMIT)?;
    let numbers = v["descriptor_numbers"]
        .as_array()
        .ok_or_else(|| Error("transfer original descriptor numbers".into()))?;
    require(
        numbers.len() == DESCRIPTORS,
        "closed transfer descriptor count",
    )?;
    let mut distinct = BTreeSet::new();
    numbers
        .iter()
        .map(|n| {
            let n = n
                .as_u64()
                .ok_or_else(|| Error("transfer descriptor number type".into()))?;
            require(
                (3..1_048_576).contains(&n) && distinct.insert(n),
                "distinct bounded transfer original descriptors",
            )?;
            Ok(n as u32)
        })
        .collect()
}
