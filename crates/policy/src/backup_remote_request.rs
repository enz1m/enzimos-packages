// SPDX-License-Identifier: MIT
//! Closed remote worker syntax; decoding does not grant a copy or receipt actor.
use enzimos_platform::{Error, Result, fd_packet::Credentials, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
pub const LIMIT: usize = 65536;
pub const DESCRIPTORS: usize = 16;
pub const ROLES: [&str; 14] = [
    "caller-pidfd",
    "caller-image",
    "root-control",
    "local-root",
    "local-repository",
    "local-credential",
    "local-configuration",
    "local-pin",
    "restic",
    "remote-configuration",
    "remote-password",
    "remote-share-password",
    "remote-pin",
    "operation-lock",
];
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("remote worker text field required".into()))
}
fn inode(v: &Value, private: bool, limit: u64) -> Result<()> {
    crate::backup_worker_request::file(v)?;
    require(
        v[7].as_u64().is_some_and(|mode| {
            mode as u32 & libc::S_IFMT == libc::S_IFREG
                && mode & 0o022 == 0
                && (!private || mode & 0o077 == 0)
        }) && v[8] == 0
            && v[9] == 0
            && v[10] == 1
            && v[2].as_u64().is_some_and(|n| n > 0 && n <= limit),
        "protected original remote file epoch",
    )
}
fn epoch(v: &Value, limit: u64) -> Result<()> {
    json::fields(v, "epoch mount bytes_sha256")?;
    inode(&v["epoch"], true, limit)?;
    require(
        v["mount"].as_u64().is_some_and(|n| n > 0),
        "remote record mount required",
    )?;
    crate::identity::sha(text(v, "bytes_sha256")?).map(|_| ())
}
pub fn context(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema role id receipt_id direction snapshot remote source destination local_configuration local_pin local_root local_repository local_header local_credential operation_lock remote_authenticated copy_complete worker_closed receipt_complete scheduler_enabled automatic_retry",
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["role"] == "remote-copy-context"
            && matches!(v["direction"].as_str(), Some("replicate" | "retrieve")),
        "closed remote copy role/direction",
    )?;
    crate::backup_worker_request::id(text(v, "id")?)?;
    if v["direction"] == "retrieve" {
        crate::identity::safe_id(text(v, "receipt_id")?)?;
    } else {
        require(
            v["receipt_id"].is_null(),
            "replication cannot create a retrieval receipt",
        )?;
    }

    crate::identity::sha(text(v, "snapshot")?)?;
    for flag in [
        "remote_authenticated",
        "copy_complete",
        "worker_closed",
        "receipt_complete",
        "scheduler_enabled",
        "automatic_retry",
    ] {
        require(
            v[flag] == false,
            "request cannot assert remote authority or completion",
        )?;
    }
    let remote = &v["remote"];
    json::fields(
        remote,
        "schema role boot_id inputs caller restic pin pin_epoch rotation_epoch remote_identity_authenticated copy_complete worker_closed scheduler_enabled",
    )?;
    require(
        remote["schema"].as_u64() == Some(1) && remote["role"] == "remote-repository-context",
        "closed original remote role",
    )?;
    crate::identity::uuid(text(remote, "boot_id")?)?;
    for flag in [
        "remote_identity_authenticated",
        "copy_complete",
        "worker_closed",
        "scheduler_enabled",
    ] {
        require(
            remote[flag] == false,
            "remote inputs cannot assert authentication or completion",
        )?;
    }
    crate::backup_remote_record::pin(&remote["pin"])?;
    epoch(&remote["pin_epoch"], 32768)?;
    if !remote["rotation_epoch"].is_null() {
        epoch(
            &remote["rotation_epoch"],
            crate::backup_remote_record::ROTATION_LIMIT as u64,
        )?;
    }
    let inputs = &remote["inputs"];
    json::fields(
        inputs,
        "configuration binding original_epochs parent mount source credential_bytes_read",
    )?;
    require(
        inputs["credential_bytes_read"] == false
            && inputs["source"] == v["source"]
            && inputs["mount"].as_u64().is_some_and(|n| n > 0),
        "original remote inputs cannot read credentials or substitute source",
    )?;
    crate::backup_remote_endpoint::validate(&inputs["configuration"])?;
    let parent = inputs["parent"]
        .as_array()
        .ok_or_else(|| Error("remote input parent shape".into()))?;
    require(
        parent.len() == 5
            && parent.iter().all(Value::is_u64)
            && parent[0].as_u64().is_some_and(|n| n > 0)
            && parent[1].as_u64().is_some_and(|n| n > 0)
            && parent[2].as_u64().is_some_and(|mode| {
                mode as u32 & libc::S_IFMT == libc::S_IFDIR && mode & 0o022 == 0
            })
            && parent[3] == 0
            && parent[4] == 0,
        "protected Root remote input parent",
    )?;
    let epochs = inputs["original_epochs"]
        .as_array()
        .ok_or_else(|| Error("remote input epochs required".into()))?;
    require(epochs.len() == 3, "exact remote input epoch count")?;
    for (i, e) in epochs.iter().enumerate() {
        inode(e, i > 0, if i == 0 { 32768 } else { 4096 })?;
    }
    let binding = &inputs["binding"];
    json::fields(binding, "configuration_sha256 credentials")?;
    require(
        binding["configuration_sha256"] == remote["pin"]["configuration_sha256"],
        "original remote pin public binding differs",
    )?;
    let credentials = binding["credentials"]
        .as_object()
        .ok_or_else(|| Error("remote credential metadata map required".into()))?;
    require(
        credentials.len() == 2,
        "closed remote credential metadata count",
    )?;
    for (name, index) in [
        ("/etc/enzimos/backup-remote.password", 1),
        ("/etc/enzimos/backup-remote.share-password", 2),
    ] {
        let e = &epochs[index];
        let nanos = |seconds: &Value, ns: &Value| -> Result<i64> {
            seconds
                .as_i64()
                .and_then(|s| s.checked_mul(1_000_000_000))
                .and_then(|s| ns.as_i64().and_then(|n| s.checked_add(n)))
                .ok_or_else(|| Error("remote credential timestamp bound".into()))
        };
        require(
            credentials.get(name)
                == Some(&value!([
                    e[0],
                    e[1],
                    e[2],
                    nanos(&e[3], &e[4])?,
                    nanos(&e[5], &e[6])?
                ])),
            "remote credential metadata differs from original epoch",
        )?;
    }
    let local = value!({"caller":remote["caller"],"source":v["source"],"boot_id":remote["boot_id"],"configuration":v["local_configuration"],"pin":v["local_pin"],"root_directory":v["local_root"],"repository_directory":v["local_repository"],"destination":v["destination"],"header":v["local_header"],"operation_lock":v["operation_lock"],"restic":remote["restic"]});
    crate::backup_existing_repository_wire::validate(&local)?;
    json::fields(&v["local_credential"], "inode mount")?;
    inode(&v["local_credential"]["inode"], true, 4096)?;
    require(
        v["local_credential"]["mount"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "original local credential mount",
    )?;
    let mut objects = BTreeSet::new();
    for e in epochs.iter().chain([
        &remote["caller"]["image_epoch"],
        &remote["restic"]["inode"],
        &remote["pin_epoch"]["epoch"],
        &v["local_credential"]["inode"],
        &v["local_configuration"]["inode"],
        &v["local_pin"]["inode"],
        &v["operation_lock"]["inode"],
        &v["local_header"]["identity"],
    ]) {
        require(
            objects.insert((e[0].as_u64().unwrap(), e[1].as_u64().unwrap())),
            "remote worker original file roles alias one inode",
        )?;
    }
    require(
        json::canonical(v)?.len() <= LIMIT,
        "bounded original remote context",
    )
}
pub fn request(v: &Value) -> Result<()> {
    json::fields(v, "schema kind id boot_id worker context")?;
    require(
        v["schema"].as_u64() == Some(1) && v["kind"] == "remote-copy",
        "closed remote worker kind",
    )?;
    context(&v["context"])?;
    require(
        v["id"] == v["context"]["id"] && v["boot_id"] == v["context"]["remote"]["boot_id"],
        "remote worker original attempt/boot differs",
    )?;
    crate::backup_worker_intent::worker(&v["worker"], text(v, "id")?)?;
    require(
        json::canonical(v)?.len() <= LIMIT,
        "bounded sealed remote request",
    )
}
pub fn frame(v: &Value, r: &Value, sender: &Credentials) -> Result<Vec<u32>> {
    request(r)?;
    json::fields(v, "schema kind id request_sha256 descriptor_numbers intent")?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["kind"] == "remote-copy"
            && v["id"] == r["id"]
            && v["request_sha256"] == json::fingerprint(r)?
            && sender.uid == 0
            && sender.gid == 0
            && r["context"]["remote"]["caller"]["pid"] == sender.pid,
        "remote frame differs from original Root sender",
    )?;
    crate::backup_existing_repository_wire::intent(&v["intent"], LIMIT)?;
    let numbers = v["descriptor_numbers"]
        .as_array()
        .ok_or_else(|| Error("remote descriptor numbers required".into()))?;
    require(
        numbers.len() == DESCRIPTORS,
        "exact remote descriptor count",
    )?;
    let mut distinct = BTreeSet::new();
    numbers
        .iter()
        .map(|n| {
            let n = n
                .as_u64()
                .ok_or_else(|| Error("remote descriptor number type".into()))?;
            require(
                (3..1_048_576).contains(&n) && distinct.insert(n),
                "distinct bounded original remote descriptor numbers",
            )?;
            Ok(n as u32)
        })
        .collect()
}
