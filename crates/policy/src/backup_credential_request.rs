// SPDX-License-Identifier: MIT
//! Closed credential-review syntax; no decoded record grants execution authority.
use enzimos_platform::{Error, Result, fd_packet::Credentials, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub(crate) const KIND: &str = "credential-review";
pub(crate) const LIMIT: usize = 65536;
pub(crate) const DESCRIPTORS: usize = 13;
pub(crate) const ROLES: [&str; 11] = [
    "caller-pidfd",
    "caller-image",
    "root",
    "repository",
    "current-credential",
    "next-credential",
    "restic",
    "configuration",
    "pin",
    "operation-lock",
    "enrollment",
];
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("credential review text field required".into()))
}
fn credential(v: &Value) -> Result<()> {
    json::fields(v, "inode mount")?;
    crate::backup_worker_request::file(&v["inode"])?;
    let f = &v["inode"];
    require(
        f[7].as_u64()
            .is_some_and(|m| m as u32 & libc::S_IFMT == libc::S_IFREG && m & 0o077 == 0)
            && f[8] == 0
            && f[9] == 0
            && f[10] == 1
            && f[2].as_u64().is_some_and(|n| (1..=4096).contains(&n))
            && v["mount"].as_u64().is_some_and(|n| n > 0),
        "original private credential review input required",
    )
}
pub(crate) fn context(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema role id boot_id caller source enrollment input_identity destination configuration pin root_directory repository_directory current_credential next_credential restic header operation_lock worker_closed review_complete key_creation_replayed old_access_revoked credential_exported",
    )?;
    require(
        v["schema"] == 1 && v["role"] == "credential-review-context",
        "closed credential review context role",
    )?;
    crate::backup_worker_request::id(text(v, "id")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    for flag in [
        "worker_closed",
        "review_complete",
        "key_creation_replayed",
        "old_access_revoked",
        "credential_exported",
    ] {
        require(
            v[flag] == false,
            "credential request cannot claim completion, export or key mutation",
        )?;
    }
    crate::backup_existing_repository_wire::validate(v)?;
    credential(&v["current_credential"])?;
    credential(&v["next_credential"])?;
    require(
        v["current_credential"]["inode"][0] == v["next_credential"]["inode"][0]
            && v["current_credential"]["mount"] == v["source"]["mount"]["unique_mount_id"]
            && v["next_credential"]["mount"] == v["current_credential"]["mount"],
        "credential inputs must belong to the original live Root mount",
    )?;
    let input = &v["input_identity"];
    json::fields(
        input,
        "filesystem_uuid root_uuid root_id root_path inode size mtime_ns ctime_ns",
    )?;
    let root = &v["source"]["root"];
    require(
        input["filesystem_uuid"] == v["source"]["configuration"]["filesystem_uuid"]
            && input["root_uuid"] == root["uuid"]
            && input["root_id"] == root["id"]
            && input["root_path"] == root["path"]
            && input["inode"] == v["next_credential"]["inode"][1]
            && input["size"] == v["next_credential"]["inode"][2],
        "candidate persistent input binding changed",
    )?;
    for (time, at) in [("mtime_ns", 3), ("ctime_ns", 5)] {
        let epoch = &v["next_credential"]["inode"];
        let actual = epoch[at]
            .as_i64()
            .and_then(|s| s.checked_mul(1_000_000_000))
            .and_then(|s| epoch[at + 1].as_i64().and_then(|n| s.checked_add(n)));
        require(
            actual.is_some_and(|n| n > 0) && input[time].as_i64() == actual,
            "candidate persistent input timestamps changed",
        )?;
    }
    let enrollment = &v["enrollment"];
    json::fields(enrollment, "id file bytes_sha256 directory mount")?;
    crate::identity::safe_id(text(enrollment, "id")?)?;
    crate::identity::sha(text(enrollment, "bytes_sha256")?)?;
    crate::backup_worker_request::file(&enrollment["file"])?;
    let f = &enrollment["file"];
    require(
        f[7] == (libc::S_IFREG | 0o600)
            && f[8] == 0
            && f[9] == 0
            && f[10] == 1
            && f[2]
                .as_u64()
                .is_some_and(|n| (1..=crate::backup_credential_record::LIMIT as u64).contains(&n))
            && enrollment["mount"].as_u64().is_some_and(|n| n > 0),
        "original Root-private enrollment file required",
    )?;
    let parent = enrollment["directory"]
        .as_array()
        .ok_or_else(|| Error("enrollment directory shape required".into()))?;
    require(
        parent.len() == 5
            && parent.iter().all(Value::is_u64)
            && parent[0].as_u64().is_some_and(|n| n > 0)
            && parent[1].as_u64().is_some_and(|n| n > 0)
            && parent[2] == 0
            && parent[3] == 0
            && parent[4] == (libc::S_IFDIR | 0o700),
        "protected enrollment original parent required",
    )?;
    let mut distinct = BTreeSet::new();
    for file in [
        &v["caller"]["image_epoch"],
        &v["header"]["identity"],
        &v["current_credential"]["inode"],
        &v["next_credential"]["inode"],
        &v["configuration"]["inode"],
        &v["pin"]["inode"],
        &v["restic"]["inode"],
        &v["operation_lock"]["inode"],
        &enrollment["file"],
    ] {
        require(
            distinct.insert((file[0].as_u64().unwrap(), file[1].as_u64().unwrap())),
            "credential request original file roles alias",
        )?;
    }
    require(
        json::canonical(v)?.len() <= LIMIT,
        "credential context bound",
    )
}
pub(crate) fn request(v: &Value) -> Result<()> {
    json::fields(v, "schema kind id boot_id worker context")?;
    require(
        v["schema"] == 1 && v["kind"] == KIND,
        "credential request cannot substitute another task",
    )?;
    context(&v["context"])?;
    require(
        v["id"] == v["context"]["id"] && v["boot_id"] == v["context"]["boot_id"],
        "credential attempt/boot mismatch",
    )?;
    crate::backup_worker_intent::worker(&v["worker"], text(v, "id")?)?;
    require(
        json::canonical(v)?.len() <= LIMIT,
        "sealed credential request bound",
    )
}
pub(crate) fn frame(v: &Value, request_value: &Value, sender: &Credentials) -> Result<Vec<u32>> {
    request(request_value)?;
    json::fields(v, "schema kind id request_sha256 descriptor_numbers intent")?;
    require(
        v["schema"] == 1
            && v["kind"] == KIND
            && v["id"] == request_value["id"]
            && v["request_sha256"] == json::fingerprint(request_value)?
            && sender.pid == request_value["context"]["caller"]["pid"].as_u64().unwrap() as u32
            && sender.uid == 0
            && sender.gid == 0,
        "credential frame not from original Root caller/request",
    )?;
    crate::backup_existing_repository_wire::intent(&v["intent"], LIMIT)?;
    let numbers = v["descriptor_numbers"]
        .as_array()
        .ok_or_else(|| Error("credential descriptor numbers required".into()))?;
    require(
        numbers.len() == DESCRIPTORS,
        "closed credential descriptor count",
    )?;
    let mut distinct = BTreeSet::new();
    numbers
        .iter()
        .map(|n| {
            let n = n
                .as_u64()
                .ok_or_else(|| Error("credential descriptor number type".into()))?;
            require(
                (3..1_048_576).contains(&n) && distinct.insert(n),
                "credential descriptor numbers must be bounded and distinct",
            )?;
            Ok(n as u32)
        })
        .collect()
}
