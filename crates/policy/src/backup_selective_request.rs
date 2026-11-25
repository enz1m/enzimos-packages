// SPDX-License-Identifier: MIT
//! Closed selective-file syntax; decoded data cannot construct a worker or export actor.
use enzimos_platform::{Error, Result, fd_packet::Credentials, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub(crate) const KIND: &str = "selective-file-export";
pub(crate) const LIMIT: usize = 65536;
pub(crate) const DESCRIPTORS: usize = 11;
pub(crate) const ROLES: [&str; 9] = [
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
        .ok_or_else(|| Error("selective export text field required".into()))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Tree,
}
impl Kind {
    pub(crate) fn context(self) -> &'static str {
        match self {
            Self::File => "selective-file-context",
            Self::Tree => "selective-tree-context",
        }
    }
    pub(crate) fn request(self) -> &'static str {
        match self {
            Self::File => KIND,
            Self::Tree => "selective-tree-export",
        }
    }
    pub(crate) fn operation(self) -> &'static str {
        match self {
            Self::File => "file-restore-export",
            Self::Tree => "tree-restore-export",
        }
    }
    pub(crate) fn parse(v: &Value) -> Result<Self> {
        match v.as_str() {
            Some(KIND) => Ok(Self::File),
            Some("selective-tree-export") => Ok(Self::Tree),
            _ => Err(enzimos_platform::Error(
                "closed selected export role required".into(),
            )),
        }
    }
}
/// Validate a selective export selection.
///
/// # Errors
///
/// Fails when a field is missing or invalid.
pub fn selection(v: &Value) -> Result<()> {
    json::fields(v, "id snapshot path")?;
    crate::identity::safe_id(text(v, "id")?)?;
    crate::identity::sha(text(v, "snapshot")?)?;
    crate::backup_selective_result::file_path(text(v, "path")?).map(|_| ())
}
/// Validate a selective export context.
///
/// # Errors
///
/// Fails when a field is missing or invalid.
pub fn context(v: &Value) -> Result<()> {
    context_kind(v, Kind::File)
}
pub(crate) fn context_kind(v: &Value, kind: Kind) -> Result<()> {
    json::fields(
        v,
        "schema role id boot_id caller source selection destination configuration pin root_directory repository_directory credential restic header operation_lock worker_closed export_complete live_home_written metadata_restored per_user_authorized",
    )?;
    require(
        v["schema"] == 1 && v["role"] == kind.context(),
        "closed selective context role",
    )?;
    crate::backup_worker_request::id(text(v, "id")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    selection(&v["selection"])?;
    for flag in [
        "worker_closed",
        "export_complete",
        "live_home_written",
        "metadata_restored",
        "per_user_authorized",
    ] {
        require(
            v[flag] == false,
            "selective request cannot manufacture closure, export or user delivery",
        )?;
    }
    crate::backup_existing_repository_wire::validate(v)?;
    json::fields(&v["credential"], "inode mount")?;
    let file = &v["credential"]["inode"];
    crate::backup_worker_request::file(file)?;
    require(
        file[7]
            .as_u64()
            .is_some_and(|m| m as u32 & libc::S_IFMT == libc::S_IFREG && m & 0o077 == 0)
            && file[8] == 0
            && file[9] == 0
            && file[10] == 1
            && file[2].as_u64().is_some_and(|n| (1..=4096).contains(&n))
            && v["credential"]["mount"] == v["source"]["mount"]["unique_mount_id"],
        "original private Root credential required for selective export",
    )?;
    let mut distinct = BTreeSet::new();
    for file in [
        &v["caller"]["image_epoch"],
        &v["header"]["identity"],
        &v["credential"]["inode"],
        &v["configuration"]["inode"],
        &v["pin"]["inode"],
        &v["restic"]["inode"],
        &v["operation_lock"]["inode"],
    ] {
        require(
            distinct.insert((
                enzimos_platform::json::unsigned(&file[0])?,
                enzimos_platform::json::unsigned(&file[1])?,
            )),
            "selective descriptor roles alias",
        )?;
    }
    require(
        json::canonical(v)?.len() <= LIMIT,
        "selective context bound",
    )
}
pub(crate) fn request(v: &Value) -> Result<()> {
    json::fields(v, "schema kind id boot_id worker context")?;
    require(
        v["schema"] == 1,
        "selective request cannot substitute another task",
    )?;
    context_kind(&v["context"], Kind::parse(&v["kind"])?)?;
    require(
        v["id"] == v["context"]["id"] && v["boot_id"] == v["context"]["boot_id"],
        "selective attempt/boot mismatch",
    )?;
    crate::backup_worker_intent::worker(&v["worker"], text(v, "id")?)?;
    require(
        json::canonical(v)?.len() <= LIMIT,
        "sealed selective request bound",
    )
}
pub(crate) fn frame(v: &Value, request_value: &Value, sender: &Credentials) -> Result<Vec<u32>> {
    request(request_value)?;
    json::fields(v, "schema kind id request_sha256 descriptor_numbers intent")?;
    require(
        v["schema"] == 1
            && v["kind"] == request_value["kind"]
            && v["id"] == request_value["id"]
            && v["request_sha256"] == json::fingerprint(request_value)?
            && sender.pid
                == enzimos_platform::json::unsigned(&request_value["context"]["caller"]["pid"])?
                    as u32
            && sender.uid == 0
            && sender.gid == 0,
        "selective frame not from original Root caller/request",
    )?;
    crate::backup_existing_repository_wire::intent(&v["intent"], LIMIT)?;
    let numbers = v["descriptor_numbers"]
        .as_array()
        .ok_or_else(|| Error("selective descriptor numbers required".into()))?;
    require(
        numbers.len() == DESCRIPTORS,
        "closed selective descriptor count",
    )?;
    let mut distinct = BTreeSet::new();
    numbers
        .iter()
        .map(|n| {
            let n = n
                .as_u64()
                .ok_or_else(|| Error("selective descriptor number type".into()))?;
            require(
                (3..1_048_576).contains(&n) && distinct.insert(n),
                "selective descriptor numbers must be bounded and distinct",
            )?;
            Ok(n as u32)
        })
        .collect()
}
