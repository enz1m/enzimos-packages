// SPDX-License-Identifier: MIT
//! Closed delivery-copy review data. Decoding grants no actor, path or execution authority.
use crate::{delivery_export::MAX_FILE, identity};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;
pub(crate) const LIMIT: usize = 8192;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub id: String,
    pub filename: String,
    pub group_nonce: String,
    pub grant_sha256: String,
    pub recipient_uid: u32,
    pub recipient_gid: u32,
    pub supervisor_pid: u32,
    pub supervisor_start: u64,
    pub boot_id: String,
    pub home: (u64, u64, u32, u32, u32),
    pub home_mount: u64,
    pub source: files::FileIdentity,
    pub source_mount: u64,
    pub bytes: u64,
    pub sha256: String,
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("delivery request text required".into()))
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| Error("delivery request integer required".into()))
}
impl Request {
    pub(crate) fn decode(body: &[u8]) -> Result<Self> {
        let v = json::decode(body, LIMIT)?;
        let schema = v["schema"].as_u64();
        let fields = match schema {
            Some(2) => {
                "schema role id group_nonce grant_sha256 recipient supervisor boot_id home home_mount source source_mount bytes sha256"
            }
            Some(3) => {
                "schema role id filename group_nonce grant_sha256 recipient supervisor boot_id home home_mount source source_mount bytes sha256"
            }
            _ => return Err(Error("delivery request schema differs".into())),
        };
        json::fields(&v, fields)?;
        json::fields(&v["recipient"], "uid gid")?;
        json::fields(&v["supervisor"], "pid start_ticks uid")?;
        require(
            matches!(schema, Some(2 | 3))
                && v["role"] == "exclusive-delivery-copy"
                && v["supervisor"]["uid"].as_u64() == Some(0),
            "delivery request schema or role differs",
        )?;
        let uid = number(&v["recipient"], "uid")?;
        let gid = number(&v["recipient"], "gid")?;
        let pid = number(&v["supervisor"], "pid")?;
        let start = number(&v["supervisor"], "start_ticks")?;
        require(
            (1000..i32::MAX as u64).contains(&uid)
                && (1..i32::MAX as u64).contains(&gid)
                && (2..i32::MAX as u64).contains(&pid)
                && start > 0,
            "delivery recipient or supervisor identity bound",
        )?;
        let home: (u64, u64, u32, u32, u32) = serde_json::from_value(v["home"].clone())?;
        let source: files::FileIdentity = serde_json::from_value(v["source"].clone())?;
        let bytes = number(&v, "bytes")?;
        let home_mount = number(&v, "home_mount")?;
        let source_mount = number(&v, "source_mount")?;
        require(
            home.0 > 0
                && home.1 > 0
                && home.2 == uid as u32
                && home.4 & libc::S_IFMT == libc::S_IFDIR
                && home.4 & 0o022 == 0
                && home_mount > 0
                && source_mount > 0
                && source.0 > 0
                && source.1 > 0
                && source.2 == bytes
                && bytes <= MAX_FILE
                && source.7 & libc::S_IFMT == libc::S_IFREG
                && source.7 & 0o7777 == 0o600
                && source.8 == 0
                && source.9 == 0
                && source.10 == 1
                && (0..1_000_000_000).contains(&source.4)
                && (0..1_000_000_000).contains(&source.6),
            "delivery original descriptor metadata differs",
        )?;
        let group_nonce = text(&v, "group_nonce")?;
        crate::delivery_worker_group::membership_value(group_nonce)?;
        let id = identity::safe_id(text(&v, "id")?)?;
        let filename = if schema == Some(2) {
            format!("enzimos-restored-{id}.bin")
        } else {
            text(&v, "filename")?.into()
        };
        require(
            crate::delivery_cancel::filename(&filename),
            "safe delivery request filename required",
        )?;
        Ok(Self {
            filename,
            group_nonce: group_nonce.into(),
            id: identity::safe_id(text(&v, "id")?)?.into(),
            grant_sha256: identity::sha(text(&v, "grant_sha256")?)?.into(),
            recipient_uid: uid as u32,
            recipient_gid: gid as u32,
            supervisor_pid: pid as u32,
            supervisor_start: start,
            boot_id: identity::uuid(text(&v, "boot_id")?)?.into(),
            home,
            home_mount,
            source,
            source_mount,
            bytes,
            sha256: identity::sha(text(&v, "sha256")?)?.into(),
        })
    }
}
