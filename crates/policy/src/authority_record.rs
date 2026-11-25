// SPDX-License-Identifier: MIT
//! Interrupted authority publication blocks admission; it never authorizes replay.
use crate::{authority, identity};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub(crate) const MAXIMUM: usize = 32;
pub(crate) fn hashes(value: &Value) -> Result<()> {
    let rows = value
        .as_object()
        .ok_or_else(|| Error("authority file hashes missing".into()))?;
    require(
        rows.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == authority::FILES.into_iter().collect(),
        "authority file set changed",
    )?;
    for hash in rows.values() {
        identity::sha(
            hash.as_str()
                .ok_or_else(|| Error("authority file hash type".into()))?,
        )?;
    }
    Ok(())
}
pub(crate) fn validate(record: &Value, id: &str) -> Result<()> {
    json::fields(
        record,
        "schema id phase boot filesystem_uuid authority before after approved local summary",
    )?;
    identity::safe_id(id)?;
    require(
        record["schema"] == 1
            && record["id"] == id
            && matches!(
                record["phase"].as_str(),
                Some("intent" | "publishing" | "complete" | "uncertain")
            ),
        "authority publication phase or identity refused",
    )?;
    identity::uuid(
        record["boot"]
            .as_str()
            .ok_or_else(|| Error("authority publication boot missing".into()))?,
    )?;
    identity::uuid(
        record["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| Error("authority publication filesystem missing".into()))?,
    )?;
    hashes(&record["before"])?;
    hashes(&record["after"])?;
    let mounted = &record["authority"];
    json::fields(mounted, "filesystem_uuid subvolume mount inode")?;
    let path = mounted["subvolume"]["path"]
        .as_str()
        .ok_or_else(|| Error("authority subvolume path missing".into()))?;
    identity::safe_id(path)?;
    crate::birth::object(
        &mounted["subvolume"],
        path,
        mounted["subvolume"]["parent_uuid"].as_str(),
    )?;
    let inode = mounted["inode"]
        .as_array()
        .ok_or_else(|| Error("authority inode missing".into()))?;
    require(
        inode.len() == 5
            && inode.iter().all(|n| n.as_u64().is_some())
            && inode[0].as_u64().unwrap() > 0
            && inode[1].as_u64().unwrap() > 0
            && inode[2] == 0
            && inode[3].as_u64().unwrap() <= u64::from(u32::MAX)
            && inode[4].as_u64().unwrap() <= u64::from(u32::MAX)
            && inode[4].as_u64().unwrap() & 0o177777 == 0o40700
            && mounted["mount"].as_u64().is_some_and(|n| n > 0),
        "authority mounted inode or mode refused",
    )?;
    json::fields(
        &record["summary"],
        "status approved_packagers added removed local_keys_kept",
    )?;
    require(
        record["summary"]["status"] == "authority-refresh-dry-run"
            && ["added", "removed"]
                .iter()
                .all(|k| record["summary"][*k].as_u64().is_some_and(|n| n <= 4096)),
        "authority review summary refused",
    )?;
    require(
        record["after"]["gpg.conf"] == json::sha256(authority::CONFIG.as_bytes()),
        "authority publication configuration changed",
    )?;
    let mut seen = BTreeSet::new();
    for key in ["approved", "local"] {
        let rows = record[key]
            .as_array()
            .ok_or_else(|| Error("authority selected keys missing".into()))?;
        require(
            rows.len() <= 4096 && (key != "approved" || rows.len() >= authority::MINIMUM_APPROVED),
            "authority key count refused",
        )?;
        let mut previous = None;
        for row in rows {
            let fp = authority::fingerprint(
                row.as_str()
                    .ok_or_else(|| Error("authority fingerprint type".into()))?,
            )?;
            require(
                previous.is_none_or(|p: &str| p < fp)
                    && seen.insert(fp)
                    && !authority::MASTERS.contains(&fp),
                "authority keys overlap, are unordered or include pinned master trust",
            )?;
            previous = Some(fp);
        }
    }
    require(
        record["summary"]["approved_packagers"] == record["approved"].as_array().unwrap().len()
            && record["summary"]["local_keys_kept"] == record["local"]
            && record["authority"]["filesystem_uuid"] == record["filesystem_uuid"],
        "authority summary or mounted identity changed",
    )
}
pub(crate) fn prefix(before: &Value, after: &Value, written: usize) -> Result<Value> {
    hashes(before)?;
    hashes(after)?;
    require(
        written <= authority::FILES.len(),
        "authority publication prefix bound",
    )?;
    let mut expected = before.clone();
    for name in authority::FILES.iter().take(written) {
        expected[*name] = after[*name].clone();
    }
    Ok(expected)
}
pub(crate) fn transition(prior: Option<&Value>, record: &Value, id: &str) -> Result<()> {
    validate(record, id)?;
    if let Some(prior) = prior {
        validate(prior, id)?;
        let mut normalized = record.clone();
        normalized["phase"] = prior["phase"].clone();
        require(
            normalized == *prior
                && matches!(
                    (prior["phase"].as_str(), record["phase"].as_str()),
                    (Some("intent"), Some("publishing"))
                        | (Some("publishing"), Some("complete" | "uncertain"))
                ),
            "authority publication cannot replay or change its intent",
        )
    } else {
        require(
            record["phase"] == "intent",
            "authority checkpoint must start with intent",
        )
    }
}
