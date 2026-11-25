// SPDX-License-Identifier: MIT
//! Publisher-origin ownership. An observed source is never an owned fallback.
use crate::identity::{safe_id, sha, uuid};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| Error("birth text field".into()))
}
pub(crate) fn object(v: &Value, path: &str, parent: Option<&str>) -> Result<()> {
    json::fields(v, "path id uuid parent_uuid")?;
    require(
        text(v, "path")? == path && v["id"].as_u64().is_some_and(|n| n >= 256),
        "birth path/ID mismatch",
    )?;
    uuid(text(v, "uuid")?)?;
    match parent {
        Some(p) => {
            uuid(text(v, "parent_uuid")?)?;
            require(v["parent_uuid"] == p, "birth parent lineage mismatch")
        }
        None => require(v["parent_uuid"].is_null(), "birth parent lineage mismatch"),
    }
}
pub(crate) fn validate(v: &Value, identifier: &str, fs_uuid: &str) -> Result<()> {
    json::fields(
        v,
        "schema transaction phase filesystem_uuid created_boot source target_name inventory_sha256 snapshot root history",
    )?;
    safe_id(identifier)?;
    uuid(fs_uuid)?;
    require(
        v["schema"].as_u64() == Some(1)
            && text(v, "transaction")? == identifier
            && text(v, "filesystem_uuid")? == fs_uuid,
        "birth schema/transaction/filesystem mismatch",
    )?;
    uuid(text(v, "created_boot")?)?;
    let source = &v["source"];
    json::fields(source, "path id uuid ownership")?;
    safe_id(text(source, "path")?)?;
    uuid(text(source, "uuid")?)?;
    require(
        source["id"].as_u64().is_some_and(|n| n >= 256) && source["ownership"] == "not-established",
        "source observation is not ownership",
    )?;
    let target = format!("enzimos-old-{identifier}");
    safe_id(&target)?;
    require(
        v["target_name"] == target && v["target_name"] != source["path"],
        "birth destination mismatch",
    )?;
    sha(text(v, "inventory_sha256")?)?;
    let phase = match text(v, "phase")? {
        "intent" => 0,
        "snapshot-recorded" => 1,
        "root-recorded" => 2,
        "ready" | "retired" => 3,
        _ => return Err(Error("invalid birth phase".into())),
    };
    if phase == 0 {
        return require(
            v["snapshot"].is_null() && v["root"].is_null() && v["history"].is_null(),
            "intent cannot claim created objects",
        );
    }
    let snapshot = &v["snapshot"];
    json::fields(snapshot, "number object")?;
    let number = snapshot["number"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
        .ok_or_else(|| Error("birth snapshot number".into()))?;
    object(
        &snapshot["object"],
        &format!("{}/.snapshots/{number}/snapshot", text(source, "path")?),
        Some(text(source, "uuid")?),
    )?;
    if phase == 1 {
        require(
            v["root"].is_null() && v["history"].is_null(),
            "snapshot phase cannot claim a root",
        )?;
    } else {
        object(
            &v["root"],
            &target,
            Some(text(&snapshot["object"], "uuid")?),
        )?;
        if phase == 2 {
            require(
                v["history"].is_null(),
                "unfinished root cannot claim history",
            )?;
        } else {
            object(&v["history"], &format!("{target}/.snapshots"), None)?;
        }
    }
    let mut ids = BTreeSet::new();
    let mut uuids = BTreeSet::new();
    for obj in [source, &snapshot["object"], &v["root"], &v["history"]] {
        if obj.is_null() {
            continue;
        }
        require(
            ids.insert(enzimos_platform::json::unsigned(&obj["id"])?)
                && uuids.insert(text(obj, "uuid")?),
            "birth identities are not independent",
        )?;
    }
    Ok(())
}
pub fn parse_show(body: &str, path: &str) -> Result<Value> {
    require(body.len() <= 256 * 1024, "Btrfs metadata bound")?;
    let mut fields = std::collections::BTreeMap::new();
    for line in body.lines() {
        if let Some((k, v)) = line.trim().split_once(':')
            && matches!(k, "UUID" | "Parent UUID" | "Subvolume ID")
        {
            require(
                fields.insert(k, v.trim()).is_none(),
                "ambiguous Btrfs birth metadata",
            )?;
        }
    }
    let get = |k| {
        fields
            .get(k)
            .copied()
            .ok_or_else(|| Error("missing Btrfs birth field".into()))
    };
    let parent = get("Parent UUID")?;
    let parent = if parent == "-" {
        Value::Null
    } else {
        serde_json::json!(uuid(parent)?)
    };
    let id = get("Subvolume ID")?
        .parse::<u64>()
        .map_err(|_| Error("invalid Btrfs ID".into()))?;
    require(id >= 256, "invalid Btrfs ID")?;
    Ok(serde_json::json!({"path":path,"id":id,"uuid":uuid(get("UUID")?)?,"parent_uuid":parent}))
}
/// A checkpoint cannot skip ahead, change its already recorded origin, or replay.
pub(crate) fn advance(previous: &Value, next: &Value) -> Result<()> {
    let identifier = text(previous, "transaction")?;
    let filesystem = text(previous, "filesystem_uuid")?;
    validate(previous, identifier, filesystem)?;
    validate(next, identifier, filesystem)?;
    let expected = match text(previous, "phase")? {
        "intent" => "snapshot-recorded",
        "snapshot-recorded" => "root-recorded",
        "root-recorded" => "ready",
        _ => {
            return Err(Error(
                "terminal birth record cannot be advanced or reused".into(),
            ));
        }
    };
    require(
        next["phase"] == expected,
        "birth checkpoint skipped or replayed",
    )?;
    for key in [
        "schema",
        "transaction",
        "filesystem_uuid",
        "created_boot",
        "source",
        "target_name",
        "inventory_sha256",
    ] {
        require(next[key] == previous[key], "birth origin changed")?;
    }
    for key in ["snapshot", "root", "history"] {
        if !previous[key].is_null() {
            require(next[key] == previous[key], "recorded birth object changed")?;
        }
    }
    Ok(())
}
