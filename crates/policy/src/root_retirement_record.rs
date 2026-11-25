// SPDX-License-Identifier: MIT
//! Root-retirement records bind exact independent objects, never path ownership.
use crate::{identity, recovery_image, recovery_records as records};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub fn coordinator(v: &Value) -> Result<()> {
    let fields = "image uefi_entry uefi_previous bios_title bios_previous bios_own options";
    json::fields(
        v,
        &if v.get("uefi_mode").is_some() {
            format!("{fields} uefi_mode")
        } else {
            fields.into()
        },
    )?;
    require(
        v.get("uefi_mode")
            .is_none_or(|v| matches!(v.as_str(), Some("default" | "one-shot"))),
        "root coordinator UEFI mode",
    )?;
    recovery_image::identifier(records::text(v, "image")?)?;
    let entry = records::text(v, "uefi_entry")?;
    let short = entry
        .strip_prefix("enzimos-root-retire-")
        .and_then(|s| s.strip_suffix(".conf"))
        .ok_or_else(|| Error("root coordinator entry name".into()))?;
    require(
        short.len() == 16
            && short
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "root coordinator entry digest",
    )?;
    records::literal_entry(records::text(v, "uefi_previous")?)?;
    require(
        v["uefi_previous"] != entry
            && v["bios_title"] == format!("enzimOS root retirement {short}"),
        "root coordinator previous default or title",
    )?;
    for key in ["bios_previous", "bios_own"] {
        require(
            v[key].as_u64().is_some_and(|n| (1..=256).contains(&n)),
            "root coordinator BIOS default",
        )?;
    }
    require(
        v["bios_previous"] != v["bios_own"],
        "coordinator cannot adopt existing BIOS default",
    )?;
    records::command_line(records::text(v, "options")?)
}
pub fn validate(v: &Value, id: &str) -> Result<()> {
    let base =
        "schema id phase filesystem_uuid created_boot birth targets next_step inflight plan_sha256";
    let coordinated = v.get("coordinator").is_some();
    json::fields(
        v,
        &if coordinated {
            format!("{base} coordinator")
        } else {
            base.into()
        },
    )?;
    identity::safe_id(id)?;
    require(
        v["schema"].as_u64() == Some(if coordinated { 2 } else { 1 })
            && v["id"] == id
            && matches!(
                v["phase"].as_str(),
                Some("prepared" | "executing" | "deleted" | "complete" | "abandoned")
            ),
        "root retirement identity or state",
    )?;
    if coordinated {
        coordinator(&v["coordinator"])?;
    }
    for key in ["filesystem_uuid", "created_boot"] {
        identity::uuid(records::text(v, key)?)?;
    }
    let birth = identity::safe_id(records::text(v, "birth")?)?;
    identity::sha(records::text(v, "plan_sha256")?)?;
    let targets = v["targets"]
        .as_array()
        .ok_or_else(|| Error("root retirement targets array".into()))?;
    require(
        (1..=64).contains(&targets.len()),
        "root retirement target count",
    )?;
    let superseded = birth.starts_with("superseded-");
    let mut paths = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut uuids = BTreeSet::new();
    for row in targets {
        json::fields(row, "role path id uuid parent_uuid")?;
        let role = records::text(row, "role")?;
        require(
            if superseded {
                matches!(role, "nested-subvolume" | "root-subvolume")
            } else {
                matches!(role, "history-store" | "root-subvolume")
            },
            "root retirement target role",
        )?;
        let path = records::text(row, "path")?;
        identity::safe_id(&path.replace('/', "-"))?;
        require(
            !path.starts_with('/')
                && path
                    .split('/')
                    .all(|p| !p.is_empty() && !matches!(p, "." | "..")),
            "root retirement target path",
        )?;
        let object_id = row["id"]
            .as_u64()
            .filter(|n| *n >= 256)
            .ok_or_else(|| Error("root retirement subvolume ID".into()))?;
        let uuid = identity::uuid(records::text(row, "uuid")?)?;
        if !row["parent_uuid"].is_null() {
            identity::uuid(records::text(row, "parent_uuid")?)?;
        }
        require(
            paths.insert(path) && ids.insert(object_id) && uuids.insert(uuid),
            "root retirement targets must be distinct",
        )?;
    }
    require(
        targets
            .last()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["role"]
            == "root-subvolume"
            && targets
                .iter()
                .filter(|v| v["role"] == "root-subvolume")
                .count()
                == 1,
        "root must be the only last target",
    )?;
    if superseded {
        let root = records::text(
            targets
                .last()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
            "path",
        )?;
        let actual = targets[..targets.len() - 1]
            .iter()
            .map(|v| records::text(v, "path"))
            .collect::<Result<Vec<_>>>()?;
        require(
            actual.iter().all(|p| p.starts_with(&format!("{root}/"))),
            "superseded targets must be descendants",
        )?;
        let mut ordered = actual.clone();
        ordered.sort_by(|a, b| {
            b.matches('/')
                .count()
                .cmp(&a.matches('/').count())
                .then_with(|| a.cmp(b))
        });
        require(
            actual == ordered,
            "superseded targets must be deepest first",
        )?;
    }
    let count = targets.len() as u64;
    let next = v["next_step"]
        .as_u64()
        .ok_or_else(|| Error("root retirement progress integer".into()))?;
    require(
        next <= count
            && (v["inflight"].is_null() || v["inflight"].as_u64() == Some(next) && next < count),
        "root retirement progress or in-flight step",
    )?;
    require(
        v["phase"] != "prepared" || next == 0 && v["inflight"].is_null(),
        "prepared root retirement advanced",
    )?;
    require(
        !matches!(v["phase"].as_str(), Some("deleted" | "complete"))
            || next == count && v["inflight"].is_null(),
        "root retirement completion without every step",
    )?;
    let seal = json::fingerprint(
        &serde_json::json!({"filesystem_uuid":v["filesystem_uuid"],"birth":v["birth"],"targets":v["targets"]}),
    )?;
    require(
        v["plan_sha256"] == seal,
        "root retirement target plan digest mismatch",
    )
}
