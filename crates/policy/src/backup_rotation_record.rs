// SPDX-License-Identifier: MIT
//! Closed legacy rotation records. Data never supplies a filesystem actor.
use crate::{identity, recovery_records as records};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub const MAXIMUM: usize = 16;
// A4096-point copy map plus the original ID inventory exceeds the old32KiB read cap.
pub const LIMIT: usize = 1024 * 1024;
pub const MAX_POINTS: usize = 4096;
pub const BOUNDARIES: [[Option<&str>; 7]; 6] = [
    [
        Some("old"),
        Some("new"),
        None,
        Some("old"),
        Some("new"),
        None,
        Some("old"),
    ],
    [
        None,
        Some("new"),
        Some("old"),
        Some("old"),
        Some("new"),
        None,
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        Some("old"),
        Some("new"),
        None,
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        None,
        Some("new"),
        Some("old"),
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        Some("new"),
        None,
        Some("old"),
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        Some("new"),
        None,
        Some("old"),
        Some("new"),
    ],
];
pub fn boundary(state: &[Option<&str>; 7]) -> Result<usize> {
    BOUNDARIES
        .iter()
        .position(|row| row == state)
        .ok_or_else(|| Error("rotation is outside exact recorded boundaries".into()))
}
pub fn credential_identity(v: &Value) -> Result<()> {
    json::fields(
        v,
        "inode size mtime_ns root_id filesystem_uuid root_uuid root_path",
    )?;
    for key in ["inode", "size", "mtime_ns", "root_id"] {
        require(
            v[key].as_u64().is_some_and(|n| n > 0),
            "rotation credential integral identity",
        )?;
    }
    require(
        v["size"].as_u64().unwrap() <= 4096 && v["root_id"].as_u64().unwrap() >= 256,
        "rotation credential size/root bound",
    )?;
    identity::uuid(records::text(v, "filesystem_uuid")?)?;
    identity::uuid(records::text(v, "root_uuid")?)?;
    identity::safe_id(records::text(v, "root_path")?).map(|_| ())
}
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase created_boot repository_binding old_points input_identity password_identity repository_inode new_repository_sha256 new_repository_inode copies",
    )?;
    identity::safe_id(id)?;
    require(
        v["schema"].as_u64() == Some(1) && v["id"] == id,
        "rotation record schema/id",
    )?;
    let phase = records::text(v, "phase")?;
    require(
        matches!(
            phase,
            "prepared"
                | "copied"
                | "switching"
                | "switched"
                | "discarding"
                | "complete"
                | "abandoned"
        ),
        "rotation phase",
    )?;
    identity::uuid(records::text(v, "created_boot")?)?;
    json::fields(
        &v["repository_binding"],
        "filesystem_uuid repository_sha256",
    )?;
    identity::uuid(records::text(&v["repository_binding"], "filesystem_uuid")?)?;
    identity::sha(records::text(
        &v["repository_binding"],
        "repository_sha256",
    )?)?;
    credential_identity(&v["input_identity"])?;
    credential_identity(&v["password_identity"])?;
    require(
        v["input_identity"] != v["password_identity"],
        "rotation credentials alias",
    )?;
    require(
        v["repository_inode"].as_u64().is_some_and(|n| n > 0),
        "rotation original repository inode",
    )?;
    let points = v["old_points"]
        .as_array()
        .ok_or_else(|| Error("rotation points array".into()))?;
    require(
        (1..=MAX_POINTS).contains(&points.len()),
        "rotation point bound",
    )?;
    let mut previous: Option<&str> = None;
    for point in points {
        let point = point
            .as_str()
            .ok_or_else(|| Error("rotation point text".into()))?;
        identity::sha(point)?;
        require(
            previous.is_none_or(|p| p < point),
            "rotation points must be sorted distinct",
        )?;
        previous = Some(point);
    }
    let copied = phase != "prepared" && !(phase == "abandoned" && v["copies"].is_null());
    if copied {
        identity::sha(records::text(v, "new_repository_sha256")?)?;
        require(
            v["new_repository_sha256"] != v["repository_binding"]["repository_sha256"]
                && v["new_repository_inode"].as_u64().is_some_and(|n| n > 0)
                && v["new_repository_inode"] != v["repository_inode"],
            "rotation copied repository aliases old",
        )?;
        let copies = v["copies"]
            .as_object()
            .ok_or_else(|| Error("rotation copy map".into()))?;
        require(
            copies.len() == points.len(),
            "rotation copy mapping cardinality",
        )?;
        let mut targets = BTreeSet::new();
        for point in points {
            let target = copies
                .get(point.as_str().unwrap())
                .and_then(Value::as_str)
                .ok_or_else(|| Error("rotation copy mapping missing source".into()))?;
            identity::sha(target)?;
            require(targets.insert(target), "rotation copy target duplicated")?;
        }
    } else {
        require(
            v["copies"].is_null()
                && v["new_repository_sha256"].is_null()
                && v["new_repository_inode"].is_null(),
            "uncopied rotation claims new repository",
        )?;
    }
    Ok(())
}

/// Existing rotation inventories preserve full encrypted snapshot rows without
/// applying historical metadata or relaxing distinct full ID/tree requirements.
pub(crate) fn points(
    code: Option<i32>,
    bytes: &[u8],
) -> Result<std::collections::BTreeMap<String, Value>> {
    require(code == Some(0), "rotation inventory failed or uncertain")?;
    let rows = if bytes.is_empty() {
        Value::Array(vec![])
    } else {
        json::decode(bytes, 4 * 1024 * 1024)?
    };
    let rows = rows
        .as_array()
        .ok_or_else(|| Error("rotation snapshot array".into()))?;
    require(rows.len() <= MAX_POINTS, "rotation snapshot count bound")?;
    let mut result = std::collections::BTreeMap::new();
    for row in rows {
        let id = records::text(row, "id")?;
        identity::sha(id)?;
        identity::sha(records::text(row, "tree")?)?;
        require(
            result.insert(id.into(), row.clone()).is_none(),
            "duplicate rotation snapshot",
        )?;
    }
    Ok(result)
}
