// SPDX-License-Identifier: MIT
//! Closed remote copy metadata checks. Data alone never proves worker closure.
use crate::{backup_points, identity};
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::collections::BTreeMap;
pub(crate) const LIMIT: usize = 4 * 1024 * 1024;
pub(crate) fn inventory(v: &Value) -> Result<BTreeMap<&str, &Value>> {
    let rows = v
        .as_array()
        .ok_or_else(|| Error("remote snapshot inventory required".into()))?;
    require(rows.len() <= 10000, "remote snapshot inventory bound")?;
    let mut result = BTreeMap::new();
    for row in rows {
        require(row.is_object(), "snapshot inventory row required")?;
        let id = row["id"].as_str().unwrap_or("");
        identity::sha(id)?;
        require(
            result.insert(id, row).is_none(),
            "duplicate snapshot inventory ID",
        )?;
        if let Some(original) = row.get("original") {
            identity::sha(original.as_str().unwrap_or(""))?;
        }
    }
    Ok(result)
}
pub(crate) fn selected<'a>(v: &'a Value, id: &str) -> Result<&'a Value> {
    identity::sha(id)?;
    let rows = inventory(v)?;
    require(
        rows.len() == 1 && rows.contains_key(id),
        "exact selected snapshot required",
    )?;
    let row = rows[id];
    backup_points::scope(row, id)?;
    identity::sha(row["tree"].as_str().unwrap_or(""))?;
    crate::snapshot_queries::utc(&row["time"])?;
    Ok(row)
}
fn lineage(row: &Value) -> &str {
    row.get("original")
        .unwrap_or_else(|| &row["id"])
        .as_str()
        .unwrap_or("")
}
fn equivalent(source: &Value, copied: &Value) -> Result<()> {
    let id = copied["id"].as_str().unwrap_or("");
    backup_points::scope(copied, id)?;
    identity::sha(copied["tree"].as_str().unwrap_or(""))?;
    require(
        lineage(copied) == lineage(source),
        "copied snapshot lineage differs",
    )?;
    let content = |row: &Value| {
        let mut record = row.as_object().unwrap().clone();
        for key in ["id", "short_id", "parent", "original"] {
            record.remove(key);
        }
        record
    };
    require(
        content(source) == content(copied),
        "copied snapshot content or metadata differs",
    )?;
    Ok(())
}
/// Existing copied points are accepted only for replication's idempotent vendor
/// copy query. Publication still needs the actual original closed worker actor.
pub(crate) fn replicated(source: &Value, id: &str, destination: &Value) -> Result<String> {
    let source = selected(source, id)?;
    let rows = inventory(destination)?;
    let matches = rows
        .values()
        .filter(|row| lineage(row) == lineage(source))
        .collect::<Vec<_>>();
    require(matches.len() == 1, "remote copy lineage is not unique")?;
    equivalent(source, matches[0])?;
    Ok(matches[0]["id"].as_str().unwrap().into())
}
/// All original rotation points map bijectively to an exact new inventory.
/// Index lineage once so the closed10,000-point bound remains linear-logarithmic.
pub(crate) fn rotation_copies(
    old: &Value,
    new: &Value,
    copies: &serde_json::Map<String, Value>,
) -> Result<()> {
    let old = inventory(old)?;
    let new = inventory(new)?;
    require(
        !copies.is_empty() && old.len() == copies.len() && new.len() == copies.len(),
        "remote rotation copy inventory cardinality",
    )?;
    let mut lineages = BTreeMap::new();
    for row in new.values() {
        require(
            lineages.insert(lineage(row), *row).is_none(),
            "ambiguous new remote rotation lineage",
        )?;
    }
    let mut targets = std::collections::BTreeSet::new();
    for (id, target) in copies {
        identity::sha(id)?;
        let target = target.as_str().unwrap_or("");
        identity::sha(target)?;
        let source = old
            .get(id.as_str())
            .ok_or_else(|| Error("rotation map has foreign original snapshot".into()))?;
        backup_points::scope(source, id)?;
        identity::sha(source["tree"].as_str().unwrap_or(""))?;
        crate::snapshot_queries::utc(&source["time"])?;
        let copied = lineages
            .get(lineage(source))
            .ok_or_else(|| Error("rotation copied lineage missing".into()))?;
        require(
            copied["id"] == target && targets.insert(target),
            "rotation target differs or aliases mapping",
        )?;
        equivalent(source, copied)?;
    }
    Ok(())
}
pub(crate) fn retrieval_admission(source: &Value, id: &str, before: &Value) -> Result<()> {
    let source = selected(source, id)?;
    let rows = inventory(before)?;
    require(
        rows.values().all(|row| {
            row["id"] != id
                && row["id"] != lineage(source)
                && row.get("original").and_then(Value::as_str) != Some(lineage(source))
        }),
        "point already present; retrieval cannot adopt or replay",
    )
}
pub(crate) fn retrieved(source: &Value, id: &str, before: &Value, after: &Value) -> Result<String> {
    retrieval_admission(source, id, before)?;
    let source = selected(source, id)?;
    let old = inventory(before)?;
    let new = inventory(after)?;
    require(
        old.iter()
            .all(|(id, row)| new.get(id).is_some_and(|current| current == row)),
        "retrieval removed or changed an original snapshot",
    )?;
    let additions = new
        .iter()
        .filter(|(id, _)| !old.contains_key(*id))
        .collect::<Vec<_>>();
    require(
        additions.len() == 1,
        "retrieval must create exactly one snapshot",
    )?;
    equivalent(source, additions[0].1)?;
    Ok(additions[0].0.to_string())
}
