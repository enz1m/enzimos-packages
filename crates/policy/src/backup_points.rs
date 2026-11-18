// SPDX-License-Identifier: MIT
//! Bounded authenticated vendor metadata is display information, never restore authority.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
pub const LIMIT: usize = 512 * 1024;
const REQUIRED: &[&str] = &[
    "/backup-source/system",
    "/backup-source/home",
    "/backup-source/boot",
    "/backup-source/inventory",
];
pub fn scope(row: &Value, identifier: &str) -> Result<()> {
    crate::identity::sha(identifier)?;
    require(
        row["id"] == identifier
            && row["hostname"] == "enzimos"
            && row["tags"] == value!(["enzimos-whole-linux"]),
        "backup point identity or whole-system scope differs",
    )?;
    let paths = row["paths"]
        .as_array()
        .ok_or_else(|| Error("backup point source roots required".into()))?;
    require(
        (4..=12).contains(&paths.len()),
        "backup point source root count",
    )?;
    let mut seen = BTreeSet::new();
    for path in paths {
        let path = path
            .as_str()
            .ok_or_else(|| Error("backup point source root type".into()))?;
        let additional = path
            .strip_prefix("/backup-source/additional/")
            .is_some_and(|name| {
                (1..=32).contains(&name.len())
                    && name.as_bytes()[0].is_ascii_lowercase()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
        require(
            (REQUIRED.contains(&path) || additional) && seen.insert(path),
            "unqualified or repeated backup point source root",
        )?;
    }
    require(
        REQUIRED.iter().all(|path| seen.contains(path)),
        "backup point omits a required source root",
    )
}
pub fn rows(code: Option<i32>, bytes: &[u8]) -> Result<Value> {
    require(
        code == Some(0),
        "backup point observation failed; no replay",
    )?;
    let body = json::decode(bytes, LIMIT)?;
    let records = body
        .as_array()
        .ok_or_else(|| Error("backup point inventory required".into()))?;
    require(records.len() <= 10000, "backup point inventory count")?;
    let mut identifiers = BTreeSet::new();
    let mut result = Vec::new();
    for row in records {
        require(row.is_object(), "backup point record type")?;
        let identifier = row["id"]
            .as_str()
            .ok_or_else(|| Error("full backup point ID required".into()))?;
        crate::identity::sha(identifier)?;
        require(
            identifiers.insert(identifier),
            "duplicate backup point identity",
        )?;
        if row["hostname"] != "enzimos" || row["tags"] != value!(["enzimos-whole-linux"]) {
            continue;
        }
        scope(row, identifier)?;
        let size = match row.get("summary") {
            None => None,
            Some(summary) => {
                let summary = summary
                    .as_object()
                    .ok_or_else(|| Error("backup point summary type".into()))?;
                match summary.get("total_bytes_processed") {
                    None | Some(Value::Null) => None,
                    Some(size) => Some(
                        size.as_u64()
                            .ok_or_else(|| Error("backup point size bound".into()))?,
                    ),
                }
            }
        };
        let (date, time) = crate::snapshot_queries::utc(&row["time"])?;
        result.push((
            date,
            identifier.to_owned(),
            value!({"id":identifier,"time":time,"where":"local",
            "complete":true,"scope":"whole-system","size_bytes":size}),
        ));
    }
    result.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    result.truncate(100);
    Ok(Value::Array(
        result.into_iter().map(|(_, _, row)| row).collect(),
    ))
}
