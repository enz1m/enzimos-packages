// SPDX-License-Identifier: MIT
//! Native bounded Snapper metadata queries retain source/configuration and vendor identity.
use crate::{
    backup_source::Source, backup_source_layout::Dataset, settings_command::Command,
    storage_runtime::Guard,
};
use chrono::{DateTime, Datelike, NaiveDateTime, SecondsFormat, Timelike, Utc};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
const MAX_BYTES: usize = 512 * 1024;
fn number(v: &Value, empty: bool) -> Result<Option<u64>> {
    if empty && (v.is_null() || v == "") {
        return Ok(None);
    }
    let n = v.as_u64().or_else(|| {
        v.as_str()
            .filter(|s| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
    });
    require(n.is_some_and(|n| n < 1u64 << 63), "invalid snapshot number")?;
    Ok(n)
}
pub(crate) fn utc(v: &Value) -> Result<(DateTime<Utc>, String)> {
    let s = v
        .as_str()
        .filter(|s| s.len() <= 80)
        .ok_or_else(|| Error("invalid snapshot date".into()))?;
    let date = DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .or_else(|_| {
            ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
                .iter()
                .find_map(|format| NaiveDateTime::parse_from_str(s, format).ok())
                .map(|d| d.and_utc())
                .ok_or_else(|| Error("invalid snapshot date".into()))
        })
        .map_err(|_| Error("invalid snapshot date".into()))?;
    require(
        (1..=9999).contains(&date.year()),
        "snapshot date year bound",
    )?;
    let date = date
        .with_nanosecond((date.nanosecond() / 1000) * 1000)
        .ok_or_else(|| Error("snapshot date precision".into()))?;
    let text = date.to_rfc3339_opts(
        if date.nanosecond() == 0 {
            SecondsFormat::Secs
        } else {
            SecondsFormat::Micros
        },
        true,
    );
    Ok((date, text))
}
struct Row {
    date: DateTime<Utc>,
    original_date: String,
    number: u64,
    public: Value,
}
/// A backup's own source snapshot, still owned by its receipt: the backup
/// retires it, and it is no one's history or restore point. A snapshot whose
/// receipt is gone stays listed so it can be removed.
fn backup_source(kind: &str, cleanup: &str, description: &str, owned: bool) -> bool {
    owned
        && kind == "single"
        && cleanup.is_empty()
        && description == crate::backup_snapshot_creation::DESCRIPTION
}
fn parse(v: &Value, owned: &BTreeSet<u64>) -> Result<Vec<Row>> {
    let rows = v
        .as_array()
        .ok_or_else(|| Error("snapshot inventory list required".into()))?;
    require(rows.len() <= 10000, "snapshot inventory count bound")?;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for row in rows {
        require(row.is_object(), "snapshot record object required")?;
        let n = number(&row["number"], false)?
            .ok_or_else(|| enzimos_platform::Error("snapshot number required".into()))?;
        if n == 0 {
            continue;
        }
        require(seen.insert(n), "duplicate snapshot number")?;
        let kind = row["type"]
            .as_str()
            .ok_or_else(|| Error("snapshot kind required".into()))?;
        let cleanup = row
            .get("cleanup")
            .map_or(Some(""), Value::as_str)
            .ok_or_else(|| Error("snapshot cleanup type".into()))?;
        let description = row
            .get("description")
            .map_or(Some(""), Value::as_str)
            .ok_or_else(|| Error("snapshot description type".into()))?;
        require(
            matches!(kind, "single" | "pre" | "post")
                && matches!(cleanup, "" | "timeline" | "number" | "empty-pre-post")
                && description.len() <= 4096,
            "snapshot kind/cleanup/description bound",
        )?;
        if backup_source(kind, cleanup, description, owned.contains(&n)) {
            continue;
        }
        let (date, text) = utc(&row["date"])?;
        let pre = number(&row["pre-number"], true)?;
        result.push(Row { date,original_date:enzimos_platform::json::string(&row["date"])?.into(),number:n,public:value!({"number":n,"date":text,"kind":kind,"description":description,"cleanup":cleanup,"pre_number":pre}) });
    }
    Ok(result)
}
fn snapshot_rows(v: &Value, owned: &BTreeSet<u64>) -> Result<Value> {
    let mut rows = parse(v, owned)?;
    rows.sort_by(|a, b| b.date.cmp(&a.date).then(b.number.cmp(&a.number)));
    Ok(Value::Array(
        rows.into_iter().take(100).map(|r| r.public).collect(),
    ))
}
fn sample() -> Result<(Value, Value)> {
    let guard = Guard::observe()?;
    let command = Command::open("/usr/bin/snapper")?;
    let mut sources = Vec::new();
    for (name, path, archive) in [("root", "/", "system"), ("home", "/home", "home")] {
        sources.push(Source::open(
            Dataset {
                name: name.into(),
                path: path.into(),
                archive: archive.into(),
            },
            &guard,
        )?);
    }
    // Display only: an unreadable receipt registry lists every snapshot.
    let receipts = crate::backup_history::receipt_snapshots(&guard).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut snapshots = serde_json::Map::new();
    let mut history = serde_json::Map::new();
    for source in &sources {
        source.recheck()?;
        let name = &source.dataset().name;
        let body = command.run_timeout(
            &["--no-dbus", "--utc", "--jsonout", "-c", name, "list"],
            &[0],
            MAX_BYTES,
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(5)),
        )?;
        source.recheck()?;
        let v = json::decode(&body, MAX_BYTES)?;
        require(
            v.is_object() && v.get(name).is_some(),
            "missing snapshot configuration inventory",
        )?;
        let owned = receipts
            .iter()
            .filter(|(source, _)| source == name)
            .map(|(_, number)| *number)
            .collect();
        let rows = parse(&v[name], &owned)?;
        let latest = rows.iter().map(|r| r.original_date.as_str()).max();
        history.insert(
            name.clone(),
            value!({"snapshots":rows.len(),"latest":latest}),
        );
        snapshots.insert(name.clone(), snapshot_rows(&v[name], &owned)?);
    }
    for source in &sources {
        source.recheck()?;
    }
    command.recheck()?;
    guard.recheck()?;
    Ok((Value::Object(snapshots), Value::Object(history)))
}
pub fn snapshots() -> Result<Value> {
    Ok(sample()?.0)
}
pub fn history() -> Result<Value> {
    let timer = Command::open("/usr/bin/systemctl")?;
    let home_history = crate::home_history_control::parse(&timer.run_timeout(
        &["is-enabled", "enzimos-home-history.timer"],
        &[0, 1],
        4096,
        Duration::from_secs(5),
    )?)?;
    let retention = crate::home_retention::observation()?;
    let home_retention = retention["policy"].clone();
    let mut result = sample()?.1;
    result["home_history"] = home_history;
    result["home_retention"] = home_retention;
    require(
        crate::home_retention::observation()? == retention,
        "home retention changed during history query",
    )?;
    require(
        crate::home_history_control::parse(&timer.run_timeout(
            &["is-enabled", "enzimos-home-history.timer"],
            &[0, 1],
            4096,
            Duration::from_secs(5),
        )?)? == result["home_history"],
        "home timer changed during history query",
    )?;
    timer.recheck()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_receipt_owned_backup_snapshot_leaves_history() {
        let row = |number: u64, cleanup: &str, description: &str| {
            value!({"number":number,"type":"single","date":"2026-11-24 10:23:43","cleanup":cleanup,
                "description":description})
        };
        let rows = value!([
            row(65, "", crate::backup_snapshot_creation::DESCRIPTION),
            row(66, "", crate::backup_snapshot_creation::DESCRIPTION),
            row(67, "number", "enzimOS home history"),
            row(68, "", "taken by hand"),
            row(69, "number", crate::backup_snapshot_creation::DESCRIPTION),
        ]);
        let owned = BTreeSet::from([66, 68]);
        let numbers = snapshot_rows(&rows, &owned)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["number"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(numbers, [69, 68, 67, 65]);
        assert_eq!(parse(&rows, &owned).unwrap().len(), 4);
    }
}
