// SPDX-License-Identifier: MIT
//! Native bounded Snapper metadata queries retain source/configuration and vendor identity.
use crate::{
    backup_source::Source, backup_source_layout::Dataset, settings_command::Command,
    storage_runtime::Guard,
};
use chrono::{DateTime, Datelike, NaiveDateTime, SecondsFormat, Timelike, Utc};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::time::{Duration, Instant};
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
fn parse(v: &Value) -> Result<Vec<Row>> {
    let rows = v
        .as_array()
        .ok_or_else(|| Error("snapshot inventory list required".into()))?;
    require(rows.len() <= 10000, "snapshot inventory count bound")?;
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();
    for row in rows {
        require(row.is_object(), "snapshot record object required")?;
        let n = number(&row["number"], false)?.unwrap();
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
        let (date, text) = utc(&row["date"])?;
        let pre = number(&row["pre-number"], true)?;
        result.push(Row { date,original_date:row["date"].as_str().unwrap().into(),number:n,public:value!({"number":n,"date":text,"kind":kind,"description":description,"cleanup":cleanup,"pre_number":pre}) });
    }
    Ok(result)
}
pub fn snapshot_rows(v: &Value) -> Result<Value> {
    let mut rows = parse(v)?;
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
        let rows = parse(&v[name])?;
        let latest = rows.iter().map(|r| r.original_date.as_str()).max();
        history.insert(
            name.clone(),
            value!({"snapshots":rows.len(),"latest":latest}),
        );
        snapshots.insert(name.clone(), snapshot_rows(&v[name])?);
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
