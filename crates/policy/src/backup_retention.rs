// SPDX-License-Identifier: MIT
//! Backup retention policy: which old backups automatic cleanup removes.
//!
//! The policy lives in `/etc/enzimos/backup-retention.json` (shipped with a
//! default, changed from Settings). It is deliberately outside the backup
//! configuration, so tuning it never invalidates the reviewed automatic-backup
//! opt-in. Tiers follow restic's `forget --keep-*` semantics: newest first, a
//! snapshot is kept by a tier when it is the newest one of a calendar bucket
//! (day, ISO week, month, year, in UTC) among that tier's most recent N buckets;
//! `last` keeps the N newest outright. A snapshot kept by any tier stays.
use crate::{operation, settings_file::Config};
use chrono::{DateTime, Datelike, Utc};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;

pub const PATH: &str = "/etc/enzimos/backup-retention.json";
const LIMIT: usize = 4096;
pub(crate) const TIERS: [&str; 5] = ["last", "daily", "weekly", "monthly", "yearly"];

/// Two weeks of dailies, two months of weeklies, a year of monthlies, two
/// yearlies, and never fewer than the three newest backups.
pub(crate) fn default_policy() -> Value {
    value!({"schema":1,"automatic":true,"last":3,"daily":14,"weekly":8,"monthly":12,"yearly":2})
}

fn counts(v: &Value) -> Result<()> {
    require(
        v["automatic"].is_boolean()
            && TIERS
                .iter()
                .all(|tier| v[*tier].is_u64() && v[*tier].as_u64().is_some_and(|n| n <= 1000))
            && v["last"].as_u64().is_some_and(|n| n >= 1),
        "backup retention bounds: every tier 0-1000, at least the newest backup kept",
    )
}

/// Smallest and largest space limit for the backup drive.
pub(crate) const BUDGET_MIN: u64 = 1 << 30;
const BUDGET_MAX: u64 = 1 << 60;

fn budget_valid(v: &Value) -> Result<&'static str> {
    match v.get("budget_bytes") {
        None => Ok(""),
        Some(Value::Null) => Ok(" budget_bytes"),
        Some(b) => {
            require(
                b.as_u64()
                    .is_some_and(|n| (BUDGET_MIN..=BUDGET_MAX).contains(&n)),
                "backup space limit: at least 1 GiB",
            )?;
            Ok(" budget_bytes")
        }
    }
}

/// The stored document. `budget_bytes` (optional, null = no limit) caps the
/// space the backups may use on the drive; the oldest go first.
pub(crate) fn validate_policy(v: &Value) -> Result<()> {
    let budget = budget_valid(v)?;
    json::fields(
        v,
        &format!("schema automatic last daily weekly monthly yearly{budget}"),
    )?;
    require(v["schema"] == 1, "backup retention schema")?;
    counts(v)
}

/// A Settings selection: the same fields without the schema.
pub fn validate(selection: &Value) -> Result<()> {
    let budget = budget_valid(selection)?;
    json::fields(
        selection,
        &format!("automatic last daily weekly monthly yearly{budget}"),
    )?;
    counts(selection)
}

/// The space limit, if one is set.
#[must_use]
pub fn budget(policy: &Value) -> Option<u64> {
    policy["budget_bytes"].as_u64()
}

/// The current policy; the shipped file is required, a missing one is the default.
pub fn policy() -> Result<Value> {
    if std::fs::symlink_metadata(PATH).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(default_policy());
    }
    let config = Config::open(PATH, LIMIT)?;
    let value = json::decode(&config.body, LIMIT)?;
    validate_policy(&value)?;
    Ok(value)
}

/// Snapshot IDs a policy removes from `points` (time, id), any order.
pub fn select(points: &[(DateTime<Utc>, String)], policy: &Value) -> Vec<String> {
    let mut ordered = points.to_vec();
    // Newest first; equal times break ties by ID so the result is deterministic.
    ordered.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let mut keep = BTreeSet::new();
    for tier in TIERS {
        let mut remaining = policy[tier].as_u64().unwrap_or(0);
        let mut previous: Option<(i32, u32, u32)> = None;
        for (time, id) in &ordered {
            if remaining == 0 {
                break;
            }
            let bucket = match tier {
                "last" => None,
                "daily" => Some((time.year(), time.month(), time.day())),
                "weekly" => Some((time.iso_week().year(), time.iso_week().week(), 0)),
                "monthly" => Some((time.year(), time.month(), 0)),
                _ => Some((time.year(), 0, 0)),
            };
            if bucket.is_none() || bucket != previous {
                keep.insert(id.clone());
                previous = bucket;
                remaining -= 1;
            }
        }
    }
    let mut remove = ordered
        .into_iter()
        .filter(|(_, id)| !keep.contains(id))
        .map(|(_, id)| id)
        .collect::<Vec<_>>();
    remove.sort();
    remove
}

/// Last cleanup outcome per repository ("local", "remote"), for Settings.
const STATUS: &str = "backup-retention-status.json";
const STATUS_LIMIT: usize = 8192;

pub fn status() -> Result<Value> {
    let path = std::path::Path::new(operation::CONTROL).join(STATUS);
    Ok(
        match enzimos_platform::files::read_optional(&path, STATUS_LIMIT, Some(0), true)? {
            Some(bytes) => json::decode(&bytes, STATUS_LIMIT)?,
            None => value!({}),
        },
    )
}

pub fn publish_status(kind: &str, outcome: &Value) -> Result<()> {
    require(
        matches!(kind, "local" | "remote"),
        "backup retention status kind",
    )?;
    let mut all = status().unwrap_or_else(|_| value!({}));
    if !all.is_object() {
        all = value!({});
    }
    let mut row = outcome.clone();
    row["at_unix"] = value!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    );
    all[kind] = row;
    let path = std::path::Path::new(operation::CONTROL).join(STATUS);
    enzimos_platform::files::atomic_bounded(
        &path,
        &json::canonical(&all)?,
        0o600,
        Some(0),
        true,
        STATUS_LIMIT,
    )
}

pub fn observation() -> Result<Value> {
    crate::namespaces::initial()?;
    let policy = policy()?;
    Ok(value!({"policy":policy}))
}

/// Publish a new policy. Existing backups change only at the next cleanup.
pub fn set<F: FnMut() -> Result<()>>(
    selection: &Value,
    expected: &Value,
    mut authorize: F,
) -> Result<Value> {
    crate::namespaces::initial()?;
    operation::root_only()?;
    validate(selection)?;
    let lock = operation::lock()?;
    if std::fs::symlink_metadata(PATH).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        // A removed file reads as the default; recreate it so it can be changed.
        enzimos_platform::files::atomic(
            std::path::Path::new(PATH),
            &json::canonical(&default_policy())?,
            0o644,
            Some(0),
            false,
        )?;
    }
    let mut config = Config::open(PATH, LIMIT)?;
    let before = json::decode(&config.body, LIMIT)?;
    validate_policy(&before)?;
    require(
        value!({"policy":before}) == *expected,
        "backup retention plan changed",
    )?;
    let mut next = selection.clone();
    next["schema"] = value!(1);
    validate_policy(&next)?;
    authorize()?;
    lock.recheck()?;
    config.recheck()?;
    config.publish(&json::canonical(&next)?)?;
    config.recheck()?;
    lock.recheck()?;
    let mut result = selection.clone();
    result["existing_backups_removed"] = value!(false);
    Ok(result)
}
