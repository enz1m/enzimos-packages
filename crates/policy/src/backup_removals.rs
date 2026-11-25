// SPDX-License-Identifier: MIT
//! Files people asked to remove from their backups ("Remove from backups" in
//! Files). Home history drops them at once; the backup drive is changed the
//! next time a backup runs with it attached, so an unplugged drive only delays
//! the removal. The queue (`/var/lib/enzimos-history/removals.json`) is shared
//! with the history service under its lock.
use crate::storage_runtime::Guard;
use enzimos_platform::{Result, backup_rules, files, require};
use serde_json::{Value, json as value};
use std::path::{Path, PathBuf};

fn queue_path() -> PathBuf {
    Path::new(backup_rules::STATE).join("removals.json")
}

fn lock() -> Result<files::Lock> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(lock) =
            files::Lock::try_acquire(&Path::new(backup_rules::STATE).join("lock"), 0)?
        {
            return Ok(lock);
        }
        require(std::time::Instant::now() < deadline, "history state busy")?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Queued removals as repository paths (`/backup-source/home/...`), with the
/// rows they came from.
#[must_use]
pub(crate) fn pending() -> Vec<(String, Value)> {
    let Ok(bytes) = std::fs::read(queue_path()) else {
        return Vec::new();
    };
    if bytes.len() > 4 * 1024 * 1024 {
        return Vec::new();
    }
    let Ok(Value::Array(rows)) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter_map(|row| {
            let path = row["path"].as_str()?;
            backup_rules::valid_excluded(path).ok()?;
            let full = backup_rules::restic_pattern(&format!("/backup-source/home/{path}"))?;
            Some((full, row))
        })
        .take(1000)
        .collect()
}

fn drop_applied(applied: &[Value]) -> Result<()> {
    let _lock = lock()?;
    let rows: Vec<Value> = std::fs::read(queue_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|row| !applied.contains(row))
        .collect();
    let temporary = queue_path().with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec(&rows)?)?;
    std::fs::rename(&temporary, queue_path())?;
    Ok(())
}

/// Apply the queue with the destination attached. Never fails the backup:
/// the outcome is returned for the status document.
#[must_use]
pub(crate) fn apply_locked(guard: &Guard, lock: &files::Lock) -> Value {
    let queued = pending();
    if queued.is_empty() {
        return value!({"applied":0,"pending":0});
    }
    let paths: Vec<String> = queued.iter().map(|(p, _)| p.clone()).collect();
    match crate::backup_restic_runtime::retention::rewrite_locked(guard, lock, &paths) {
        Ok(()) => {
            let rows: Vec<Value> = queued.into_iter().map(|(_, row)| row).collect();
            match drop_applied(&rows) {
                Ok(()) => value!({"applied":rows.len(),"pending":pending().len()}),
                Err(e) => value!({"applied":rows.len(),"pending":pending().len(),"reason":e.0}),
            }
        }
        Err(e) => {
            value!({"applied":0,"pending":paths.len(),"reason":e.0.chars().take(160).collect::<String>()})
        }
    }
}
