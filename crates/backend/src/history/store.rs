// SPDX-License-Identifier: MIT
//! Root-owned history state in `/var/lib/enzimos-history` (mode 0700).
//!
//! People change their own rules only through the service, so nothing here is
//! read from their home. Every file is small, bounded and replaced atomically.
use enzimos_platform::{
    Error, Result,
    backup_rules::{self, Rules},
    files, require,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// State directory.
pub(crate) const STATE: &str = backup_rules::STATE;
const MAX_EXCLUDED: usize = 256;
const MAX_REMOVALS: usize = 1000;
/// Default free space kept on the home filesystem, in percent.
pub(crate) const DEFAULT_FREE_PERCENT: u32 = 15;

/// Where state lives (overridable in tests).
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}
impl Default for Store {
    fn default() -> Self {
        Self {
            root: PathBuf::from(STATE),
        }
    }
}

fn read_json(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 4 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().ok_or_else(|| Error("state path".into()))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.{}", files::random_hex(8)?, "tmp"));
    std::fs::write(&temporary, serde_json::to_vec(value)?)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

/// A queued removal from the external backup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Removal {
    /// Account that asked.
    pub uid: u32,
    /// Path relative to `/home` (e.g. `alice/Documents/a.txt`).
    pub path: String,
    /// When it was asked, seconds since the epoch.
    pub requested: i64,
}

impl Store {
    /// A store rooted elsewhere (tests).
    #[must_use]
    pub fn at(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
    /// The state directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    fn user_path(&self, uid: u32) -> PathBuf {
        self.root.join("users").join(format!("{uid}.json"))
    }
    /// Rules for one account; automatic rules are on by default.
    #[must_use]
    pub fn rules(&self, uid: u32) -> Rules {
        backup_rules::read_rules(&self.root, uid)
    }
    /// Save one account's rules.
    ///
    /// # Errors
    /// Refuses invalid or too many exclusions.
    pub(crate) fn set_rules(&self, uid: u32, rules: &Rules) -> Result<()> {
        require(rules.excluded.len() <= MAX_EXCLUDED, "too-many-exclusions")?;
        for path in &rules.excluded {
            backup_rules::valid_excluded(path)?;
        }
        write_json(
            &self.user_path(uid),
            &json!({"automatic": rules.automatic, "excluded": rules.excluded}),
        )
    }
    /// Every account with saved rules.
    #[must_use]
    pub fn users(&self) -> Vec<u32> {
        let Ok(dir) = std::fs::read_dir(self.root.join("users")) else {
            return Vec::new();
        };
        let mut uids: Vec<u32> = dir
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".json")?.parse().ok())
            .collect();
        uids.sort_unstable();
        uids
    }
    /// Free space kept on the home filesystem, percent (5–50).
    #[must_use]
    pub fn free_percent(&self) -> u32 {
        read_json(&self.root.join("settings.json"))
            .and_then(|v| v["free_percent"].as_u64())
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| (5..=50).contains(n))
            .unwrap_or(DEFAULT_FREE_PERCENT)
    }
    /// Change the free space floor.
    ///
    /// # Errors
    /// Refuses values outside 5–50.
    pub(crate) fn set_free_percent(&self, percent: u32) -> Result<()> {
        require((5..=50).contains(&percent), "invalid-free-percent")?;
        write_json(
            &self.root.join("settings.json"),
            &json!({"free_percent": percent}),
        )
    }
    /// Removals from the external backup still to be done.
    #[must_use]
    pub(crate) fn removals(&self) -> Vec<Removal> {
        read_json(&self.root.join("removals.json"))
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|r| {
                Some(Removal {
                    uid: u32::try_from(r["uid"].as_u64()?).ok()?,
                    path: r["path"]
                        .as_str()
                        .filter(|p| backup_rules::valid_excluded(p).is_ok())?
                        .to_owned(),
                    requested: r["requested"].as_i64()?,
                })
            })
            .collect()
    }
    /// Replace the removal queue.
    ///
    /// # Errors
    /// Refuses more than the bound.
    pub(crate) fn set_removals(&self, removals: &[Removal]) -> Result<()> {
        require(removals.len() <= MAX_REMOVALS, "too-many-removals")?;
        let rows: Vec<Value> = removals
            .iter()
            .map(|r| json!({"uid": r.uid, "path": r.path, "requested": r.requested}))
            .collect();
        write_json(&self.root.join("removals.json"), &Value::Array(rows))
    }
    /// Snapshot numbers already pruned of skipped folders.
    #[must_use]
    pub fn pruned(&self) -> Vec<u32> {
        read_json(&self.root.join("pruned.json"))
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|n| u32::try_from(n.as_u64()?).ok())
            .collect()
    }
    /// Remember pruned snapshot numbers (only ones that still exist).
    ///
    /// # Errors
    /// Fails on write errors.
    pub(crate) fn set_pruned(&self, numbers: &[u32]) -> Result<()> {
        write_json(&self.root.join("pruned.json"), &json!(numbers))
    }
    /// Cached measurement.
    #[must_use]
    pub fn usage(&self) -> Option<Value> {
        read_json(&self.root.join("usage.json"))
    }
    /// Save a measurement.
    ///
    /// # Errors
    /// Fails on write errors.
    pub(crate) fn set_usage(&self, usage: &Value) -> Result<()> {
        write_json(&self.root.join("usage.json"), usage)
    }
    /// Take the history lock (blocking up to `wait`).
    ///
    /// # Errors
    /// `busy` when another history change holds it.
    pub fn lock(&self, wait: std::time::Duration) -> Result<files::Lock> {
        std::fs::create_dir_all(&self.root)?;
        let deadline = std::time::Instant::now() + wait;
        loop {
            if let Some(lock) = files::Lock::try_acquire(&self.root.join("lock"), 0)? {
                return Ok(lock);
            }
            require(std::time::Instant::now() < deadline, "busy")?;
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
}

/// Seconds since the epoch.
#[must_use]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
