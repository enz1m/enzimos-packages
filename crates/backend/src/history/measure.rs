// SPDX-License-Identifier: MIT
//! Background measurement for Settings: how much space home history and system
//! snapshots really take, and where the space in each home goes.
//!
//! "History space" is the data snapshots keep alive that the live tree no
//! longer uses. Unchanged files share inode, size and change time with the
//! live file and are skipped; only changed files have their physical extents
//! read, and extents the live file still uses are not counted. Compressed data
//! is counted at its uncompressed size, so figures are approximate.
use super::{Snapshot, store::Store};
use enzimos_platform::{Result, backup_rules, fsview};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

const EXTENT_LIMIT: usize = 6_000_000;

type Key = (u64, i64, i64, u64);
fn key(m: &std::fs::Metadata) -> Key {
    (m.ino(), m.ctime(), m.ctime_nsec(), m.size())
}

/// Shared walk state.
struct Walk {
    deadline: Instant,
    complete: bool,
}
impl Walk {
    /// Visit every entry below `root` on the same device. The callback gets the
    /// directory, entry metadata, the path relative to `root` and its depth.
    fn walk(
        &mut self,
        root: &File,
        visit: &mut dyn FnMut(&File, &std::ffi::OsStr, &std::fs::Metadata, &str, usize) -> bool,
    ) {
        let Ok(device) = root.metadata().map(|m| m.dev()) else {
            return;
        };
        let Ok(root) = root.try_clone() else { return };
        let mut stack = vec![(root, String::new(), 0usize)];
        while let Some((directory, rel, depth)) = stack.pop() {
            if Instant::now() > self.deadline {
                self.complete = false;
                return;
            }
            let Ok(listing) = fsview::entries(&directory, 1 << 20) else {
                continue;
            };
            for entry in listing {
                let Ok(meta) = fsview::stat_at(&directory, &entry.name) else {
                    continue;
                };
                let name = entry.name.to_string_lossy();
                let child_rel = if rel.is_empty() {
                    name.into_owned()
                } else {
                    format!("{rel}/{name}")
                };
                let descend = visit(&directory, &entry.name, &meta, &child_rel, depth);
                if descend
                    && meta.is_dir()
                    && meta.dev() == device
                    && depth < 128
                    && let Ok(Some(child)) = fsview::child_directory(&directory, &entry.name)
                {
                    stack.push((child, child_rel, depth + 1));
                }
            }
        }
    }
}

/// Bytes snapshots keep alive beyond the live tree.
///
/// `live` is the live subvolume; `snapshots` the open snapshot roots.
fn kept_alive(walk: &mut Walk, live: &File, snapshots: &[File]) -> Option<u64> {
    let mut live_keys: HashSet<Key> = HashSet::new();
    walk.walk(live, &mut |_, _, m, _, _| {
        if m.is_file() {
            live_keys.insert(key(m));
        }
        true
    });
    let mut seen: HashSet<Key> = HashSet::new();
    let mut extents: HashSet<(u64, u64)> = HashSet::new();
    let mut inline = 0u64;
    let mut changed_inodes: HashSet<u64> = HashSet::new();
    let mut overflow = false;
    for root in snapshots {
        walk.walk(root, &mut |dir, name, m, _, _| {
            if m.is_file() && m.blocks() > 0 {
                let k = key(m);
                if !live_keys.contains(&k) && seen.insert(k) {
                    changed_inodes.insert(m.ino());
                    if let Ok(file) =
                        fsview::open_beneath(dir, std::path::Path::new(name), libc::O_RDONLY)
                        && let Ok(list) = fsview::extents(&file, 1 << 20)
                    {
                        for (physical, length) in list {
                            if physical == 0 {
                                inline += length;
                            } else if extents.len() < EXTENT_LIMIT {
                                extents.insert((physical, length));
                            } else {
                                overflow = true;
                            }
                        }
                    }
                }
            }
            !overflow
        });
    }
    if overflow {
        return None;
    }
    // Data a changed file still shares with its live version is not history.
    walk.walk(live, &mut |dir, name, m, _, _| {
        if m.is_file()
            && changed_inodes.contains(&m.ino())
            && let Ok(file) = fsview::open_beneath(dir, std::path::Path::new(name), libc::O_RDONLY)
            && let Ok(list) = fsview::extents(&file, 1 << 20)
        {
            for extent in list {
                extents.remove(&extent);
            }
        }
        true
    });
    Some(extents.iter().map(|(_, l)| l).sum::<u64>() + inline)
}

/// Where the space in one home goes.
fn home_breakdown(walk: &mut Walk, home: &File, rules: &backup_rules::Rules) -> Value {
    let found: HashMap<String, backup_rules::Reason> =
        backup_rules::scan(home, rules, backup_rules::Bounds::default())
            .map(|s| s.found.into_iter().map(|f| (f.path, f.reason)).collect())
            .unwrap_or_default();
    let mut total = 0u64;
    let mut folders: BTreeMap<String, u64> = BTreeMap::new();
    let mut skipped: BTreeMap<String, (backup_rules::Reason, u64)> = BTreeMap::new();
    walk.walk(home, &mut |_, _, m, rel, _| {
        let bytes = m.blocks() * 512;
        total += bytes;
        let parts: Vec<&str> = rel.splitn(3, '/').collect();
        if !parts.is_empty() {
            *folders.entry(parts[0].to_owned()).or_default() += bytes;
        }
        if parts.len() >= 2 {
            *folders
                .entry(format!("{}/{}", parts[0], parts[1]))
                .or_default() += bytes;
        }
        // The skipped folder this entry is (or is inside), by ancestor prefix.
        let ancestor = std::iter::once(rel.len())
            .chain(rel.match_indices('/').map(|(i, _)| i))
            .filter_map(|end| rel.get(..end))
            .find(|prefix| found.contains_key(*prefix));
        if let Some(prefix) = ancestor {
            let reason = found[prefix];
            skipped.entry(prefix.to_owned()).or_insert((reason, 0)).1 += bytes;
        }
        true
    });
    let mut by_reason: BTreeMap<&str, u64> = BTreeMap::new();
    for (reason, bytes) in skipped.values() {
        *by_reason.entry(reason.key()).or_default() += bytes;
    }
    let mut top: Vec<(String, u64)> = folders.into_iter().collect();
    top.sort_by_key(|row| std::cmp::Reverse(row.1));
    top.truncate(200);
    let mut skipped_rows: Vec<(String, backup_rules::Reason, u64)> =
        skipped.into_iter().map(|(p, (r, b))| (p, r, b)).collect();
    skipped_rows.sort_by_key(|row| std::cmp::Reverse(row.2));
    skipped_rows.truncate(100);
    json!({
        "total": total,
        "folders": top.iter().map(|(p, b)| json!({"path": p, "bytes": b})).collect::<Vec<_>>(),
        "skipped": by_reason,
        "skipped_folders": skipped_rows.iter().map(|(p, r, b)| json!({"path": p, "reason": r.key(), "bytes": b})).collect::<Vec<_>>(),
    })
}

/// Open snapshot roots of a Snapper configuration (`.snapshots` under `base`).
fn snapshot_roots(base: &File, numbers: Option<&[u32]>) -> Vec<File> {
    let Ok(Some(dir)) = fsview::child_directory(base, std::ffi::OsStr::new(".snapshots")) else {
        return Vec::new();
    };
    let mut numbers: Vec<u32> = match numbers {
        Some(n) => n.to_vec(),
        None => fsview::entries(&dir, 100_000)
            .map(|l| {
                l.into_iter()
                    .filter_map(|e| e.name.to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default(),
    };
    numbers.sort_unstable();
    numbers
        .iter()
        .filter_map(|n| super::open_snapshot(&dir, *n).ok())
        .collect()
}

/// Measure everything and return the cached document.
///
/// # Errors
/// Fails when `/home` cannot be opened.
pub fn measure(store: &Store, history: &[Snapshot], budget: std::time::Duration) -> Result<Value> {
    let started = super::store::now();
    let mut walk = Walk {
        deadline: Instant::now() + budget,
        complete: true,
    };
    let home_root = fsview::open_directory(std::path::Path::new(super::HOME_ROOT))?;
    let numbers: Vec<u32> = history.iter().map(|s| s.number).collect();
    let home_snapshots = snapshot_roots(&home_root, Some(&numbers));
    let history_bytes = kept_alive(&mut walk, &home_root, &home_snapshots);
    let (system_bytes, system_count) = match fsview::open_directory(std::path::Path::new("/")) {
        Ok(root) => {
            let roots = snapshot_roots(&root, None);
            (kept_alive(&mut walk, &root, &roots), roots.len())
        }
        Err(_) => (None, 0),
    };
    let mut users = Map::new();
    if let Ok(listing) = fsview::entries(&home_root, 10_000) {
        for entry in listing
            .into_iter()
            .filter(|e| e.kind.is_dir() && e.name != ".snapshots")
        {
            let Ok(Some(home)) = fsview::child_directory(&home_root, &entry.name) else {
                continue;
            };
            let Ok(uid) = home.metadata().map(|m| m.uid()) else {
                continue;
            };
            let Ok(owner) = super::Owner::lookup(uid) else {
                continue;
            };
            if owner.home.as_os_str() != entry.name.as_os_str() {
                continue;
            }
            users.insert(
                uid.to_string(),
                home_breakdown(&mut walk, &home, &store.rules(uid)),
            );
        }
    }
    let usage = json!({
        "schema": 1,
        "time": started,
        "complete": walk.complete,
        "home": {
            "history_bytes": history_bytes,
            "snapshots": history.len(),
            "oldest": history.first().map(|s| s.time),
            "newest": history.last().map(|s| s.time),
        },
        "system": {"snapshot_bytes": system_bytes, "snapshots": system_count},
        "users": users,
    });
    store.set_usage(&usage)?;
    Ok(usage)
}

/// The cached document as one caller may see it: totals, and only their own
/// home's breakdown.
#[must_use]
pub fn for_caller(usage: Option<Value>, uid: u32) -> Value {
    let Some(mut usage) = usage else {
        return json!({"schema": 1, "time": null});
    };
    let mine = usage["users"][uid.to_string()].take();
    if let Some(object) = usage.as_object_mut() {
        object.remove("users");
        object.insert("mine".into(), mine);
    }
    usage
}
