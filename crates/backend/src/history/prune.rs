// SPDX-License-Identifier: MIT
//! Changes to home history snapshots: dropping skipped folders from new
//! snapshots, removing files a person asked to forget, and making room when the
//! disk runs low. Snapshots are made writable only for the change and are always
//! made read-only again.
use super::{Owner, Snapshot, open_snapshot, store::Store};
use enzimos_platform::{Error, Result, backup_rules, fsview, require};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Keeps a snapshot writable for the lifetime of the guard.
struct Writable<'a>(&'a File);
impl<'a> Writable<'a> {
    fn open(subvolume: &'a File) -> Result<Self> {
        fsview::set_subvolume_readonly(subvolume, false)?;
        Ok(Self(subvolume))
    }
}
impl Drop for Writable<'_> {
    fn drop(&mut self) {
        if fsview::set_subvolume_readonly(self.0, true).is_err() {
            eprintln!("enzimos-history: could not make a snapshot read-only again");
        }
    }
}

/// What a change did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Entries removed.
    pub removed: u64,
    /// Entries kept because someone else owned them.
    pub kept: u64,
    /// Snapshots changed.
    pub snapshots: u32,
}
impl std::ops::AddAssign for Outcome {
    fn add_assign(&mut self, o: Self) {
        self.removed += o.removed;
        self.kept += o.kept;
        self.snapshots += o.snapshots;
    }
}

/// Remove home-relative `rel` (inside `home`, a home folder in a writable
/// snapshot), keeping entries not owned by `uid`.
fn remove(home: &File, rel: &Path, uid: u32) -> Result<(u64, u64)> {
    let name = rel.file_name().ok_or_else(|| Error("path".into()))?;
    let parent = match rel.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => fsview::open_beneath(home, parent, libc::O_RDONLY | libc::O_DIRECTORY)?,
        None => home.try_clone()?,
    };
    fsview::remove_tree(&parent, name, uid, 0)
}

/// Accounts with a home folder directly under the snapshot root.
fn owners_in(root: &File) -> Vec<(Owner, File)> {
    let Ok(listing) = fsview::entries(root, 10_000) else {
        return Vec::new();
    };
    listing
        .into_iter()
        .filter(|e| e.kind.is_dir() && e.name != ".snapshots")
        .filter_map(|e| {
            let dir = fsview::child_directory(root, &e.name).ok()??;
            let uid = dir.metadata().ok()?.uid();
            let owner = Owner::lookup(uid).ok()?;
            (owner.home.as_os_str() == e.name.as_os_str()).then_some((owner, dir))
        })
        .collect()
}

/// Drop skipped folders (per each account's rules) from one snapshot.
///
/// # Errors
/// Fails when the snapshot cannot be made writable.
pub fn prune_snapshot(store: &Store, root: &File, homes: Vec<(Owner, File)>) -> Result<Outcome> {
    let mut plan = Vec::new();
    for (owner, home) in homes {
        let rules = store.rules(owner.uid);
        let scan = backup_rules::scan(&home, &rules, backup_rules::Bounds::default())?;
        if !scan.found.is_empty() {
            plan.push((owner, home, scan.found));
        }
    }
    let mut outcome = Outcome::default();
    if plan.is_empty() {
        return Ok(outcome);
    }
    let _writable = Writable::open(root)?;
    for (owner, home, found) in plan {
        for item in found {
            if let Ok((removed, kept)) = remove(&home, Path::new(&item.path), owner.uid) {
                outcome.removed += removed;
                outcome.kept += kept;
            }
        }
    }
    outcome.snapshots = 1;
    Ok(outcome)
}

/// Prune every home history snapshot not pruned yet.
///
/// # Errors
/// Fails when the snapshot list or state cannot be read or written.
pub fn prune_pending(store: &Store, snapshots: &File, list: &[Snapshot]) -> Result<Outcome> {
    let done = store.pruned();
    let mut pruned: Vec<u32> = list
        .iter()
        .map(|s| s.number)
        .filter(|n| done.contains(n))
        .collect();
    let mut outcome = Outcome::default();
    for snapshot in list.iter().filter(|s| !done.contains(&s.number)) {
        let Ok(root) = open_snapshot(snapshots, snapshot.number) else {
            continue;
        };
        match prune_snapshot(store, &root, owners_in(&root)) {
            Ok(o) => {
                outcome += o;
                pruned.push(snapshot.number);
            }
            Err(e) => eprintln!(
                "enzimos-history: snapshot {} not pruned: {}",
                snapshot.number, e.0
            ),
        }
    }
    pruned.sort_unstable();
    store.set_pruned(&pruned)?;
    Ok(outcome)
}

/// Remove the caller's `paths` (home-relative) from every home history snapshot.
///
/// # Errors
/// Fails when a snapshot that holds one of them cannot be changed.
pub fn forget(
    owner: &Owner,
    snapshots: &File,
    list: &[Snapshot],
    paths: &[&Path],
) -> Result<Outcome> {
    let mut outcome = Outcome::default();
    for snapshot in list {
        let Ok(root) = open_snapshot(snapshots, snapshot.number) else {
            continue;
        };
        let Ok(home) = owner.home_in(&root) else {
            continue;
        };
        let present: Vec<&Path> = paths
            .iter()
            .copied()
            .filter(|p| {
                fsview::open_beneath(&home, p, libc::O_PATH)
                    .and_then(|f| Ok(f.metadata()?))
                    .is_ok_and(|m| m.uid() == owner.uid)
            })
            .collect();
        if present.is_empty() {
            continue;
        }
        let _writable = Writable::open(&root)?;
        for path in present {
            let (removed, kept) = remove(&home, path, owner.uid)?;
            outcome.removed += removed;
            outcome.kept += kept;
        }
        outcome.snapshots += 1;
    }
    Ok(outcome)
}

/// Free fraction of the filesystem holding `path`, in percent.
///
/// # Errors
/// Fails when statvfs fails.
#[allow(unsafe_code, reason = "Linux syscall ABI (statvfs).")]
pub fn free_percent(path: &Path) -> Result<(f64, u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Error("path".into()))?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is NUL-terminated and `s` is writable statvfs storage.
    let rc = unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) };
    require(rc == 0, "statvfs failed")?;
    // SAFETY: statvfs succeeded and initialized `s`.
    let s = unsafe { s.assume_init() };
    let size = s.f_blocks.saturating_mul(s.f_frsize);
    let free = s.f_bavail.saturating_mul(s.f_frsize);
    require(size > 0, "empty filesystem")?;
    Ok((free as f64 * 100.0 / size as f64, free, size))
}

/// Delete one home history snapshot through Snapper, waiting for the space.
///
/// # Errors
/// Fails when Snapper refuses.
pub fn delete_snapshot(number: u32) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/snapper")
        .args([
            "--no-dbus",
            "-c",
            "home",
            "delete",
            "--sync",
            &number.to_string(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()?;
    require(status.success(), "snapshot delete failed")
}

/// Keep at least the configured free space: delete the oldest home history
/// snapshots (never the newest) until there is room. Returns whether there is
/// room for a new snapshot.
///
/// # Errors
/// Fails when free space cannot be read.
pub fn guard(
    store: &Store,
    list: &[Snapshot],
    mut delete: impl FnMut(u32) -> Result<()>,
    mut free: impl FnMut() -> Result<f64>,
) -> Result<bool> {
    let floor = f64::from(store.free_percent());
    for (deleted, snapshot) in list.iter().take(list.len().saturating_sub(1)).enumerate() {
        if free()? >= floor || deleted >= 24 {
            break;
        }
        delete(snapshot.number)?;
        eprintln!(
            "enzimos-history: removed snapshot {} to keep {floor}% free",
            snapshot.number
        );
    }
    Ok(free()? >= floor)
}

#[cfg(test)]
pub(crate) fn tests_remove(home: &File, rel: &Path, uid: u32) -> Result<(u64, u64)> {
    remove(home, rel, uid)
}
