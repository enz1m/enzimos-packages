// SPDX-License-Identifier: MIT
//! Previous versions of a person's own files from local home history.
//!
//! Home history is a Snapper configuration of `/home`; each snapshot holds every
//! home. A caller only ever sees entries inside their *current* home path that
//! they owned at snapshot time, reached without symlinks or `..`, and only from
//! snapshots enzimOS took for home history (never backup-source or update
//! snapshots). Mutations (pruning skipped folders, removing a file from
//! history) are root-side and serialized by one lock.
pub mod measure;
pub mod prune;
pub mod service;
pub mod store;

use enzimos_platform::{Error, Result, fsview, require};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The Snapper home configuration's subvolume.
pub const HOME_ROOT: &str = "/home";
/// Snapshots of the home subvolume.
pub const SNAPSHOTS: &str = "/home/.snapshots";
/// Description enzimOS gives home history snapshots (automatic and manual).
pub const DESCRIPTION: &str = "enzimOS home history";
/// Most snapshots considered.
const MAX_SNAPSHOTS: usize = 2000;

/// One home history snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Snapper number.
    pub number: u32,
    /// Creation time, seconds since the epoch (UTC).
    pub time: i64,
    /// Snapper cleanup algorithm (`timeline`, `number`, ...).
    pub cleanup: String,
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml.get(start..)?.find(&close)? + start;
    xml.get(start..end)
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse Snapper's `YYYY-MM-DD HH:MM:SS` (UTC).
#[must_use]
pub fn parse_date(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b' '
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let n = |r: std::ops::Range<usize>| text.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, s) = (
        n(0..4)?,
        n(5..7)?,
        n(8..10)?,
        n(11..13)?,
        n(14..16)?,
        n(17..19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// Parse one Snapper `info.xml`; `None` unless it is a home history snapshot.
#[must_use]
pub fn parse_info(xml: &str) -> Option<Snapshot> {
    if tag(xml, "description")? != DESCRIPTION {
        return None;
    }
    Some(Snapshot {
        number: tag(xml, "num")?.trim().parse().ok().filter(|n| *n > 0)?,
        time: parse_date(tag(xml, "date")?.trim())?,
        cleanup: tag(xml, "cleanup").unwrap_or_default().trim().to_owned(),
    })
}

/// Home history snapshots in `snapshots` (an open `.snapshots`), oldest first.
///
/// # Errors
/// Fails when the directory cannot be listed.
pub fn list(snapshots: &File) -> Result<Vec<Snapshot>> {
    let mut found = Vec::new();
    for entry in fsview::entries(snapshots, 100_000)? {
        let Some(number) = entry.name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if !entry.kind.is_dir() || number == 0 {
            continue;
        }
        let Ok(Some(dir)) = fsview::child_directory(snapshots, &entry.name) else {
            continue;
        };
        let Ok(bytes) = fsview::read_head(&dir, "info.xml", 64 * 1024) else {
            continue;
        };
        if let Some(snapshot) = parse_info(&String::from_utf8_lossy(&bytes))
            && snapshot.number == number
        {
            found.push(snapshot);
        }
    }
    found.sort_by_key(|s| s.number);
    let skip = found.len().saturating_sub(MAX_SNAPSHOTS);
    Ok(found.split_off(skip))
}

/// Open the subvolume of snapshot `number`.
///
/// # Errors
/// Fails when it is gone.
pub fn open_snapshot(snapshots: &File, number: u32) -> Result<File> {
    fsview::open_beneath(
        snapshots,
        Path::new(&format!("{number}/snapshot")),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
}

/// A caller and where their home lives below `/home`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    /// Account UID (≥ 1000).
    pub uid: u32,
    /// Home path relative to `/home`, e.g. `alice`.
    pub home: PathBuf,
}
impl Owner {
    /// Resolve an account's home from the account database.
    ///
    /// # Errors
    /// Refuses system accounts and homes outside `/home`.
    pub fn lookup(uid: u32) -> Result<Self> {
        require((1000..u32::MAX).contains(&uid), "not-authorized")?;
        let account = enzimos_platform::accounts::lookup_uid(uid)?;
        Self::from_home(uid, &account.home)
    }
    /// Build from a known home path.
    ///
    /// # Errors
    /// Refuses homes outside `/home` or with unusual components.
    pub fn from_home(uid: u32, home: &str) -> Result<Self> {
        let rel = Path::new(home)
            .strip_prefix(HOME_ROOT)
            .map_err(|_| Error("home-not-covered".into()))?
            .to_path_buf();
        fsview::relative(&rel).map_err(|_| Error("home-not-covered".into()))?;
        require(rel.as_os_str() != ".snapshots", "home-not-covered")?;
        Ok(Self { uid, home: rel })
    }
    /// Home-relative path of an absolute path the caller named; `None` is the
    /// home itself.
    ///
    /// # Errors
    /// Refuses paths outside the caller's home.
    pub fn relative(&self, path: &str) -> Result<Option<PathBuf>> {
        let home = Path::new(HOME_ROOT).join(&self.home);
        let path = Path::new(path);
        let rest = path
            .strip_prefix(&home)
            .map_err(|_| Error("path-not-allowed".into()))?;
        if rest.as_os_str().is_empty() {
            return Ok(None);
        }
        fsview::relative(rest).map_err(|_| Error("path-not-allowed".into()))?;
        Ok(Some(rest.to_path_buf()))
    }
    /// The caller's home inside an open snapshot, if it was theirs then.
    ///
    /// # Errors
    /// `not-found` when the home did not exist or belonged to someone else.
    pub fn home_in(&self, snapshot: &File) -> Result<File> {
        let home = fsview::open_beneath(snapshot, &self.home, libc::O_RDONLY | libc::O_DIRECTORY)?;
        require(home.metadata()?.uid() == self.uid, "not-found")?;
        Ok(home)
    }
}

/// A file's identity for telling versions apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stamp {
    /// Inode number (kept across Btrfs snapshots).
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time (s, ns).
    pub mtime: (i64, i64),
    /// Change time (s, ns); any content write changes it.
    pub ctime: (i64, i64),
    /// `f` file, `d` folder, `l` link, `o` other.
    pub kind: char,
}
impl Stamp {
    /// From metadata.
    #[must_use]
    pub fn of(m: &std::fs::Metadata) -> Self {
        let t = m.file_type();
        Self {
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
            kind: if t.is_file() {
                'f'
            } else if t.is_dir() {
                'd'
            } else if t.is_symlink() {
                'l'
            } else {
                'o'
            },
        }
    }
    fn same_content(&self, other: &Self) -> bool {
        self.kind == other.kind && self.size == other.size && self.mtime == other.mtime
    }
}

/// One distinct earlier version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// Snapshot holding it (the oldest snapshot with this content).
    pub number: u32,
    /// When that snapshot was taken.
    pub time: i64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time of this version.
    pub mtime: i64,
    /// Same content as the file now.
    pub current: bool,
}

/// Metadata of `rel` in the caller's home inside `snapshot`, if owned by them.
fn stat_in(owner: &Owner, snapshot: &File, rel: &Path) -> Option<std::fs::Metadata> {
    let home = owner.home_in(snapshot).ok()?;
    let file = fsview::open_beneath(&home, rel, libc::O_PATH).ok()?;
    let meta = file.metadata().ok()?;
    (meta.uid() == owner.uid).then_some(meta)
}

/// Distinct earlier versions of `rel`, newest first. `live` is the file's
/// current metadata, if it still exists.
///
/// # Errors
/// Fails when the snapshot list cannot be read.
pub fn versions(
    owner: &Owner,
    snapshots: &File,
    list: &[Snapshot],
    rel: &Path,
    live: Option<&std::fs::Metadata>,
) -> Result<Vec<Version>> {
    let live = live.map(Stamp::of);
    let mut result: Vec<(Stamp, Version)> = Vec::new();
    for snapshot in list {
        let Ok(root) = open_snapshot(snapshots, snapshot.number) else {
            continue;
        };
        let Some(meta) = stat_in(owner, &root, rel) else {
            continue;
        };
        let stamp = Stamp::of(&meta);
        if result.last().is_some_and(|(s, _)| s.same_content(&stamp)) {
            continue;
        }
        result.push((
            stamp,
            Version {
                number: snapshot.number,
                time: snapshot.time,
                size: stamp.size,
                mtime: stamp.mtime.0,
                current: live.is_some_and(|l| l.same_content(&stamp)),
            },
        ));
    }
    let mut versions: Vec<Version> = result.into_iter().map(|(_, v)| v).collect();
    versions.reverse();
    versions.truncate(1000);
    Ok(versions)
}

/// One entry of a folder as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Name.
    pub name: String,
    /// `f`, `d`, `l` or `o`.
    pub kind: char,
    /// Size in bytes.
    pub size: u64,
    /// Modification time.
    pub mtime: i64,
    /// Still exists now (same name in the live folder).
    pub exists: bool,
}

/// The caller's entries of folder `rel` (`None` = home) in a snapshot.
///
/// # Errors
/// `not-found` when the folder did not exist or was not theirs.
pub fn folder(
    owner: &Owner,
    snapshot: &File,
    rel: Option<&Path>,
    live: Option<&File>,
) -> Result<Vec<Item>> {
    let home = owner.home_in(snapshot)?;
    let directory = match rel {
        None => home,
        Some(rel) => fsview::open_beneath(&home, rel, libc::O_RDONLY | libc::O_DIRECTORY)?,
    };
    require(directory.metadata()?.uid() == owner.uid, "not-found")?;
    let mut items = Vec::new();
    for entry in fsview::entries(&directory, 20_000)? {
        if rel.is_none() && entry.name == ".snapshots" {
            continue;
        }
        let Ok(meta) = fsview::stat_at(&directory, &entry.name) else {
            continue;
        };
        if meta.uid() != owner.uid {
            continue;
        }
        let stamp = Stamp::of(&meta);
        items.push(Item {
            name: String::from_utf8_lossy(entry.name.as_bytes()).into_owned(),
            kind: stamp.kind,
            size: stamp.size,
            mtime: stamp.mtime.0,
            exists: live.is_some_and(|l| fsview::stat_at(l, &entry.name).is_ok()),
        });
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(items)
}

/// Open the caller's regular file `rel` from a snapshot, read-only.
///
/// # Errors
/// `not-found` unless it is a regular file the caller owned then.
pub fn open(owner: &Owner, snapshot: &File, rel: &Path) -> Result<File> {
    let home = owner.home_in(snapshot)?;
    let file = fsview::open_beneath(&home, rel, libc::O_RDONLY)?;
    let meta = file.metadata()?;
    require(meta.is_file() && meta.uid() == owner.uid, "not-found")?;
    Ok(file)
}

/// The caller's live folder `rel` (`None` = home), if it exists.
#[must_use]
pub fn live_folder(owner: &Owner, home_root: &File, rel: Option<&Path>) -> Option<File> {
    let path = match rel {
        None => owner.home.clone(),
        Some(rel) => owner.home.join(rel),
    };
    fsview::open_beneath(home_root, &path, libc::O_RDONLY | libc::O_DIRECTORY).ok()
}

/// Live metadata of `rel` in the caller's home.
#[must_use]
pub fn live_meta(owner: &Owner, home_root: &File, rel: &Path) -> Option<std::fs::Metadata> {
    let file = fsview::open_beneath(home_root, &owner.home.join(rel), libc::O_PATH).ok()?;
    file.metadata().ok()
}

/// Whether a name is a plain single path component.
#[must_use]
pub fn plain_name(name: &OsStr) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.as_bytes().contains(&b'/')
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
