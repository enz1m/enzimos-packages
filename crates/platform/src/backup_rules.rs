// SPDX-License-Identifier: MIT
//! What backups and home history skip: build output, caches, game downloads,
//! the Trash, and folders a person excluded.
//!
//! Build folders are recognised only next to the file that makes them
//! rebuildable (Asimov-style sentinels), so a folder that merely happens to be
//! called `build` or `target` is kept. The same rules drive the external
//! backup (an exclusion list recorded with each backup) and home history
//! (removed from each new snapshot).
use crate::{Result, fsview, require};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

/// Why a folder is skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// Rebuildable project output (`target`, `node_modules`, virtualenvs, ...).
    Build,
    /// Caches, including folders tagged with CACHEDIR.TAG.
    Cache,
    /// Installed game files that the store downloads again.
    Games,
    /// The Trash.
    Trash,
    /// A folder the person excluded.
    Excluded,
}
impl Reason {
    /// Stable key used in files and on the wire.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Cache => "cache",
            Self::Games => "games",
            Self::Trash => "trash",
            Self::Excluded => "excluded",
        }
    }
}

/// Folders rebuilt from a file next to them.
const SENTINELS: &[(&str, &[&str])] = &[
    ("node_modules", &["package.json"]),
    ("bower_components", &["bower.json"]),
    ("target", &["Cargo.toml", "pom.xml"]),
    (
        ".gradle",
        &[
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        ],
    ),
    (
        "build",
        &[
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        ],
    ),
    (".next", &["package.json"]),
    (".nuxt", &["package.json"]),
    (".output", &["nuxt.config.ts", "nuxt.config.js"]),
    (".svelte-kit", &["package.json"]),
    (".parcel-cache", &["package.json"]),
    (".turbo", &["package.json"]),
    (".angular", &["angular.json"]),
    ("vendor", &["go.mod", "composer.json"]),
    ("Pods", &["Podfile"]),
    (".dart_tool", &["pubspec.yaml"]),
    (".stack-work", &["stack.yaml"]),
    ("dist-newstyle", &["cabal.project"]),
    ("_build", &["mix.exs", "dune-project"]),
    ("deps", &["mix.exs"]),
    ("zig-cache", &["build.zig"]),
    (".zig-cache", &["build.zig"]),
    ("zig-out", &["build.zig"]),
    (".terraform", &[".terraform.lock.hcl"]),
    (
        ".venv",
        &["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"],
    ),
];
/// Folders that are caches wherever they are.
const ALWAYS: &[&str] = &[
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".hypothesis",
    ".ipynb_checkpoints",
    ".sass-cache",
];
/// Home-relative folders skipped as a whole.
const HOME: &[(&str, Reason)] = &[
    (".cache", Reason::Cache),
    (".local/share/Trash", Reason::Trash),
    (".local/share/baloo", Reason::Cache),
    (".local/share/flatpak/repo/tmp", Reason::Cache),
];
/// Steam library folders that hold downloadable game data (never compatdata,
/// which holds Proton saves and settings).
const STEAM: &[&str] = &["common", "downloading", "shadercache", "temp"];
const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Rules for one home.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    /// Apply the automatic rules (build output, caches, games, Trash).
    pub automatic: bool,
    /// Home-relative folders the person excluded.
    pub excluded: Vec<String>,
}

/// Classify the directory `name` found in `parent` at home-relative `rel`.
#[must_use]
pub fn classify(
    rules: &Rules,
    parent: &File,
    name: &OsStr,
    rel: &str,
    directory: Option<&File>,
) -> Option<Reason> {
    if rules.excluded.iter().any(|e| e == rel) {
        return Some(Reason::Excluded);
    }
    if !rules.automatic {
        return None;
    }
    if let Some((_, reason)) = HOME.iter().find(|(path, _)| *path == rel) {
        return Some(*reason);
    }
    // Flatpak app caches: .var/app/<id>/cache
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.len() == 4 && parts[0] == ".var" && parts[1] == "app" && parts[3] == "cache" {
        return Some(Reason::Cache);
    }
    let text = name.to_str().unwrap_or_default();
    if parts.len() >= 2
        && parts[parts.len() - 2] == "steamapps"
        && STEAM.contains(&text)
        && fsview::has_file(parent, "libraryfolders.vdf")
    {
        return Some(Reason::Games);
    }
    if ALWAYS.contains(&text) {
        return Some(Reason::Cache);
    }
    if let Some((_, files)) = SENTINELS.iter().find(|(dir, _)| *dir == text)
        && files.iter().any(|f| fsview::has_file(parent, f))
    {
        return Some(Reason::Build);
    }
    if text.starts_with("cmake-build-") && fsview::has_file(parent, "CMakeLists.txt") {
        return Some(Reason::Build);
    }
    let directory = directory?;
    if fsview::has_file(directory, "pyvenv.cfg") {
        return Some(Reason::Build);
    }
    if fsview::read_head(directory, "CACHEDIR.TAG", CACHEDIR_SIGNATURE.len())
        .is_ok_and(|head| head == CACHEDIR_SIGNATURE)
    {
        return Some(Reason::Cache);
    }
    None
}

/// A skipped folder, home-relative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// Home-relative path.
    pub path: String,
    /// Why it is skipped.
    pub reason: Reason,
}

/// Bounds for a scan; the walk stops (and reports `truncated`) past them.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Directories visited at most.
    pub directories: usize,
    /// Folders reported at most.
    pub found: usize,
    /// Depth below the home.
    pub depth: usize,
}
impl Default for Bounds {
    fn default() -> Self {
        Self {
            directories: 2_000_000,
            found: 20_000,
            depth: 64,
        }
    }
}

/// Result of a scan.
#[derive(Debug, Default)]
pub struct Scan {
    /// Folders to skip, in walk order.
    pub found: Vec<Found>,
    /// True when a bound stopped the walk early.
    pub truncated: bool,
}

/// Walk the directories of a home (open at `home`), never descending into a
/// skipped folder, a symlink or another mount.
///
/// # Errors
/// Fails when the home itself cannot be read.
pub fn scan(home: &File, rules: &Rules, bounds: Bounds) -> Result<Scan> {
    let device = home.metadata()?.dev();
    let mut scan = Scan::default();
    let mut visited = 0usize;
    let mut stack: Vec<(File, String, usize)> = vec![(home.try_clone()?, String::new(), 0)];
    while let Some((directory, rel, depth)) = stack.pop() {
        let Ok(listing) = fsview::entries(&directory, 1 << 20) else {
            continue;
        };
        for entry in listing {
            if !entry.kind.is_dir() {
                continue;
            }
            visited += 1;
            if visited > bounds.directories || scan.found.len() >= bounds.found {
                scan.truncated = true;
                return Ok(scan);
            }
            let child_rel = if rel.is_empty() {
                String::from_utf8_lossy(entry.name.as_bytes()).into_owned()
            } else {
                format!("{rel}/{}", String::from_utf8_lossy(entry.name.as_bytes()))
            };
            if rel.is_empty() && entry.name == ".snapshots" {
                continue;
            }
            let child = fsview::child_directory(&directory, &entry.name)
                .ok()
                .flatten();
            if let Some(reason) =
                classify(rules, &directory, &entry.name, &child_rel, child.as_ref())
            {
                scan.found.push(Found {
                    path: child_rel,
                    reason,
                });
                continue;
            }
            let Some(child) = child else { continue };
            if child.metadata().map(|m| m.dev()).ok() != Some(device) {
                continue;
            }
            if depth + 1 >= bounds.depth {
                scan.truncated = true;
                continue;
            }
            stack.push((child, child_rel, depth + 1));
        }
    }
    Ok(scan)
}

/// Where people's rules are kept (root only).
pub const STATE: &str = "/var/lib/enzimos-history";

/// One account's rules from `<root>/users/<uid>.json`; automatic rules are on
/// unless turned off, and invalid entries are ignored.
#[must_use]
pub fn read_rules(root: &std::path::Path, uid: u32) -> Rules {
    let value: serde_json::Value = std::fs::read(root.join("users").join(format!("{uid}.json")))
        .ok()
        .filter(|b| b.len() <= 1024 * 1024)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    Rules {
        automatic: value["automatic"].as_bool().unwrap_or(true),
        excluded: value["excluded"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter(|p| valid_excluded(p).is_ok())
                    .take(256)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// A restic exclude pattern for an absolute path, or `None` when the name
/// cannot be written literally (it is then simply backed up).
#[must_use]
pub fn restic_pattern(path: &str) -> Option<String> {
    let plain = path.split('/').all(|part| {
        part.trim() == part
            && !part.starts_with('#')
            && !part.starts_with('!')
            && !part
                .chars()
                .any(|c| c.is_control() || "*?[]\\$".contains(c))
    });
    plain.then(|| path.to_owned())
}

/// The `skipped.txt` exclude file for one backup: for each home folder
/// (`name`, its directory in the read-only source snapshot, its rules), the
/// skipped folders under `prefix/name`, grouped by reason as comments.
#[must_use]
pub fn exclude_file(prefix: &str, homes: &[(String, File, Rules)]) -> Vec<u8> {
    let mut groups: std::collections::BTreeMap<&'static str, Vec<String>> =
        std::collections::BTreeMap::new();
    for (name, home, rules) in homes {
        let Ok(scan) = scan(home, rules, Bounds::default()) else {
            continue;
        };
        for found in scan.found {
            if let Some(pattern) = restic_pattern(&format!("{prefix}/{name}/{}", found.path)) {
                groups.entry(found.reason.key()).or_default().push(pattern);
            }
        }
    }
    let mut out = String::from("# enzimOS: folders skipped by rule; restic --exclude-file\n");
    for (reason, patterns) in groups {
        out.push_str(&format!("# {reason}\n"));
        for pattern in patterns {
            out.push_str(&pattern);
            out.push('\n');
        }
    }
    out.into_bytes()
}

/// Validate a home-relative path a person asked to exclude.
///
/// # Errors
/// Refuses empty, absolute, noncanonical, overlong or control-character paths.
pub fn valid_excluded(path: &str) -> Result<()> {
    fsview::relative(std::path::Path::new(path))?;
    require(
        path.len() <= 1024 && !path.chars().any(char::is_control) && path != ".snapshots",
        "invalid excluded path",
    )
}
