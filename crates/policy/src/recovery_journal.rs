// SPDX-License-Identifier: MIT
//! Fixed control-storage journals reject orphan writes and changed mount identities.
use crate::{
    catalog, operation, recovery_activation, recovery_image, recovery_publication,
    recovery_records,
    storage_runtime::{Guard, IndependentGuard},
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
pub type Records = BTreeMap<String, Value>;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Jobs,
    Runs,
    Activations,
    Workflows,
    Images,
    Publications,
    Media,
}
impl Kind {
    pub(crate) fn folder(self) -> &'static str {
        match self {
            Self::Jobs => "recovery-jobs",
            Self::Runs => "recovery-runs",
            Self::Activations => "recovery-activations",
            Self::Workflows => "recovery-workflows",
            Self::Images => "recovery-images",
            Self::Publications => "recovery-publications",
            Self::Media => "media-restores",
        }
    }
    pub fn validate(self, value: &Value, id: &str) -> Result<()> {
        match self {
            Self::Jobs => recovery_records::job(value, id),
            Self::Runs => recovery_records::run(value, id),
            Self::Activations => recovery_activation::validate(value, id),
            Self::Workflows => recovery_records::workflow(value, id),
            Self::Images => recovery_image::validate(value, id),
            Self::Publications => recovery_publication::validate(value, id),
            Self::Media => crate::media_receipt::validate(value, id),
        }
    }
    pub(crate) fn limit(self) -> usize {
        match self {
            Self::Runs => 65536,
            Self::Workflows | Self::Media => 8192,
            _ => catalog::MAX_CATALOG,
        }
    }
    pub(crate) fn maximum(self) -> usize {
        if matches!(self, Self::Images | Self::Publications) {
            recovery_image::MAX_IMAGES
        } else {
            recovery_records::MAX_JOBS
        }
    }
    pub(crate) fn identifier(self, id: &str) -> Result<()> {
        if matches!(self, Self::Images | Self::Publications) {
            recovery_image::identifier(id)?;
        } else {
            recovery_records::job_id(id)?;
        }
        Ok(())
    }
}
fn unchanged(previous: &Value, next: &Value, keys: &[&str]) -> Result<()> {
    for key in keys {
        require(
            previous[*key] == next[*key],
            "recovery transaction origin changed",
        )?;
    }
    Ok(())
}
pub fn transition(kind: Kind, previous: Option<&Value>, next: &Value, id: &str) -> Result<()> {
    kind.validate(next, id)?;
    let Some(previous) = previous else {
        return require(
            match kind {
                Kind::Jobs => next["phase"] == "planned",
                Kind::Runs => next["phase"] == "staged",
                Kind::Activations => next["phase"] == "prepared",
                Kind::Workflows => next["state"] == "prepared",
                Kind::Images => next["phase"] == "intent",
                Kind::Publications => true,
                Kind::Media => next["phase"] == "running",
            },
            "recovery record cannot adopt an already advanced transaction",
        );
    };
    kind.validate(previous, id)?;
    match kind {
        Kind::Media => {
            unchanged(
                previous,
                next,
                &["schema", "id", "plan_sha256", "media_origin"],
            )?;
            require(
                matches!(
                    (previous["phase"].as_str(), next["phase"].as_str()),
                    (Some("running"), Some("executed" | "failed"))
                        | (Some("executed"), Some("complete"))
                ),
                "media restore checkpoint skipped or replayed",
            )?;
        }
        Kind::Publications => {
            return Err(Error(
                "publication intent cannot be overwritten or reused".into(),
            ));
        }
        Kind::Images => {
            unchanged(
                previous,
                next,
                &[
                    "schema",
                    "id",
                    "created_boot",
                    "filesystem_uuid",
                    "control",
                    "boot_uuid",
                    "inputs",
                    "options",
                ],
            )?;
            let valid = matches!(
                (previous["phase"].as_str(), next["phase"].as_str()),
                (Some("intent"), Some("artifacts")) | (Some("artifacts" | "ready"), Some("ready"))
            );
            require(
                valid && previous != next,
                "recovery image checkpoint skipped or replayed",
            )?;
            let before = previous["observations"].as_object().unwrap();
            let after = next["observations"].as_object().unwrap();
            for (mode, observation) in before {
                require(
                    after
                        .get(mode)
                        .is_some_and(|next| next["first"] == observation["first"]),
                    "first recovery boot observation changed",
                )?;
            }
        }
        Kind::Jobs => {
            unchanged(previous, next, &["plan"])?;
            let expected = match previous["phase"].as_str() {
                Some("planned") => "creating",
                Some("creating") => "root-recorded",
                Some("root-recorded") => "staged",
                _ => {
                    return Err(Error(
                        "terminal recovery staging record cannot be reused".into(),
                    ));
                }
            };
            require(
                next["phase"] == expected,
                "recovery staging checkpoint skipped or replayed",
            )?;
            for key in ["stage_boot", "root", "history"] {
                if !previous[key].is_null() {
                    require(
                        next[key] == previous[key],
                        "recorded recovery object changed",
                    )?;
                }
            }
        }
        Kind::Runs => {
            unchanged(
                previous,
                next,
                &[
                    "schema",
                    "id",
                    "plan_sha256",
                    "flavor",
                    "image",
                    "created_boot",
                    "entry",
                ],
            )?;
            let valid = matches!(
                (previous["phase"].as_str(), next["phase"].as_str()),
                (Some("staged"), Some("running"))
                    | (Some("running"), Some("executed" | "failed"))
                    | (Some("executed"), Some("complete"))
            );
            require(valid, "recovery run checkpoint skipped, replayed or failed")?;
            if previous["phase"] == "executed" {
                unchanged(previous, next, &["result"])?;
            }
        }
        Kind::Activations => {
            unchanged(previous, next, &["intent"])?;
            let valid = matches!(
                (previous["phase"].as_str(), next["phase"].as_str()),
                (Some("prepared"), Some("published"))
                    | (Some("published"), Some("selecting"))
                    | (Some("selecting"), Some("selected"))
                    | (Some("selected"), Some("selected" | "adopted"))
                    | (Some("adopted"), Some("adopted"))
            );
            require(
                valid && previous != next,
                "activation checkpoint skipped or replayed",
            )?;
            if !previous["selection"].is_null() {
                unchanged(previous, next, &["selection"])?;
            }
        }
        Kind::Workflows => {
            unchanged(
                previous,
                next,
                &["schema", "id", "plan_sha256", "flavor", "boot_id"],
            )?;
            let actions = [
                "stage",
                "review",
                "prepare-publication",
                "publish",
                "select",
            ];
            let position = |v: &Value| {
                v["action"]
                    .as_str()
                    .and_then(|a| actions.iter().position(|s| *s == a))
            };
            let valid = if previous["state"] == "prepared" {
                next["state"] == "running" && next["action"] == "stage"
            } else if previous["state"] == "running" {
                let a = position(previous)
                    .ok_or_else(|| Error("workflow running without action".into()))?;
                next["state"] == "running"
                    && (position(next) == Some(a + 1)
                        || a == 2
                            && position(next) == Some(a)
                            && previous["activation_sha256"].is_null()
                            && !next["activation_sha256"].is_null())
                    || a == 4 && next["state"] == "complete" && next["action"] == "select"
            } else {
                false
            };
            require(valid, "workflow checkpoint skipped or replayed")?;
            if !previous["activation_sha256"].is_null() {
                unchanged(previous, next, &["activation_sha256"])?;
            }
        }
    }
    Ok(())
}
enum Authority {
    Online(Guard),
    Independent(IndependentGuard),
}
impl Authority {
    fn control(&self) -> &File {
        match self {
            Self::Online(g) => g.control(),
            Self::Independent(g) => g.control(),
        }
    }
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Online(g) => g.recheck(),
            Self::Independent(g) => g.recheck(),
        }
    }
    fn control_mount_id(&self) -> u64 {
        match self {
            Self::Online(g) => g.control_mount_id(),
            Self::Independent(g) => g.control_mount_id(),
        }
    }
}
pub struct Journal {
    kind: Kind,
    path: PathBuf,
    directory: Option<File>,
    guard: Authority,
    pub records: Records,
    original_records: BTreeMap<String, crate::control_record::Retained>,
}
impl Journal {
    pub(crate) fn folder(&self) -> &str {
        self.kind.folder()
    }
    pub(crate) fn recheck_finished_origin(
        &self,
        published: &crate::root_retirement_online_finish_origin::Published<'_>,
    ) -> Result<()> {
        require(
            matches!(self.kind, Kind::Activations) && published.folder() == self.kind.folder(),
            "original activation journal required",
        )?;
        self.recheck()?;
        require(
            self.records.get(published.id()) == Some(published.before()),
            "finish differs from original activation selection",
        )?;
        for (id, row) in &self.original_records {
            if id == published.id() {
                published.require_original_member(row)?;
            } else {
                require(
                    row.value()? == &self.records[id],
                    "unrelated activation changed",
                )?;
            }
        }
        require(
            self.original_records.contains_key(published.id()),
            "original activation descriptor missing",
        )?;
        self.recheck()
    }
    /// Re-read the complete registry; directory identity alone does not pin its records.
    pub fn unchanged(&self) -> Result<()> {
        self.recheck()?;
        require(
            self.original_records.len() == self.records.len(),
            "recovery record epoch inventory differs",
        )?;
        for (id, original) in &self.original_records {
            require(
                original.value()? == &self.records[id],
                "recovery record differs from its original epoch",
            )?;
        }
        let current = match &self.guard {
            Authority::Online(_) => Self::open(self.kind, false)?,
            Authority::Independent(g) => Self::open_independent(self.kind, false, g.plan())?,
        };
        require(
            current.records == self.records,
            "recovery registry changed during operation",
        )?;
        for original in self.original_records.values() {
            original.recheck()?;
        }
        Ok(())
    }
    /// Bounded repeated authority checks use original cached values plus full
    /// actual epochs and exact membership; they never reopen a new JSON baseline.
    pub fn checkpoint(&self) -> Result<()> {
        self.recheck()?;
        require(
            self.records.len() == self.original_records.len(),
            "original recovery checkpoint record count changed",
        )?;
        if let Some(directory) = &self.directory {
            let m = directory.metadata()?;
            require(
                m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
                "original recovery checkpoint directory protection",
            )?;
            let current = files::directory_names(directory, self.kind.maximum().max(1))?
                .into_iter()
                .map(|name| {
                    name.into_string()
                        .map_err(|_| Error("recovery checkpoint filename encoding".into()))
                })
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            require(
                current
                    == self
                        .original_records
                        .keys()
                        .map(|id| format!("{id}.json"))
                        .collect(),
                "original recovery checkpoint membership changed",
            )?;
        } else {
            require(
                self.original_records.is_empty(),
                "missing original recovery checkpoint directory",
            )?;
        }
        for (id, original) in &self.original_records {
            require(
                self.records.get(id) == Some(original.checkpoint_value()?),
                "original recovery checkpoint value changed",
            )?;
        }
        self.recheck()
    }
    /// Original record epochs are review evidence, never executable authority.
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.unchanged()?;
        let records = self
            .original_records
            .iter()
            .map(|(id, record)| Ok((id.clone(), record.evidence()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let directory = self
            .directory
            .as_ref()
            .map(|file| file.metadata().map(|m| files::identity(&m)))
            .transpose()?;
        Ok(
            serde_json::json!({"records":records,"directory":directory,"mount":self.guard.control_mount_id()}),
        )
    }
    pub fn open(kind: Kind, create: bool) -> Result<Self> {
        Self::open_guarded(kind, create, Authority::Online(Guard::observe()?))
    }
    pub fn open_independent(kind: Kind, create: bool, plan: &Value) -> Result<Self> {
        Self::open_guarded(
            kind,
            create,
            Authority::Independent(IndependentGuard::observe(plan)?),
        )
    }
    fn open_guarded(kind: Kind, create: bool, guard: Authority) -> Result<Self> {
        let path = Path::new(operation::CONTROL).join(kind.folder());
        if create {
            files::ensure_directory(&path, 0o700, 0)?;
        }
        let directory =
            files::optional_directory_relative(guard.control(), Path::new(kind.folder()), Some(0))?;
        let mut records = Records::new();
        let mut original_records = BTreeMap::new();
        if let Some(dir) = &directory {
            require(
                dir.metadata()?.mode() & 0o7777 == 0o700
                    && mount_identity::id(dir.as_fd(), true)? == guard.control_mount_id(),
                "unsafe or independently mounted recovery journal",
            )?;
            let entries = files::directory_names(
                dir,
                kind.maximum() + usize::from(matches!(kind, Kind::Workflows)),
            )?;
            require(
                entries.len()
                    <= kind.maximum()
                        + if matches!(kind, Kind::Workflows) {
                            1
                        } else {
                            0
                        },
                "recovery journal object count bound",
            )?;
            for entry in entries {
                let name = entry
                    .into_string()
                    .map_err(|_| Error("recovery journal filename encoding".into()))?;
                let entry =
                    enzimos_platform::directory_entry::Entry::observe(dir, Path::new(&name))?;
                require(
                    entry.metadata()?.mode() & 0o077 == 0,
                    "unsafe recovery journal mode",
                )?;
                if matches!(kind, Kind::Workflows) && name == "lock" {
                    let lock = files::open_relative(dir, Path::new("lock"))?;
                    entry.matches(&lock)?;
                    let metadata = lock.metadata()?;
                    require(
                        metadata.uid() == 0
                            && metadata.mode() & 0o077 == 0
                            && metadata.nlink() == 1
                            && metadata.len() == 0
                            && mount_identity::id(lock.as_fd(), true)? == guard.control_mount_id(),
                        "unsafe recovery workflow lock",
                    )?;
                    continue;
                }
                let id = name.strip_suffix(".json").ok_or_else(|| {
                    Error("unknown or interrupted recovery journal publication".into())
                })?;
                kind.identifier(id)?;
                require(
                    records.len() < kind.maximum(),
                    "recovery journal record count bound",
                )?;
                let original = crate::control_record::Retained::open(
                    dir,
                    Path::new(&name),
                    kind.limit(),
                    guard.control_mount_id(),
                )?;
                let value = original.value()?.clone();
                kind.validate(&value, id)?;
                entry.recheck()?;
                records.insert(id.into(), value);
                original_records.insert(id.into(), original);
            }
        }
        let journal = Self {
            kind,
            path,
            directory,
            guard,
            records,
            original_records,
        };
        journal.recheck()?;
        Ok(journal)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        if let Some(held) = &self.directory {
            let current = files::directory(&self.path, Some(0))?;
            let a = held.metadata()?;
            let b = current.metadata()?;
            require(
                (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
                    && mount_identity::id(held.as_fd(), true)? == self.guard.control_mount_id()
                    && mount_identity::id(current.as_fd(), true)? == self.guard.control_mount_id(),
                "recovery journal replaced",
            )?;
        } else {
            require(
                matches!(std::fs::symlink_metadata(&self.path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "recovery journal appeared during observation",
            )?;
        }
        Ok(())
    }
    pub fn save(
        &mut self,
        id: &str,
        next: Value,
        previous: Option<&Value>,
        operation: &files::Lock,
    ) -> Result<()> {
        operation.recheck()?;
        self.unchanged()?;
        self.kind.validate(&next, id)?;
        require(
            json::canonical(&next)?.len() < self.kind.limit(),
            "recovery journal byte bound",
        )?;
        transition(self.kind, previous, &next, id)?;
        require(
            self.directory.is_some() && self.records.get(id) == previous,
            "recovery journal cannot adopt existing record",
        )?;
        let name = format!("{id}.json");
        operation.recheck()?;
        if let Some(expected) = previous {
            let original = self
                .original_records
                .get_mut(id)
                .ok_or_else(|| Error("original recovery record epoch missing".into()))?;
            require(
                original.value()? == expected,
                "recovery record changed before commit",
            )?;
            original.replace(&next)?;
        } else {
            require(
                self.records.len() < self.kind.maximum(),
                "recovery journal full",
            )?;
            let original = crate::control_record::Retained::create(
                self.directory.as_ref().unwrap(),
                Path::new(&name),
                &next,
                self.kind.limit(),
                self.guard.control_mount_id(),
            )?;
            self.original_records.insert(id.into(), original);
        }
        self.records.insert(id.into(), next);
        self.recheck()?;
        operation.recheck()
    }
}
