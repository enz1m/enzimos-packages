// SPDX-License-Identifier: MIT
//! Explicit Root retention; exact authenticated IDs, durable attempt, no replay.
use super::{Image, Runtime};
use crate::{
    backup_admission::Repository, backup_configuration::Configuration,
    backup_credential::Credential, backup_destination::Destination,
    backup_repository_header::Header, backup_rotation_context::Quiet, backup_rotation_record,
    control_record::Observation, control_registry, operation, storage_runtime::Guard,
};
use enzimos_platform::{
    Error, Result, files, json,
    local_restic::{self, RotationTask},
    mount_identity, publication, require,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

pub(crate) struct Plan {
    pub(crate) before: BTreeMap<String, String>,
    pub(crate) remaining: BTreeMap<String, String>,
    pub(crate) remove: Vec<String>,
    /// Managed enzimOS points, oldest first.
    managed: Vec<(chrono::DateTime<chrono::Utc>, String)>,
}
fn inventory(code: Option<i32>, bytes: &[u8]) -> Result<BTreeMap<String, Value>> {
    require(code == Some(0), "retention authenticated inventory refused")?;
    let data = json::decode(bytes, 4 * 1024 * 1024)?;
    let rows = data
        .as_array()
        .ok_or_else(|| Error("retention inventory array".into()))?;
    require(rows.len() <= 10000, "retention inventory count")?;
    let mut result = BTreeMap::new();
    for row in rows {
        let id = crate::recovery_records::text(row, "id")?;
        crate::identity::sha(id)?;
        require(
            row.is_object() && result.insert(id.into(), row.clone()).is_none(),
            "duplicate retention snapshot ID",
        )?;
    }
    Ok(result)
}
impl Plan {
    /// `protect`: snapshots that must stay whatever their time says (the backup or
    /// copy this cleanup runs after; a wrong clock must never remove it).
    pub(crate) fn observe(
        code: Option<i32>,
        bytes: &[u8],
        policy: &Value,
        protect: &[String],
    ) -> Result<Self> {
        crate::backup_retention::validate_policy(policy)?;
        let rows = inventory(code, bytes)?;
        let mut managed = Vec::new();
        let mut before = BTreeMap::new();
        for (id, row) in rows {
            before.insert(id.clone(), json::fingerprint(&row)?);
            if row["hostname"] == "enzimos" && row["tags"] == value!(["enzimos-whole-linux"]) {
                crate::backup_points::scope(&row, &id)?;
                let (time, _) = crate::snapshot_queries::utc(&row["time"])?;
                managed.push((time, id));
            }
        }
        // Only exact enzimOS whole-system points are candidates; foreign rows stay.
        let remove = crate::backup_retention::select(&managed, policy)
            .into_iter()
            .filter(|id| {
                !protect
                    .iter()
                    .any(|kept| kept == id || (kept.len() >= 8 && id.starts_with(kept.as_str())))
            })
            .collect::<Vec<_>>();
        require(
            remove.len() <= 4096,
            "retention removal batch exceeds one explicit command",
        )?;
        let mut remaining = before.clone();
        for id in &remove {
            remaining.remove(id);
        }
        managed.sort();
        Ok(Self {
            before,
            remaining,
            remove,
            managed,
        })
    }
    /// Also remove the `count` oldest managed points the policy keeps, never the
    /// newest one and never a protected one (the space limit).
    pub(crate) fn add_oldest(&mut self, count: usize, protect: &[String]) {
        let newest = self.managed.last().map(|(_, id)| id.clone());
        let extra: Vec<String> = self
            .managed
            .iter()
            .map(|(_, id)| id)
            .filter(|id| {
                Some(*id) != newest.as_ref()
                    && !self.remove.contains(id)
                    && !protect.iter().any(|kept| {
                        kept == *id || (kept.len() >= 8 && id.starts_with(kept.as_str()))
                    })
            })
            .take(count)
            .cloned()
            .collect();
        for id in extra {
            self.remaining.remove(&id);
            self.remove.push(id);
        }
        self.remove.sort();
    }
    pub(crate) fn require_after(&self, code: Option<i32>, bytes: &[u8]) -> Result<()> {
        let actual = inventory(code, bytes)?
            .into_iter()
            .map(|(id, row)| Ok((id, json::fingerprint(&row)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        require(
            actual == self.remaining,
            "retention snapshot outcome differs; review required, no replay",
        )
    }
}
fn validate(v: &Value, id: &str) -> Result<()> {
    crate::identity::safe_id(id)?;
    json::fields(
        v,
        "schema id phase filesystem_uuid configuration_sha256 repository_sha256 before_sha256 remaining_sha256 remove policy",
    )?;
    require(
        v["schema"] == 1
            && v["id"] == id
            && matches!(
                v["phase"].as_str(),
                Some("prepared" | "complete" | "abandoned")
            ),
        "retention attempt schema/identity/phase",
    )?;
    crate::identity::uuid(crate::recovery_records::text(v, "filesystem_uuid")?)?;
    for name in [
        "configuration_sha256",
        "repository_sha256",
        "before_sha256",
        "remaining_sha256",
    ] {
        crate::identity::sha(crate::recovery_records::text(v, name)?)?;
    }
    crate::backup_retention::validate_policy(&v["policy"])?;
    let ids = v["remove"]
        .as_array()
        .ok_or_else(|| Error("retention attempt selected IDs".into()))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error("retention attempt snapshot ID".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    local_restic::Retention::new(&ids)?;
    Ok(())
}
/// Completed retention records kept once the registry nears its 32-entry bound.
const RETIRE_AT: usize = 31;
const RETAINED: usize = 16;
/// The oldest completed records to remove so `RETAINED` remain.
fn retired(mut aged: Vec<(i64, String)>) -> Vec<String> {
    if aged.len() < RETIRE_AT {
        return Vec::new();
    }
    aged.sort();
    let excess = aged.len() - RETAINED;
    aged.into_iter()
        .take(excess)
        .map(|(_, name)| name)
        .collect()
}
struct Registry {
    directory: File,
    shape: (u64, u64, u32),
    mount: u64,
    flags: i32,
    previous: BTreeMap<String, Observation>,
    selected: String,
}
impl Registry {
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn open(guard: &Guard, id: &str) -> Result<Self> {
        let directory = files::ensure_directory_relative(
            guard.control(),
            Path::new("backup-pruning"),
            0o700,
            0,
        )?;
        let m = directory.metadata()?;
        let shape = (m.dev(), m.ino(), m.mode());
        let mount = mount_identity::id(directory.as_fd(), true)?;
        require(
            m.mode() & 0o7777 == 0o700 && mount == guard.control_mount_id(),
            "retention registry protection/mount",
        )?;
        let flags = enzimos_platform::files::status_flags(&directory);
        require(flags >= 0, "retention registry status")?;
        let mut previous: BTreeMap<String, Observation> = BTreeMap::new();
        for name in files::directory_names(&directory, 32)? {
            let id = name
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                .ok_or_else(|| Error("interrupted retention registry requires review".into()))?;
            let original = Observation::open(
                &directory,
                Path::new(&format!("{id}.json")),
                512 * 1024,
                mount,
            )?;
            validate(original.value()?, id)?;
            require(
                original.value()?["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
                "foreign retention requires review; no replay",
            )?;
            let original = if original.value()?["phase"] == "prepared" {
                // An interrupted cleanup is never replayed with its old IDs: mark
                // it abandoned. Every run plans from a fresh authenticated
                // inventory and verifies the repository afterwards, so the next
                // run completes whatever this one left (forget/prune are safe to
                // repeat) instead of blocking cleanup forever.
                let mut row = original.value()?.clone();
                row["phase"] = value!("abandoned");
                validate(&row, id)?;
                original.recheck()?;
                files::atomic_relative(
                    &directory,
                    Path::new(&format!("{id}.json")),
                    &json::canonical(&row)?,
                    0o600,
                    Some(0),
                    true,
                    512 * 1024,
                )?;
                Observation::open(
                    &directory,
                    Path::new(&format!("{id}.json")),
                    512 * 1024,
                    mount,
                )?
            } else {
                original
            };
            previous.insert(id.into(), original);
        }
        // Every previous record is finished (complete or abandoned) here. Keep a bounded recent history
        // instead of refusing all retention once 31 runs have ever happened.
        if previous.len() >= RETIRE_AT {
            let mut aged = Vec::new();
            for name in previous.keys() {
                let file = files::open_relative(&directory, Path::new(&format!("{name}.json")))?;
                aged.push((file.metadata()?.mtime(), name.clone()));
            }
            for name in retired(aged) {
                previous[&name].recheck()?;
                let c_name = std::ffi::CString::new(format!("{name}.json"))
                    .map_err(|_| Error("retention registry encoding".into()))?;
                require(
                    // SAFETY: `c_name` is a NUL-terminated C string and `directory` keeps the
                    // descriptor open.
                    unsafe { libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), 0) } == 0,
                    "completed retention record retirement failed",
                )?;
                previous.remove(&name);
            }
            directory.sync_all()?;
        }
        require(
            previous.len() < 32 && !previous.contains_key(id),
            "retention registry capacity or ID already used",
        )?;
        let this = Self {
            directory,
            shape,
            mount,
            flags,
            previous,
            selected: id.into(),
        };
        this.recheck(guard)?;
        this.names(false)?;
        Ok(this)
    }
    fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let named =
            files::directory_relative(guard.control(), Path::new("backup-pruning"), Some(0))?;
        for directory in [&self.directory, &named] {
            let m = directory.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode()) == self.shape
                    && mount_identity::id(directory.as_fd(), true)? == self.mount,
                "original retention registry replaced/covered",
            )?;
        }
        require(
            enzimos_platform::files::status_flags(&self.directory) == self.flags,
            "retention registry shared flags changed",
        )?;
        for original in self.previous.values() {
            original.recheck()?;
        }
        Ok(())
    }
    fn names(&self, selected: bool) -> Result<()> {
        let mut expected = self
            .previous
            .keys()
            .map(|id| format!("{id}.json"))
            .collect::<BTreeSet<_>>();
        if selected {
            expected.insert(format!("{}.json", self.selected));
        }
        let actual = files::directory_names(&self.directory, 33)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("retention registry encoding".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        require(actual == expected, "retention registry namespace changed")
    }
}
struct Rotations {
    original: Option<(File, files::FileIdentity)>,
    documents: Vec<Observation>,
}
impl Rotations {
    fn observe(guard: &Guard, rows: &BTreeMap<String, Value>) -> Result<Self> {
        let parent = files::optional_directory_relative(
            guard.control(),
            Path::new("backup-rotation"),
            Some(0),
        )?;
        let mut documents = Vec::new();
        if let Some(parent) = &parent {
            require(
                mount_identity::id(parent.as_fd(), true)? == guard.control_mount_id(),
                "rotation records crossed control mount",
            )?;
            for (id, row) in rows {
                let observed = Observation::open(
                    parent,
                    Path::new(&format!("{id}.json")),
                    backup_rotation_record::LIMIT,
                    guard.control_mount_id(),
                )?;
                require(
                    observed.value()? == row,
                    "rotation records changed before retention",
                )?;
                documents.push(observed);
            }
        } else {
            require(rows.is_empty(), "rotation registry disappeared")?;
        }
        let original = parent
            .map(|p| {
                let epoch = files::identity(&p.metadata()?);
                Ok::<_, enzimos_platform::Error>((p, epoch))
            })
            .transpose()?;
        let this = Self {
            original,
            documents,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    fn recheck(&self, guard: &Guard) -> Result<()> {
        let named = files::optional_directory_relative(
            guard.control(),
            Path::new("backup-rotation"),
            Some(0),
        )?;
        match (&self.original, named) {
            (None, None) => {}
            (Some((held, epoch)), Some(named)) => require(
                files::identity(&held.metadata()?) == *epoch
                    && files::identity(&named.metadata()?) == *epoch
                    && mount_identity::id(held.as_fd(), true)? == guard.control_mount_id()
                    && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
                "original rotation registry replaced or changed",
            )?,
            _ => return Err(Error("rotation registry appeared/disappeared".into())),
        }
        for original in &self.documents {
            original.recheck()?;
        }
        Ok(())
    }
}
/// Manual cleanup with the current policy (`enzimos-policy backup retain`).
pub(crate) fn retain_locked(guard: &Guard, lock: &files::Lock) -> Result<Value> {
    retain_policy_locked(guard, lock, &crate::backup_retention::policy()?, &[], 0)
}
/// After a successful backup: clean up by policy unless the user turned automatic
/// cleanup off. Never fails the backup; the outcome is published as status.
pub(crate) fn after_backup_locked(
    guard: &Guard,
    lock: &files::Lock,
    created: Option<&str>,
) -> Value {
    // Best effort and independent of the policy: failed backups' leftovers
    // are not backups, so they are retired even with automatic cleanup off.
    let _ = crate::backup_history::retire_failed_locked(guard, lock);
    let outcome = (|| -> Result<Value> {
        let policy = crate::backup_retention::policy()?;
        if policy["automatic"] != true {
            return Ok(value!({"status":"automatic-cleanup-off","removed":0}));
        }
        let protect = created.map(|id| vec![id.to_owned()]).unwrap_or_default();
        let mut status = retain_policy_locked(guard, lock, &policy, &protect, 0)?;
        status["removals"] = crate::backup_removals::apply_locked(guard, lock);
        // The space limit: while the backups use more than allowed, the
        // oldest go, one per round (bounded), never the newest.
        let mut used = repository_bytes(guard).ok();
        if let Some(limit) = crate::backup_retention::budget(&policy) {
            let mut extra = 0;
            for _ in 0..8 {
                if used.is_none_or(|u| u <= limit) {
                    break;
                }
                let round = retain_policy_locked(guard, lock, &policy, &protect, 1)?;
                let removed = round["removed"].as_u64().unwrap_or(0);
                if removed == 0 {
                    break;
                }
                extra += removed;
                used = repository_bytes(guard).ok();
            }
            status["budget"] = value!({"limit":limit,"removed":extra,
                "over":used.is_some_and(|u| u > limit)});
        }
        status["used_bytes"] = value!(used);
        Ok(status)
    })();
    let status = match outcome {
        Ok(value) => value,
        Err(error) => {
            value!({"status":"failed","reason":error.0.chars().take(160).collect::<String>()})
        }
    };
    let _ = crate::backup_retention::publish_status("local", &status);
    status
}
/// `after_backup_locked` with the configured destination attached: a mounted
/// destination is borrowed, otherwise one reviewed temporary mount is owned for
/// the cleanup and closed after it. An absent or unusable drive is published
/// as a failed cleanup status; it never fails the backup that preceded it.
pub fn after_backup_attached(
    guard: &Guard,
    lock: &files::Lock,
    created: Option<&str>,
    authorize: &dyn Fn() -> Result<()>,
) -> Value {
    let attached =
        crate::backup_destination_attach::with_destination(guard, lock, authorize, || {
            Ok(after_backup_locked(guard, lock, created))
        });
    let status = match attached {
        Ok(status) => status,
        Err(error) => {
            let status =
                value!({"status":"failed","reason":error.0.chars().take(160).collect::<String>()});
            let _ = crate::backup_retention::publish_status("local", &status);
            status
        }
    };
    eprintln!(
        "enzimos-backup: cleanup {} removed={} {}",
        status["status"].as_str().unwrap_or("unknown"),
        status["removed"].as_u64().unwrap_or(0),
        status["reason"].as_str().unwrap_or("")
    );
    status
}
/// Manual cleanup (`enzimos-policy backup retain`) with the destination attached.
///
/// # Errors
///
/// Fails when the destination is not attached or retention fails.
pub fn retain_attached_locked(guard: &Guard, lock: &files::Lock) -> Result<Value> {
    crate::backup_destination_attach::with_destination(
        guard,
        lock,
        &|| {
            guard.recheck()?;
            lock.recheck()
        },
        || retain_locked(guard, lock),
    )
}
pub(crate) fn retain_policy_locked(
    guard: &Guard,
    lock: &files::Lock,
    policy: &Value,
    protect: &[String],
    oldest: usize,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    guard.recheck()?;
    lock.recheck()?;
    let id = format!("prune-{}", files::random_hex(16)?);
    // Create this operation's registry before measuring the whole Root control
    // epoch. Later owned records change only this retained child directory.
    let registry = Registry::open(guard, &id)?;
    let quiet = Quiet::observe_with(guard, true)?;
    let rotations = control_registry::read_bounded(
        guard,
        "backup-rotation",
        backup_rotation_record::MAXIMUM,
        backup_rotation_record::LIMIT,
        backup_rotation_record::validate,
    )?;
    require(
        rotations
            .values()
            .all(|r| matches!(r["phase"].as_str(), Some("complete" | "abandoned"))),
        "unfinished local rotation blocks retention",
    )?;
    let original_rotations = Rotations::observe(guard, &rotations)?;
    let idle = crate::transition_idle::Snapshot::online()?;
    let config = Configuration::open()?;
    let destination = Destination::open(&config, guard)?;
    destination.require_writable()?;
    let pin = Repository::open(&destination)?;
    let credential = Credential::open()?;
    let image = Image::open()?;
    let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
    let password = File::from(credential.descriptor()?.try_clone_to_owned()?);
    let header = Header::observe(&repository)?;
    let source = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        quiet.recheck(guard)?;
        idle.recheck()?;
        config.recheck()?;
        destination.require_writable()?;
        pin.recheck()?;
        credential.recheck()?;
        image.evidence()?;
        header.recheck(&repository)?;
        registry.recheck(guard)?;
        original_rotations.recheck(guard)?;
        require(
            control_registry::read_bounded(
                guard,
                "backup-rotation",
                backup_rotation_record::MAXIMUM,
                backup_rotation_record::LIMIT,
                backup_rotation_record::validate,
            )? == rotations,
            "rotation changed during retention",
        )
    };
    let runtime = Runtime::create(&files::random_hex(16)?, &mut || source())?;
    require(
        runtime.image_evidence()? == image.evidence()?,
        "retention vendor image changed",
    )?;
    let ongoing = || {
        source()?;
        runtime.recheck()
    };
    let query = local_restic::rotation_read(
        RotationTask::Points,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || ongoing(),
    )?;
    ongoing()?;
    runtime.empty()?;
    let mut plan = Plan::observe(query.status.code(), &query.stdout, policy, protect)?;
    plan.add_oldest(oldest, protect);
    if plan.remove.is_empty() {
        // Nothing to forget: no receipt, no repository write.
        registry.names(false)?;
        ongoing()?;
        return Ok(value!({"status":"nothing-to-remove","removed":0}));
    }
    let recipe = local_restic::Retention::new(&plan.remove)?;
    let mut row = value!({"schema":1,"id":id,"phase":"prepared","filesystem_uuid":guard.configuration["filesystem_uuid"],
        "configuration_sha256":json::fingerprint(&config.evidence()?)?,"repository_sha256":json::fingerprint(&pin.evidence()?)?,
        "before_sha256":json::fingerprint(&value!(plan.before))?,"remaining_sha256":json::fingerprint(&value!(plan.remaining))?,"remove":plan.remove,"policy":policy});
    validate(&row, &id)?;
    registry.names(false)?;
    ongoing()?;
    let path = Path::new(operation::CONTROL)
        .join("backup-pruning")
        .join(format!("{id}.json"));
    let prepared =
        publication::Prepared::write_authorized(&path, &json::canonical(&row)?, 0, &mut || {
            ongoing()
        })?;
    let mut receipt =
        publication::Chain::new(prepared.commit_retained_authorized(false, &mut || ongoing())?)?;
    let entered = || {
        ongoing()?;
        receipt.recheck()?;
        registry.names(true)
    };
    entered()?;
    let output = local_restic::retain(
        &recipe,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || entered(),
    )?;
    entered()?;
    runtime.empty()?;
    require(
        output.status.code() == Some(0),
        "retention outcome uncertain; prepared receipt retained",
    )?;
    let checked = local_restic::credential_review(
        local_restic::CredentialReview::Metadata,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || entered(),
    )?;
    entered()?;
    runtime.empty()?;
    require(
        checked.status.code() == Some(0),
        "retention metadata check failed; no replay",
    )?;
    let query = local_restic::rotation_read(
        RotationTask::Points,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || entered(),
    )?;
    entered()?;
    runtime.empty()?;
    plan.require_after(query.status.code(), &query.stdout)?;
    row["phase"] = value!("complete");
    receipt.replace(&json::canonical(&row)?, &mut || ongoing())?;
    receipt.recheck()?;
    registry.names(true)?;
    ongoing()?;
    Ok(value!({"status":"removed","removed":row["remove"].as_array().map_or(0, Vec::len)}))
}

/// Remove literal home paths from every enzimOS point (`restic rewrite
/// --forget`), then prune and check the metadata. Safe to repeat: points
/// without the paths are left as they are.
///
/// # Errors
/// Fails when the destination is unusable or a step fails (nothing is
/// claimed; the queue keeps the paths for the next backup).
pub(crate) fn rewrite_locked(guard: &Guard, lock: &files::Lock, paths: &[String]) -> Result<()> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    let recipe = local_restic::Rewrite::new(paths)?;
    let config = Configuration::open()?;
    let destination = Destination::open(&config, guard)?;
    destination.require_writable()?;
    let pin = Repository::open(&destination)?;
    let credential = Credential::open()?;
    let image = Image::open()?;
    let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
    let password = File::from(credential.descriptor()?.try_clone_to_owned()?);
    let header = Header::observe(&repository)?;
    let source = || {
        operation::root_only()?;
        guard.recheck()?;
        lock.recheck()?;
        config.recheck()?;
        destination.require_writable()?;
        pin.recheck()?;
        credential.recheck()?;
        image.evidence()?;
        header.recheck(&repository)
    };
    let runtime = Runtime::create(&files::random_hex(16)?, &mut || source())?;
    let ongoing = || {
        source()?;
        runtime.recheck()
    };
    let output = local_restic::rewrite(
        &recipe,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || ongoing(),
    )?;
    runtime.empty()?;
    require(
        output.status.code() == Some(0),
        "removal rewrite failed; kept for the next backup",
    )?;
    let pruned = local_restic::retain(
        &local_restic::Retention::new(&[])?,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || ongoing(),
    )?;
    runtime.empty()?;
    require(
        pruned.status.code() == Some(0),
        "prune after removal failed",
    )?;
    let checked = local_restic::credential_review(
        local_restic::CredentialReview::Metadata,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || ongoing(),
    )?;
    runtime.empty()?;
    require(
        checked.status.code() == Some(0),
        "metadata check after removal failed",
    )
}

/// Space the repository takes on the backup drive (allocated bytes).
///
/// # Errors
/// Fails when the configured destination is not attached.
pub(crate) fn repository_bytes(guard: &Guard) -> Result<u64> {
    let config = Configuration::open()?;
    let destination = Destination::open(&config, guard)?;
    let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
    let device = repository.metadata()?.dev();
    let mut total = 0u64;
    let mut stack = vec![repository];
    let mut visited = 0usize;
    while let Some(directory) = stack.pop() {
        for entry in enzimos_platform::fsview::entries(&directory, 1 << 20)? {
            visited += 1;
            require(visited < 10_000_000, "repository too large to measure")?;
            let meta = enzimos_platform::fsview::stat_at(&directory, &entry.name)?;
            total += meta.blocks() * 512;
            if meta.is_dir()
                && meta.dev() == device
                && let Some(child) =
                    enzimos_platform::fsview::child_directory(&directory, &entry.name)?
            {
                stack.push(child);
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn keep_one() -> Value {
        value!({"schema":1,"automatic":true,"last":1,"daily":0,"weekly":0,"monthly":0,"yearly":0})
    }
    fn point(id: char, time: &str, tags: Value) -> Value {
        value!({"id":id.to_string().repeat(64),"hostname":"enzimos","tags":tags,"time":time,
        "paths":["/backup-source/system","/backup-source/home","/backup-source/boot","/backup-source/inventory"]})
    }

    #[test]
    fn explicit_retention_preserves_mixed_tags_and_entire_foreign_rows() {
        let old = point('a', "2026-10-09T00:00:00Z", value!(["enzimos-whole-linux"]));
        let newest = point('b', "2026-10-10T00:00:00Z", value!(["enzimos-whole-linux"]));
        let foreign = point(
            'c',
            "2026-10-08T00:00:00Z",
            value!(["enzimos-whole-linux", "unrelated"]),
        );
        let plan = Plan::observe(
            Some(0),
            &json::canonical(&value!([old, newest, foreign])).unwrap(),
            &keep_one(),
            &[],
        )
        .unwrap();
        assert_eq!(plan.remove, vec!["a".repeat(64)]);
        plan.require_after(
            Some(0),
            &json::canonical(&value!([newest, foreign])).unwrap(),
        )
        .unwrap();
        assert!(
            plan.require_after(Some(0), &json::canonical(&value!([newest])).unwrap())
                .is_err()
        );
        let mut changed = foreign;
        changed["hostname"] = value!("changed");
        assert!(
            plan.require_after(
                Some(0),
                &json::canonical(&value!([newest, changed])).unwrap()
            )
            .is_err()
        );
        assert!(Plan::observe(Some(12), b"[]", &keep_one(), &[]).is_err());
        assert!(
            Plan::observe(
                Some(0),
                &json::canonical(&value!([newest, newest])).unwrap(),
                &keep_one(),
                &[]
            )
            .is_err()
        );
    }
}
