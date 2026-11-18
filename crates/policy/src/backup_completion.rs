// SPDX-License-Identifier: MIT
//! Original cleanup actors plus exact sealed output precede terminal publication.
use crate::{
    backup_attempt::Attempt, backup_inventory_stage, backup_source_capture,
    backup_transfer_observation::ClosedObservation, control_record::Retained,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "backup-completions";
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    shape_owned(file, 0)
}
fn shape_owned(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && (owner != 0 || m.gid() == 0) && m.mode() & 0o022 == 0,
        "protected original completion parent",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
pub(crate) struct Member {
    parent: File,
    parent_shape: Shape,
    owner: u32,
    name: &'static str,
    limit: usize,
    original: Option<File>,
    epoch: Option<files::FileIdentity>,
    published: Option<File>,
    published_epoch: Option<files::FileIdentity>,
}
impl Member {
    pub(crate) fn observe(parent: &File, name: &'static str, limit: usize) -> Result<Self> {
        Self::observe_owned(parent, name, limit, 0)
    }
    fn observe_owned(parent: &File, name: &'static str, limit: usize, owner: u32) -> Result<Self> {
        let parent_shape = shape_owned(parent, owner)?;
        let original = files::optional_relative(parent, Path::new(name))?;
        let epoch = original
            .as_ref()
            .map(|f| f.metadata().map(|m| files::identity(&m)))
            .transpose()?;
        if let Some(file) = &original {
            let m = file.metadata()?;
            require(
                m.is_file()
                    && m.uid() == owner
                    && (owner != 0 || m.gid() == 0)
                    && m.mode() & 0o022 == 0
                    && m.nlink() == 1
                    && m.len() <= limit as u64
                    && mount_identity::id(file.as_fd(), true)? == parent_shape.5,
                "legacy completion original member authority",
            )?;
        }
        Ok(Self {
            parent: parent.try_clone()?,
            parent_shape,
            owner,
            name,
            limit,
            original,
            epoch,
            published: None,
            published_epoch: None,
        })
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        require(
            shape_owned(&self.parent, self.owner)? == self.parent_shape,
            "original completion member parent changed",
        )?;
        let expected = self.published.as_ref().or(self.original.as_ref());
        let epoch = self.published_epoch.or(self.epoch);
        let named = files::optional_relative(&self.parent, Path::new(self.name))?;
        match (expected, named, epoch) {
            (None, None, None) => Ok(()),
            (Some(held), Some(named), Some(epoch)) => require(
                files::identity(&held.metadata()?) == epoch
                    && files::identity(&named.metadata()?) == epoch
                    && mount_identity::id(named.as_fd(), true)? == self.parent_shape.5,
                "original completion member replaced or changed",
            ),
            _ => Err(enzimos_platform::Error(
                "completion member appeared/disappeared; retain intent".into(),
            )),
        }
    }
    pub(crate) fn original_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.recheck()?;
        let bytes = self
            .original
            .as_ref()
            .map(|file| files::read_file(file, self.limit, Some(self.owner), true))
            .transpose()?;
        self.recheck()?;
        Ok(bytes)
    }
    pub(crate) fn published_bytes(&self) -> Result<Vec<u8>> {
        self.recheck()?;
        let file = self
            .published
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("original member has not published".into()))?;
        let bytes = files::read_file(file, self.limit, Some(self.owner), true)?;
        self.recheck()?;
        Ok(bytes)
    }
    pub(crate) fn publish(
        &mut self,
        bytes: &[u8],
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.recheck()?;
        require(
            self.published.is_none(),
            "original completion member already published; no replay",
        )?;
        let file = if let Some(original) = &self.original {
            files::atomic_replace_original(
                &self.parent,
                Path::new(self.name),
                bytes,
                0o600,
                Some(self.owner),
                self.limit,
                original,
            )?
        } else {
            files::atomic_relative_retained(
                &self.parent,
                Path::new(self.name),
                bytes,
                0o600,
                Some(self.owner),
                false,
                self.limit,
            )?
        };
        self.published_epoch = Some(files::identity(&file.metadata()?));
        self.published = Some(file);
        authorize()?;
        self.recheck()
    }
}
pub struct Prepared<'p, 's, 'g> {
    attempt: &'p Attempt<'g>,
    source: &'p backup_source_capture::Retired<'s, 'g>,
    stage: &'p backup_inventory_stage::Retired<'s, 'g>,
    closed: &'p ClosedObservation<'p>,
    registry: File,
    registry_shape: Shape,
    legacy: File,
    legacy_shape: Shape,
    record: Retained,
    value: Value,
    members: Vec<Member>,
    entered: bool,
    ready: bool,
}
impl<'p, 's, 'g> Prepared<'p, 's, 'g> {
    pub fn enter(
        attempt: &'p Attempt<'g>,
        source: &'p backup_source_capture::Retired<'s, 'g>,
        stage: &'p backup_inventory_stage::Retired<'s, 'g>,
        closed: &'p ClosedObservation<'p>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        source.require_completion(attempt, stage, closed)?;
        let summary = closed.original_summary()?;
        let log = closed.original_log()?;
        let guard = source.guard();
        let registry =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let registry_shape = shape(&registry)?;
        require(
            registry_shape.2 & 0o7777 == 0o700
                && registry_shape.5 == guard.control_mount_id()
                && files::directory_names(&registry, 256)?.len() < 256,
            "completion registry authority/capacity",
        )?;
        // Preserve legacy file locations without following aliases or adopting
        // unrelated filesystem state. Root-private canonical authority stays in control.
        let legacy = files::directory(Path::new("/var/lib/enzimos"), Some(0))?;
        let legacy_shape = shape(&legacy)?;
        require(
            crate::filesystem::observe(legacy.as_fd())?["filesystem_uuid"]
                == guard.configuration["filesystem_uuid"],
            "legacy completion data directory is outside original source filesystem",
        )?;
        let mut members = Vec::new();
        for parent in [guard.control(), &legacy] {
            for (name, limit) in [
                ("last-backup.log", 2 * 1024 * 1024),
                ("last-backup.json", 32768),
            ] {
                members.push(Member::observe(parent, name, limit)?);
            }
        }
        authorize()?;
        source.require_completion(attempt, stage, closed)?;
        let value = value!({"schema":1,"id":attempt.id()?,"phase":"prepared",
            "source_sha256":json::fingerprint(&source.evidence()?)?,"stage_sha256":json::fingerprint(&stage.evidence()?)?,
            "closed_sha256":json::fingerprint(&closed.evidence()?)?,"summary_sha256":json::fingerprint(&summary)?,
            "log_sha256":json::sha256(&log),"snapshot_id":summary["snapshot_id"],"backup_complete":false});
        let record = Retained::create(
            &registry,
            Path::new(&format!("{}.json", attempt.id()?)),
            &value,
            8192,
            registry_shape.5,
        )?;
        let this = Self {
            attempt,
            source,
            stage,
            closed,
            registry,
            registry_shape,
            legacy,
            legacy_shape,
            record,
            value,
            members,
            entered: false,
            ready: false,
        };
        this.recheck()?;
        Ok(this)
    }
    fn retained(&self) -> Result<()> {
        self.source.evidence()?;
        self.stage.evidence()?;
        self.closed.recheck()?;
        let guard = self.source.guard();
        self.source.lock().recheck()?;
        let registry = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        let legacy = files::directory(Path::new("/var/lib/enzimos"), Some(0))?;
        require(
            shape(&self.registry)? == self.registry_shape
                && shape(&registry)? == self.registry_shape
                && shape(&self.legacy)? == self.legacy_shape
                && shape(&legacy)? == self.legacy_shape,
            "original completion registry/legacy parent changed",
        )?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value
                && self.value["source_sha256"] == json::fingerprint(&self.source.evidence()?)?
                && self.value["stage_sha256"] == json::fingerprint(&self.stage.evidence()?)?
                && self.value["closed_sha256"] == json::fingerprint(&self.closed.evidence()?)?
                && self.value["summary_sha256"]
                    == json::fingerprint(&self.closed.original_summary()?)?
                && self.value["log_sha256"] == json::sha256(&self.closed.original_log()?),
            "original completion proof or artifact changed",
        )?;
        for member in &self.members {
            member.recheck()?;
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        self.retained()?;
        self.source
            .require_completion(self.attempt, self.stage, self.closed)
    }
    pub(crate) fn require_attempt(&self, attempt: &Attempt<'_>) -> Result<()> {
        require(
            self.attempt.same_actor(attempt)
                && self.entered
                && self.ready
                && self.value["phase"] == "publication-entered",
            "original typed publication not ready for this attempt",
        )?;
        self.recheck()?;
        require(
            self.members.iter().all(|m| m.published.is_some()),
            "original legacy files have not all published",
        )
    }
    pub(crate) fn snapshot_id(&self) -> Result<String> {
        self.retained()?;
        Ok(self.closed.original_summary()?["snapshot_id"]
            .as_str()
            .unwrap()
            .to_owned())
    }
    pub fn publish(
        mut self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Completed<'p, 's, 'g>> {
        authorize()?;
        self.recheck()?;
        require(
            !self.entered,
            "original completion already entered; no replay",
        )?;
        self.entered = true;
        self.value["phase"] = value!("publication-entered");
        self.record.replace(&self.value)?;
        let log = self.closed.original_log()?;
        let summary = json::canonical(&self.closed.original_summary()?)?;
        for index in 0..self.members.len() {
            authorize()?;
            self.recheck()?;
            let is_log = self.members[index].name == "last-backup.log";
            self.members[index].publish(if is_log { &log } else { &summary }, authorize)?;
        }
        authorize()?;
        self.recheck()?;
        self.ready = true;
        let attempt = self.attempt.commit_completed(&self, authorize)?;
        self.value["phase"] = value!("completed");
        self.value["backup_complete"] = value!(true);
        self.value["attempt"] = attempt;
        self.record.replace(&self.value)?;
        let completed = Completed { original: self };
        completed.evidence()?;
        Ok(completed)
    }
}
pub struct Completed<'p, 's, 'g> {
    original: Prepared<'p, 's, 'g>,
}
impl Completed<'_, '_, '_> {
    /// Exact original vendor summary is returned only after this actual durable
    /// completion; named legacy JSON or a copied receipt cannot reconstruct it.
    pub fn summary(&self) -> Result<Value> {
        let receipt = self.evidence()?;
        let summary = self.original.closed.original_summary()?;
        require(
            json::fingerprint(&summary)? == receipt["summary_sha256"]
                && summary["snapshot_id"] == receipt["snapshot_id"],
            "original completed summary binding changed",
        )?;
        self.evidence()?;
        Ok(summary)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.original.retained()?;
        require(
            self.original.value["phase"] == "completed"
                && self.original.value["backup_complete"] == true
                && self.original.value["attempt"] == self.original.attempt.completed_record()?,
            "original completed backup publication changed",
        )?;
        Ok(self.original.value.clone())
    }
}
