// SPDX-License-Identifier: MIT
//! Original online receipt observation for staging, online progress, abandonment
//! and finishing. No delete actor: a progress publication only records intent.
use crate::{catalog, control_record::Observation, operation, storage_runtime::Guard};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Executing,
    Deleted,
    Complete,
    Abandoned,
}
impl Phase {
    fn text(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Executing => "executing",
            Self::Deleted => "deleted",
            Self::Complete => "complete",
            Self::Abandoned => "abandoned",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Prepared,
            Self::Executing,
            Self::Deleted,
            Self::Complete,
            Self::Abandoned,
        ]
        .into_iter()
        .find(|phase| phase.text() == text)
    }
}
/// Kind of one owned receipt publication; each has its own exact validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transition {
    Staging,
    Completion,
    Progress,
    Abandon,
}
fn validate_transition(kind: Transition, before: &Value, next: &Value, id: &str) -> Result<()> {
    match kind {
        Transition::Staging => validate_staging_transition(before, next, id),
        Transition::Completion => validate_completion_transition(before, next, id),
        Transition::Progress => validate_progress_transition(before, next, id),
        Transition::Abandon => validate_abandon_transition(before, next, id),
    }
}
fn validate_observed(row: &Value, id: &str, filesystem: &Value, phase: Phase) -> Result<()> {
    crate::root_retirement_record::validate(row, id)?;
    let root_uuid = enzimos_platform::json::array(&row["targets"])?
        .last()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["uuid"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?;
    require(
        row["phase"] == phase.text()
            && row["filesystem_uuid"] == *filesystem
            && id == format!("root-{}", root_uuid.replace('-', "")),
        "original online Root receipt phase/filesystem/target mismatch",
    )
}
pub struct Journal<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    folder: File,
    epoch: files::FileIdentity,
    record: Observation,
    id: String,
    phase: Phase,
    folder_flags: i32,
    record_flags: i32,
}
impl<'a> Journal<'a> {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        id: &str,
        phase: Phase,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::safe_id(id)?;
        guard.recheck()?;
        lock.recheck()?;
        let folder =
            files::directory_relative(guard.control(), Path::new("root-retirements"), Some(0))?;
        require(
            folder.metadata()?.gid() == 0 && folder.metadata()?.mode() & 0o7777 == 0o700,
            "original private Root receipt directory protection",
        )?;
        let epoch = files::identity(&folder.metadata()?);
        let record = Observation::open(
            &folder,
            Path::new(&format!("{id}.json")),
            catalog::MAX_CATALOG,
            guard.control_mount_id(),
        )?;
        let folder_flags = enzimos_platform::files::status_flags(&folder);
        // SAFETY: F_GETFL takes no pointers and `record` keeps the descriptor open.
        let record_flags = unsafe { libc::fcntl(record.descriptor()?.as_raw_fd(), libc::F_GETFL) };
        require(
            folder_flags >= 0
                && record_flags >= 0
                && folder_flags & libc::O_ACCMODE == libc::O_RDONLY
                && record_flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original online Root receipt read-only descriptions required",
        )?;
        let this = Self {
            guard,
            lock,
            folder,
            epoch,
            record,
            id: id.into(),
            phase,
            folder_flags,
            record_flags,
        };
        this.recheck()?;
        Ok(this)
    }
    /// Observe the receipt in whatever valid phase it currently has. The phase
    /// is then fixed for this actor exactly as with [`Journal::observe`].
    pub(crate) fn observe_current(
        guard: &'a Guard,
        lock: &'a files::Lock,
        id: &str,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::identity::safe_id(id)?;
        guard.recheck()?;
        lock.recheck()?;
        let phase = {
            let folder =
                files::directory_relative(guard.control(), Path::new("root-retirements"), Some(0))?;
            let record = Observation::open(
                &folder,
                Path::new(&format!("{id}.json")),
                catalog::MAX_CATALOG,
                guard.control_mount_id(),
            )?;
            record.value()?["phase"]
                .as_str()
                .and_then(Phase::parse)
                .ok_or_else(|| enzimos_platform::Error("Root receipt phase unknown".into()))?
        };
        Self::observe(guard, lock, id, phase)
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub fn recheck(&self) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        let named = files::directory_relative(
            self.guard.control(),
            Path::new("root-retirements"),
            Some(0),
        )?;
        require(
            files::identity(&self.folder.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.folder.as_fd(), true)? == self.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == self.guard.control_mount_id(),
            "original online Root receipt directory changed/covered",
        )?;
        self.record.recheck()?;
        require(
            enzimos_platform::files::status_flags(&self.folder) == self.folder_flags
                // SAFETY: F_GETFL takes no pointers and `self.record` keeps the descriptor open.
                && unsafe { libc::fcntl(self.record.descriptor()?.as_raw_fd(), libc::F_GETFL) }
                    == self.record_flags,
            "original online Root receipt description flags changed",
        )?;
        let row = self.record.value()?;
        validate_observed(
            row,
            &self.id,
            &self.guard.configuration["filesystem_uuid"],
            self.phase,
        )?;
        self.record.recheck()?;
        self.lock.recheck()?;
        self.guard.recheck()
    }
    /// One durable staging intent publication. This does not install boot entries
    /// or authorize deletion; the consuming caller must retain all other actors.
    /// Any uncertain failure consumes this actor and cannot be retried through it.
    pub(crate) fn publish_staged(
        self,
        next: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>> {
        self.publish_transition(next, Transition::Staging, authorize)
    }
    /// One durable online execution step of an unstaged receipt (see
    /// [`next_progress`]). Recording an in-flight step performs no deletion; the
    /// caller deletes only after this publication and its full rechecks.
    pub(crate) fn publish_progress(
        self,
        next: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>> {
        self.publish_transition(next, Transition::Progress, authorize)
    }
    /// End an unstaged receipt that is not deleted: it stops refusing other
    /// operations and grants nothing. Remaining targets stay as they are.
    pub(crate) fn publish_abandoned(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>> {
        self.recheck()?;
        let mut next = self.record.value()?.clone();
        next["phase"] = serde_json::json!("abandoned");
        self.publish_transition(&next, Transition::Abandon, authorize)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn publish_transition(
        mut self,
        next: &Value,
        transition: Transition,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>> {
        self.recheck()?;
        let before = self.record.value()?.clone();
        validate_transition(transition, &before, next, &self.id)?;
        let next_phase = next["phase"]
            .as_str()
            .and_then(Phase::parse)
            .ok_or_else(|| enzimos_platform::Error("Root receipt successor phase".into()))?;
        let names = files::directory_names(&self.folder, 16)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut others = BTreeMap::new();
        for name in &names {
            let name = name
                .to_str()
                .ok_or_else(|| enzimos_platform::Error("Root receipt name encoding".into()))?;
            let id = name.strip_suffix(".json").ok_or_else(|| {
                enzimos_platform::Error("unexpected Root receipt directory member".into())
            })?;
            crate::identity::safe_id(id)?;
            if id != self.id {
                let original = Observation::open(
                    &self.folder,
                    Path::new(name),
                    catalog::MAX_CATALOG,
                    self.guard.control_mount_id(),
                )?;
                crate::root_retirement_record::validate(original.value()?, id)?;
                others.insert(name.to_owned(), original);
            }
        }
        require(
            names.contains(&std::ffi::OsString::from(format!("{}.json", self.id))),
            "original selected Root receipt missing from retained membership",
        )?;
        authorize()?;
        self.recheck()?;
        require(
            files::directory_names(&self.folder, 16)?
                .into_iter()
                .collect::<BTreeSet<_>>()
                == names,
            "Root receipt membership changed before owned publication",
        )?;
        for original in others.values() {
            original.recheck()?;
        }
        let old_epoch = self.epoch;
        let old_flags = enzimos_platform::files::status_flags(&self.folder);
        require(
            old_flags >= 0 && old_flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original Root receipt directory read-only description required",
        )?;
        let predecessor = self.record.replace_with_predecessor(next)?;
        let record_flags =
            // SAFETY: F_GETFL takes no pointers and `self.record` keeps the descriptor open.
            unsafe { libc::fcntl(self.record.descriptor()?.as_raw_fd(), libc::F_GETFL) };
        require(
            record_flags >= 0 && record_flags & libc::O_ACCMODE == libc::O_RDONLY,
            "owned staged receipt read-only successor required",
        )?;
        self.record_flags = record_flags;
        // This epoch is obtained only after our actual owned rename completed.
        let after = files::identity(&self.folder.metadata()?);
        require(
            (
                old_epoch.0,
                old_epoch.1,
                old_epoch.7,
                old_epoch.8,
                old_epoch.9,
                old_epoch.10,
            ) == (after.0, after.1, after.7, after.8, after.9, after.10)
                && enzimos_platform::files::status_flags(&self.folder) == old_flags,
            "owned staging changed original directory identity/protection/description",
        )?;
        self.epoch = after;
        self.phase = next_phase;
        let published = Published {
            journal: self,
            predecessor,
            before,
            names,
            others,
            original_directory: old_epoch,
            directory_flags: old_flags,
            transition,
        };
        published.recheck()?;
        authorize()?;
        published.recheck()?;
        Ok(published)
    }
    pub fn record(&self) -> Result<&Value> {
        self.recheck()?;
        self.record.value()
    }
    pub(crate) fn require_original_source(&self, guard: &Guard, lock: &files::Lock) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "online Root receipt belongs to another original source actor",
        )?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"id":self.id,"record":self.record.value()?,"original":self.record.evidence()?,
            "directory_epoch":self.epoch,"execution_authorized":false}),
        )
    }
    pub(crate) fn duplicate_observation(&self) -> Result<Observation> {
        self.recheck()?;
        let result = Observation::open(
            &self.folder,
            Path::new(&format!("{}.json", self.id)),
            catalog::MAX_CATALOG,
            self.guard.control_mount_id(),
        )?;
        require(
            result.evidence()? == self.record.evidence()?,
            "online Root receipt differs from original held actor",
        )?;
        self.recheck()?;
        Ok(result)
    }
}

/// Actual one-use staging publication with the unlinked original inode retained.
/// No constructor accepts metadata, and this actor supplies no delete authority.
pub struct Published<'a> {
    journal: Journal<'a>,
    predecessor: crate::control_record::Predecessor,
    before: Value,
    names: BTreeSet<std::ffi::OsString>,
    others: BTreeMap<String, Observation>,
    original_directory: files::FileIdentity,
    directory_flags: i32,
    transition: Transition,
}
impl Published<'_> {
    pub(crate) fn require_original_directory(
        &self,
        parent: &File,
        original: files::FileIdentity,
    ) -> Result<()> {
        self.recheck()?;
        require(
            original == self.original_directory
                && files::identity(&parent.metadata()?) == self.journal.epoch
                && mount_identity::id(parent.as_fd(), true)?
                    == self.journal.guard.control_mount_id()
                && enzimos_platform::files::status_flags(&parent) == self.directory_flags,
            "staging producer differs from original registry directory",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_member(
        &self,
        original: &crate::control_record::Retained,
    ) -> Result<()> {
        self.recheck()?;
        self.predecessor.require_original_retained(original)?;
        self.recheck()
    }
    pub(crate) fn require_source(&self, guard: &Guard, lock: &files::Lock) -> Result<()> {
        require(
            std::ptr::eq(self.journal.guard, guard) && std::ptr::eq(self.journal.lock, lock),
            "staged Root receipt belongs to another original guard/lock",
        )?;
        self.recheck()
    }
    pub(crate) fn before(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.before)
    }
    pub fn recheck(&self) -> Result<()> {
        require(
            enzimos_platform::files::status_flags(&self.journal.folder) == self.directory_flags,
            "owned staging original directory description flags changed",
        )?;
        self.predecessor.recheck()?;
        self.journal.recheck()?;
        require(
            files::directory_names(&self.journal.folder, 16)?
                .into_iter()
                .collect::<BTreeSet<_>>()
                == self.names,
            "owned staging changed unrelated Root receipt membership",
        )?;
        for original in self.others.values() {
            original.recheck()?;
        }
        validate_transition(
            self.transition,
            &self.before,
            self.journal.record.value()?,
            &self.journal.id,
        )?;
        self.predecessor.recheck()
    }
    pub(crate) fn require_original_observation(&self, original: &Observation) -> Result<()> {
        self.recheck()?;
        self.predecessor.require_original_observation(original)?;
        self.recheck()
    }
    pub fn record(&self) -> Result<&Value> {
        self.recheck()?;
        self.journal.record.value()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"before":self.before,"published":self.journal.evidence()?,
            "execution_authorized":false,"boot_entries_installed":false}),
        )
    }
}
pub(crate) fn validate_staging_transition(before: &Value, next: &Value, id: &str) -> Result<()> {
    crate::root_retirement_record::validate(before, id)?;
    crate::root_retirement_record::validate(next, id)?;
    require(
        before["schema"] == 1
            && before["phase"] == "prepared"
            && before.get("coordinator").is_none()
            && next["schema"] == 2,
        "only original unstaged prepared receipt may acquire staging intent",
    )?;
    let mut expected = before.clone();
    expected["schema"] = serde_json::json!(2);
    expected["coordinator"] = next["coordinator"].clone();
    require(
        *next == expected,
        "staging changed original retirement identity/progress",
    )?;
    let root = enzimos_platform::json::array(&before["targets"])?
        .last()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
    require(
        id == format!(
            "root-{}",
            crate::recovery_records::text(root, "uuid")?.replace('-', "")
        ),
        "staging receipt must identify original Root UUID",
    )?;
    let entry = format!(
        "enzimos-root-retire-{}.conf",
        id.get(5..21).unwrap_or_default()
    );
    require(
        next["coordinator"]["uefi_entry"] == entry
            && next["coordinator"].get("uefi_mode").is_some(),
        "native staging requires exact original Root entry and explicit UEFI mode",
    )?;
    crate::root_retirement_parameters::Parameters::parse(crate::recovery_records::text(
        &next["coordinator"],
        "options",
    )?)?
    .matches_record(next)
}

/// Completion retains the actual deleted predecessor and current complete inode.
/// Only the consuming finish orchestrator may request its one publication.
pub struct Completed<'a> {
    published: Published<'a>,
}
impl<'a> Journal<'a> {
    pub(crate) fn publish_complete(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Completed<'a>> {
        self.recheck()?;
        let mut next = self.record.value()?.clone();
        next["phase"] = serde_json::json!("complete");
        let published = self.publish_transition(&next, Transition::Completion, authorize)?;
        let result = Completed { published };
        result.recheck()?;
        Ok(result)
    }
}
impl Completed<'_> {
    pub fn recheck(&self) -> Result<()> {
        self.published.recheck()
    }
    pub(crate) fn require_source(&self, guard: &Guard, lock: &files::Lock) -> Result<()> {
        self.published.require_source(guard, lock)
    }
    pub(crate) fn require_original_directory(
        &self,
        parent: &File,
        before: files::FileIdentity,
    ) -> Result<()> {
        self.published.require_original_directory(parent, before)
    }
    pub(crate) fn require_original_member(
        &self,
        old: &crate::control_record::Retained,
    ) -> Result<()> {
        self.published.require_original_member(old)
    }
    pub(crate) fn require_original_observation(&self, old: &Observation) -> Result<()> {
        self.published.require_original_observation(old)
    }
    pub(crate) fn before(&self) -> Result<&Value> {
        self.published.before()
    }
    pub fn record(&self) -> Result<&Value> {
        self.published.record()
    }
}
/// The one successor of an online execution step, mirroring the offline
/// journal: prepared -> executing; executing(n) -> in-flight n; in-flight n ->
/// executing(n + 1), or deleted after the last target. Only unstaged (schema 1,
/// no coordinator) receipts progress online.
pub(crate) fn next_progress(before: &Value) -> Result<Value> {
    let id = crate::recovery_records::text(before, "id")?;
    crate::root_retirement_record::validate(before, id)?;
    require(
        before["schema"] == 1 && before.get("coordinator").is_none(),
        "only an unstaged Root receipt progresses online",
    )?;
    let count = enzimos_platform::json::array(&before["targets"])?.len() as u64;
    let next_step = enzimos_platform::json::unsigned(&before["next_step"])?;
    let mut next = before.clone();
    match (before["phase"].as_str(), before["inflight"].as_u64()) {
        (Some("prepared"), None) => next["phase"] = serde_json::json!("executing"),
        (Some("executing"), None) => {
            require(next_step < count, "no remaining Root target to begin")?;
            next["inflight"] = serde_json::json!(next_step);
        }
        (Some("executing"), Some(inflight)) => {
            require(inflight == next_step, "Root in-flight step differs")?;
            next["next_step"] = serde_json::json!(next_step + 1);
            next["inflight"] = Value::Null;
            if next_step + 1 == count {
                next["phase"] = serde_json::json!("deleted");
            }
        }
        _ => {
            return Err(enzimos_platform::Error(
                "Root receipt phase has no online successor".into(),
            ));
        }
    }
    crate::root_retirement_record::validate(&next, id)?;
    Ok(next)
}
fn validate_progress_transition(before: &Value, next: &Value, id: &str) -> Result<()> {
    crate::root_retirement_record::validate(before, id)?;
    crate::root_retirement_record::validate(next, id)?;
    require(
        *next == next_progress(before)?,
        "online progress changed original identity or skipped a step",
    )
}
fn validate_abandon_transition(before: &Value, next: &Value, id: &str) -> Result<()> {
    crate::root_retirement_record::validate(before, id)?;
    crate::root_retirement_record::validate(next, id)?;
    require(
        before["schema"] == 1
            && before.get("coordinator").is_none()
            && matches!(before["phase"].as_str(), Some("prepared" | "executing")),
        "only an unstaged, undeleted Root receipt may be abandoned",
    )?;
    let mut expected = before.clone();
    expected["phase"] = serde_json::json!("abandoned");
    require(
        *next == expected,
        "abandonment changed original identity or progress",
    )
}
fn validate_completion_transition(before: &Value, next: &Value, id: &str) -> Result<()> {
    crate::root_retirement_record::validate(before, id)?;
    crate::root_retirement_record::validate(next, id)?;
    require(
        before["phase"] == "deleted",
        "only original deleted receipt may complete",
    )?;
    let mut expected = before.clone();
    expected["phase"] = serde_json::json!("complete");
    require(
        next == &expected,
        "finish changed original identity/coordinator/deletion cursor",
    )
}
