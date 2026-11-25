// SPDX-License-Identifier: MIT
//! Original ledger inodes and exclusion survive every owned record transition.
use super::{operation_record as record, system_wire::hex};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const CAPACITY: usize = 128;
/// Finished rows kept as history once the ledger fills; older ones are retired.
const RETAINED_FINISHED: usize = 48;
/// Unsubmitted plans older than this are abandoned and may be retired.
const ABANDONED_PLAN_SECONDS: i64 = 3600;
/// One caller can hold at most this many unsubmitted plans at a time.
const PLANS_PER_OWNER: usize = 16;
/// Closed set of providers whose own server-created row changes during retirement.
#[cfg(feature = "update-worker")]
pub(crate) fn retirement_operation(operation: &str) -> bool {
    matches!(
        operation,
        "boot-retire" | "root-retire-prepare" | "root-retire-stage" | "root-retire-finish"
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Operations,
    History,
    #[cfg(feature = "update-worker")]
    Backup,
}
struct Epoch {
    file: File,
    identity: files::FileIdentity,
    body: Value,
}
pub struct Store<G> {
    path: PathBuf,
    directory: File,
    shape: (u64, u64, u32, u32, u32),
    mount: u64,
    lock: files::Lock,
    lock_identity: files::FileIdentity,
    owner: u32,
    epochs: BTreeMap<String, Epoch>,
    guard: G,
    kind: Kind,
}
fn shape(file: &File, owner: u32) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o7777 == 0o700,
        "job-storage-unsafe",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
impl<G: Fn() -> Result<()>> Store<G> {
    pub fn open(path: &Path, guard: G) -> Result<Self> {
        Self::open_owned(path, 0, guard)
    }
    pub(crate) fn open_owned(path: &Path, owner: u32, guard: G) -> Result<Self> {
        Self::open_kind(path, owner, guard, Kind::Operations)
    }
    pub(crate) fn open_history(path: &Path, owner: u32, guard: G) -> Result<Self> {
        Self::open_kind(path, owner, guard, Kind::History)
    }
    #[cfg(feature = "update-worker")]
    pub(crate) fn open_backup(path: &Path, owner: u32, guard: G) -> Result<Self> {
        Self::open_kind(path, owner, guard, Kind::Backup)
    }
    fn open_kind(path: &Path, owner: u32, guard: G, kind: Kind) -> Result<Self> {
        guard()?;
        let directory = files::ensure_directory(path, 0o700, owner)?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let lock = files::Lock::try_acquire(&path.join("lock"), owner)?
            .ok_or_else(|| Error("job-store-busy".into()))?;
        let lock_identity = files::identity(&lock.as_file().metadata()?);
        let mut store = Self {
            path: path.into(),
            shape: shape(&directory, owner)?,
            directory,
            mount,
            lock,
            lock_identity,
            owner,
            epochs: BTreeMap::new(),
            guard,
            kind,
        };
        store.recheck()?;
        // Enumeration stays on the retained directory description. Startup may
        // observe historical receipts; a live service never adopts a new epoch.
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", store.directory.as_raw_fd()))? {
            let name = entry?.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error("job-store-needs-review".into()))?;
            if name == "lock" {
                continue;
            }
            if name.starts_with(".enzimos-write-") {
                // A write interrupted by a crash left its private temporary inode;
                // it was never published, so removing it loses nothing.
                store.remove_interrupted_write(name)?;
                continue;
            }
            let id = name
                .strip_suffix(".json")
                .filter(|s| hex(s, 32))
                .ok_or_else(|| Error("job-store-needs-review".into()))?;
            require(store.epochs.len() < CAPACITY, "job-capacity")?;
            let file = files::open_relative(&store.directory, Path::new(name))?;
            let identity = files::identity(&file.metadata()?);
            let body = json::decode(
                &files::read_file(&file, record::MAX_DOCUMENT, Some(owner), true)?,
                record::MAX_DOCUMENT,
            )?;
            store.validate(&body)?;
            require(body["request_id"] == id, "job-record-invalid")?;
            store.epochs.insert(
                id.into(),
                Epoch {
                    file,
                    identity,
                    body,
                },
            );
        }
        store.recheck_all()?;
        let active = store
            .epochs
            .iter()
            .filter(|(_, e)| match kind {
                Kind::Operations => matches!(e.body["state"].as_str(), Some("queued" | "running")),
                Kind::History => matches!(e.body["state"].as_str(), Some("prepared" | "running")),
                #[cfg(feature = "update-worker")]
                Kind::Backup => matches!(
                    e.body["state"].as_str(),
                    Some(
                        "review-awaiting-approval" | "reviewing" | "awaiting-approval" | "running"
                    )
                ),
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in active {
            let mut next = store.epochs[&id].body.clone();
            next["state"] = value!("uncertain");
            store.publish(&id, next)?;
        }
        Ok(store)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn remove_interrupted_write(&self, name: &str) -> Result<()> {
        let file = files::open_relative(&self.directory, Path::new(name))?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == self.owner
                && m.nlink() == 1
                && m.len() <= record::MAX_DOCUMENT as u64,
            "job-store-needs-review",
        )?;
        let c_name =
            std::ffi::CString::new(name).map_err(|_| Error("job-store-needs-review".into()))?;
        require(
            // SAFETY: `c_name` is a NUL-terminated CString and `self.directory` keeps the
            // descriptor open.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), c_name.as_ptr(), 0) } == 0,
            "job-store-needs-review",
        )?;
        self.directory.sync_all()?;
        Ok(())
    }
    fn validate(&self, body: &Value) -> Result<()> {
        match self.kind {
            Kind::Operations => record::validate(body),
            Kind::History => super::jobs::validate(
                body,
                body["request_id"]
                    .as_str()
                    .ok_or_else(|| Error("job-record-invalid".into()))?,
            ),
            #[cfg(feature = "update-worker")]
            Kind::Backup => super::backup_setup_record::validate(body),
        }
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    fn recheck(&self) -> Result<()> {
        (self.guard)()?;
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&self.directory, self.owner)? == self.shape
                && shape(&named, self.owner)? == self.shape
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "job-storage-unsafe",
        )?;
        let named = files::open_relative(&self.directory, Path::new("lock"))?;
        let held = self.lock.as_file();
        require(
            files::identity(&held.metadata()?) == self.lock_identity
                && files::identity(&named.metadata()?) == self.lock_identity
                && self.lock_identity.2 == 0
                && self.lock_identity.7 & 0o7777 == 0o600
                && self.lock_identity.8 == self.owner
                && self.lock_identity.9 == self.owner
                && self.lock_identity.10 == 1
                && mount_identity::id(held.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "job-storage-unsafe",
        )?;
        enzimos_platform::flock_identity::exclusive(held)?;
        // SAFETY: flock takes no pointers and `named` keeps the descriptor open.
        let rc = unsafe { libc::flock(named.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let error = std::io::Error::last_os_error();
        require(
            rc == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "job-storage-unsafe",
        )?;
        enzimos_platform::flock_identity::exclusive(held)
    }
    fn recheck_epoch(&self, id: &str) -> Result<()> {
        self.recheck()?;
        let e = self
            .epochs
            .get(id)
            .ok_or_else(|| Error("job-not-found".into()))?;
        let named = files::open_relative(&self.directory, Path::new(&format!("{id}.json")))?;
        require(
            files::identity(&e.file.metadata()?) == e.identity
                && files::identity(&named.metadata()?) == e.identity
                && e.identity.7 & 0o7777 == 0o600
                && e.identity.8 == self.owner
                && e.identity.9 == self.owner
                && e.identity.10 == 1
                && mount_identity::id(e.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && json::decode(
                    &files::read_file(&e.file, record::MAX_DOCUMENT, Some(self.owner), true)?,
                    record::MAX_DOCUMENT,
                )? == e.body,
            "job-storage-unsafe",
        )
    }
    fn recheck_all(&self) -> Result<()> {
        self.recheck()?;
        let mut seen = 0;
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))? {
            let name = entry?.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error("job-store-needs-review".into()))?;
            if name == "lock" {
                continue;
            }
            let id = name
                .strip_suffix(".json")
                .ok_or_else(|| Error("job-store-needs-review".into()))?;
            require(self.epochs.contains_key(id), "job-store-needs-review")?;
            self.recheck_epoch(id)?;
            seen += 1;
        }
        require(seen == self.epochs.len(), "job-store-needs-review")
    }
    /// Finished rows never change again; uncertain rows still need review and stay.
    fn finished(&self, body: &Value) -> bool {
        match self.kind {
            Kind::Operations => matches!(body["state"].as_str(), Some("completed" | "cancelled")),
            Kind::History => body["state"] == "completed",
            #[cfg(feature = "update-worker")]
            Kind::Backup => matches!(
                body["state"].as_str(),
                Some("completed" | "cancelled" | "rolled-back")
            ),
        }
    }
    fn unsubmitted(&self, body: &Value) -> bool {
        match self.kind {
            Kind::Operations => body["state"] == "planned",
            Kind::History => false,
            #[cfg(feature = "update-worker")]
            Kind::Backup => matches!(
                body["state"].as_str(),
                Some("planned" | "review-awaiting-approval")
            ),
        }
    }
    /// Make room before a new row: retire finished rows beyond a recent history
    /// and plans abandoned for an hour, each by its exact retained inode.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn retire(&mut self) -> Result<()> {
        if self.epochs.len() + 8 < CAPACITY {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let mut finished = Vec::new();
        let mut abandoned = Vec::new();
        for (id, epoch) in &self.epochs {
            let modified = epoch.identity.3;
            if self.finished(&epoch.body) {
                finished.push((modified, id.clone()));
            } else if self.unsubmitted(&epoch.body) && now - modified > ABANDONED_PLAN_SECONDS {
                abandoned.push(id.clone());
            }
        }
        finished.sort();
        let excess = finished.len().saturating_sub(RETAINED_FINISHED);
        let victims = finished
            .into_iter()
            .take(excess)
            .map(|(_, id)| id)
            .chain(abandoned)
            .collect::<Vec<_>>();
        for id in victims {
            self.recheck_epoch(&id)?;
            let name = std::ffi::CString::new(format!("{id}.json"))
                .map_err(|_| Error("job-record-invalid".into()))?;
            require(
                // SAFETY: `name` is a NUL-terminated CString and `self.directory` keeps the
                // descriptor open.
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == 0,
                "job-storage-unsafe",
            )?;
            self.epochs.remove(&id);
        }
        self.directory.sync_all()?;
        self.recheck_all()
    }
    pub(crate) fn publish(&mut self, id: &str, next: Value) -> Result<()> {
        self.recheck_all()?;
        self.validate(&next)?;
        require(
            next["request_id"] == id && hex(id, 32),
            "job-request-invalid",
        )?;
        let name = format!("{id}.json");
        let bytes = record::canonical(&next)?;
        let file = if let Some(previous) = self.epochs.get(id) {
            match self.kind {
                Kind::Operations => record::transition(&previous.body, &next)?,
                Kind::History => super::jobs::transition(&previous.body, &next)?,
                #[cfg(feature = "update-worker")]
                Kind::Backup => super::backup_setup_record::transition(&previous.body, &next)?,
            }
            files::atomic_replace_original(
                &self.directory,
                Path::new(&name),
                &bytes,
                0o600,
                Some(self.owner),
                record::MAX_DOCUMENT,
                &previous.file,
            )?
        } else {
            self.retire()?;
            let owner_plans = self
                .epochs
                .values()
                .filter(|e| e.body["owner_uid"] == next["owner_uid"] && self.unsubmitted(&e.body))
                .count();
            require(owner_plans < PLANS_PER_OWNER, "job-capacity")?;
            require(
                self.epochs.len() < CAPACITY
                    && match self.kind {
                        Kind::Operations => next["state"] == "planned",
                        Kind::History => next["state"] == "prepared",
                        #[cfg(feature = "update-worker")]
                        Kind::Backup => {
                            matches!(
                                next["state"].as_str(),
                                Some("planned" | "review-awaiting-approval")
                            ) && next["attempts"] == 0
                        }
                    },
                "job-capacity",
            )?;
            files::atomic_relative_retained(
                &self.directory,
                Path::new(&name),
                &bytes,
                0o600,
                Some(self.owner),
                false,
                record::MAX_DOCUMENT,
            )?
        };
        self.epochs.insert(
            id.into(),
            Epoch {
                identity: files::identity(&file.metadata()?),
                file,
                body: next,
            },
        );
        self.recheck_all()
    }
    pub fn status(&self, id: &str, uid: u32) -> Result<Value> {
        require(hex(id, 32) && uid < u32::MAX, "job-request-invalid")?;
        self.recheck_all()?;
        let e = self
            .epochs
            .get(id)
            .ok_or_else(|| Error("job-not-found".into()))?;
        require(e.body["owner_uid"] == uid, "job-owner-mismatch")?;
        Ok(e.body.clone())
    }
    #[cfg(feature = "update-worker")]
    pub(crate) fn optional_status(&self, id: &str, uid: u32) -> Result<Option<Value>> {
        self.recheck_all()?;
        if self.epochs.contains_key(id) {
            self.status(id, uid).map(Some)
        } else {
            Ok(None)
        }
    }
    pub fn plan<F: FnOnce() -> Result<Value>>(
        &mut self,
        id: &str,
        uid: u32,
        operation: &str,
        make: F,
    ) -> Result<Value> {
        require(self.kind == Kind::Operations, "job-record-invalid")?;
        require(hex(id, 32) && uid < u32::MAX, "job-request-invalid")?;
        self.recheck_all()?;
        if self.epochs.contains_key(id) {
            let e = self.status(id, uid)?;
            require(e["operation"] == operation, "job-request-invalid")?;
            return Ok(e);
        }
        self.retire()?;
        require(self.epochs.len() < CAPACITY, "job-capacity")?;
        let body = record::initial(id, uid, operation, make()?)?;
        self.publish(id, body.clone())?;
        Ok(body)
    }
    pub fn advance(
        &mut self,
        id: &str,
        uid: u32,
        digest: &str,
        state: &str,
        progress: &str,
        result: Value,
    ) -> Result<Value> {
        require(self.kind == Kind::Operations, "job-record-invalid")?;
        let mut next = self.status(id, uid)?;
        require(
            hex(digest, 64) && next["plan_sha256"] == digest,
            "job-plan-changed",
        )?;
        next["state"] = value!(state);
        next["progress"] = value!(progress);
        next["result"] = result;
        self.publish(id, next.clone())?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests;

/// Only the original held ledger creates this observation. Decoded records do
/// not grant exemption, mutation, receipt completion or filesystem retirement.
#[cfg(feature = "update-worker")]
pub(crate) struct References {
    directory: File,
    shape: (u64, u64, u32, u32, u32),
    mount: u64,
    lock: File,
    lock_identity: files::FileIdentity,
    owner: u32,
    names: std::collections::BTreeSet<String>,
    epochs: BTreeMap<String, Epoch>,
    own: Option<(String, Value)>,
}
#[cfg(feature = "update-worker")]
impl References {
    pub(crate) fn recheck<G: Fn() -> Result<()>>(&self, store: &Store<G>) -> Result<()> {
        store.recheck_all()?;
        require(
            store.kind == Kind::Operations
                && store.owner == self.owner
                && shape(&self.directory, self.owner)? == self.shape
                && store.shape == self.shape
                && store.mount == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && files::identity(&self.lock.metadata()?) == self.lock_identity
                && store.lock_identity == self.lock_identity,
            "original retirement ledger changed",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.lock)?;
        require(
            store
                .epochs
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                == self.names,
            "original retirement ledger membership changed",
        )?;
        for (id, original) in &self.epochs {
            let current = &store.epochs[id];
            require(
                files::identity(&original.file.metadata()?) == original.identity
                    && current.identity == original.identity
                    && current.body == original.body
                    && json::decode(
                        &files::read_file(
                            &original.file,
                            record::MAX_DOCUMENT,
                            Some(self.owner),
                            true,
                        )?,
                        record::MAX_DOCUMENT,
                    )? == original.body
                    && mount_identity::id(original.file.as_fd(), true)? == self.mount,
                "original retirement ledger record replaced/changed",
            )?;
        }
        if let Some((id, before)) = &self.own {
            let current = &store.epochs[id].body;
            require(
                current["operation"]
                    .as_str()
                    .is_some_and(retirement_operation)
                    && matches!(
                        current["state"].as_str(),
                        Some("planned" | "queued" | "running")
                    )
                    && (before["state"] == "planned" || current["state"] != "planned")
                    && (before["state"] != "running" || current["state"] == "running")
                    && [
                        "request_id",
                        "owner_uid",
                        "operation",
                        "plan",
                        "plan_sha256",
                    ]
                    .iter()
                    .all(|k| current[*k] == before[*k])
                    && current["result"].is_null(),
                "original retirement own job exemption changed",
            )?;
        }
        Ok(())
    }
    /// Return observed data only, after rechecking actual original ledger actors.
    pub(crate) fn records<G: Fn() -> Result<()>>(&self, store: &Store<G>) -> Result<Value> {
        self.recheck(store)?;
        Ok(value!(
            self.epochs
                .iter()
                .map(|(id, epoch)| (id.clone(), epoch.body.clone()))
                .collect::<BTreeMap<_, _>>()
        ))
    }
    pub(crate) fn evidence<G: Fn() -> Result<()>>(&self, store: &Store<G>) -> Result<Value> {
        self.recheck(store)?;
        Ok(
            value!({"directory":self.shape,"mount":self.mount,"lock":self.lock_identity,"epochs":self.epochs.iter().map(|(id,e)| (id.clone(),e.identity)).collect::<BTreeMap<_,_>>(),"own_request":self.own.as_ref().map(|(id,_)| id)}),
        )
    }

    /// Compare a Root target against the actual immutable server-owned request.
    /// This supplies no deletion authority and does not exempt any other row.
    pub(crate) fn require_root_target<G: Fn() -> Result<()>>(
        &self,
        store: &Store<G>,
        filesystem_uuid: &str,
        root_uuid: &str,
        plan_sha256: &str,
    ) -> Result<()> {
        enzimos_policy::identity::uuid(filesystem_uuid)?;
        enzimos_policy::identity::uuid(root_uuid)?;
        enzimos_policy::identity::sha(plan_sha256)?;
        self.recheck(store)?;
        if let Some((_, own)) = &self.own {
            let selection = &own["plan"]["selection"];
            let matched = match own["operation"].as_str() {
                Some("root-retire-prepare") => {
                    selection["root_uuid"] == root_uuid && selection["plan_sha256"] == plan_sha256
                }
                Some("root-retire-stage" | "root-retire-finish") => {
                    selection["id"] == format!("root-{}", root_uuid.replace('-', ""))
                }
                _ => false,
            };
            require(
                matched
                    && own["plan"]["observation"]["filesystem_uuid"] == filesystem_uuid
                    && own["plan"]["observation"]["plan_sha256"] == plan_sha256,
                "original job exemption is for another Root retirement target",
            )?;
        }
        self.recheck(store)
    }
    pub(crate) fn require_unmentioned<G: Fn() -> Result<()>>(
        &self,
        store: &Store<G>,
        generation: &str,
    ) -> Result<()> {
        self.require_unmentioned_inner(store, generation, None)
    }
    pub(crate) fn require_unmentioned_with_conclusions<G: Fn() -> Result<()>>(
        &self,
        store: &Store<G>,
        generation: &str,
        conclusions: &enzimos_policy::recovery_conclusions::Observation<'_>,
    ) -> Result<()> {
        conclusions.recheck()?;
        self.require_unmentioned_inner(store, generation, Some(conclusions))?;
        conclusions.recheck()
    }
    fn require_unmentioned_inner<G: Fn() -> Result<()>>(
        &self,
        store: &Store<G>,
        generation: &str,
        conclusions: Option<&enzimos_policy::recovery_conclusions::Observation<'_>>,
    ) -> Result<()> {
        enzimos_policy::identity::safe_id(generation)?;
        self.recheck(store)?;
        if let Some((_, own)) = &self.own {
            require(
                own["operation"] == "boot-retire"
                    && own["plan"]["selection"]["generation"] == generation,
                "original job exemption is for another generation",
            )?;
        }
        for epoch in self.epochs.values() {
            require(
                matches!(
                    epoch.body["state"].as_str(),
                    Some("planned" | "completed" | "cancelled")
                ),
                "unfinished backend operation prevents boot retirement",
            )?;
            if epoch.body["state"] != "cancelled" {
                require(
                    !enzimos_policy::boot_retirement_plan::mentions(&epoch.body, generation)?
                        || conclusions
                            .map(|c| c.historical_backend_record(&epoch.body))
                            .transpose()?
                            .unwrap_or(false),
                    "original backend record protects boot generation",
                )?;
            }
        }
        self.recheck(store)
    }
}
#[cfg(feature = "update-worker")]
impl<G: Fn() -> Result<()>> Store<G> {
    pub(crate) fn reference_snapshot(&self, exempt: Option<&str>) -> Result<References> {
        self.recheck_all()?;
        require(
            self.kind == Kind::Operations,
            "original operation ledger required",
        )?;
        let own = exempt
            .map(|id| {
                let row = self
                    .epochs
                    .get(id)
                    .ok_or_else(|| Error("original retirement own request missing".into()))?;
                require(
                    row.body["operation"]
                        .as_str()
                        .is_some_and(retirement_operation)
                        && matches!(
                            row.body["state"].as_str(),
                            Some("planned" | "queued" | "running")
                        ),
                    "only original server-owned retirement job may be exempted",
                )?;
                Ok::<_, Error>((id.to_owned(), row.body.clone()))
            })
            .transpose()?;
        let epochs = self
            .epochs
            .iter()
            .filter(|(id, _)| Some(id.as_str()) != exempt)
            .map(|(id, e)| {
                Ok((
                    id.clone(),
                    Epoch {
                        file: e.file.try_clone()?,
                        identity: e.identity,
                        body: e.body.clone(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let snapshot = References {
            directory: self.directory.try_clone()?,
            shape: self.shape,
            mount: self.mount,
            lock: self.lock.as_file().try_clone()?,
            lock_identity: self.lock_identity,
            owner: self.owner,
            names: self.epochs.keys().cloned().collect(),
            epochs,
            own,
        };
        snapshot.recheck(self)?;
        Ok(snapshot)
    }
}
