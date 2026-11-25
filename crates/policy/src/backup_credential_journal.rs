// SPDX-License-Identifier: MIT
//! Original Root enrollment journal actors survive review; JSON cannot reopen them.
use crate::{backup_credential_record as record, storage_runtime::Guard};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const FOLDER: &str = "backup-credentials";
type Shape = (u64, u64, u32, u32, u32);
fn shape(f: &File, owner: u32) -> Result<Shape> {
    let m = f.metadata()?;
    require(
        m.is_dir()
            && m.uid() == owner
            && (owner != 0 || m.gid() == 0)
            && m.mode() & 0o7777 == 0o700,
        "original private credential enrollment directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
struct Row {
    file: File,
    epoch: files::FileIdentity,
    bytes: Vec<u8>,
    value: Value,
}
struct Store {
    path: PathBuf,
    directory: File,
    shape: Shape,
    mount: u64,
    owner: u32,
    rows: BTreeMap<String, Row>,
}
impl Store {
    fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for name in files::directory_names(&self.directory, record::CAPACITY)? {
            let name = name
                .into_string()
                .map_err(|_| enzimos_platform::Error("credential journal name encoding".into()))?;
            let id = name.strip_suffix(".json").ok_or_else(|| {
                enzimos_platform::Error(
                    "unknown/interrupted credential journal requires review".into(),
                )
            })?;
            crate::identity::safe_id(id)?;
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
    fn observe(path: &Path, owner: u32, mount: u64) -> Result<Self> {
        let directory = files::directory(path, Some(owner))?;
        require(
            mount_identity::id(directory.as_fd(), true)? == mount,
            "credential journal left original control mount",
        )?;
        let mut this = Self {
            path: path.into(),
            shape: shape(&directory, owner)?,
            directory,
            mount,
            owner,
            rows: BTreeMap::new(),
        };
        for name in this.names()? {
            let file = files::open_relative(&this.directory, Path::new(&name))?;
            let m = file.metadata()?;
            require(
                m.is_file()
                    && m.uid() == owner
                    && m.gid() == this.shape.3
                    && m.mode() & 0o7777 == 0o600
                    && m.nlink() == 1
                    && mount_identity::id(file.as_fd(), true)? == mount,
                "credential journal original inode authority",
            )?;
            let epoch = files::identity(&m);
            let bytes = files::read_file(&file, record::LIMIT, Some(owner), true)?;
            let value = json::decode(&bytes, record::LIMIT)?;
            record::validate(
                &value,
                name.strip_suffix(".json")
                    .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?,
            )?;
            require(
                files::identity(&file.metadata()?) == epoch,
                "credential journal changed during observation",
            )?;
            this.rows.insert(
                name,
                Row {
                    file,
                    epoch,
                    bytes,
                    value,
                },
            );
        }
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.directory, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && self.names()? == self.rows.keys().cloned().collect::<Vec<_>>(),
            "original credential journal directory/membership changed",
        )?;
        for (name, row) in &self.rows {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&named.metadata()?) == row.epoch
                    && files::identity(&row.file.metadata()?) == row.epoch
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && mount_identity::id(row.file.as_fd(), true)? == self.mount
                    && files::read_file(&row.file, record::LIMIT, Some(self.owner), true)?
                        == row.bytes
                    && files::identity(&named.metadata()?) == row.epoch
                    && files::identity(&row.file.metadata()?) == row.epoch,
                "original credential journal inode replaced or changed",
            )?;
        }
        Ok(())
    }
    fn prepared(&self, id: &str) -> Result<&Row> {
        self.recheck()?;
        crate::identity::safe_id(id)?;
        let name = format!("{id}.json");
        let row = self
            .rows
            .get(&name)
            .ok_or_else(|| enzimos_platform::Error("credential enrollment not found".into()))?;
        require(
            row.value["schema"] == 2
                && row.value["phase"] == "prepared"
                && self
                    .rows
                    .iter()
                    .all(|(other, r)| other == &name || r.value["phase"] == "complete"),
            "legacy, completed or other uncertain enrollment requires review; no replay",
        )?;
        Ok(row)
    }
}
/// Original admission. Completion consumes this actor plus the original sealed
/// worker report and actual whole-worker closure; evidence cannot recreate it.
pub struct Enrollment<'g> {
    identity: std::sync::Arc<()>,
    guard: &'g Guard,
    lock: &'g files::Lock,
    store: Store,
    id: String,
}
impl<'g> Enrollment<'g> {
    pub fn observe(guard: &'g Guard, lock: &'g files::Lock, id: &str) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        crate::identity::safe_id(id)?;
        let store = Store::observe(
            &Path::new(crate::operation::CONTROL).join(FOLDER),
            0,
            guard.control_mount_id(),
        )?;
        let this = Self {
            identity: std::sync::Arc::new(()),
            guard,
            lock,
            store,
            id: id.into(),
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.store.prepared(&self.id)?;
        self.guard.recheck()?;
        self.lock.recheck()
    }
    pub(crate) fn actor_identity(&self) -> Result<std::sync::Arc<()>> {
        self.recheck()?;
        Ok(std::sync::Arc::clone(&self.identity))
    }
    pub(crate) fn require_original(&self, guard: &Guard, lock: &files::Lock) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "credential enrollment requires original storage/operation actors",
        )?;
        self.recheck()
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.store.prepared(&self.id)?.file)
    }
    pub fn require_input(
        &self,
        candidate: &crate::backup_credential_candidate::Candidate<'_>,
    ) -> Result<()> {
        self.recheck()?;
        candidate.require_guard(self.guard)?;
        require(
            self.record()?["input_identity"] == *candidate.persistent_identity()?,
            "candidate input changed since original enrollment",
        )?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let row = self.store.prepared(&self.id)?;
        Ok(
            value!({"record":row.value,"file":row.epoch,"bytes_sha256":json::sha256(&row.bytes),
            "directory":self.store.shape,"mount":self.store.mount}),
        )
    }
    pub fn record(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.store.prepared(&self.id)?.value)
    }
    pub fn complete<'a>(
        mut self,
        closed: crate::backup_credential_report::Closed<'g>,
        candidate: &'a crate::backup_credential_candidate::Candidate<'g>,
        expected_review: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Completed<'a, 'g>> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        crate::identity::sha(expected_review)?;
        require(
            closed.review_sha256()? == expected_review,
            "credential review changed; review again",
        )?;
        let key = closed.require_enrollment(&self, candidate)?;
        let mut next = self.record()?.clone();
        next["phase"] = value!("complete");
        next["new_key"] = value!(key);
        record::validate(&next, &self.id)?;
        let mut bytes = json::canonical(&next)?;
        bytes.push(b'\n');
        require(
            bytes.len() <= record::LIMIT,
            "completed credential journal bound",
        )?;
        let name = format!("{}.json", self.id);
        // Sample fresh permission and every retained original immediately before
        // the sole atomic publication. No key creation or replay is performed.
        authorize()?;
        closed.require_enrollment(&self, candidate)?;
        require(
            closed.review_sha256()? == expected_review,
            "original credential review digest changed before completion",
        )?;
        let original = &self.store.prepared(&self.id)?.file;
        authorize()?;
        let file = files::atomic_replace_original(
            &self.store.directory,
            Path::new(&name),
            &bytes,
            0o600,
            Some(0),
            record::LIMIT,
            original,
        )?;
        let epoch = files::identity(&file.metadata()?);
        self.store.rows.insert(
            name,
            Row {
                file,
                epoch,
                bytes,
                value: next,
            },
        );
        let completed = Completed {
            guard: self.guard,
            lock: self.lock,
            store: self.store,
            id: self.id,
            key,
            closed,
            candidate,
        };
        completed.recheck()?;
        Ok(completed)
    }
}
/// Original completed inode and original typed review actors remain retained.
/// This supplies no credential replacement, export or old-key revocation.
pub struct Completed<'a, 'g> {
    guard: &'g Guard,
    lock: &'g files::Lock,
    store: Store,
    id: String,
    key: String,
    closed: crate::backup_credential_report::Closed<'g>,
    candidate: &'a crate::backup_credential_candidate::Candidate<'g>,
}
impl Completed<'_, '_> {
    pub fn result(&self) -> Result<Value> {
        self.recheck()?;
        let mut result = self.closed.result()?;
        result["receipt_completed"] = value!(true);
        require(
            result["new_key"] == self.key && result["enrollment"] == self.id,
            "completed credential result differs from original journal",
        )?;
        self.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.candidate.require_guard(self.guard)?;
        self.closed.recheck()?;
        self.store.recheck()?;
        let row = self
            .store
            .rows
            .get(&format!("{}.json", self.id))
            .ok_or_else(|| {
                enzimos_platform::Error("original completed enrollment missing".into())
            })?;
        record::validate(&row.value, &self.id)?;
        require(
            row.value["phase"] == "complete"
                && row.value["schema"] == 2
                && row.value["new_key"] == self.key
                && row.value["input_identity"] == *self.candidate.persistent_identity()?,
            "original completed enrollment or input changed",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let row = &self.store.rows[&format!("{}.json", self.id)];
        Ok(
            value!({"record":row.value,"file":row.epoch,"bytes_sha256":json::sha256(&row.bytes),
            "closed_review":self.closed.evidence()?,"enrollment_complete":true,
            "credential_exported":false,"old_access_revoked":false}),
        )
    }
}

/// Admit a fresh enrollment only from the original complete journal family.
/// The returned registry retains those same actual member descriptions across
/// its own known publication; no JSON snapshot can recreate that transition.
pub fn new_registry(
    guard: &Guard,
    id: &str,
) -> Result<enzimos_platform::receipt_registry::Registry> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    guard.recheck()?;
    let directory = files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
    require(
        mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
        "enrollment journal crossed original control mount",
    )?;
    let path = Path::new(crate::operation::CONTROL).join(FOLDER);
    let store = Store::observe(&path, 0, guard.control_mount_id())?;
    require(
        store.rows.len() < record::CAPACITY
            && !store.rows.contains_key(&format!("{id}.json"))
            && store
                .rows
                .values()
                .all(|row| row.value["phase"] == "complete"),
        "enrollment exists, capacity reached or uncertain prior outcome requires review; no replay",
    )?;
    let registry = enzimos_platform::receipt_registry::Registry::observe(
        &path,
        &directory,
        &format!("{id}.json"),
        0,
    )?;
    store.recheck()?;
    registry.require_original_members(
        &store
            .rows
            .iter()
            .map(|(name, row)| (name.clone(), &row.file))
            .collect(),
    )?;
    guard.recheck()?;
    Ok(registry)
}
