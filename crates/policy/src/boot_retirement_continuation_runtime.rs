// SPDX-License-Identifier: MIT
//! One explicit fresh continuation over original objects, never a decoded executor.
use super::*;
use crate::boot_volume::{ReplacedArtifact, RetiredArtifact};
use enzimos_platform::{
    named_retirement::{Quarantined, Removed},
    publication,
};
struct Runtime<'a, 'u> {
    admission: Admission<'a>,
    approval: Approval,
    journal: ContinuationJournal,
    authorize: &'u mut dyn FnMut() -> Result<()>,
    retired: BTreeMap<PathBuf, RetiredArtifact>,
    bios: Option<ReplacedArtifact>,
    directory: Option<(Directory, Removed)>,
    catalog_done: bool,
}
impl Runtime<'_, '_> {
    fn barrier(&self) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        self.admission.guard.recheck()?;
        self.admission.lock.recheck()?;
        self.admission.volume.writable()?;
        self.approval.require_journal(&self.journal)?;
        self.admission
            .registry
            .recheck_boot_continuation(&self.journal)?;
        self.journal
            .require_original_observation(&self.admission.record)?;
        self.admission
            .references
            .as_ref()
            .ok_or_else(|| Error("original continuation references missing".into()))?
            .recheck_owned(&self.journal)
    }
    fn verify(&mut self) -> Result<()> {
        (self.authorize)()?;
        self.barrier()?;
        self.admission.catalog.recheck()?;
        require(
            self.admission.guard.backup_root_binding()? == self.admission.source,
            "original continuation source changed outside owned operation",
        )?;
        for directory in self.admission.directories.values() {
            directory.recheck(&self.admission.volume)?;
        }
        for artifact in self.admission.artifacts.values() {
            artifact.recheck()?;
        }
        for retired in self.retired.values() {
            retired.recheck()?;
        }
        if let Some(bios) = &self.bios {
            bios.recheck()?;
        }
        if let Some((original, removed)) = &self.directory {
            removed.recheck()?;
            require(
                files::identity(&original.file.metadata()?)
                    == files::identity(&removed.descriptor()?.metadata()?)
                    && mount_identity::id(original.file.as_fd(), true)?
                        == self.admission.volume.unique,
                "actual original removed generation directory changed",
            )?;
        }
        self.admission
            .loaders
            .as_ref()
            .ok_or_else(|| Error("original loader closure missing".into()))?
            .recheck_owned(&self.admission, &self.journal, self.bios.as_ref())?;
        self.admission
            .signed
            .as_ref()
            .ok_or_else(|| Error("original signed closure missing".into()))?
            .recheck_owned(&self.admission, &self.journal, &self.retired)?;
        self.barrier()?;
        (self.authorize)()
    }
    fn state(&self, index: usize) -> Result<String> {
        self.barrier()?;
        match &self.admission.roles[index] {
            Role::Catalog => {
                self.admission.catalog.recheck()?;
                json::fingerprint(&self.admission.catalog.data)
            }
            Role::File(path) => {
                if path == Path::new("limine/limine.conf")
                    && let Some(bios) = &self.bios
                {
                    return crate::boot_retirement_plan::file_state(&json::sha256(
                        &files::read_file(
                            bios.file()?,
                            crate::boot_entries::MAX_TEXT,
                            Some(0),
                            true,
                        )?,
                    ));
                }
                if let Some(artifact) = self.admission.artifacts.get(path) {
                    artifact.recheck()?;
                    crate::boot_retirement_plan::file_state(&artifact.sha)
                } else {
                    let full = self.admission.volume.path(path)?;
                    if let Some(retired) = self.retired.get(&full) {
                        retired.recheck()?;
                    } else {
                        require(
                            self.admission.observed_states[index]
                                == json::fingerprint(&value!({"absent":true}))?,
                            "new absence lacks original baseline or actual owned removal",
                        )?;
                    }
                    // Actual original parent memberships remain held/rechecked;
                    // a recreated member cannot be accepted as a recorded absence.
                    for directory in self.admission.directories.values() {
                        directory.recheck(&self.admission.volume)?;
                    }
                    json::fingerprint(&value!({"absent":true}))
                }
            }
            Role::Directory(path) => {
                if let Some(directory) = self.admission.directories.get(path) {
                    directory.recheck(&self.admission.volume)?;
                    json::fingerprint(&value!({"absent":false,"members":directory.names}))
                } else {
                    if let Some((_, removed)) = &self.directory {
                        removed.recheck()?;
                    } else {
                        require(
                            self.admission.observed_states[index]
                                == json::fingerprint(&value!({"absent":true}))?,
                            "directory absence lacks actual original baseline or owned removal",
                        )?;
                    }
                    json::fingerprint(&value!({"absent":true}))
                }
            }
        }
    }
    fn persist(&mut self, next: Value) -> Result<()> {
        self.verify()?;
        let guard = self.admission.guard;
        let lock = self.admission.lock;
        let authorize = &mut self.authorize;
        // Atomic original receipt replacement performs its own descriptor/name
        // checks. Full cross-family joins run immediately before and after it;
        // never invoke a named-old-row check during its known own rename.
        self.journal.publish(&next, &mut || {
            guard.recheck()?;
            lock.recheck()?;
            authorize()
        })?;
        self.verify()
    }
    fn remove_file(&mut self, path: &Path) -> Result<()> {
        self.verify()?;
        let artifact = self
            .admission
            .artifacts
            .get(path)
            .ok_or_else(|| Error("actual original continuation artifact missing".into()))?;
        let parent = self.admission.volume.directory(path.parent().unwrap())?;
        let guard = self.admission.guard;
        let lock = self.admission.lock;
        let references = self.admission.references.as_ref().unwrap();
        let journal = &self.journal;
        let loaders = self.admission.loaders.as_ref().unwrap();
        let authorize = &mut self.authorize;
        let mut permission = || {
            guard.recheck()?;
            lock.recheck()?;
            references.recheck_owned(journal)?;
            loaders.recheck_live_boot()?;
            authorize()
        };
        let removed = artifact
            .quarantine_original(&parent, 256 * 1024 * 1024, &mut permission)?
            .unlink(&mut permission)?;
        let artifact = self
            .admission
            .artifacts
            .remove(path)
            .ok_or_else(|| Error("actual original artifact already retired".into()))?;
        let retired = artifact.into_retired(removed)?;
        self.admission
            .directories
            .get_mut(path.parent().unwrap())
            .ok_or_else(|| Error("original continuation artifact parent missing".into()))?
            .advance_removed(
                &self.admission.volume,
                retired.removal()?,
                path.file_name().unwrap().to_str().unwrap(),
            )?;
        self.admission.loaders.as_mut().unwrap().retire_original(
            &self.admission.volume,
            path,
            &retired,
        )?;
        if path.starts_with("enzimos/secure-boot") {
            self.admission
                .signed
                .as_mut()
                .unwrap()
                .retire_original_image(&self.admission.volume, path, &retired)?;
        }
        let full = self.admission.volume.path(path)?;
        require(
            self.retired.insert(full, retired).is_none(),
            "actual continuation artifact cannot retire twice",
        )?;
        self.verify()
    }
    fn rewrite_bios(&mut self) -> Result<()> {
        self.verify()?;
        require(
            self.bios.is_none(),
            "actual original BIOS rewrite cannot replay",
        )?;
        let path = Path::new("limine/limine.conf");
        let artifact = self
            .admission
            .artifacts
            .get(path)
            .ok_or_else(|| Error("actual original BIOS source missing".into()))?;
        let old = files::read_file(&artifact.file, crate::boot_entries::MAX_TEXT, Some(0), true)?;
        let generation = self.journal.id().strip_prefix("boot-").unwrap();
        let text = crate::boot_retirement_plan::without_bios(
            std::str::from_utf8(&old).map_err(|_| Error("original BIOS text encoding".into()))?,
            generation,
        )?;
        let guard = self.admission.guard;
        let lock = self.admission.lock;
        let references = self.admission.references.as_ref().unwrap();
        let journal = &self.journal;
        let loaders = self.admission.loaders.as_ref().unwrap();
        let authorize = &mut self.authorize;
        let mut permission = || {
            guard.recheck()?;
            lock.recheck()?;
            references.recheck_owned(journal)?;
            loaders.recheck_live_boot()?;
            authorize()
        };
        let pending = publication::Prepared::write_authorized(
            &self.admission.volume.path(path)?,
            text.as_bytes(),
            0,
            &mut permission,
        )?;
        artifact.require_original_publication(&pending)?;
        let committed = pending.commit_retained_authorized(true, &mut permission)?;
        let original = self
            .admission
            .artifacts
            .remove(path)
            .ok_or_else(|| Error("actual original BIOS artifact already replaced".into()))?;
        let replaced = original.into_replaced(committed)?;
        // Another retained loader descriptor is joined to this actual owned
        // replacement before its old view is retired.
        self.admission.loaders.as_mut().unwrap().replace_bios(
            &self.admission.volume,
            &replaced,
            &text,
        )?;
        self.admission
            .directories
            .get_mut(Path::new("limine"))
            .ok_or_else(|| Error("actual original BIOS parent missing".into()))?
            .advance_replaced(&self.admission.volume, &replaced, "limine.conf")?;
        self.bios = Some(replaced);
        self.verify()
    }
    fn remove_directory(&mut self, path: &Path) -> Result<()> {
        self.verify()?;
        require(
            self.directory.is_none(),
            "actual original generation directory cannot retire twice",
        )?;
        let original = self
            .admission
            .directories
            .get(path)
            .ok_or_else(|| Error("actual original generation directory missing".into()))?;
        require(
            original.names.is_empty() && files::directory_is_empty(&original.file)?,
            "actual original generation directory still has members",
        )?;
        let parent = self.admission.volume.directory(path.parent().unwrap())?;
        let before = files::identity(&original.file.metadata()?);
        let guard = self.admission.guard;
        let lock = self.admission.lock;
        let references = self.admission.references.as_ref().unwrap();
        let journal = &self.journal;
        let loaders = self.admission.loaders.as_ref().unwrap();
        let authorize = &mut self.authorize;
        let mut permission = || {
            guard.recheck()?;
            lock.recheck()?;
            references.recheck_owned(journal)?;
            loaders.recheck_live_boot()?;
            authorize()
        };
        let removed = Quarantined::enter_original(
            &parent,
            &original.file,
            Path::new(path.file_name().unwrap()),
            0,
            65536,
            before,
            &mut permission,
        )?
        .unlink(&mut permission)?;
        require(
            removed.before_epoch()? == before
                && files::identity(&removed.descriptor()?.metadata()?)
                    == files::identity(&original.file.metadata()?),
            "actual original empty generation removal differs",
        )?;
        let original = self.admission.directories.remove(path).unwrap();
        self.admission
            .directories
            .get_mut(path.parent().unwrap())
            .ok_or_else(|| Error("actual original generations parent missing".into()))?
            .advance_removed(
                &self.admission.volume,
                &removed,
                path.file_name().unwrap().to_str().unwrap(),
            )?;
        self.admission.loaders.as_mut().unwrap().retire_directory(
            &self.admission.volume,
            path,
            &removed,
        )?;
        self.directory = Some((original, removed));
        self.verify()
    }
    fn apply(&mut self, index: usize) -> Result<()> {
        let role = self.admission.roles[index].clone();
        match role {
            Role::File(path) if path == Path::new("limine/limine.conf") => self.rewrite_bios(),
            Role::File(path) => self.remove_file(&path),
            Role::Directory(path) => self.remove_directory(&path),
            Role::Catalog => {
                self.verify()?;
                require(
                    !self.catalog_done,
                    "actual owned catalog commit cannot replay",
                )?;
                for i in 0..index {
                    require(
                        self.state(i)? == self.journal.current()?["intent"]["steps"][i]["after"],
                        "actual original resource closure not after before catalog commit",
                    )?;
                }
                let before = self.journal.current()?.clone();
                let generation = self.journal.id().strip_prefix("boot-").unwrap();
                let after = crate::boot_retirement_plan::tombstone(
                    &self.admission.catalog.data,
                    generation,
                    before["intent"]["created_boot"].as_str().unwrap(),
                )?;
                require(
                    json::fingerprint(&after)? == before["intent"]["steps"][index]["after"],
                    "fresh catalog tombstone differs from recorded immutable outcome",
                )?;
                let guard = self.admission.guard;
                let lock = self.admission.lock;
                let references = self.admission.references.as_ref().unwrap();
                let journal = &self.journal;
                let loaders = self.admission.loaders.as_ref().unwrap();
                let authorize = &mut self.authorize;
                self.admission.catalog.data = after;
                self.admission.catalog.commit_owned_authorized(&mut || {
                    guard.recheck()?;
                    lock.recheck()?;
                    references.recheck_owned(journal)?;
                    loaders.recheck_live_boot()?;
                    authorize()
                })?;
                self.catalog_done = true;
                self.verify()
            }
        }
    }
    fn execute(&mut self, progress: &mut dyn FnMut(&str) -> Result<()>) -> Result<Value> {
        self.verify()?;
        let mut record = self.journal.current()?.clone();
        if record["phase"] == "complete" {
            return Ok(
                value!({"status":"retirement-already-complete","id":self.journal.id(),"root_subvolume_retained":true}),
            );
        }
        if record["phase"] == "prepared" {
            record["phase"] = value!("executing");
            self.persist(record.clone())?;
        }
        let count = self.admission.roles.len();
        for index in record["next_step"].as_u64().unwrap() as usize..count {
            self.verify()?;
            for prior in 0..index {
                require(
                    self.state(prior)? == record["intent"]["steps"][prior]["after"],
                    "completed actual original continuation resource drift",
                )?;
            }
            let step = record["intent"]["steps"][index].clone();
            let observed = self.state(index)?;
            if record["inflight"].is_null() {
                require(
                    step["before"] == observed,
                    "unstarted continuation resource changed; adoption refused",
                )?;
                record["inflight"] = value!(index);
                self.persist(record.clone())?;
            } else {
                require(
                    record["inflight"] == index
                        && (step["before"] == observed || step["after"] == observed),
                    "actual interrupted continuation outcome unknown",
                )?;
            }
            if step["before"] == observed {
                progress("finishing")?;
                self.apply(index)?;
            }
            self.verify()?;
            require(
                self.state(index)? == step["after"],
                "actual owned continuation side effect not durably observed",
            )?;
            record["next_step"] = value!(index + 1);
            record["inflight"] = Value::Null;
            self.persist(record.clone())?;
        }
        self.verify()?;
        for index in 0..count {
            require(
                self.state(index)? == record["intent"]["steps"][index]["after"],
                "final actual original continuation resource drift",
            )?;
        }
        record["phase"] = value!("complete");
        self.persist(record)?;
        Ok(
            value!({"status":"retirement-complete","id":self.journal.id(),"generation":self.journal.id().strip_prefix("boot-").unwrap(),"root_subvolume_retained":true,"automatic_replay":false}),
        )
    }
}
pub fn resume_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    review_sha256: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    authorize()?;
    let admission = Admission::observe(guard, lock, id)?;
    let approval = Approval::admit(&admission, review_sha256)?;
    let journal = ContinuationJournal::observe(&admission)?;
    approval.require_journal(&journal)?;
    let mut runtime = Runtime {
        admission,
        approval,
        journal,
        authorize,
        retired: BTreeMap::new(),
        bios: None,
        directory: None,
        catalog_done: false,
    };
    runtime.verify()?;
    runtime.execute(progress)
}
