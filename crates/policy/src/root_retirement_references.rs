// SPDX-License-Identifier: MIT
//! Retain every original online registry/journal before Root retirement planning.
//! Read-only observation; the complete kernel mount/process gate remains separate.
use crate::{
    catalog::Transaction,
    control_registry::Snapshot as Registry,
    recovery_journal::{Journal, Kind},
    storage_runtime::Guard,
    transition_idle::Snapshot,
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json as value};
use std::os::fd::AsFd;

/// Supplied by the actual server-held backend ledger. Implementations retain
/// and recheck their original descriptions; JSON evidence is never an actor.
pub trait References {
    fn recheck(&self) -> Result<()>;
    fn records(&self) -> Result<Value>;
    fn planning_evidence(&self) -> Result<Value>;
}
#[expect(
    clippy::large_enum_variant,
    reason = "Built once per operation and rarely moved; boxing would only add an allocation."
)]
enum Backend<'a> {
    Standalone(crate::boot_backend_references::Observation<'a>),
    Server(&'a dyn References),
}
impl Backend<'_> {
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Standalone(actor) => actor.recheck(),
            Self::Server(actor) => actor.recheck(),
        }
    }
    fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = match self {
            Self::Standalone(actor) => actor.evidence()?,
            Self::Server(actor) => {
                value!({"records":actor.records()?, "original":actor.planning_evidence()?})
            }
        };
        self.recheck()?;
        Ok(result)
    }
}

pub struct Observation<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    source: Value,
    idle: Snapshot,
    catalog: std::sync::Arc<Transaction>,
    registries: Vec<Registry<'a>>,
    journals: Vec<Journal>,
    original: Value,
    backend: Backend<'a>,
    pins: crate::generation_pins::Snapshot<'a>,
}
impl<'a> Observation<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_inner(guard, lock, None, None, authorize)
    }
    /// The caller supplies the original server actor, never an exempt request ID.
    pub fn observe_referenced(
        guard: &'a Guard,
        lock: &'a files::Lock,
        references: &'a dyn References,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_inner(guard, lock, Some(references), None, authorize)
    }
    /// A pending row is admitted only through its original retained journal actor.
    pub(crate) fn observe_journal(
        guard: &'a Guard,
        lock: &'a files::Lock,
        journal: &crate::root_retirement_online_journal::Journal<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::observe_inner(guard, lock, None, Some(journal), authorize)
    }
    pub fn observe_journal_referenced(
        guard: &'a Guard,
        lock: &'a files::Lock,
        references: &'a dyn References,
        journal: &crate::root_retirement_online_journal::Journal<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        journal.recheck()?;
        Self::observe_inner(guard, lock, Some(references), Some(journal), authorize)
    }
    fn observe_inner(
        guard: &'a Guard,
        lock: &'a files::Lock,
        references: Option<&'a dyn References>,
        journal: Option<&crate::root_retirement_online_journal::Journal<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let source = guard.backup_root_binding()?;
        let idle = match journal {
            Some(original) => Snapshot::root_retirement(original)?,
            None => Snapshot::online()?,
        };
        require(
            idle.guard.backup_root_binding()? == source,
            "original Root retirement idle source differs",
        )?;
        let catalog = std::sync::Arc::new(Transaction::begin()?);
        require(
            catalog.config == guard.configuration,
            "original Root retirement catalog source differs",
        )?;
        let mut registries = Vec::new();
        for (folder, key) in [
            ("boot-publications", "boot_publications"),
            ("update-workers", "update_workers"),
            ("module-views", "module_views"),
            ("authority-refresh", "authority_refresh"),
            ("root-births", "births"),
            ("root-rebind-journal", "rebinds"),
            ("retirement-journals", "retirement"),
            ("boot-retirements", "boot_retirement"),
            ("root-retirements", "root_retirement"),
        ] {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            registries.push(Registry::observe(guard, folder, &idle.records[key])?);
        }
        let mut journals = Vec::new();
        for (kind, key) in [
            (Kind::Jobs, "jobs"),
            (Kind::Runs, "runs"),
            (Kind::Activations, "activations"),
            (Kind::Workflows, "workflows"),
            (Kind::Images, "images"),
            (Kind::Publications, "publications"),
            (Kind::Media, "media"),
        ] {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            let journal = Journal::open(kind, false)?;
            require(
                value!(journal.records) == idle.records[key],
                "Root retirement recovery references changed before original retention",
            )?;
            journal.checkpoint()?;
            journals.push(journal);
        }
        let backend = match references {
            Some(actor) => {
                actor.recheck()?;
                Backend::Server(actor)
            }
            None => {
                Backend::Standalone(crate::boot_backend_references::Observation::observe(guard)?)
            }
        };
        let pins = crate::generation_pins::Snapshot::observe(guard)?;
        let control_name = enzimos_platform::json::string(&guard.configuration["control_subvol"])?;
        let (control_identity, control_readonly) =
            crate::subvolume::observe(guard.control().as_fd(), control_name)?;
        require(
            !control_readonly,
            "original Root retirement control must be writable",
        )?;
        let original = value!({"source":source,"records":idle.records,"catalog":catalog.data,
            "catalog_identity":catalog.evidence()?,"control_identity":control_identity,"control_readonly":control_readonly,"backend":backend.evidence()?,"pins":pins.evidence()?,
            "registries":registries.iter().map(Registry::evidence).collect::<Result<Vec<_>>>()?,
            "journals":journals.iter().map(Journal::evidence).collect::<Result<Vec<_>>>()?});
        let this = Self {
            guard,
            lock,
            source,
            idle,
            catalog,
            registries,
            journals,
            original,
            backend,
            pins,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        require(
            self.guard.backup_root_binding()? == self.source
                && self.idle.guard.backup_root_binding()? == self.source,
            "original Root retirement reference source changed",
        )?;
        // Check retained original descriptions before any pathname re-observation.
        for registry in &self.registries {
            registry.recheck()?;
            authorize()?;
        }
        for journal in &self.journals {
            journal.checkpoint()?;
            authorize()?;
        }
        require(
            crate::subvolume::observe(
                self.guard.control().as_fd(),
                enzimos_platform::json::string(&self.guard.configuration["control_subvol"])?,
            )? == (self.original["control_identity"].clone(), false),
            "original Root retirement control subvolume changed",
        )?;
        self.backend.recheck()?;
        self.pins.recheck()?;
        require(
            self.backend.evidence()? == self.original["backend"]
                && self.pins.evidence()? == self.original["pins"],
            "original Root retirement backend/pins changed",
        )?;
        self.catalog.recheck()?;
        require(
            self.catalog.data == self.original["catalog"]
                && self.idle.records == self.original["records"],
            "original Root retirement reference data changed",
        )?;
        self.idle.recheck()?;
        require(
            self.catalog.evidence()? == self.original["catalog_identity"]
                && value!(
                    self.registries
                        .iter()
                        .map(Registry::evidence)
                        .collect::<Result<Vec<_>>>()?
                ) == self.original["registries"]
                && value!(
                    self.journals
                        .iter()
                        .map(Journal::evidence)
                        .collect::<Result<Vec<_>>>()?
                ) == self.original["journals"],
            "Root retirement references no longer name original retained objects",
        )?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    /// Independent original barriers during one owned Root publication. The Root
    /// registry's known temporary file and directory delta belong to its actual
    /// publication actor; every other retained description remains exact.
    pub(crate) fn root_receipt_barrier(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.family_publication_barrier(&["root-retirements"], authorize)
    }
    fn family_publication_barrier(
        &self,
        folders: &[&str],
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        require(
            self.guard.backup_root_binding()? == self.source,
            "original Root publication source changed",
        )?;
        for original in self
            .registries
            .iter()
            .filter(|r| !folders.contains(&r.folder()))
        {
            original.recheck()?;
            authorize()?;
        }
        for original in &self.journals {
            if !folders.contains(&original.folder()) {
                original.checkpoint()?;
            }
            authorize()?;
        }
        self.backend.recheck()?;
        self.pins.recheck()?;
        self.catalog.recheck()?;
        require(
            self.backend.evidence()? == self.original["backend"]
                && self.pins.evidence()? == self.original["pins"]
                && self.catalog.data == self.original["catalog"]
                && self.catalog.evidence()? == self.original["catalog_identity"]
                && crate::subvolume::observe(
                    self.guard.control().as_fd(),
                    enzimos_platform::json::string(&self.guard.configuration["control_subvol"])?,
                )? == (self.original["control_identity"].clone(), false),
            "independent original Root publication references changed",
        )?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    pub(crate) fn begin_root_receipt(
        &mut self,
        targets: &crate::root_retirement_objects::Targets<'_>,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<enzimos_platform::receipt_registry::Registry> {
        self.require_target_references(targets, record, authorize)?;
        require(
            record["schema"] == 1
                && record["phase"] == "prepared"
                && record["next_step"] == 0
                && record["inflight"].is_null(),
            "fresh original prepared Root intent required",
        )?;
        let id = crate::recovery_records::text(record, "id")?;
        require(
            self.original["records"]["root_retirement"]
                .get(id)
                .is_none()
                && self.original["records"]["root_retirement"]
                    .as_object()
                    .is_some_and(|rows| rows.len() < 16),
            "existing or overfull Root receipt registry cannot be adopted",
        )?;
        let index = self
            .registries
            .iter()
            .position(|r| r.folder() == "root-retirements")
            .ok_or_else(|| {
                enzimos_platform::Error("original Root receipt registry missing".into())
            })?;
        let absent = self.registries[index].originally_absent()?;
        let folder = std::path::Path::new(crate::operation::CONTROL).join("root-retirements");
        let leaf = format!("{id}.json");
        let registry = if absent {
            let created = enzimos_platform::created_directory::Created::create(
                self.guard.control(),
                std::path::Path::new("root-retirements"),
                0,
                &mut || self.root_receipt_barrier(authorize),
            )?;
            created.require_parent(
                self.guard.control(),
                std::path::Path::new("root-retirements"),
            )?;
            created.into_receipt_registry(&folder, &leaf, &mut || {
                self.root_receipt_barrier(authorize)
            })?
        } else {
            let parent = files::directory_relative(
                self.guard.control(),
                std::path::Path::new("root-retirements"),
                Some(0),
            )?;
            let registry =
                enzimos_platform::receipt_registry::Registry::observe(&folder, &parent, &leaf, 0)?;
            self.registries[index].bind_existing_receipt_registry(&registry, &leaf)?;
            registry
        };
        self.registries.remove(index);
        self.root_receipt_barrier(authorize)?;
        registry.recheck()?;
        Ok(registry)
    }
    pub(crate) fn verify_new_root_receipt(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier(authorize)?;
        self.idle.recheck_new_root_receipt(registry, record)?;
        registry.recheck()?;
        self.root_receipt_barrier(authorize)
    }
    /// Original reference families remain retained across one actual staging intent.
    pub(crate) fn verify_staged_root_receipt(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier(authorize)?;
        let registry = self
            .registries
            .iter()
            .find(|r| r.folder() == "root-retirements")
            .ok_or_else(|| {
                enzimos_platform::Error("original staging Root registry missing".into())
            })?;
        registry.recheck_staged_root(published)?;
        self.idle.recheck_staged_root(published)?;
        self.root_receipt_barrier(authorize)?;
        registry.recheck_staged_root(published)?;
        published.recheck()
    }
    pub(crate) fn verify_finished_origin(
        &self,
        published: &crate::root_retirement_online_finish_origin::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        published.require_source(self.guard, self.lock)?;
        require(
            matches!(published.folder(), "root-births" | "recovery-activations"),
            "fixed finish origin family required",
        )?;
        self.family_publication_barrier(&[published.folder()], authorize)?;
        if published.folder() == "root-births" {
            self.registries
                .iter()
                .find(|row| row.folder() == published.folder())
                .ok_or_else(|| enzimos_platform::Error("original birth registry missing".into()))?
                .recheck_finished_origin(published)?;
        } else {
            self.journals
                .iter()
                .find(|row| row.folder() == published.folder())
                .ok_or_else(|| {
                    enzimos_platform::Error("original activation journal missing".into())
                })?
                .recheck_finished_origin(published)?;
        }
        self.idle.recheck_finished_origin(published)?;
        self.family_publication_barrier(&[published.folder()], authorize)?;
        published.recheck_owned(authorize)
    }
    pub(crate) fn completion_publication_barrier(
        &self,
        origin: &crate::root_retirement_online_finish_origin::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        origin.require_source(self.guard, self.lock)?;
        self.family_publication_barrier(&[origin.folder(), "root-retirements"], authorize)
    }
    pub(crate) fn verify_finished_completion(
        &self,
        origin: &crate::root_retirement_online_finish_origin::Published<'_>,
        receipt: &crate::root_retirement_online_journal::Completed<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        origin.require_source(self.guard, self.lock)?;
        receipt.require_source(self.guard, self.lock)?;
        self.family_publication_barrier(&[origin.folder(), "root-retirements"], authorize)?;
        for registry in &self.registries {
            if registry.folder() == "root-retirements" {
                registry.recheck_completed_root(receipt)?;
            } else if registry.folder() == origin.folder() {
                registry.recheck_finished_origin(origin)?;
            }
        }
        for journal in &self.journals {
            if journal.folder() == origin.folder() {
                journal.recheck_finished_origin(origin)?;
            }
        }
        self.idle.recheck_finished_completion(origin, receipt)?;
        origin.recheck_completed(receipt, authorize)?;
        self.family_publication_barrier(&[origin.folder(), "root-retirements"], authorize)?;
        receipt.recheck()
    }
    pub(crate) fn require_target_references(
        &self,
        targets: &crate::root_retirement_objects::Targets<'_>,
        prepared: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        targets.require_original_source(self.guard, self.lock, authorize)?;
        let rows = targets.rows(authorize)?;
        require(
            prepared["targets"] == rows
                && prepared["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"],
            "original online target references/intent differ",
        )?;
        crate::root_retirement_record::validate(prepared, prepared["id"].as_str().unwrap_or(""))?;
        self.unmentioned(&rows, prepared)?;
        self.recheck(authorize)?;
        targets.recheck(authorize)
    }
    /// Online execution of an unstaged receipt: every reference family must
    /// still be silent about *all* of its targets (deleted ones included), and
    /// the retained present targets must be exactly the receipt's remaining
    /// ones, in order. Completed backend preparation history is compared with
    /// the receipt's original prepared form.
    pub(crate) fn require_remaining_references(
        &self,
        remaining: Option<&crate::root_retirement_objects::Targets<'_>>,
        receipt: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        let id = receipt["id"].as_str().unwrap_or("");
        crate::root_retirement_record::validate(receipt, id)?;
        require(
            receipt["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"]
                && receipt["schema"] == 1
                && receipt.get("coordinator").is_none()
                && matches!(receipt["phase"].as_str(), Some("prepared" | "executing")),
            "online execution requires an unstaged undeleted receipt",
        )?;
        let all = &receipt["targets"];
        if let Some(targets) = remaining {
            targets.require_original_source(self.guard, self.lock, authorize)?;
            let rows = targets.rows(authorize)?;
            let expected = all
                .as_array()
                .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
                .iter()
                .filter(|row| rows.as_array().is_some_and(|rows| rows.contains(row)))
                .cloned()
                .collect::<Vec<_>>();
            require(
                rows.as_array().is_some_and(|rows| *rows == expected),
                "retained remaining targets differ from the receipt",
            )?;
        }
        let mut prepared = receipt.clone();
        prepared["phase"] = value!("prepared");
        prepared["next_step"] = value!(0);
        prepared["inflight"] = Value::Null;
        crate::root_retirement_record::validate(&prepared, id)?;
        self.unmentioned(all, &prepared)?;
        self.recheck(authorize)?;
        if let Some(targets) = remaining {
            targets.recheck(authorize)?;
        }
        Ok(())
    }
    /// Every original reference family is silent about `rows`.
    fn unmentioned(&self, rows: &Value, prepared: &Value) -> Result<()> {
        use crate::root_retirement_offline_ledgers::{
            backend_unmentioned, concluded_activation, identity_unmentioned, staging_unmentioned,
        };
        let rows = rows.clone();
        crate::root_retirement_offline_catalog::unmentioned(&self.original["catalog"], &rows)?;
        let jobs = enzimos_platform::json::object(&self.original["records"]["jobs"])?;
        let activations = enzimos_platform::json::object(&self.original["records"]["activations"])?;
        let mut concluded = std::collections::BTreeSet::new();
        for (id, job) in jobs {
            let done = activations
                .get(id)
                .map(|row| concluded_activation(row, job))
                .transpose()?
                .unwrap_or(false);
            staging_unmentioned(job, &rows, done)?;
            if done {
                concluded.insert(id.clone());
            }
        }
        for (id, activation) in activations {
            let job = jobs.get(id).ok_or_else(|| {
                enzimos_platform::Error("original activation staging row missing".into())
            })?;
            if !concluded_activation(activation, job)? {
                let roots = crate::root_retirement_offline_publications::historical_roots(
                    &activation["intent"],
                )?;
                let root = enzimos_platform::json::array(&rows)?
                    .last()
                    .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["path"]
                    .as_str()
                    .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?;
                require(
                    roots
                        .iter()
                        .all(|path| path != root && !path.starts_with(&format!("{root}/"))),
                    "original activation loader protects online Root target",
                )?;
            }
        }
        for pin in enzimos_platform::json::object(&self.original["pins"]["pins"])?.values() {
            identity_unmentioned(&pin["material"]["root_identity"], &rows)?;
        }
        for row in enzimos_platform::json::object(&self.original["records"]["rebinds"])?.values() {
            identity_unmentioned(&row["source"], &rows)?;
            require(
                enzimos_platform::json::array(&rows)?
                    .iter()
                    .all(|target| target["uuid"] != row["snapshot"]["uuid"]),
                "original rebind source snapshot protects online Root target",
            )?;
        }
        let historical_jobs = jobs
            .iter()
            .map(|(id, row)| (id.clone(), row.clone()))
            .collect();
        for row in enzimos_platform::json::object(&self.original["backend"]["records"])?.values() {
            require(
                matches!(
                    row["state"].as_str(),
                    Some("planned" | "completed" | "cancelled")
                ),
                "unfinished other backend operation prevents online Root retirement",
            )?;
            if !crate::recovery_conclusions::historical(row, &historical_jobs, &concluded)
                && !crate::root_retirement_conclusions::historical(row, prepared)
            {
                backend_unmentioned(row, &rows)?;
            }
        }
        Ok(())
    }
    pub(crate) fn catalog_actor(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<std::sync::Arc<Transaction>> {
        self.recheck(authorize)?;
        Ok(std::sync::Arc::clone(&self.catalog))
    }
    pub(crate) fn require_original_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "Root references belong to another original source actor",
        )?;
        self.recheck(authorize)
    }
    pub(crate) fn original_after_staging(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&Value> {
        self.verify_staged_root_receipt(published, authorize)?;
        Ok(&self.original)
    }
    /// Immutable originally retained image receipt; callers must separately run
    /// the normal or exact owned-publication reference barrier before comparison.
    pub(crate) fn original_image_receipt(&self, id: &str) -> Result<&Value> {
        self.original["records"]["images"]
            .get(id)
            .ok_or_else(|| enzimos_platform::Error("original ready image receipt missing".into()))
    }
    pub(crate) fn original(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.original)
    }
    /// Diagnostic evidence cannot grant target ownership or deletion authority.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = value!({"original":self.original,"execution_authorized":false,
            "kernel_reference_observation_complete":false});
        self.recheck(authorize)?;
        Ok(result)
    }
}
