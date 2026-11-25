// SPDX-License-Identifier: MIT
//! Online transitions observe every independent durable journal before mutation.
use crate::{
    birth, birth_runtime, control_registry,
    recovery_journal::{Journal, Kind},
    recovery_publication, recovery_records as records, retirement_journal, root_rebind_record,
    root_retirement_record,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, require};
use serde_json::{Value, json};
/// Root receipts admit other transitions only once complete or abandoned; the
/// one actual owner may additionally be prepared, executing or deleted.
pub(crate) fn root_retirements_idle(
    rows: &crate::recovery_journal::Records,
    filesystem: &str,
    owner: Option<&str>,
) -> bool {
    rows.iter().all(|(id, v)| {
        (matches!(v["phase"].as_str(), Some("complete" | "abandoned"))
            || Some(id.as_str()) == owner
                && matches!(
                    v["phase"].as_str(),
                    Some("prepared" | "executing" | "deleted")
                ))
            && v["filesystem_uuid"] == filesystem
    })
}
/// Proof that no online transition journal holds an in-flight record.
pub struct Snapshot {
    /// Storage guard the journals were read from.
    pub guard: Guard,
    /// The observed journal records.
    pub records: Value,
    adoption: Option<String>,
    planned: Option<String>,
    publishing: Option<String>,
    authority: Option<String>,
    module_view: Option<String>,
    worker: Option<String>,
    rebind: Option<String>,
    boot_publication: Option<String>,
    root_retirement: Option<crate::control_record::Observation>,
}
#[expect(
    clippy::too_many_arguments,
    reason = "Each optional argument names one independent in-flight marker."
)]
fn observe_inner(
    guard: &Guard,
    adoption: Option<&str>,
    planned: Option<&str>,
    publishing: Option<&str>,
    authority: Option<&str>,
    module_view: Option<&str>,
    worker: Option<&str>,
    rebind: Option<&str>,
    boot_publication: Option<&str>,
    boot_retirement_owner: Option<&str>,
    root_retirement_owner: Option<&str>,
) -> Result<Value> {
    observe_inner_catalog(
        guard,
        adoption,
        planned,
        publishing,
        authority,
        module_view,
        worker,
        rebind,
        boot_publication,
        boot_retirement_owner,
        root_retirement_owner,
        None,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "Each optional argument names one independent in-flight marker."
)]
fn observe_inner_catalog(
    guard: &Guard,
    adoption: Option<&str>,
    planned: Option<&str>,
    publishing: Option<&str>,
    authority: Option<&str>,
    module_view: Option<&str>,
    worker: Option<&str>,
    rebind: Option<&str>,
    boot_publication: Option<&str>,
    boot_retirement_owner: Option<&str>,
    root_retirement_owner: Option<&str>,
    catalog_pending: Option<&enzimos_platform::publication::Prepared>,
) -> Result<Value> {
    let filesystem = records::text(&guard.configuration, "filesystem_uuid")?;
    let boot_publications = control_registry::read(
        guard,
        "boot-publications",
        128,
        crate::generation_publication::validate,
    )?;
    if let Some(pending) = catalog_pending {
        crate::generation_pending::observe_pending(
            guard,
            boot_publication.and_then(|id| boot_publications.get(id)),
            pending,
        )?;
    } else {
        crate::generation_pending::observe(
            guard,
            boot_publication.and_then(|id| boot_publications.get(id)),
        )?;
    }
    require(
        boot_publications.iter().all(|(id, row)| {
            (row["phase"] == "complete" || Some(id.as_str()) == boot_publication)
                && row["filesystem_uuid"] == filesystem
        }),
        "unfinished or foreign boot generation publication requires review",
    )?;
    let update_workers = control_registry::read(
        guard,
        "update-workers",
        crate::update_worker_record::MAXIMUM,
        crate::update_worker_record::validate,
    )?;
    require(
        update_workers.iter().all(|(id, record)| {
            (record["phase"] == "complete" || Some(id.as_str()) == worker)
                && record["request"]["filesystem_uuid"] == filesystem
        }),
        "unfinished or foreign update worker requires review",
    )?;
    let module_views = control_registry::read(
        guard,
        "module-views",
        crate::module_view_record::MAXIMUM,
        crate::module_view_record::validate,
    )?;
    require(
        module_views.iter().all(|(id, record)| {
            record["filesystem_uuid"] == filesystem
                && (record["phase"] == "complete" || Some(id.as_str()) == module_view)
        }),
        "unfinished or foreign module view requires review",
    )?;
    let authority_refresh = control_registry::read(
        guard,
        "authority-refresh",
        crate::authority_record::MAXIMUM,
        crate::authority_record::validate,
    )?;
    require(
        authority_refresh.iter().all(|(id, record)| {
            record["filesystem_uuid"] == filesystem
                && (record["phase"] == "complete" || Some(id.as_str()) == authority)
        }),
        "unfinished or foreign authority publication requires review",
    )?;
    let births =
        control_registry::read(guard, "root-births", birth_runtime::MAX_RECORDS, |v, id| {
            birth::validate(v, id, filesystem)
        })?;
    require(
        births
            .values()
            .all(|v| matches!(v["phase"].as_str(), Some("ready" | "retired"))),
        "unfinished fallback birth requires review",
    )?;
    let rebinds = control_registry::read(
        guard,
        "root-rebind-journal",
        32,
        root_rebind_record::validate,
    )?;
    require(
        rebinds.values().all(|v| {
            (v["phase"] == "complete" || v["id"].as_str() == rebind)
                && v["filesystem_uuid"] == filesystem
        }),
        "unfinished or foreign root rebind requires review",
    )?;
    let retirement = control_registry::read(
        guard,
        "retirement-journals",
        retirement_journal::MAX_RECORDS,
        retirement_journal::validate,
    )?;
    require(
        retirement.is_empty(),
        "independent retirement records prevent online transition",
    )?;
    let boot_retirement = control_registry::read(
        guard,
        "boot-retirements",
        retirement_journal::MAX_RECORDS,
        retirement_journal::validate,
    )?;
    require(
        boot_retirement.iter().all(|(id, v)| {
            (v["phase"] == "complete" || Some(id.as_str()) == boot_retirement_owner)
                && v["intent"]["filesystem_uuid"] == filesystem
        }),
        "unfinished or foreign boot retirement requires review",
    )?;
    let root_retirement = control_registry::read(
        guard,
        "root-retirements",
        16,
        root_retirement_record::validate,
    )?;
    require(
        root_retirements_idle(&root_retirement, filesystem, root_retirement_owner),
        "unfinished or foreign root retirement requires review",
    )?;
    let jobs = Journal::open(Kind::Jobs, false)?;
    let workflows = Journal::open(Kind::Workflows, false)?;
    let runs = Journal::open(Kind::Runs, false)?;
    let images = Journal::open(Kind::Images, false)?;
    let publications = Journal::open(Kind::Publications, false)?;
    let activations = Journal::open(Kind::Activations, false)?;
    let media = Journal::open(Kind::Media, false)?;
    require(
        media.records.iter().all(|(id, v)| {
            v["phase"] == "complete" || Some(id.as_str()) == adoption && v["phase"] == "executed"
        }),
        "unfinished media restoration requires explicit review",
    )?;
    require(
        jobs.records.iter().all(|(id, v)| {
            v["phase"] == "staged" || Some(id.as_str()) == planned && v["phase"] == "planned"
        }),
        "planned or incomplete recovery staging requires review",
    )?;
    if let Some(id) = planned {
        require(
            jobs.records
                .get(id)
                .is_some_and(|v| v["phase"] == "planned"),
            "exact unstarted recovery plan required",
        )?;
    }
    require(
        workflows.records.values().all(|v| v["state"] == "complete"),
        "uncertain recovery workflow requires review",
    )?;
    require(
        runs.records.iter().all(|(id, v)| {
            matches!(v["phase"].as_str(), Some("complete" | "abandoned"))
                || Some(id.as_str()) == planned && v["phase"] == "staged"
        }),
        "unfinished recovery run requires review",
    )?;
    require(
        images.records.iter().all(|(id, v)| {
            (v["phase"] == "ready" || Some(id.as_str()) == publishing)
                && v["filesystem_uuid"] == filesystem
        }),
        "unfinished or foreign recovery image requires review",
    )?;
    for (id, journal) in &publications.records {
        if Some(id.as_str()) == publishing {
            if let Some(image) = images.records.get(id) {
                let mut normalized = image.clone();
                normalized["phase"] = json!("intent");
                normalized["observations"] = json!({});
                require(
                    normalized == journal["record"],
                    "active image differs from immutable publication",
                )?;
            }
            continue;
        }
        let image = images
            .records
            .get(id)
            .ok_or_else(|| enzimos_platform::Error("orphan image publication".into()))?;
        recovery_publication::expected_record(journal, image)?;
    }
    require(
        activations.records.values().all(|v| {
            matches!(
                v["phase"].as_str(),
                Some("published" | "selected" | "adopted")
            )
        }),
        "unfinished activation requires independent review",
    )?;
    require(
        !activations.records.iter().any(|(id, v)| {
            Some(id.as_str()) != adoption
                && v["phase"] != "adopted"
                && v["intent"]["job"]["root"]["path"] == guard.configuration["root_subvol"]
        }),
        "running restored root requires explicit observed adoption",
    )?;
    for journal in [
        &jobs,
        &workflows,
        &runs,
        &images,
        &publications,
        &activations,
        &media,
    ] {
        journal.unchanged()?;
    }
    guard.recheck()?;
    Ok(
        json!({"boot_publications":boot_publications,"update_workers":update_workers,"module_views":module_views,"authority_refresh":authority_refresh,"births":births,"rebinds":rebinds,"retirement":retirement,"boot_retirement":boot_retirement,"root_retirement":root_retirement,
        "jobs":jobs.records,"workflows":workflows.records,"runs":runs.records,"images":images.records,"publications":publications.records,"activations":activations.records,"media":media.records}),
    )
}
// Ordinary online transitions never exempt a retirement receipt.
#[expect(
    clippy::too_many_arguments,
    reason = "Each optional argument names one independent in-flight marker."
)]
fn observe(
    guard: &Guard,
    adoption: Option<&str>,
    planned: Option<&str>,
    publishing: Option<&str>,
    authority: Option<&str>,
    module_view: Option<&str>,
    worker: Option<&str>,
    rebind: Option<&str>,
    boot_publication: Option<&str>,
) -> Result<Value> {
    observe_inner(
        guard,
        adoption,
        planned,
        publishing,
        authority,
        module_view,
        worker,
        rebind,
        boot_publication,
        None,
        None,
    )
}
impl Snapshot {
    /// Only an actual original Root new-row registry admits its own in-flight
    /// receipt. This does not change the original snapshot or adopt other rows.
    /// The receipt is compared with the actual retained descriptor, not JSON
    /// metadata claimed to represent a directory or publication.
    pub(crate) fn recheck_boot_retirement(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        registry.recheck()?;
        let id = records::text(&record["intent"], "id")?;
        crate::identity::safe_id(id)?;
        let generation = id.strip_prefix("boot-").ok_or_else(|| {
            enzimos_platform::Error("fixed boot retirement receipt identity".into())
        })?;
        crate::identity::safe_id(generation)?;
        retirement_journal::validate(record, id)?;
        require(
            record["intent"]["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"]
                && self.records["boot_retirement"].get(id).is_none()
                && enzimos_platform::json::array(&record["intent"]["steps"])?
                    .iter()
                    .all(|s| {
                        matches!(
                            s["kind"].as_str(),
                            Some(
                                "uefi-entry"
                                    | "bios-menu"
                                    | "boot-file"
                                    | "boot-directory"
                                    | "catalog"
                            )
                        )
                    }),
            "own boot retirement cannot adopt an existing or foreign receipt",
        )?;
        let directory = enzimos_platform::files::directory_relative(
            self.guard.control(),
            std::path::Path::new("boot-retirements"),
            Some(0),
        )?;
        registry.require_directory(&directory, &format!("{id}.json"))?;
        require(
            enzimos_platform::mount_identity::id(std::os::fd::AsFd::as_fd(&directory), true)?
                == self.guard.control_mount_id()
                && enzimos_platform::json::decode(
                    &enzimos_platform::files::read_file(
                        registry.descriptor()?,
                        crate::catalog::MAX_CATALOG,
                        Some(0),
                        true,
                    )?,
                    crate::catalog::MAX_CATALOG,
                )? == *record,
            "own boot retirement differs from actual original receipt",
        )?;
        let observed = observe_inner(
            &self.guard,
            self.adoption.as_deref(),
            self.planned.as_deref(),
            self.publishing.as_deref(),
            self.authority.as_deref(),
            self.module_view.as_deref(),
            self.worker.as_deref(),
            self.rebind.as_deref(),
            self.boot_publication.as_deref(),
            Some(id),
            None,
        )?;
        let mut expected = self.records.clone();
        expected["boot_retirement"][id] = record.clone();
        require(
            observed == expected,
            "independent transition records changed outside own retirement",
        )?;
        registry.recheck()?;
        self.guard.recheck()
    }
    /// A new prepared Root row is checked through its actual publication chain.
    /// Existing online observations cannot use this to adopt or replay a receipt.
    pub(crate) fn recheck_new_root_receipt(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        registry.recheck()?;
        let id = records::text(record, "id")?;
        root_retirement_record::validate(record, id)?;
        let root_uuid = records::text(
            enzimos_platform::json::array(&record["targets"])?
                .last()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
            "uuid",
        )?;
        require(
            self.root_retirement.is_none()
                && record["schema"] == 1
                && record["phase"] == "prepared"
                && record["next_step"] == 0
                && record["inflight"].is_null()
                && record["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"]
                && id == format!("root-{}", root_uuid.replace('-', ""))
                && self.records["root_retirement"].get(id).is_none()
                && self.records["root_retirement"]
                    .as_object()
                    .is_some_and(|rows| rows.len() < 16),
            "new Root publication cannot adopt an existing, foreign or advanced receipt",
        )?;
        let directory = enzimos_platform::files::directory_relative(
            self.guard.control(),
            std::path::Path::new("root-retirements"),
            Some(0),
        )?;
        registry.require_directory(&directory, &format!("{id}.json"))?;
        require(
            enzimos_platform::mount_identity::id(std::os::fd::AsFd::as_fd(&directory), true)?
                == self.guard.control_mount_id()
                && enzimos_platform::json::decode(
                    &enzimos_platform::files::read_file(
                        registry.descriptor()?,
                        crate::catalog::MAX_CATALOG,
                        Some(0),
                        true,
                    )?,
                    crate::catalog::MAX_CATALOG,
                )? == *record,
            "new Root row differs from actual original publication chain",
        )?;
        let observed = observe_inner(
            &self.guard,
            self.adoption.as_deref(),
            self.planned.as_deref(),
            self.publishing.as_deref(),
            self.authority.as_deref(),
            self.module_view.as_deref(),
            self.worker.as_deref(),
            self.rebind.as_deref(),
            self.boot_publication.as_deref(),
            None,
            Some(id),
        )?;
        let mut expected = self.records.clone();
        expected["root_retirement"][id] = record.clone();
        require(
            observed == expected,
            "independent transition changed outside actual new Root receipt",
        )?;
        registry.recheck()?;
        self.guard.recheck()
    }
    pub(crate) fn boot_publication(id: &str) -> Result<Self> {
        crate::identity::safe_id(id)?;
        let mut snapshot = Self::online()?;
        require(
            snapshot.records["boot_publications"].get(id).is_none(),
            "existing generation publication cannot be adopted",
        )?;
        snapshot.boot_publication = Some(id.into());
        Ok(snapshot)
    }
    pub(crate) fn boot_checkpoint(&mut self, record: &Value) -> Result<()> {
        let id = records::text(record, "generation")?;
        require(
            self.boot_publication.as_deref() == Some(id),
            "generation publication checkpoint scope differs",
        )?;
        crate::generation_publication::transition(
            self.records["boot_publications"].get(id),
            record,
            id,
        )?;
        self.records["boot_publications"][id] = record.clone();
        self.recheck()
    }
    /// Only an actual original phase-qualified receipt admits its own pending row.
    pub(crate) fn root_retirement(
        journal: &crate::root_retirement_online_journal::Journal<'_>,
    ) -> Result<Self> {
        journal.recheck()?;
        let original = journal.duplicate_observation()?;
        let row = original.value()?;
        let id = records::text(row, "id")?;
        let guard = Guard::observe()?;
        require(
            row["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "original online Root receipt/idle source differs",
        )?;
        let records = observe_inner(
            &guard,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(id),
        )?;
        require(
            records["root_retirement"][id] == *row,
            "original Root receipt changed during idle observation",
        )?;
        let this = Self {
            guard,
            records,
            adoption: None,
            planned: None,
            publishing: None,
            authority: None,
            module_view: None,
            worker: None,
            rebind: None,
            boot_publication: None,
            root_retirement: Some(original),
        };
        journal.recheck()?;
        this.recheck()?;
        Ok(this)
    }
    /// Observe every online transition journal and require them idle.
    ///
    /// # Errors
    ///
    /// Fails when a journal holds an in-flight record or cannot be read.
    pub fn online() -> Result<Self> {
        Self::new(None, None)
    }
    pub(crate) fn adoption(id: &str) -> Result<Self> {
        records::job_id(id)?;
        Self::new(Some(id), None)
    }
    pub(crate) fn planned_run(id: &str) -> Result<Self> {
        records::job_id(id)?;
        Self::new(None, Some(id))
    }
    fn new(adoption: Option<&str>, planned: Option<&str>) -> Result<Self> {
        let guard = Guard::observe()?;
        let records = observe(
            &guard, adoption, planned, None, None, None, None, None, None,
        )?;
        Ok(Self {
            guard,
            records,
            adoption: adoption.map(str::to_owned),
            planned: planned.map(str::to_owned),
            publishing: None,
            authority: None,
            module_view: None,
            worker: None,
            rebind: None,
            boot_publication: None,
            root_retirement: None,
        })
    }
    /// Admit only this actual staging producer's replacement of the original
    /// selected receipt. Other idle records remain exact original comparisons.
    pub(crate) fn recheck_finished_origin(
        &self,
        published: &crate::root_retirement_online_finish_origin::Published<'_>,
    ) -> Result<()> {
        let original = self.root_retirement.as_ref().ok_or_else(|| {
            enzimos_platform::Error("finish requires original deleted receipt".into())
        })?;
        original.recheck()?;
        let row = original.value()?;
        let id = records::text(row, "id")?;
        require(
            row["phase"] == "deleted" && self.records["root_retirement"][id] == *row,
            "finish original deleted selection changed",
        )?;
        let key = match published.folder() {
            "root-births" => "births",
            "recovery-activations" => "activations",
            _ => {
                return Err(enzimos_platform::Error(
                    "unknown finish origin family".into(),
                ));
            }
        };
        require(
            self.records[key].get(published.id()) == Some(published.before()),
            "finish original idle origin differs",
        )?;
        let mut expected = self.records.clone();
        expected[key][published.id()] = published.next().clone();
        require(
            observe_inner(
                &self.guard,
                self.adoption.as_deref(),
                self.planned.as_deref(),
                self.publishing.as_deref(),
                self.authority.as_deref(),
                self.module_view.as_deref(),
                self.worker.as_deref(),
                self.rebind.as_deref(),
                self.boot_publication.as_deref(),
                None,
                Some(id),
            )? == expected,
            "independent transition families changed across finish metadata publication",
        )?;
        original.recheck()?;
        self.guard.recheck()
    }
    pub(crate) fn recheck_finished_completion(
        &self,
        origin: &crate::root_retirement_online_finish_origin::Published<'_>,
        receipt: &crate::root_retirement_online_journal::Completed<'_>,
    ) -> Result<()> {
        let original = self.root_retirement.as_ref().ok_or_else(|| {
            enzimos_platform::Error("completion original deleted receipt absent".into())
        })?;
        receipt.require_original_observation(original)?;
        let before = receipt.before()?;
        let id = records::text(before, "id")?;
        require(
            self.records["root_retirement"][id] == *before,
            "completion original idle receipt differs",
        )?;
        let key = match origin.folder() {
            "root-births" => "births",
            "recovery-activations" => "activations",
            _ => return Err(enzimos_platform::Error("completion origin family".into())),
        };
        require(
            self.records[key].get(origin.id()) == Some(origin.before()),
            "completion original idle origin differs",
        )?;
        let mut expected = self.records.clone();
        expected[key][origin.id()] = origin.next().clone();
        expected["root_retirement"][id] = receipt.record()?.clone();
        require(
            observe_inner(
                &self.guard,
                self.adoption.as_deref(),
                self.planned.as_deref(),
                self.publishing.as_deref(),
                self.authority.as_deref(),
                self.module_view.as_deref(),
                self.worker.as_deref(),
                self.rebind.as_deref(),
                self.boot_publication.as_deref(),
                None,
                None,
            )? == expected,
            "independent transition families changed across durable completion",
        )?;
        receipt.require_original_observation(original)?;
        self.guard.recheck()
    }
    pub(crate) fn recheck_staged_root(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
    ) -> Result<()> {
        let original = self.root_retirement.as_ref().ok_or_else(|| {
            enzimos_platform::Error("staging requires original selected Root observation".into())
        })?;
        published.require_original_observation(original)?;
        let before = published.before()?;
        let id = records::text(before, "id")?;
        require(
            self.records["root_retirement"][id] == *before
                && before["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"],
            "staging producer differs from original idle Root selection/source",
        )?;
        self.guard.recheck()?;
        let mut expected = self.records.clone();
        expected["root_retirement"][id] = published.record()?.clone();
        require(
            observe_inner(
                &self.guard,
                self.adoption.as_deref(),
                self.planned.as_deref(),
                self.publishing.as_deref(),
                self.authority.as_deref(),
                self.module_view.as_deref(),
                self.worker.as_deref(),
                self.rebind.as_deref(),
                self.boot_publication.as_deref(),
                None,
                Some(id),
            )? == expected,
            "independent transition records changed around owned staging publication",
        )?;
        published.require_original_observation(original)?;
        self.guard.recheck()
    }
    /// Verify every journal is unchanged.
    ///
    /// # Errors
    ///
    /// Fails when a journal changed.
    pub fn recheck(&self) -> Result<()> {
        self.recheck_with_catalog(None)
    }
    /// [`Snapshot::recheck`] while `pending` is the only catalog change.
    ///
    /// # Errors
    ///
    /// Fails when a journal changed or the catalog differs from `pending`.
    pub fn recheck_catalog_pending(
        &self,
        pending: &enzimos_platform::publication::Prepared,
    ) -> Result<()> {
        self.recheck_with_catalog(Some(pending))
    }
    fn recheck_with_catalog(
        &self,
        catalog_pending: Option<&enzimos_platform::publication::Prepared>,
    ) -> Result<()> {
        let root_owner = self
            .root_retirement
            .as_ref()
            .map(|actor| {
                actor.recheck()?;
                let row = actor.value()?;
                let id = records::text(row, "id")?;
                require(
                    self.records["root_retirement"][id] == *row,
                    "original pending Root receipt changed",
                )?;
                Ok::<_, enzimos_platform::Error>(id)
            })
            .transpose()?;
        require(
            observe_inner_catalog(
                &self.guard,
                self.adoption.as_deref(),
                self.planned.as_deref(),
                self.publishing.as_deref(),
                self.authority.as_deref(),
                self.module_view.as_deref(),
                self.worker.as_deref(),
                self.rebind.as_deref(),
                self.boot_publication.as_deref(),
                None,
                root_owner,
                catalog_pending,
            )? == self.records,
            "independent transition records changed",
        )
    }
}

/// Read-only continuation census. Only an actual original Root receipt descriptor
/// can select its own pending row; returned data cannot construct a Snapshot or actor.
pub(crate) fn inspect_boot_continuation(
    guard: &Guard,
    receipt: &crate::control_record::Observation,
) -> Result<Value> {
    use enzimos_platform::{files, mount_identity};
    use std::{os::fd::AsFd, path::Path};
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    guard.recheck()?;
    receipt.recheck()?;
    let row = receipt.value()?;
    let id = records::text(&row["intent"], "id")?;
    crate::retirement_journal::validate(row, id)?;
    require(
        id.starts_with("boot-")
            && row["intent"]["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
        "actual continuation receipt/source differs",
    )?;
    let parent =
        files::directory_relative(guard.control(), Path::new("boot-retirements"), Some(0))?;
    let named = files::open_relative(&parent, Path::new(&format!("{id}.json")))?;
    require(
        files::identity(&named.metadata()?) == files::identity(&receipt.descriptor()?.metadata()?)
            && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
            && mount_identity::id(receipt.descriptor()?.as_fd(), true)? == guard.control_mount_id(),
        "pending exception requires actual original named Root receipt",
    )?;
    let observed = observe_inner(
        guard,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(id),
        None,
    )?;
    require(
        observed["boot_retirement"][id] == *row,
        "actual selected continuation row changed",
    )?;
    receipt.recheck()?;
    guard.recheck()?;
    Ok(observed)
}

mod continuation;
