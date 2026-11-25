use super::*;

impl Snapshot {
    pub(crate) fn prepare_rebind(&mut self, id: &str) -> Result<()> {
        crate::identity::safe_id(id)?;
        self.recheck()?;
        require(
            self.rebind.is_none() && self.records["rebinds"].get(id).is_none(),
            "root rebind cannot adopt an existing attempt",
        )?;
        self.rebind = Some(id.into());
        Ok(())
    }
    pub(crate) fn rebind_checkpoint(&mut self, record: &Value) -> Result<()> {
        let id = records::text(record, "id")?;
        require(
            self.rebind.as_deref() == Some(id)
                && record["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"],
            "root rebind checkpoint scope changed",
        )?;
        root_rebind_record::validate(record, id)?;
        if let Some(before) = self.records["rebinds"].get(id) {
            require(
                before["phase"] == "prepared" && record["phase"] == "complete",
                "root rebind checkpoint cannot replay",
            )?;
            for (key, old) in enzimos_platform::json::object(before)? {
                if !matches!(key.as_str(), "phase" | "journal_sha256") {
                    require(record[key] == *old, "root rebind immutable intent changed")?;
                }
            }
        } else {
            require(
                record["phase"] == "prepared",
                "root rebind must persist preparation first",
            )?;
        }
        self.records["rebinds"][id] = record.clone();
        self.recheck()
    }
    /// Called only by an explicit Root resume under the operation lock.
    pub(crate) fn rebind_existing(record: &Value) -> Result<Self> {
        let id = records::text(record, "id")?;
        root_rebind_record::validate(record, id)?;
        require(
            record["phase"] == "prepared",
            "root rebind resume requires unfinished preparation",
        )?;
        let guard = Guard::observe()?;
        let observed = observe(&guard, None, None, None, None, None, None, Some(id), None)?;
        require(
            observed["rebinds"][id] == *record,
            "root rebind resume durable record changed",
        )?;
        Ok(Self {
            guard,
            records: observed,
            adoption: None,
            planned: None,
            publishing: None,
            authority: None,
            module_view: None,
            worker: None,
            rebind: Some(id.into()),
            boot_publication: None,
            root_retirement: None,
        })
    }
    pub(crate) fn recorded_run(&mut self, id: &str, record: &Value) -> Result<()> {
        require(
            self.planned.as_deref() == Some(id) && self.records["runs"].get(id).is_none(),
            "run snapshot cannot adopt existing attempt",
        )?;
        records::run(record, id)?;
        require(
            record["phase"] == "staged"
                && record["plan_sha256"] == self.records["jobs"][id]["plan"]["plan_sha256"],
            "run snapshot differs from planned transaction",
        )?;
        self.records["runs"][id] = record.clone();
        self.recheck()
    }
    pub(crate) fn publication_continuation(journal: &Journal, id: &str) -> Result<Self> {
        require(
            journal.folder() == Kind::Publications.folder(),
            "original publication journal required",
        )?;
        journal.unchanged()?;
        let original = journal
            .records
            .get(id)
            .ok_or_else(|| enzimos_platform::Error("original publication intent missing".into()))?;
        crate::recovery_publication::validate(original, id)?;
        let guard = Guard::observe()?;
        let records = observe(&guard, None, None, Some(id), None, None, None, None, None)?;
        require(
            records["publications"][id] == *original,
            "publication journal differs from original idle reference",
        )?;
        let this = Self {
            guard,
            records,
            adoption: None,
            planned: None,
            publishing: Some(id.into()),
            authority: None,
            module_view: None,
            worker: None,
            rebind: None,
            boot_publication: None,
            root_retirement: None,
        };
        journal.unchanged()?;
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn publication(id: &str) -> Result<Self> {
        crate::recovery_image::identifier(id)?;
        let mut snapshot = Self::online()?;
        require(
            snapshot.records["images"].get(id).is_none()
                && snapshot.records["publications"].get(id).is_none(),
            "existing image publication cannot be adopted",
        )?;
        snapshot.publishing = Some(id.into());
        Ok(snapshot)
    }
    pub(crate) fn authority_refresh(id: &str) -> Result<Self> {
        crate::identity::safe_id(id)?;
        let mut snapshot = Self::online()?;
        require(
            snapshot.records["authority_refresh"].get(id).is_none(),
            "existing authority attempt cannot be adopted",
        )?;
        snapshot.authority = Some(id.into());
        Ok(snapshot)
    }
    pub(crate) fn authority_checkpoint(&mut self, id: &str, record: &Value) -> Result<()> {
        require(
            self.authority.as_deref() == Some(id),
            "authority checkpoint identity changed",
        )?;
        crate::authority_record::transition(self.records["authority_refresh"].get(id), record, id)?;
        self.records["authority_refresh"][id] = record.clone();
        self.recheck()
    }
    pub(crate) fn module_view(id: &str) -> Result<Self> {
        crate::identity::safe_id(id)?;
        let mut snapshot = Self::online()?;
        require(
            snapshot.records["module_views"].get(id).is_none(),
            "existing module view cannot be adopted",
        )?;
        snapshot.module_view = Some(id.into());
        Ok(snapshot)
    }
    pub(crate) fn module_checkpoint(&mut self, id: &str, record: &Value) -> Result<()> {
        require(
            self.module_view.as_deref() == Some(id),
            "module view checkpoint identity changed",
        )?;
        crate::module_view_record::transition(self.records["module_views"].get(id), record, id)?;
        self.records["module_views"][id] = record.clone();
        self.recheck()
    }
    pub(crate) fn prepare_worker(&mut self, id: &str) -> Result<()> {
        crate::identity::safe_id(id)?;
        self.recheck()?;
        require(
            self.worker.is_none()
                && self.module_view.is_some()
                && self.records["update_workers"].get(id).is_none(),
            "worker attempt cannot adopt an existing record",
        )?;
        self.worker = Some(id.into());
        Ok(())
    }
    /// Require that the worker checkpoint `record` still belongs to the retained owner.
    ///
    /// # Errors
    ///
    /// Fails when the owner or supervisor changed.
    pub fn worker_checkpoint(&mut self, record: &Value) -> Result<()> {
        let id = record["id"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("worker checkpoint identity missing".into()))?;
        require(
            self.worker.as_deref() == Some(id)
                && (record["request"]["caller"]["pid"] == std::process::id()
                    || record["supervisor"]["pid"] == std::process::id()),
            "worker checkpoint owner changed",
        )?;
        crate::update_worker_record::execution_request(&record["request"])?;
        let view = record["request"]["module_view"]["id"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("worker module identity missing".into()))?;
        require(
            self.module_view.as_deref() == Some(view)
                && self.records["module_views"][view] == record["request"]["module_view"],
            "worker module checkpoint changed",
        )?;
        crate::update_worker_record::transition(
            self.records["update_workers"].get(id),
            record,
            id,
        )?;
        self.records["update_workers"][id] = record.clone();
        self.recheck()
    }
    pub(crate) fn worker_history(&mut self, id: &str, checkpoints: &[Value]) -> Result<()> {
        require(
            self.worker.as_deref() == Some(id),
            "worker history scope changed",
        )?;
        let before = self.records["update_workers"]
            .get(id)
            .ok_or_else(|| enzimos_platform::Error("worker starting snapshot absent".into()))?;
        let terminal = crate::update_worker_record::history(before, checkpoints, id)?;
        require(
            terminal["request"]["caller"]["pid"] == std::process::id()
                && terminal["request"]["boot_id"] == crate::operation::boot_id()?,
            "worker history caller or boot changed",
        )?;
        let view = enzimos_platform::json::string(&terminal["request"]["module_view"]["id"])?;
        require(
            self.module_view.as_deref() == Some(view)
                && self.records["module_views"][view] == terminal["request"]["module_view"],
            "worker history module scope changed",
        )?;
        // All unrelated records, mounts and the final durable worker receipt must
        // still equal the caller's original snapshot. Never infer missing phases.
        self.records["update_workers"][id] = terminal;
        self.recheck()
    }
    /// Only the exact Root supervisor of an already measured handoff may attach.
    ///
    /// # Errors
    ///
    /// Fails when the record is not a handed-off worker of this boot.
    pub fn worker_handoff(record: &Value) -> Result<Self> {
        let id = record["id"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("worker handoff identity missing".into()))?;
        crate::update_worker_record::validate(record, id)?;
        crate::update_worker_record::execution_request(&record["request"])?;
        require(
            record["phase"] == "handed-off"
                && record["supervisor"]["pid"] == std::process::id()
                && record["request"]["boot_id"] == crate::operation::boot_id()?,
            "worker handoff owner, phase or boot changed",
        )?;
        let view = record["request"]["module_view"]["id"]
            .as_str()
            .ok_or_else(|| {
                enzimos_platform::Error("worker handoff module identity missing".into())
            })?;
        let guard = Guard::observe()?;
        let observed = observe(
            &guard,
            None,
            None,
            None,
            None,
            Some(view),
            Some(id),
            None,
            None,
        )?;
        require(
            observed["update_workers"][id] == *record
                && observed["module_views"][view] == record["request"]["module_view"],
            "worker handoff differs from durable independent records",
        )?;
        Ok(Self {
            guard,
            records: observed,
            adoption: None,
            planned: None,
            publishing: None,
            authority: None,
            module_view: Some(view.into()),
            worker: Some(id.into()),
            rebind: None,
            boot_publication: None,
            root_retirement: None,
        })
    }
    pub(crate) fn publication_checkpoint(
        &mut self,
        id: &str,
        record: Option<&Value>,
        publication: Option<&Value>,
    ) -> Result<()> {
        require(
            self.publishing.as_deref() == Some(id),
            "publication checkpoint identity differs",
        )?;
        if let Some(publication) = publication {
            crate::recovery_publication::validate(publication, id)?;
            require(
                self.records["publications"].get(id).is_none(),
                "publication intent cannot be replaced",
            )?;
            self.records["publications"][id] = publication.clone();
        }
        if let Some(record) = record {
            crate::recovery_journal::transition(
                Kind::Images,
                self.records["images"].get(id),
                record,
                id,
            )?;
            self.records["images"][id] = record.clone();
        }
        self.recheck()
    }
}
