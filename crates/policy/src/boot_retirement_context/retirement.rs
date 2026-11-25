use super::*;

impl<'a, 'g: 'a> Context<'a, 'g> {
    pub(crate) fn root_receipt_barrier(
        &self,
        targets: &crate::root_retirement_objects::Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier_inner(targets, None, None, authorize)
    }
    pub(crate) fn verify_owned_signing_namespace(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        targets: &crate::root_retirement_objects::Targets<'_>,
        original: &crate::root_retirement_signed_namespace::Original<'_>,
        state: &crate::root_retirement_signed_namespace::State<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier_inner(targets, Some((original, state)), None, authorize)?;
        let registry = self
            .reference_registries
            .iter()
            .find(|r| r.folder() == "root-retirements")
            .ok_or_else(|| Error("original Root signing registry missing".into()))?;
        registry.recheck_staged_root(published)?;
        self.idle.recheck_staged_root(published)?;
        self.root_receipt_barrier_inner(targets, Some((original, state)), None, authorize)?;
        registry.recheck_staged_root(published)?;
        published.recheck()
    }
    pub(crate) fn verify_owned_root_entry(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &crate::root_retirement_objects::Targets<'_>,
        original: &crate::root_retirement_signed_namespace::Original<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::State<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        pending.require_frame(receipt, signer, authorize)?;
        let state = crate::root_retirement_signed_namespace::State::Published(signer);
        self.root_receipt_barrier_inner(
            targets,
            Some((original, &state)),
            Some(pending),
            authorize,
        )?;
        let registry = self
            .reference_registries
            .iter()
            .find(|r| r.folder() == "root-retirements")
            .ok_or_else(|| Error("original pending Root entry registry missing".into()))?;
        registry.recheck_staged_root(receipt)?;
        self.idle.recheck_staged_root(receipt)?;
        self.root_receipt_barrier_inner(
            targets,
            Some((original, &state)),
            Some(pending),
            authorize,
        )?;
        pending.require_frame(receipt, signer, authorize)?;
        registry.recheck_staged_root(receipt)?;
        receipt.recheck()
    }
    pub(super) fn root_receipt_barrier_inner(
        &self,
        targets: &crate::root_retirement_objects::Targets<'_>,
        namespace: Option<(
            &crate::root_retirement_signed_namespace::Original<'_>,
            &crate::root_retirement_signed_namespace::State<'_, '_>,
        )>,
        pending: Option<&crate::root_retirement_loader_publication::State<'_, '_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        targets.require_original_source(self.guard, self.lock, authorize)?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.transaction.recheck()?;
        let firmware_matches = match pending {
            Some(pending) if pending.require_original_firmware(&self.firmware, authorize)? => true,
            _ => firmware()? == self.firmware,
        };
        require(
            self.guard.backup_root_binding()? == self.original["source"]
                && self.transaction.data == self.original["catalog"]
                && self.transaction.evidence()? == self.original["catalog_epoch"]
                && firmware_matches
                && command_line()? == self.command_line,
            "original Root boot publication source changed",
        )?;
        for original in self
            .reference_registries
            .iter()
            .filter(|r| r.folder() != "root-retirements")
        {
            original.recheck()?;
            authorize()?;
        }
        for original in &self.reference_journals {
            original.unchanged()?;
            authorize()?;
        }
        self.pins.recheck()?;
        self.volume.writable()?;
        if pending.is_none() {
            self.recheck_root_loader_directory()?;
        }
        for original in &self.directories {
            if original.relative == "loader/entries"
                && let Some(pending) = pending
            {
                pending.require_original_directory(
                    &original.file,
                    self.root_loader_directory.ok_or_else(|| {
                        Error("pending Root entry requires original directory epoch".into())
                    })?,
                    &original.names,
                    authorize,
                )?;
                continue;
            }
            original.recheck(&self.volume)?;
            authorize()?;
        }
        for (name, original) in &self.artifacts {
            if let Some(pending) = pending
                && pending.require_original_artifact(name, original, authorize)?
            {
                continue;
            }
            original.recheck()?;
            authorize()?;
        }
        if let Some((original, state)) = namespace {
            original.require_source(self.guard, self.lock, authorize)?;
            state.require_original(original, authorize)?;
            self.signed_inventory
                .recheck_original_members(&self.volume, authorize)?;
            state.require_original(original, authorize)?;
        } else {
            self.signed_inventory.recheck(&self.volume, authorize)?;
        }
        root_loaders_unmentioned(&self.texts, &targets.rows(authorize)?)?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    pub(crate) fn bind_root_receipt(
        &mut self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
        targets: &crate::root_retirement_objects::Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier(targets, authorize)?;
        registry.recheck()?;
        let index = self
            .reference_registries
            .iter()
            .position(|r| r.folder() == "root-retirements")
            .ok_or_else(|| Error("original Root boot receipt registry missing".into()))?;
        let id = crate::recovery_records::text(record, "id")?;
        let parent = files::directory_relative(
            self.guard.control(),
            Path::new("root-retirements"),
            Some(0),
        )?;
        registry.require_directory(&parent, &format!("{id}.json"))?;
        require(
            mount_identity::id(parent.as_fd(), true)? == self.guard.control_mount_id(),
            "Root boot receipt registry crosses original control mount",
        )?;
        if self.root_registry_absent {
            registry.require_original_members(&Default::default())?;
        } else {
            self.reference_registries[index]
                .bind_existing_receipt_registry(registry, &format!("{id}.json"))?;
        }
        self.reference_registries.remove(index);
        self.root_receipt_barrier(targets, authorize)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is a distinct retained input of this step."
    )]
    pub(crate) fn compile_root_stage(
        &self,
        targets: &crate::root_retirement_objects::Targets<'_>,
        record: &Value,
        image: &crate::root_retirement_online_image::Image<'_>,
        source: &crate::root_retirement_online_encryption::Source<'_>,
        exit: &str,
        mode: crate::root_retirement_stage_contract::UefiMode,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::root_retirement_stage_contract::Stage> {
        self.protect_root_targets(targets, authorize)?;
        require(
            record["targets"] == targets.rows(authorize)?
                && record["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"],
            "staging record differs from original protected targets/source",
        )?;
        image.require_original_source(self.guard, self.lock, authorize)?;
        source.require_original_source(self.guard, self.lock, authorize)?;
        let staged = crate::root_retirement_stage_contract::prepare(
            record,
            image.record(authorize)?,
            source.uuid(authorize)?,
            crate::recovery_records::text(&self.guard.configuration, "control_subvol")?,
            &self.volume.uuid,
            &self.texts["loader/loader.conf"],
            &self.texts["limine/limine.conf"],
            exit,
            mode,
        )?;
        let entry = crate::recovery_records::text(&staged.record["coordinator"], "uefi_entry")?;
        let directory = self
            .directories
            .iter()
            .find(|d| d.relative == "loader/entries")
            .ok_or_else(|| Error("original UEFI entry directory missing".into()))?;
        require(
            !directory.names.contains(entry),
            "staging cannot adopt existing coordinator entry",
        )?;
        self.protect_root_targets(targets, authorize)?;
        image.require_original_source(self.guard, self.lock, authorize)?;
        source.require_original_source(self.guard, self.lock, authorize)?;
        Ok(staged)
    }
    pub(crate) fn verify_staged_root_receipt(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        targets: &crate::root_retirement_objects::Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier(targets, authorize)?;
        let registry = self
            .reference_registries
            .iter()
            .find(|r| r.folder() == "root-retirements")
            .ok_or_else(|| Error("original Root staging boot registry missing".into()))?;
        registry.recheck_staged_root(published)?;
        self.idle.recheck_staged_root(published)?;
        self.root_receipt_barrier(targets, authorize)?;
        registry.recheck_staged_root(published)?;
        published.recheck()
    }
    pub(crate) fn verify_new_root_receipt(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
        targets: &crate::root_retirement_objects::Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root_receipt_barrier(targets, authorize)?;
        self.idle.recheck_new_root_receipt(registry, record)?;
        registry.recheck()?;
        self.root_receipt_barrier(targets, authorize)
    }
    pub(crate) fn protect_root_targets(
        &self,
        targets: &crate::root_retirement_objects::Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        targets.require_original_source(self.guard, self.lock, authorize)?;
        self.recheck(authorize)?;
        root_loaders_unmentioned(&self.texts, &targets.rows(authorize)?)?;
        self.recheck(authorize)?;
        targets.recheck(authorize)
    }
    /// One original admitted execution. Existing unfinished receipts cannot be
    /// adopted, and no replay entry point reconstructs these retained actors.
    pub fn retire(
        self,
        references: &dyn runtime::References,
        expected_intent: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
        progress: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<Value> {
        runtime::retire(self, references, expected_intent, authorize, progress)
    }
    /// Keep original signature authority and source/output descriptors through
    /// actual known removals. This check supplies no new deletion authority;
    /// only original Artifact actors paired with actual Removed witnesses join.
    pub fn recheck_signed_owned_retirements(
        &self,
        retired: &BTreeMap<std::path::PathBuf, crate::boot_volume::RetiredArtifact>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.volume.recheck()?;
        for verification in &self.signed_inventory.verified {
            authorize()?;
            verification.recheck_owned_retirements(retired)?;
        }
        for artifact in retired.values() {
            artifact.recheck()?;
        }
        self.guard.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    /// Bind a new-row writer to this independently retained original registry
    /// before first publication. Decoded records cannot supply original handles.
    pub(crate) fn bind_existing_receipt_registry(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        self.reference_registries
            .iter()
            .find(|r| r.folder() == "boot-retirements")
            .ok_or_else(|| Error("original boot retirement registry missing".into()))?
            .bind_existing_receipt_registry(registry, &format!("boot-{}.json", self.generation))?;
        self.recheck(authorize)
    }
    pub fn bind_recovery_conclusions(
        &self,
        observation: &crate::recovery_conclusions::Observation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            self.reference_journals.len() == 7,
            "complete original recovery journals required",
        )?;
        observation
            .require_original_journals(&self.reference_journals[0], &self.reference_journals[2])?;
        self.recheck(authorize)
    }
    /// Preserve the closed boot-retirement plan result fields. A failed fresh
    /// preflight produces a non-retirable preview, with no intent or step grant.
    pub fn preview_plan(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let disclosed = if self.firmware["observable"] == false {
            vec!["EFI-loader-state-not-observable-on-this-boot"]
        } else {
            Vec::<&str>::new()
        };
        let mut result = value!({"status":"boot-retirement-plan","generation":self.generation,
            "retirable":false,"protection":[],"disclosed_unobservable":disclosed,
            "root_subvolume_retained":true,
            "root_identity":self.transaction.data["generations"][&self.generation]["material"]["root_identity"]});
        match self.preview_intent(authorize) {
            Ok((intent, _, _)) => {
                result["retirable"] = value!(true);
                result["plan_sha256"] = intent["intent_sha256"].clone();
                result["steps"] = value!(
                    enzimos_platform::json::array(&intent["steps"])?
                        .iter()
                        .map(|s| s["id"].clone())
                        .collect::<Vec<_>>()
                );
            }
            Err(error) => {
                result["protection"] = value!([error.to_string()]);
            }
        }
        self.recheck(authorize)?;
        Ok(result)
    }
    /// Read-only preview retains the original backend rows alongside this
    /// original boot context. A live coordinator must instead carry its own
    /// server-created ReferenceView; this method never exempts decoded rows.
    pub(crate) fn preview_intent(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Value, Value, Value)> {
        self.recheck(authorize)?;
        let backend = crate::boot_backend_references::Observation::observe(self.guard)?;
        let conclusions = crate::recovery_conclusions::Observation::observe(self.guard)?;
        self.bind_recovery_conclusions(&conclusions, authorize)?;
        backend.require_unmentioned_with_conclusions(&self.generation, &conclusions)?;
        let result = self.planned_intent(&mut || {
            backend.require_unmentioned_with_conclusions(&self.generation, &conclusions)?;
            authorize()
        })?;
        backend.require_unmentioned_with_conclusions(&self.generation, &conclusions)?;
        self.recheck(authorize)?;
        Ok((result.0, result.1, backend.evidence()?))
    }
    /// Calculate a closed intent only from actual retained preflight objects.
    /// Backend reference completion and executor admission remain separate gates.
    pub fn planned_intent(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Value, Value)> {
        self.recheck(authorize)?;
        require(
            crate::boot_retirement_references::protection(&self.idle.records, &self.generation)?
                .is_empty(),
            "original live recovery references protect boot generation",
        )?;
        let boot = operation::boot_id()?;
        let markers = self
            .command_line
            .split_whitespace()
            .filter_map(|w| w.strip_prefix("enzimos.generation="))
            .collect::<Vec<_>>();
        require(markers.len() <= 1, "ambiguous actual running generation")?;
        if let Some(marker) = markers.first() {
            identity::safe_id(marker)?;
        }
        let selected = selected(&self.texts, &self.firmware)?;
        plan::retention(
            &self.transaction.data,
            &self.generation,
            &boot,
            markers.first().copied(),
            &selected,
            &self.pins.evidence()?["pins"],
        )?;
        let (entries, _) = plan::entry_names(&self.generation)?;
        let mut ukis = BTreeMap::new();
        let mut file_hashes = BTreeMap::new();
        for (flavor, name) in ["linux", "linux-lts"].into_iter().zip(entries.iter()) {
            let relative = format!("loader/entries/{name}");
            let entry = self
                .artifacts
                .get(&relative)
                .ok_or_else(|| Error("original candidate entry description required".into()))?;
            entry.recheck()?;
            file_hashes.insert(format!("uefi-{flavor}"), entry.sha.clone());
            if let Some(path) = self.signed_inventory.entries.get(&relative) {
                let image = &self.signed_inventory.images[path];
                image.recheck()?;
                ukis.insert(path.clone(), image.sha.clone());
            }
        }
        plan::loader_references(
            &self.texts,
            &self.generation,
            &ukis.keys().cloned().collect(),
        )?;
        for name in plan::MEMBERS {
            let relative = format!("enzimos/generations/{}/{name}", self.generation);
            let a = &self.artifacts[&relative];
            a.recheck()?;
            file_hashes.insert(name.into(), a.sha.clone());
        }
        let protection = value!({"retained_generations":enzimos_platform::json::object(&self.transaction.data["generations"])?.keys().filter(|n|*n!=&self.generation).collect::<Vec<_>>(),"selected":selected,"pins":self.pins.evidence()?});
        let result = plan::intent(
            &self.transaction.data,
            &self.generation,
            &boot,
            &self.volume.uuid,
            &self.texts["limine/limine.conf"],
            &file_hashes,
            &ukis,
            &self.original,
            &protection,
        )?;
        self.recheck(authorize)?;
        Ok(result)
    }
    pub(crate) fn publish_pin(
        &mut self,
        id: &str,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            record["generation"] == self.generation
                && record["material"]
                    == self.original["catalog"]["generations"][&self.generation]["material"]
                && record["filesystem_uuid"] == self.guard.configuration["filesystem_uuid"],
            "pin must derive from original catalog material",
        )?;
        self.pins.insert_original(id, record, authorize)?;
        // Advance only the pin family using the actual exclusive producer; all
        // original catalog, ESP, firmware and reference actors remain unchanged.
        self.original["pins"] = self.pins.evidence()?;
        self.recheck(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.original)
    }
}
