// SPDX-License-Identifier: MIT
//! Original read-only control, subvolume and recovery measurements for inspection.
use crate::{
    birth_runtime::{self, Records, Store},
    catalog::Transaction,
    control_registry::Snapshot,
    recovery_journal::{Journal, Kind},
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::AsFd,
};
pub(crate) struct Observation<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    source: Value,
    births: Store,
    rebinds: Records,
    rebind_registry: Snapshot<'a>,
    retirement_registry: Snapshot<'a>,
    control_identity: Value,
    journals: Vec<(Kind, Journal)>,
    inventory: Records,
    readonly: Records,
    images: Vec<crate::recovery_image::Published>,
    pins: crate::generation_pins::Snapshot<'a>,
    backend: crate::boot_backend_references::Observation<'a>,
    data: Value,
}
pub(crate) fn staged(jobs: &Records, inventory: &Records) -> Value {
    let mut resources = BTreeMap::new();
    let mut pending = Vec::new();
    let mut drift = Vec::new();
    for (id, row) in jobs {
        if row["phase"] != "staged" {
            pending.push(id.clone());
        }
        for role in ["root", "history"] {
            let identity = &row[role];
            if identity.is_null() {
                continue;
            }
            let matches = identity["path"]
                .as_str()
                .is_some_and(|p| inventory.get(p) == Some(identity));
            let key = format!("{id}:{role}");
            if !matches {
                drift.push(key.clone());
            }
            resources.insert(key,value!({"identity":identity,"identity_matches":matches,"creation_complete":row["phase"]=="staged","deletion_authorized":false}));
        }
    }
    value!({"pending":pending,"drift":drift,"resources":resources,"retirement_enabled":false,
        "scope":"staged recovery creation records only; not recovery-image ownership or boot confirmation"})
}
impl<'a> Observation<'a> {
    pub(crate) fn complete_graph(&mut self, catalog: &Transaction, boot: &Value) -> Result<()> {
        self.recheck()?;
        catalog.recheck()?;
        require(
            boot["catalog"] == catalog.data
                && boot["source"] == self.source
                && self.data["root_references"].is_object(),
            "original boot/reference source join required",
        )?;
        let texts = boot["texts"]
            .as_object()
            .ok_or_else(|| enzimos_platform::Error("original loader texts required".into()))?;
        let mut uefi = BTreeMap::new();
        for (path, body) in texts {
            if let Some(name) = path.strip_prefix("loader/entries/") {
                let text = body.as_str().ok_or_else(|| {
                    enzimos_platform::Error("original loader text encoding".into())
                })?;
                uefi.insert(
                    name.to_owned(),
                    crate::boot_entries::fields(text, false)
                        .map_or_else(|_| value!({"unparsed":true}), |f| value!(f)),
                );
            }
        }
        let menu = crate::boot_entries::menu(
            texts
                .get("limine/limine.conf")
                .and_then(Value::as_str)
                .ok_or_else(|| enzimos_platform::Error("original BIOS menu required".into()))?,
        )?;
        let variables: Records = serde_json::from_value(boot["firmware"]["variables"].clone())?;
        let defaults = crate::recovery_reference_diagnostic::candidates(
            texts
                .get("loader/loader.conf")
                .and_then(Value::as_str)
                .ok_or_else(|| enzimos_platform::Error("original UEFI defaults required".into()))?,
            &uefi,
            &variables,
        )?;
        let records = &self.data["original_records"];
        let input = value!({"catalog":catalog.data,"root_references":self.data["root_references"],
            "images":records[Kind::Images.folder()],"publications":records[Kind::Publications.folder()],
            "jobs":records[Kind::Jobs.folder()],"activations":records[Kind::Activations.folder()],
            "pins":self.data["pins"],"rebinds":self.data["rebinds"],"operations":self.data["backend"],"retirements":self.data["retirements"],
            "uefi":uefi,"bios":menu.entries.iter().map(|e|value!({"title":e.title,"text":e.text})).collect::<Vec<_>>(),
            "defaults":defaults,"variables":boot["firmware"]["variables"],"bios_default_title":menu.entries[menu.selected-1].title,
            "efi_observable":boot["firmware"]["observable"],"boot_uuid":boot["boot_uuid"],"command_line":boot["command_line"]});
        let graph = crate::recovery_reference_diagnostic::join(&input)?;
        let mut measured = BTreeMap::new();
        for (relative, row) in enzimos_platform::json::object(&boot["artifacts"])? {
            measured.insert(
                format!("/{relative}"),
                value!({"bytes":row["bytes"],"sha256":row["sha256"]}),
            );
        }
        for image in &self.images {
            for (path, row) in image.measurements()? {
                if let Some(before) = measured.get(&path) {
                    require(
                        before == &row,
                        "independent original artifact measurements differ",
                    )?;
                }
                measured.insert(path, row);
            }
        }
        self.data["recovery_references"] =
            crate::recovery_reference_diagnostic::finish_observation(
                graph,
                &catalog.data,
                &self.births.records,
                &measured,
            )?;
        self.recheck()?;
        catalog.recheck()
    }
    pub(crate) fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        catalog: &Transaction,
        namespaces: Option<&Value>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        catalog.recheck()?;
        let source = guard.backup_root_binding()?;
        let (control_identity, control_readonly) = crate::subvolume::observe(
            guard.control().as_fd(),
            enzimos_platform::json::string(&guard.configuration["control_subvol"])?,
        )?;
        require(
            !control_readonly,
            "original inspection control must be writable",
        )?;
        let births = Store::open(false)?;
        require(
            births.configuration() == &guard.configuration
                && births.control_mount_id() == guard.control_mount_id()
                && catalog.config == guard.configuration,
            "inspection reference source changed",
        )?;
        let rebinds = crate::control_registry::read(
            guard,
            "root-rebind-journal",
            32,
            crate::root_rebind_record::validate,
        )?;
        let rebind_registry = Snapshot::observe(guard, "root-rebind-journal", &value!(rebinds))?;
        let retirements = crate::control_registry::read(
            guard,
            "retirement-journals",
            crate::retirement_journal::MAX_RECORDS,
            crate::retirement_journal::validate,
        )?;
        let retirement_registry =
            Snapshot::observe(guard, "retirement-journals", &value!(retirements))?;
        let mut journals = Vec::new();
        for kind in [
            Kind::Jobs,
            Kind::Runs,
            Kind::Activations,
            Kind::Workflows,
            Kind::Images,
            Kind::Publications,
            Kind::Media,
        ] {
            let journal = Journal::open(kind, false)?;
            journal.unchanged()?;
            journals.push((kind, journal));
        }
        let pins = crate::generation_pins::Snapshot::observe(guard)?;
        let backend = crate::boot_backend_references::Observation::observe(guard)?;
        let inventory = birth_runtime::inventory(false)?;
        let readonly = birth_runtime::inventory(true)?;
        crate::root_reference_diagnostic::validate_inventory(&inventory)?;
        crate::root_reference_diagnostic::validate_inventory(&readonly)?;
        require(
            readonly.iter().all(|(p, r)| inventory.get(p) == Some(r)),
            "inspection read-only subvolume set changed",
        )?;
        let root_births = birth_runtime::evaluate(&births.records, &inventory, &readonly)?;
        let jobs = &journals
            .iter()
            .find(|(k, _)| *k == Kind::Jobs)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .1
            .records;
        let recovery_staging = staged(jobs, &inventory);
        let image_records = &journals
            .iter()
            .find(|(k, _)| *k == Kind::Images)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .1
            .records;
        let publications = &journals
            .iter()
            .find(|(k, _)| *k == Kind::Publications)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .1
            .records;
        let mut blockers = BTreeSet::new();
        let mut image_rows = BTreeMap::new();
        let mut images = Vec::new();
        for (id, row) in publications {
            let terminal = image_records.get(id).is_some_and(|image| {
                image["phase"] == "ready"
                    && crate::recovery_publication::expected_record(row, image).is_ok()
            });
            if !terminal {
                blockers.insert(format!("pending-recovery-publication-journal:{id}"));
            }
        }
        for (id, row) in image_records {
            let mut valid = false;
            let source_matches = row["filesystem_uuid"] == guard.configuration["filesystem_uuid"]
                && ["path", "id", "uuid"]
                    .iter()
                    .all(|k| row["control"][*k] == control_identity[*k]);
            if row["phase"] == "ready" && source_matches {
                match crate::recovery_image::Published::observe(row) {
                    Ok(original) => {
                        original.recheck()?;
                        images.push(original);
                        valid = true;
                    }
                    Err(_) => {
                        blockers.insert(format!("recovery-image-binding-drift:{id}"));
                    }
                }
            } else if row["phase"] == "ready" {
                blockers.insert(format!("recovery-image-binding-drift:{id}"));
            } else {
                blockers.insert(format!("pending-recovery-publication:{id}"));
            }
            let modes: Vec<_> = enzimos_platform::json::object(&row["observations"])?
                .keys()
                .collect();
            image_rows.insert(
                id.clone(),
                value!({"phase":row["phase"],"live_bindings_match":valid,
                "software_observed_modes":modes,"deletion_authorized":false}),
            );
        }
        if image_rows.is_empty() {
            blockers.insert("no-publisher-owned-recovery-image".into());
        }
        let recovery_images = value!({"images":image_rows,"blockers":blockers,"retirement_enabled":false,
            "scope":"new image origin and software-local observations; not firmware/app health or complete references"});
        let root_references = namespaces
            .map(|n| {
                crate::root_reference_diagnostic::join(
                    &catalog.data,
                    &births.records,
                    &inventory,
                    &readonly,
                    n,
                )
            })
            .transpose()?;
        let pending_births: Vec<_> = births
            .records
            .iter()
            .filter(|(_, r)| !matches!(r["phase"].as_str(), Some("ready" | "retired")))
            .map(|(id, _)| id)
            .collect();
        let pending_rebinds: Vec<_> = rebinds
            .iter()
            .filter(|(_, r)| r["phase"] != "complete")
            .map(|(id, _)| id)
            .collect();
        let publisher_registry = value!({"generations":enzimos_platform::json::object(&catalog.data["generations"])?.len(),
            "software_confirmed":enzimos_platform::json::object(&catalog.data["generations"])?.values().filter(|r|!r["first_confirmation"].is_null()).count(),
            "pending_rebinds":pending_rebinds,"pending_births":pending_births});
        let records: BTreeMap<_, _> = journals
            .iter()
            .map(|(kind, journal)| (kind.folder(), value!(journal.records)))
            .collect();
        let data = value!({"publisher_registry":publisher_registry,"root_births":root_births,
            "root_references":root_references,"recovery_staging":recovery_staging,"recovery_images":recovery_images,
            "original_records":records,"retirements":retirements,"rebinds":rebinds,"pins":pins.evidence()?["pins"],"backend":backend.evidence()?["records"],
            "inventory":inventory,"readonly":readonly,"execution_authorized":false});
        let this = Self {
            guard,
            lock,
            source,
            births,
            rebinds,
            rebind_registry,
            retirement_registry,
            control_identity,
            journals,
            inventory,
            readonly,
            images,
            pins,
            backend,
            data,
        };
        this.recheck()?;
        catalog.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        require(
            self.guard.backup_root_binding()? == self.source,
            "inspection original source changed",
        )?;
        let current = crate::subvolume::observe(
            self.guard.control().as_fd(),
            enzimos_platform::json::string(&self.guard.configuration["control_subvol"])?,
        )?;
        require(
            current.0 == self.control_identity && !current.1,
            "original control subvolume identity changed during inspection",
        )?;
        self.retirement_registry.recheck()?;
        self.births.recheck()?;
        self.rebind_registry.recheck()?;
        require(
            crate::control_registry::read(
                self.guard,
                "root-rebind-journal",
                32,
                crate::root_rebind_record::validate,
            )? == self.rebinds,
            "inspection rebind records changed",
        )?;
        for (_, journal) in &self.journals {
            journal.unchanged()?;
        }
        for image in &self.images {
            image.recheck()?;
        }
        self.pins.recheck()?;
        self.backend.recheck()?;
        require(
            birth_runtime::inventory(false)? == self.inventory
                && birth_runtime::inventory(true)? == self.readonly,
            "inspection original subvolume census changed",
        )?;
        self.guard.recheck()?;
        self.lock.recheck()
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let mut data = self.data.clone();
        // Internal graph inputs retain their original actors but are not an
        // outward dump of private backend plans or recovery journals.
        for key in [
            "original_records",
            "rebinds",
            "retirements",
            "pins",
            "backend",
            "inventory",
            "readonly",
        ] {
            enzimos_platform::json::object_mut(&mut data)?.remove(key);
        }
        self.recheck()?;
        Ok(data)
    }
}
