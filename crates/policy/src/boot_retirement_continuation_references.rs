// SPDX-License-Identifier: MIT
//! All original independent transition/reference objects for continuation review.
use super::*;
use crate::{
    boot_backend_references, generation_pins, recovery_conclusions,
    recovery_journal::{Journal, Kind},
};
pub(super) struct References<'a> {
    guard: &'a Guard,
    records: Value,
    controls: Vec<control_registry::Snapshot<'a>>,
    journals: Vec<Journal>,
    backend: boot_backend_references::Observation<'a>,
    conclusions: recovery_conclusions::Observation<'a>,
    pins: generation_pins::Snapshot<'a>,
    generation: String,
    id: String,
}
impl<'a> References<'a> {
    pub(super) fn observe(guard: &'a Guard, receipt: &Observation) -> Result<Self> {
        let records = crate::transition_idle::inspect_boot_continuation(guard, receipt)?;
        let id = enzimos_platform::json::string(&receipt.value()?["intent"]["id"])?.to_owned();
        let generation = id
            .strip_prefix("boot-")
            .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?
            .to_owned();
        identity::safe_id(&generation)?;
        let mut controls = Vec::new();
        for (folder, key) in [
            ("boot-publications", "boot_publications"),
            ("update-workers", "update_workers"),
            ("module-views", "module_views"),
            ("authority-refresh", "authority_refresh"),
            ("root-births", "births"),
            ("root-rebind-journal", "rebinds"),
            ("retirement-journals", "retirement"),
            ("root-retirements", "root_retirement"),
        ] {
            controls.push(control_registry::Snapshot::observe(
                guard,
                folder,
                &records[key],
            )?);
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
            let journal = Journal::open(kind, false)?;
            require(
                value!(journal.records) == records[key],
                "continuation recovery references changed during retention",
            )?;
            journal.unchanged()?;
            journals.push(journal);
        }
        let backend = boot_backend_references::Observation::observe(guard)?;
        let conclusions = recovery_conclusions::Observation::observe(guard)?;
        let pins = generation_pins::Snapshot::observe(guard)?;
        let this = Self {
            guard,
            records,
            controls,
            journals,
            backend,
            conclusions,
            pins,
            generation,
            id,
        };
        this.recheck(receipt)?;
        Ok(this)
    }
    pub(super) fn recheck(&self, receipt: &Observation) -> Result<()> {
        self.guard.recheck()?;
        receipt.recheck()?;
        require(
            receipt.value()?["intent"]["id"] == self.id,
            "original continuation selection changed",
        )?;
        for control in &self.controls {
            control.recheck()?;
        }
        for journal in &self.journals {
            journal.unchanged()?;
        }
        self.conclusions.recheck()?;
        self.backend
            .require_unmentioned_with_conclusions(&self.generation, &self.conclusions)?;
        self.pins.recheck()?;
        require(
            crate::transition_idle::inspect_boot_continuation(self.guard, receipt)? == self.records,
            "original independent continuation transition changed",
        )?;
        // Remove only the retained selected receipt from this pure reference
        // calculation. Every backend row and every other native receipt remains.
        let mut independent = self.records.clone();
        require(
            enzimos_platform::json::object_mut(&mut independent["boot_retirement"])?
                .remove(&self.id)
                == Some(receipt.value()?.clone()),
            "selected original continuation receipt differs",
        )?;
        require(
            crate::boot_retirement_references::protection(&independent, &self.generation)?
                .is_empty(),
            "independent concrete reference protects continuation candidate",
        )?;
        for pin in enzimos_platform::json::object(&self.pins.evidence()?["pins"])?.values() {
            require(
                pin["generation"] != self.generation,
                "generation pin protects continuation candidate",
            )?;
        }
        self.guard.recheck()?;
        receipt.recheck()
    }
    pub(super) fn recheck_owned(&self, journal: &ContinuationJournal) -> Result<()> {
        self.guard.recheck()?;
        journal.recheck()?;
        require(
            journal.id() == self.id
                && self.records["boot_retirement"][&self.id] == *journal.before(),
            "owned continuation reference origin differs",
        )?;
        for control in &self.controls {
            control.recheck()?;
        }
        for journal in &self.journals {
            journal.unchanged()?;
        }
        self.conclusions.recheck()?;
        self.backend
            .require_unmentioned_with_conclusions(&self.generation, &self.conclusions)?;
        self.pins.recheck()?;
        let mut expected = self.records.clone();
        expected["boot_retirement"][&self.id] = journal.current()?.clone();
        require(
            crate::transition_idle::inspect_boot_continuation(self.guard, journal.observation()?)?
                == expected,
            "independent transition changed outside actual continuation publication",
        )?;
        enzimos_platform::json::object_mut(&mut expected["boot_retirement"])?.remove(&self.id);
        require(
            crate::boot_retirement_references::protection(&expected, &self.generation)?.is_empty(),
            "independent reference protects owned continuation",
        )?;
        for pin in enzimos_platform::json::object(&self.pins.evidence()?["pins"])?.values() {
            require(
                pin["generation"] != self.generation,
                "original pin protects owned continuation",
            )?;
        }
        self.guard.recheck()?;
        journal.recheck()
    }
    pub(super) fn pins(&self) -> Result<Value> {
        self.pins.recheck()?;
        Ok(self.pins.evidence()?["pins"].clone())
    }
    pub(super) fn evidence(&self, receipt: &Observation) -> Result<Value> {
        self.recheck(receipt)?;
        let controls = self
            .controls
            .iter()
            .map(super::super::control_registry::Snapshot::evidence)
            .collect::<Result<Vec<_>>>()?;
        let journals = self
            .journals
            .iter()
            .map(super::super::recovery_journal::Journal::evidence)
            .collect::<Result<Vec<_>>>()?;
        let result = value!({"controls":controls,"recovery_journals":journals,"backend":self.backend.evidence()?,"pins":self.pins.evidence()?,"own_receipt_scope":self.id,"backend_rows_exempted":false,"execution_authorized":false});
        self.recheck(receipt)?;
        Ok(result)
    }
}
