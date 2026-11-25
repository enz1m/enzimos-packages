// SPDX-License-Identifier: MIT
//! Original prepared Root ownership and complete online staging protection.
//! No cold receipt adoption, boot publication or offline delete constructor.
use crate::{
    control_record::Observation as Receipt,
    root_retirement_objects::Targets,
    root_retirement_online_boot::Boot,
    root_retirement_online_intent::{mount_protection, planned_for_receipt, unchanged_namespaces},
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::{Journal, Published},
    root_retirement_references::Observation,
    storage_runtime::{Guard, TopMount},
};
use enzimos_platform::{Result, files, json, require};
use serde_json::{Value, json as value};

pub struct Protected<'a> {
    references: &'a Observation<'a>,
    inventory: &'a Inventory<'a>,
    targets: Targets<'a>,
    receipt: Receipt,
    record: Value,
    boot: Boot<'a>,
    namespaces: crate::namespaces::Observation,
}
impl<'a> Protected<'a> {
    pub fn observe(
        guard: &'a Guard,
        top: &'a TopMount,
        lock: &'a files::Lock,
        references: &'a Observation<'a>,
        inventory: &'a Inventory<'a>,
        journal: &Journal<'_>,
        boot: Boot<'a>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        references.require_original_source(guard, lock, authorize)?;
        inventory.require_original_source(guard, top, lock, authorize)?;
        journal.require_original_source(guard, lock)?;
        let receipt = journal.duplicate_observation()?;
        let record = planned_for_receipt(
            references.original(authorize)?,
            inventory.records(authorize)?,
            receipt.value()?,
        )?;
        let targets = Targets::observe(guard, top, lock, &record["targets"], authorize)?;
        references.require_target_references(&targets, &record, authorize)?;
        boot.protect(&targets, authorize)?;
        let namespaces = crate::namespaces::observe()?;
        mount_protection(&namespaces, &record["targets"])?;
        let this = Self {
            references,
            inventory,
            targets,
            receipt,
            record,
            boot,
            namespaces,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.receipt.recheck()?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            self.receipt.value()? == &self.record
                && planned_for_receipt(
                    self.references.original(authorize)?,
                    self.inventory.records(authorize)?,
                    &self.record,
                )? == self.record,
            "original prepared staging target ownership changed",
        )?;
        self.references
            .require_target_references(&self.targets, &self.record, authorize)?;
        self.boot.protect(&self.targets, authorize)?;
        self.namespace_barrier(authorize)?;
        self.receipt.recheck()?;
        self.targets.recheck(authorize)
    }
    pub fn recheck_staged(
        &self,
        published: &Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        published.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references
                    .original_after_staging(published, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original staging ownership changed after owned receipt publication",
        )?;
        self.boot
            .verify_staged_root_receipt(published, &self.targets, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(published, authorize)?;
        published.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    /// Verify the complete original protection while only the actual known
    /// receipt and signing namespace have crossed their owned publications.
    pub(crate) fn recheck_signing(
        &self,
        published: &Published<'_>,
        state: &crate::root_retirement_signed_namespace::State<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        published.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references
                    .original_after_staging(published, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original staging ownership changed around owned signing namespace",
        )?;
        self.boot
            .verify_owned_signing_namespace(published, &self.targets, state, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(published, authorize)?;
        published.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_pending_entry(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::PendingEntry<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending entry",
        )?;
        self.boot
            .verify_pending_root_entry(receipt, &self.targets, signer, pending, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_committed_entry(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::CommittedEntry<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending entry",
        )?;
        self.boot.verify_committed_root_entry(
            receipt,
            &self.targets,
            signer,
            pending,
            authorize,
        )?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_pending_bios(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::PendingBios<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending BIOS",
        )?;
        self.boot
            .verify_pending_bios(receipt, &self.targets, signer, pending, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_committed_bios(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::CommittedBios<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending BIOS",
        )?;
        self.boot
            .verify_committed_bios(receipt, &self.targets, signer, pending, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_firmware_publication(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_firmware_publication::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending BIOS",
        )?;
        self.boot.verify_firmware_publication(
            receipt,
            &self.targets,
            signer,
            pending,
            authorize,
        )?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_committed_defaults(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::CommittedDefaults<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending BIOS",
        )?;
        self.boot
            .verify_committed_defaults(receipt, &self.targets, signer, pending, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    pub(crate) fn recheck_pending_defaults(
        &self,
        receipt: &Published<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::PendingDefaults<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        receipt.require_original_observation(&self.receipt)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        require(
            planned_for_receipt(
                self.references.original_after_staging(receipt, authorize)?,
                self.inventory.records(authorize)?,
                &self.record,
            )? == self.record,
            "original target ownership changed around actual pending BIOS",
        )?;
        self.boot
            .verify_pending_defaults(receipt, &self.targets, signer, pending, authorize)?;
        self.namespace_barrier(authorize)?;
        self.inventory.recheck(authorize)?;
        self.references
            .verify_staged_root_receipt(receipt, authorize)?;
        receipt.require_original_observation(&self.receipt)?;
        self.targets.recheck(authorize)
    }
    fn namespace_barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        let current = crate::namespaces::observe()?;
        mount_protection(&current, &self.record["targets"])?;
        unchanged_namespaces(
            &current,
            &self.namespaces,
            "original staging namespace mount observations changed",
        )?;
        authorize()
    }
    /// Compile exact options from the actual protected targets, retained loader
    /// texts, ready image and original probed encrypted Root source.
    /// No boot publication, firmware write or deletion is performed.
    pub(crate) fn compile_stage(
        &self,
        image: &crate::root_retirement_online_image::Image<'_>,
        source: &crate::root_retirement_online_encryption::Source<'_>,
        exit: &str,
        mode: crate::root_retirement_stage_contract::UefiMode,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::root_retirement_stage_contract::Stage> {
        self.recheck(authorize)?;
        let staged = self.boot.compile_root_stage(
            &self.targets,
            &self.record,
            image,
            source,
            exit,
            mode,
            authorize,
        )?;
        self.recheck(authorize)?;
        Ok(staged)
    }
    /// Reviewed staging comparison from the actual original image, encrypted
    /// source, receipt, references and complete protected boot/target context.
    /// Returned JSON is comparison data and cannot create any mutation actor.
    pub fn stage_measurement(
        &self,
        image: &crate::root_retirement_online_image::Image<'_>,
        source: &crate::root_retirement_online_encryption::Source<'_>,
        exit: &str,
        mode: crate::root_retirement_stage_contract::UefiMode,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        let staged = self.compile_stage(image, source, exit, mode, authorize)?;
        let result = value!({"filesystem_uuid":self.record["filesystem_uuid"],
            "plan_sha256":self.record["plan_sha256"],"protected":self.measurement(authorize)?,
            "image":image.evidence(authorize)?,"encrypted_source":source.evidence(authorize)?,
            "staged_record":staged.record,
            "uefi_sha256":json::sha256(staged.uefi.as_bytes()),
            "bios_sha256":json::sha256(staged.bios.as_bytes()),
            "defaults_sha256":json::sha256(staged.defaults.as_bytes()),
            "deletion_authorized":false});
        self.recheck(authorize)?;
        image.recheck(authorize)?;
        source.recheck(authorize)?;
        Ok(result)
    }
    pub fn measurement(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = value!({"filesystem_uuid":self.record["filesystem_uuid"],
            "plan_sha256":self.record["plan_sha256"],"receipt_sha256":json::fingerprint(&self.record)?,
            "reference_sha256":json::fingerprint(self.references.original(authorize)?)?,
            "loader_sha256":json::fingerprint(&self.boot.evidence(authorize)?)?,
            "target_epoch_sha256":json::fingerprint(&self.targets.planning_evidence(authorize)?)?});
        self.recheck(authorize)?;
        Ok(result)
    }
    pub fn record(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.record)
    }
}
