// SPDX-License-Identifier: MIT
//! Retained complete online boot context, exposing no boot retirement mutator.
use crate::{
    boot_retirement_context::Context, root_retirement_objects::Targets, storage_runtime::Guard,
};
use enzimos_platform::{Result, files};
use serde_json::Value;
pub struct Boot<'a> {
    original: Context<'a, 'a>,
    namespace: crate::root_retirement_signed_namespace::Namespace<'a>,
}
impl<'a> Boot<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        references: &crate::root_retirement_references::Observation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        references.require_original_source(guard, lock, authorize)?;
        let namespace =
            crate::root_retirement_signed_namespace::Namespace::observe(guard, lock, authorize)?;
        let this = Self {
            namespace,
            original: Context::observe_shared_catalog(
                guard,
                lock,
                references.catalog_actor(authorize)?,
                authorize,
            )?,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn observe_journal(
        guard: &'a Guard,
        lock: &'a files::Lock,
        references: &crate::root_retirement_references::Observation<'_>,
        journal: &crate::root_retirement_online_journal::Journal<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        references.require_original_source(guard, lock, authorize)?;
        journal.require_original_source(guard, lock)?;
        let namespace =
            crate::root_retirement_signed_namespace::Namespace::observe(guard, lock, authorize)?;
        let this = Self {
            namespace,
            original: Context::observe_shared_journal(
                guard,
                lock,
                references.catalog_actor(authorize)?,
                journal,
                authorize,
            )?,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn finish_loaders(
        self,
        journal: &crate::root_retirement_online_journal::Journal<'_>,
        inventory: &crate::root_retirement_online_inventory::Inventory<'_>,
        firmware: Option<crate::root_retirement_firmware_publication::finish::Completed<'a>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::boot_retirement_context::finish::Cleanup<'a, 'a>> {
        self.recheck(authorize)?;
        let cleanup = crate::boot_retirement_context::finish::Cleanup::observe(
            self.original,
            journal,
            inventory,
            firmware,
            authorize,
        )?;
        cleanup.run(inventory, authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.namespace.recheck(authorize)?;
        self.original.recheck(authorize)?;
        self.namespace.recheck(authorize)
    }
    pub(crate) fn protect(
        &self,
        targets: &Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.namespace.recheck(authorize)?;
        self.original.protect_root_targets(targets, authorize)?;
        self.namespace.recheck(authorize)
    }
    pub(crate) fn root_receipt_barrier(
        &self,
        targets: &Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.namespace.recheck(authorize)?;
        self.original.root_receipt_barrier(targets, authorize)?;
        self.namespace.recheck(authorize)
    }
    pub(crate) fn bind_root_receipt(
        &mut self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
        targets: &Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original
            .bind_root_receipt(registry, record, targets, authorize)
    }
    pub(crate) fn verify_new_root_receipt(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        record: &Value,
        targets: &Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.namespace.recheck(authorize)?;
        self.original
            .verify_new_root_receipt(registry, record, targets, authorize)?;
        self.namespace.recheck(authorize)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is a distinct retained input of this step."
    )]
    pub(crate) fn compile_root_stage(
        &self,
        targets: &Targets<'_>,
        record: &Value,
        image: &crate::root_retirement_online_image::Image<'_>,
        source: &crate::root_retirement_online_encryption::Source<'_>,
        exit: &str,
        mode: crate::root_retirement_stage_contract::UefiMode,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::root_retirement_stage_contract::Stage> {
        self.original
            .compile_root_stage(targets, record, image, source, exit, mode, authorize)
    }
    pub fn verify_staged_root_receipt(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.namespace.recheck(authorize)?;
        self.original
            .verify_staged_root_receipt(published, targets, authorize)?;
        self.namespace.recheck(authorize)
    }
    pub fn verify_owned_signing_namespace(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        state: &crate::root_retirement_signed_namespace::State<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_signing_namespace(
            published,
            targets,
            self.namespace.original()?,
            state,
            authorize,
        )
    }
    pub fn verify_pending_root_entry(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        pending: &crate::root_retirement_loader_publication::PendingEntry<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::Pending(pending),
            authorize,
        )
    }
    pub fn verify_committed_root_entry(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        committed: &crate::root_retirement_loader_publication::CommittedEntry<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::Committed(committed),
            authorize,
        )
    }
    pub fn verify_pending_bios(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        committed: &crate::root_retirement_loader_publication::PendingBios<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::BiosPending(committed),
            authorize,
        )
    }
    pub fn verify_committed_bios(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        committed: &crate::root_retirement_loader_publication::CommittedBios<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::BiosCommitted(committed),
            authorize,
        )
    }
    pub fn verify_firmware_publication(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        committed: &crate::root_retirement_firmware_publication::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::OneShot(committed),
            authorize,
        )
    }
    pub fn verify_committed_defaults(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        committed: &crate::root_retirement_loader_publication::CommittedDefaults<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::DefaultsCommitted(committed),
            authorize,
        )
    }
    pub fn verify_pending_defaults(
        &self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        targets: &Targets<'_>,
        signer: &crate::root_retirement_signed_namespace::Published<'_>,
        committed: &crate::root_retirement_loader_publication::PendingDefaults<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.original.verify_owned_root_entry(
            receipt,
            targets,
            self.namespace.original()?,
            signer,
            &crate::root_retirement_loader_publication::State::DefaultsPending(committed),
            authorize,
        )
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = serde_json::json!({"boot":self.original.evidence(authorize)?,
            "original_signing_namespace":self.namespace.evidence(authorize)?});
        self.recheck(authorize)?;
        Ok(result)
    }
}
