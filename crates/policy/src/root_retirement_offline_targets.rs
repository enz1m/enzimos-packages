// SPDX-License-Identifier: MIT
//! Actual offline target descriptions joined to original journal/control/origins.
//! No cold data or pathname can construct a deletion capability.
use crate::{
    root_retirement_objects::Original, root_retirement_offline_control::Control,
    root_retirement_offline_journal::Journal, root_retirement_offline_origins::Origins,
    root_retirement_offline_scope::Mounts,
};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
/// The offline retirement targets joined to their journal and origins.
pub struct Targets<'a, 's> {
    control: &'a Control<'a, 's>,
    mounts: &'a Mounts<'s>,
    journal: &'a Journal<'a, 's>,
    origins: &'a Origins<'a, 's>,
    record: Value,
    objects: Vec<Original>,
}
impl<'a, 's> Targets<'a, 's> {
    pub(crate) fn original_objects(&self) -> Result<&[Original]> {
        self.recheck()?;
        Ok(&self.objects)
    }
    pub(crate) fn first_original(&self) -> Result<&Original> {
        self.recheck()?;
        self.objects
            .first()
            .ok_or_else(|| Error("original first retirement target missing".into()))
    }
    /// Only this actual target/origin actor can identify its superseded owner.
    pub(crate) fn superseded_owner(&self) -> Result<Option<&str>> {
        self.recheck()?;
        Ok(enzimos_platform::json::string(&self.record["birth"])?.strip_prefix("superseded-"))
    }
    pub(crate) fn require_original_catalog(
        &self,
        catalog: &crate::root_retirement_offline_catalog::Catalog<'a, 's>,
    ) -> Result<()> {
        catalog.require_original_control(self.control)?;
        self.recheck()
    }
    pub(crate) fn require_original_ledgers(
        &self,
        ledgers: &crate::root_retirement_offline_ledgers::Ledgers<'a, 's>,
    ) -> Result<()> {
        ledgers.require_original_journal(self.journal)?;
        self.recheck()
    }
    pub(crate) fn require_original_journal(&self, journal: &Journal<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.journal, journal),
            "original offline targets belong to another journal",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_boot(
        &self,
        kernel: &crate::root_retirement_kernel_boot::Original<'_>,
        receipt: &crate::root_retirement_image_receipt::Receipt<'_, '_, '_>,
    ) -> Result<()> {
        self.recheck()?;
        kernel.require_original_mounts(self.mounts)?;
        kernel.matches_record(&self.record)?;
        receipt.require_original_kernel_boot(kernel)?;
        receipt.require_original_control(self.control)?;
        require(
            self.record["coordinator"]["image"] == receipt.identifier()?,
            "actual prepared retirement differs from original ready-image receipt",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_mounts(&self, mounts: &Mounts<'s>) -> Result<()> {
        require(
            std::ptr::eq(self.mounts, mounts),
            "original offline target/mount actor differs",
        )?;
        self.recheck()
    }
    pub(crate) fn rows(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.record["targets"])
    }
    pub(crate) fn observe(
        control: &'a Control<'a, 's>,
        mounts: &'a Mounts<'s>,
        journal: &'a Journal<'a, 's>,
        origins: &'a Origins<'a, 's>,
    ) -> Result<Self> {
        control.require_original_mounts(mounts)?;
        journal.require_original_control(control)?;
        origins.require_original_control(control)?;
        let record = journal.prepared_record()?;
        require(
            record["phase"] == "prepared"
                && record["next_step"] == 0
                && record["inflight"].is_null(),
            "original prepared offline targets required; cold execution cannot replay",
        )?;
        let fs = mounts.filesystem_binding()?;
        require(
            record["filesystem_uuid"] == fs["filesystem_uuid"],
            "original offline target record belongs to another filesystem",
        )?;
        let control_identity = control.evidence()?["identity"].clone();
        let mut objects = Vec::new();
        let mut ids = BTreeSet::new();
        let mut uuids = BTreeSet::new();
        for row in enzimos_platform::json::array(&record["targets"])? {
            control.require_original_mounts(mounts)?;
            journal.recheck()?;
            origins.recheck()?;
            let object = Original::observe(mounts.original_top()?, row, &fs["filesystem_uuid"])?;
            require(
                object.identity()["uuid"] != control_identity["uuid"]
                    && object.identity()["id"] != control_identity["id"]
                    && object.identity()["path"] != control_identity["path"],
                "actual original control subvolume cannot be a retirement target",
            )?;
            require(
                ids.insert(enzimos_platform::json::unsigned(&object.identity()["id"])?)
                    && uuids.insert(
                        enzimos_platform::json::string(&object.identity()["uuid"])?.to_owned(),
                    ),
                "original actual offline target identities must be distinct",
            )?;
            objects.push(object);
        }
        let root = objects
            .last()
            .ok_or_else(|| Error("offline root target absent".into()))?;
        require(
            !root.readonly(),
            "actual retired root must be original writable root",
        )?;
        origins.require_owner(&record, root.identity())?;
        let this = Self {
            control,
            mounts,
            journal,
            origins,
            record,
            objects,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.control.require_original_mounts(self.mounts)?;
        self.journal.require_original_control(self.control)?;
        self.origins.require_original_control(self.control)?;
        require(
            self.journal.prepared_record()? == self.record,
            "original offline target journal changed",
        )?;
        let fs = self.mounts.filesystem_binding()?;
        require(
            fs["filesystem_uuid"] == self.record["filesystem_uuid"],
            "original offline filesystem changed",
        )?;
        for object in &self.objects {
            object.recheck(self.mounts.original_top()?, &fs["filesystem_uuid"])?;
            self.journal.recheck()?;
        }
        self.origins.require_owner(
            &self.record,
            self.objects
                .last()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
                .identity(),
        )?;
        self.control.require_original_mounts(self.mounts)
    }
    /// JSON evidence of this retained state; it grants no deletion.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = value!({"journal":self.journal.evidence()?,"origins":self.origins.evidence()?,
            "targets":self.objects.iter().map(Original::evidence).collect::<Vec<_>>(),
            "execution_authorized":false,"loader_references_verified":false,
            "complete_kernel_subvolume_inventory_verified":false});
        self.recheck()?;
        Ok(result)
    }
}
