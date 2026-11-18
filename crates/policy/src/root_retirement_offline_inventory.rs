// SPDX-License-Identifier: MIT
//! Complete bounded kernel subvolume inventory over actual original top/targets.
//! Direct bounded kernel queries do not create a userspace child.
use crate::{
    birth_runtime::Records, root_retirement_offline_scope::Mounts,
    root_retirement_offline_targets::Targets,
};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
fn closure(inventory: &Records, targets: &Value) -> Result<()> {
    let targets = targets
        .as_array()
        .ok_or_else(|| Error("offline inventory target rows".into()))?;
    require(
        (1..=64).contains(&targets.len()) && targets.last().unwrap()["role"] == "root-subvolume",
        "one bounded final offline root target required",
    )?;
    let root = targets.last().unwrap()["path"]
        .as_str()
        .ok_or_else(|| Error("offline inventory root path".into()))?;
    crate::identity::safe_id(root)?;
    let mut expected = BTreeSet::new();
    for row in targets {
        json::fields(row, "role path id uuid parent_uuid")?;
        let path = row["path"]
            .as_str()
            .ok_or_else(|| Error("offline target path".into()))?;
        require(
            path == root || path.starts_with(&format!("{root}/")),
            "offline target outside exact root subtree",
        )?;
        require(
            expected.insert(path.to_owned()),
            "duplicate offline target path",
        )?;
        let mut identity = row.as_object().unwrap().clone();
        identity.remove("role");
        require(
            inventory.get(path) == Some(&Value::Object(identity)),
            "actual complete kernel inventory differs from original target identity",
        )?;
    }
    let actual = inventory
        .keys()
        .filter(|path| path.as_str() == root || path.starts_with(&format!("{root}/")))
        .cloned()
        .collect::<BTreeSet<_>>();
    require(
        actual == expected,
        "unrecorded nested subvolume protects offline root",
    )
}
pub struct Inventory<'a, 's> {
    mounts: &'a Mounts<'s>,
    targets: &'a Targets<'a, 's>,
    original: Records,
}
impl<'a, 's> Inventory<'a, 's> {
    pub(crate) fn first_descriptions(
        &self,
    ) -> Result<crate::root_retirement_first_delete::Descriptions<'_>> {
        self.recheck()?;
        let first = self.targets.first_original()?;
        let (target, parent) = first.descriptions();
        Ok(crate::root_retirement_first_delete::Descriptions {
            top: self.mounts.original_top()?,
            target,
            parent,
            identity: first.identity(),
            before: &self.original,
            objects: self.targets.original_objects()?,
        })
    }
    pub(crate) fn require_original_protection(
        &self,
        protection: &crate::root_retirement_offline_protection::Protection<'a, 's>,
    ) -> Result<()> {
        protection.require_unmentioned(self.targets)?;
        self.recheck()
    }
    pub(crate) fn require_original_publications(
        &self,
        publications: &crate::root_retirement_offline_publications::Publications<'a, 's>,
    ) -> Result<()> {
        publications.require_unmentioned(self.targets)?;
        self.recheck()
    }
    pub(crate) fn require_original_loaders(
        &self,
        loaders: &crate::root_retirement_offline_loaders::Loaders<'a, 's>,
    ) -> Result<()> {
        loaders.require_unmentioned(self.targets)?;
        self.recheck()
    }
    pub(crate) fn require_original_catalog(
        &self,
        catalog: &crate::root_retirement_offline_catalog::Catalog<'a, 's>,
    ) -> Result<()> {
        catalog.require_unmentioned(self.targets)?;
        self.recheck()
    }
    pub(crate) fn require_original_ledgers(
        &self,
        ledgers: &crate::root_retirement_offline_ledgers::Ledgers<'a, 's>,
    ) -> Result<()> {
        self.targets.require_original_ledgers(ledgers)?;
        ledgers.require_unmentioned_sources(self.targets)?;
        self.recheck()
    }
    pub(crate) fn require_original_journal(
        &self,
        journal: &crate::root_retirement_offline_journal::Journal<'a, 's>,
    ) -> Result<()> {
        self.targets.require_original_journal(journal)?;
        self.recheck()
    }
    pub(crate) fn require_original_boot(
        &self,
        mounts: &Mounts<'s>,
        kernel: &crate::root_retirement_kernel_boot::Original<'_>,
        receipt: &crate::root_retirement_image_receipt::Receipt<'_, '_, '_>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.mounts, mounts),
            "original kernel inventory/mount actor differs",
        )?;
        self.targets.require_original_boot(kernel, receipt)?;
        self.recheck()
    }
    pub fn observe(mounts: &'a Mounts<'s>, targets: &'a Targets<'a, 's>) -> Result<Self> {
        targets.require_original_mounts(mounts)?;
        let original = Self::query(mounts, targets)?;
        closure(&original, targets.rows()?)?;
        let this = Self {
            mounts,
            targets,
            original,
        };
        this.recheck()?;
        Ok(this)
    }
    fn query(mounts: &Mounts<'_>, targets: &Targets<'_, '_>) -> Result<Records> {
        targets.require_original_mounts(mounts)?;
        let result = crate::root_retirement_kernel_inventory::query(mounts.original_top()?)?;
        targets.require_original_mounts(mounts)?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.targets.require_original_mounts(self.mounts)?;
        let current = Self::query(self.mounts, self.targets)?;
        require(
            current == self.original,
            "complete kernel subvolume inventory changed since original observation",
        )?;
        closure(&current, self.targets.rows()?)?;
        self.targets.require_original_mounts(self.mounts)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = value!({"subvolumes":self.original,"execution_authorized":false,
            "complete_kernel_subvolume_inventory_verified":true,"userspace_query_child":false,"loader_references_verified":false});
        self.recheck()?;
        Ok(result)
    }
}
