// SPDX-License-Identifier: MIT
//! Actual owned replacement chain for an explicitly reviewed original receipt.
use super::*;
use crate::control_record::{Predecessor, Retained};
pub(crate) struct Journal {
    current: Observation,
    before: Value,
    first_epoch: files::FileIdentity,
    predecessors: Vec<Predecessor>,
    id: String,
}
impl Journal {
    pub(super) fn observe(admission: &Admission<'_>) -> Result<Self> {
        admission.recheck()?;
        let before = admission.record.value()?.clone();
        let id = before["intent"]["id"].as_str().unwrap().to_owned();
        let parent = files::directory_relative(
            admission.guard.control(),
            Path::new("boot-retirements"),
            Some(0),
        )?;
        let current = Observation::open(
            &parent,
            Path::new(&format!("{id}.json")),
            catalog::MAX_CATALOG,
            admission.guard.control_mount_id(),
        )?;
        let first_epoch = files::identity(&admission.record.descriptor()?.metadata()?);
        require(
            files::identity(&current.descriptor()?.metadata()?) == first_epoch
                && current.value()? == &before,
            "owned continuation journal differs from actual original admission",
        )?;
        let this = Self {
            current,
            before,
            first_epoch,
            predecessors: Vec::new(),
            id,
        };
        this.recheck()?;
        admission.recheck()?;
        Ok(this)
    }
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn before(&self) -> &Value {
        &self.before
    }
    pub(crate) fn current(&self) -> Result<&Value> {
        self.recheck()?;
        self.current.value()
    }
    pub(crate) fn observation(&self) -> Result<&Observation> {
        self.recheck()?;
        Ok(&self.current)
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        self.current.descriptor()
    }
    pub(crate) fn require_original_retained(&self, old: &Retained) -> Result<()> {
        self.recheck()?;
        if let Some(first) = self.predecessors.first() {
            first.require_original_retained(old)?;
        } else {
            old.recheck()?;
            require(
                files::identity(&old.descriptor()?.metadata()?) == self.first_epoch
                    && old.value()? == &self.before,
                "continuation journal original selected inode differs",
            )?;
        }
        self.recheck()
    }
    pub(crate) fn require_original_observation(&self, old: &Observation) -> Result<()> {
        self.recheck()?;
        if let Some(first) = self.predecessors.first() {
            first.require_original_observation(old)?;
        } else {
            old.recheck()?;
            require(
                files::identity(&old.descriptor()?.metadata()?) == self.first_epoch
                    && old.value()? == &self.before,
                "continuation journal original observation differs",
            )?;
        }
        self.recheck()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.current.recheck()?;
        let current = self.current.value()?;
        retirement_journal::validate(current, &self.id)?;
        require(
            current["intent"] == self.before["intent"],
            "owned continuation immutable intent changed",
        )?;
        for predecessor in &self.predecessors {
            predecessor.recheck()?;
        }
        Ok(())
    }
    pub(super) fn publish(
        &mut self,
        next: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.recheck()?;
        transition(self.current.value()?, next, &self.id)?;
        require(
            self.predecessors.len() < 64,
            "owned continuation publication bound",
        )?;
        let predecessor = self.current.replace_with_predecessor(next)?;
        self.predecessors.push(predecessor);
        self.recheck()?;
        require(
            self.current.value()? == next,
            "owned continuation publication readback differs",
        )?;
        authorize()?;
        self.recheck()
    }
}
fn transition(old: &Value, next: &Value, id: &str) -> Result<()> {
    retirement_journal::validate(old, id)?;
    retirement_journal::validate(next, id)?;
    require(
        old["intent"] == next["intent"] && old != next,
        "immutable continuation intent or no-op checkpoint",
    )?;
    let number = old["next_step"].as_u64().unwrap();
    let count = old["intent"]["steps"].as_array().unwrap().len() as u64;
    let allowed = match (
        old["phase"].as_str().unwrap(),
        next["phase"].as_str().unwrap(),
    ) {
        ("prepared", "executing") => next["next_step"] == number && next["inflight"].is_null(),
        ("executing", "executing") => {
            old["inflight"].is_null() && next["next_step"] == number && next["inflight"] == number
                || old["inflight"] == number
                    && next["next_step"] == number + 1
                    && next["inflight"].is_null()
        }
        ("executing", "complete") => {
            number == count && next["next_step"] == count && next["inflight"].is_null()
        }
        _ => false,
    };
    require(
        allowed,
        "continuation checkpoint must advance exactly one actual owned boundary",
    )
}
