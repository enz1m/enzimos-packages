// SPDX-License-Identifier: MIT
//! Original private setup job ledger; live epochs are never adopted by pathname.
use super::{backup_setup_record as record, operation_store::Store};
use enzimos_platform::{Result, require, secret};
use serde_json::{Value, json as value};
use std::{fs::File, os::unix::fs::MetadataExt, path::Path};
pub(crate) struct SetupStore<G> {
    store: Store<G>,
}
impl<G: Fn() -> Result<()>> SetupStore<G> {
    pub(crate) fn open(path: &Path, guard: G) -> Result<Self> {
        enzimos_policy::namespaces::initial()?;
        Self::open_owned(path, 0, guard)
    }
    pub(crate) fn open_owned(path: &Path, owner: u32, guard: G) -> Result<Self> {
        Ok(Self {
            store: Store::open_backup(path, owner, guard)?,
        })
    }
    pub(crate) fn status(&self, id: &str, uid: u32) -> Result<Value> {
        record::public(&self.store.status(id, uid)?)
    }
    /// Record `rolled-back` for an `uncertain` enrollment whose retraction a
    /// later `reset-uncertain` proved (see `backup_setup_failure::reset_settles`).
    pub(crate) fn reconcile_reset(
        &mut self,
        id: &str,
        uid: u32,
        proof: Option<&Value>,
        facts: super::backup_setup_failure::Facts,
    ) -> Result<bool> {
        let Some(mut v) = self.store.optional_status(id, uid)? else {
            return Ok(false);
        };
        if !super::backup_setup_failure::reset_settles(&v, proof, facts) {
            return Ok(false);
        }
        v["state"] = value!("rolled-back");
        self.store.publish(id, v)?;
        Ok(true)
    }
    pub(crate) fn private(&self, id: &str, uid: u32, sha: &str) -> Result<Value> {
        let v = self.store.status(id, uid)?;
        require(v["plan_sha256"] == sha, "job-plan-changed")?;
        Ok(v)
    }
    #[cfg(test)]
    pub(crate) fn plan_review(
        &mut self,
        id: &str,
        uid: u32,
        selection: &str,
        mode: &str,
    ) -> Result<Value> {
        self.admit_review(id, uid, selection, mode)
            .map(|(value, _)| value)
    }
    /// Return creation status from the same retained ledger critical section.
    /// An existing awaiting record is an observation, never a second worker.
    pub(crate) fn admit_review(
        &mut self,
        id: &str,
        uid: u32,
        selection: &str,
        mode: &str,
    ) -> Result<(Value, bool)> {
        require(super::system_wire::hex(id, 32), "job-request-invalid")?;
        enzimos_policy::identity::sha(selection)?;
        enzimos_policy::backup_setup_plan::Mode::parse(mode)?;
        if let Some(v) = self.store.optional_status(id, uid)? {
            require(
                v["plan"]["selection_id"] == selection && v["plan"]["mode"] == mode,
                "job-plan-changed",
            )?;
            return Ok((record::public(&v)?, false));
        }
        let plan = value!({"schema":1,"operation":"backup-device-review","id":id,"owner_uid":uid,"mode":mode,"selection_id":selection});
        let v = record::initial(id, uid, plan)?;
        self.store.publish(id, v.clone())?;
        Ok((record::public(&v)?, true))
    }
    pub(crate) fn change(&mut self, id: &str, uid: u32, sha: &str, state: &str) -> Result<Value> {
        let mut v = self.private(id, uid, sha)?;
        // Only queue_input owns the attempt increment and original sealed FD.
        require(
            !matches!(state, "awaiting-approval" | "completed" | "password-retry"),
            "job-transition-refused",
        )?;
        v["state"] = value!(state);
        self.store.publish(id, v.clone())?;
        record::public(&v)
    }
    pub(crate) fn reviewed(
        &mut self,
        id: &str,
        uid: u32,
        sha: &str,
        plan: &enzimos_policy::backup_setup_plan::Plan<'_, '_, '_>,
    ) -> Result<Value> {
        let mut v = self.private(id, uid, sha)?;
        require(v["state"] == "reviewing", "job-transition-refused")?;
        v["state"] = value!("planned");
        v["plan_sha256"] = value!(plan.digest()?);
        v["plan"] = plan.value()?;
        self.store.publish(id, v.clone())?;
        record::public(&v)
    }
    pub(crate) fn queue_input(
        &mut self,
        id: &str,
        uid: u32,
        sha: &str,
        input: &secret::Retained,
    ) -> Result<Value> {
        input.recheck()?;
        let file = File::from(input.fd()?.try_clone_to_owned()?);
        require(file.metadata()?.uid() == uid, "job-owner-mismatch")?;
        let mut v = self.private(id, uid, sha)?;
        require(
            v["plan"]["operation"] == "backup-initial-setup"
                && matches!(
                    v["state"].as_str(),
                    Some("planned" | "password-retry" | "refused")
                )
                && enzimos_platform::json::unsigned(&v["attempts"])? < record::MAX_ATTEMPTS,
            "job-transition-refused",
        )?;
        v["attempts"] = value!(enzimos_platform::json::unsigned(&v["attempts"])? + 1);
        v["state"] = value!("awaiting-approval");
        input.recheck()?;
        self.store.publish(id, v.clone())?;
        input.recheck()?;
        record::public(&v)
    }
    pub(crate) fn settle(
        &mut self,
        id: &str,
        uid: u32,
        sha: &str,
        finished: &super::backup_setup_coordinator::Finished,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        authorize()?;
        let mut v = self.private(id, uid, sha)?;
        require(
            v["state"] == "running" && &v["plan"] == finished.plan(),
            "job-plan-changed",
        )?;
        let retry = finished.result()["status"] == "backup-password-retry";
        v["state"] = value!(if retry { "password-retry" } else { "completed" });
        authorize()?;
        self.store.publish(id, v.clone())?;
        authorize()?;
        record::public(&v)
    }
}
#[cfg(test)]
#[path = "backup_setup_store_tests.rs"]
mod tests;
