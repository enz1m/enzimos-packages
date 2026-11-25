// SPDX-License-Identifier: MIT
//! Completed original native provision attempt; no JSON/cold-load authority.
use crate::backup_worker_intent::{Completed, Intent};
use enzimos_platform::{Result, require};
use serde_json::Value;
pub struct Provisioned<'g> {
    completed: Completed<'g>,
    original: Value,
    bound: Option<crate::backup_setup_binding::Bound<'g>>,
}
impl<'g> Provisioned<'g> {
    pub(crate) fn from_completed(intent: Intent<'g>) -> Result<Self> {
        let completed = intent.into_completed()?;
        let original = completed.value()?;
        require(
            original["request"]["stage"] == "provision"
                && original["result"]["status"] == "provisioned",
            "provision witness requires original completed composite attempt",
        )?;
        crate::backup_worker_result::for_request(&original["result"], &original["request"])?;
        let this = Self {
            completed,
            original,
            bound: None,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.completed.recheck()?;
        if let Some(bound) = &self.bound {
            let pin = bound.value()?;
            require(
                pin["filesystem_uuid"] == self.original["request"]["mount"]["filesystem_uuid"]
                    && pin["repository_sha256"] == self.original["result"]["header"]["sha256"],
                "original pin differs from completed provision attempt",
            )?;
        }
        require(
            self.completed.value()? == self.original,
            "original completed provision record changed",
        )
    }
    pub fn result(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.original["result"])
    }
    pub fn from_bound(
        intent: Intent<'g>,
        bound: crate::backup_setup_binding::Bound<'g>,
    ) -> Result<Self> {
        let mut this = Self::from_completed(intent)?;
        this.bound = Some(bound);
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn public_result(&self) -> Result<Value> {
        self.recheck()?;
        require(
            self.bound.is_some(),
            "repository-bound result requires original newly published pin",
        )?;
        Ok(
            serde_json::json!({"status":"backup-repository-bound","mode":self.original["result"]["mode"],
            "destination_uuid":self.original["request"]["mount"]["filesystem_uuid"],
            "repository_sha256":self.original["result"]["header"]["sha256"],
            "automatic_backup_enabled":false,"recovery_key_exported":false,"existing_data_deleted":false}),
        )
    }
    pub(crate) fn plan(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.original["request"]["plan"])
    }
}
