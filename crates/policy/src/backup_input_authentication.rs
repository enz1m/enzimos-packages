// SPDX-License-Identifier: MIT
//! Completed original input authentication; never constructed from a result JSON.
use crate::{
    backup_secret_input::Validated,
    backup_worker_intent::{Completed, Intent},
};
use enzimos_platform::{Result, files, require};
use serde_json::Value;
use std::fs::File;
pub struct Authenticated<'g, 'i> {
    intent: Completed<'g>,
    input: &'i Validated,
    original: Value,
}
impl<'g, 'i> Authenticated<'g, 'i> {
    pub fn from_completed(intent: Intent<'g>, input: &'i Validated) -> Result<Self> {
        let intent = intent.into_completed()?;
        intent.recheck()?;
        input.recheck()?;
        let v = intent.value()?;
        let request = &v["request"];
        let file = File::from(input.descriptor()?.try_clone_to_owned()?);
        require(
            v["phase"] == "complete"
                && v["worker_scope_closed"] == true
                && request["task"] == "authenticate-input"
                && request["plan"]["mode"] == "adopt"
                && v["result"]["status"] == "authenticated"
                && request["credential"]["identity"]
                    == serde_json::to_value(files::identity(&file.metadata()?))?
                && request["reader"] == input.reader_evidence()?
                && request["plan"]["owner_uid"] == input.owner(),
            "input witness requires original completed authentication of same sealed input",
        )?;
        let this = Self {
            intent,
            input,
            original: v,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.intent.recheck()?;
        self.input.recheck()?;
        require(
            self.intent.value()? == self.original,
            "original input authentication witness changed",
        )
    }
    pub fn key_id(&self) -> Result<&str> {
        self.recheck()?;
        enzimos_platform::json::string(&self.original["result"]["key_id"])
    }
    pub fn input(&self) -> Result<&Validated> {
        self.recheck()?;
        Ok(self.input)
    }
}
/// Both separate mounts/workers authenticated the same original input, plan,
/// encrypted header and current key. No cold-load or JSON constructor exists.
pub struct Confirmed<'a, 'g, 'i> {
    first: &'a Authenticated<'g, 'i>,
    second: &'a Authenticated<'g, 'i>,
}
fn pair(first: &Value, second: &Value, first_key: &str, second_key: &str) -> Result<()> {
    require(
        first["stage"] == "adoption-probe"
            && first["outer"].is_null()
            && second["stage"] == "adoption-confirm"
            && !second["outer"].is_null()
            && first["id"] != second["id"]
            && first["mount"] != second["mount"]
            && first["plan"] == second["plan"]
            && first["credential"] == second["credential"]
            && first["reader"] == second["reader"]
            && first["header"] == second["header"]
            && first_key == second_key,
        "adoption confirmation differs from original probe/input/plan/header/key or fresh mount",
    )
}
impl<'a, 'g, 'i> Confirmed<'a, 'g, 'i> {
    pub fn new(
        first: &'a Authenticated<'g, 'i>,
        second: &'a Authenticated<'g, 'i>,
    ) -> Result<Self> {
        let this = Self { first, second };
        this.recheck()?;
        Ok(this)
    }
    /// One fresh recheck per witness. Every witness recheck re-reads its
    /// worker journal and re-asks the caller's approval, so this is evaluated
    /// once and then compared from the rechecked originals; it runs at every
    /// checkpoint of the adoption provision worker.
    pub fn recheck(&self) -> Result<()> {
        self.first.recheck()?;
        self.second.recheck()?;
        let (first, second) = (&self.first.original, &self.second.original);
        let key = |v: &'a Value| {
            v["result"]["key_id"].as_str().ok_or_else(|| {
                enzimos_platform::Error("authenticated input witness key required".into())
            })
        };
        pair(
            &first["request"],
            &second["request"],
            key(first)?,
            key(second)?,
        )?;
        require(
            std::ptr::eq(self.first.input, self.second.input),
            "confirmation must retain same original input object",
        )
    }
    pub fn input(&self) -> Result<&Validated> {
        self.recheck()?;
        self.second.input()
    }
    pub fn key_id(&self) -> Result<&str> {
        self.recheck()?;
        self.second.key_id()
    }
    pub fn matches_plan(&self, plan: &crate::backup_setup_plan::Plan<'_, '_, '_>) -> Result<()> {
        plan.recheck_identity()?;
        require(
            self.plan()? == plan.original(),
            "original confirmation belongs to a different provision plan",
        )
    }
    pub(crate) fn plan(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.second.original["request"]["plan"])
    }
}
