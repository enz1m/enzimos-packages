// SPDX-License-Identifier: MIT
//! Original adopted recovery conclusions are protection observations, never
//! deletion, birth ownership or replay authority. No decoded-data constructor.
use crate::{
    identity,
    recovery_journal::{Journal, Kind, Records},
    storage_runtime::Guard,
};
use enzimos_platform::{Result, require};
use std::collections::BTreeSet;
fn concluded(jobs: &Records, activations: &Records) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for (id, activation) in activations {
        identity::safe_id(id)?;
        require(
            jobs.get(id) == Some(&activation["intent"]["job"]),
            "original recovery conclusion job differs",
        )?;
        if activation["phase"] == "adopted" && activation["superseded"]["legacy_detached"] == true {
            require(
                jobs[id]["phase"] == "staged",
                "original recovery conclusion requires staged job",
            )?;
            result.insert(id.clone());
        }
    }
    Ok(result)
}
pub(crate) fn historical(
    row: &serde_json::Value,
    jobs: &Records,
    concluded: &BTreeSet<String>,
) -> bool {
    if row["operation"] != "recovery-prepare" || row["state"] != "completed" {
        return false;
    }
    let (Some(id), Some(request)) = (
        row["result"]["recovery_id"].as_str(),
        row["request_id"].as_str(),
    ) else {
        return false;
    };
    enzimos_platform::json::fields(
        &row["result"],
        "recovery_id plan_sha256 activation_available",
    )
    .is_ok()
        && row["result"]["activation_available"] == false
        && enzimos_platform::json::fields(&row["plan"]["selection"], "birth generation").is_ok()
        && request.len() == 32
        && request
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && id == format!("api-{request}")
        && concluded.contains(id)
        && jobs.get(id).is_some_and(|job| {
            job["phase"] == "staged"
                && job["plan"]["source_birth"]["transaction"]
                    .as_str()
                    .is_some_and(|birth| row["plan"]["selection"]["birth"].as_str() == Some(birth))
                && job["plan"]["plan_sha256"].as_str().is_some_and(|sha| {
                    identity::sha(sha).is_ok() && row["result"]["plan_sha256"].as_str() == Some(sha)
                })
                && job["plan"]["generation"]
                    .as_str()
                    .is_some_and(|generation| {
                        row["plan"]["selection"]["generation"].as_str() == Some(generation)
                    })
        })
}
pub struct Observation<'g> {
    guard: &'g Guard,
    jobs: Journal,
    activations: Journal,
    concluded: BTreeSet<String>,
}
impl<'g> Observation<'g> {
    pub fn observe(guard: &'g Guard) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let jobs = Journal::open(Kind::Jobs, false)?;
        let activations = Journal::open(Kind::Activations, false)?;
        let concluded = concluded(&jobs.records, &activations.records)?;
        let this = Self {
            guard,
            jobs,
            activations,
            concluded,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.jobs.checkpoint()?;
        self.activations.checkpoint()?;
        require(
            concluded(&self.jobs.records, &self.activations.records)? == self.concluded,
            "original recovery conclusions changed",
        )?;
        self.guard.recheck()
    }
    pub fn require_original_journals(&self, jobs: &Journal, activations: &Journal) -> Result<()> {
        self.recheck()?;
        require(
            self.jobs.evidence()? == jobs.evidence()?
                && self.activations.evidence()? == activations.evidence()?,
            "conclusions require independently retained original journals",
        )?;
        self.recheck()
    }
    pub fn is_concluded(&self, id: &str) -> Result<bool> {
        identity::safe_id(id)?;
        self.recheck()?;
        Ok(self.concluded.contains(id))
    }
    /// Only a completed, non-replayable recovery-prepare receipt can be history.
    pub fn historical_backend_record(&self, row: &serde_json::Value) -> Result<bool> {
        self.recheck()?;
        let result = historical(row, &self.jobs.records, &self.concluded);
        self.recheck()?;
        Ok(result)
    }
}
