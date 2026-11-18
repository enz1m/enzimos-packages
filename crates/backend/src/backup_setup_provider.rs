// SPDX-License-Identifier: MIT
//! Fresh native discovery/review reconstructs and verifies the original server plan.
use enzimos_platform::{Result, files, require};
use enzimos_policy::{
    backup_candidates::Discovery,
    backup_mount_review::{self, Review},
    backup_secret_input::Validated,
    backup_setup_plan::{Mode, Plan},
};
use serde_json::Value;
use std::path::Path;
fn lock() -> Result<files::Lock> {
    files::Lock::try_acquire(Path::new("/run/enzimos/operation.lock"), 0)?
        .ok_or_else(|| enzimos_platform::Error("service-busy".into()))
}
pub fn review(
    initial: &Value,
    authorize: &dyn Fn() -> Result<()>,
    publish: &mut dyn FnMut(&Plan<'_, '_, '_>) -> Result<()>,
) -> Result<()> {
    enzimos_policy::namespaces::initial()?;
    authorize()?;
    let operation = lock()?;
    let discovery = Discovery::observe()?;
    let selection = discovery.select(initial["selection_id"].as_str().unwrap_or(""))?;
    let id = initial["id"].as_str().unwrap_or("");
    backup_mount_review::review(&selection, id, &operation, authorize)?;
    let review = Review::open(&selection, id, &operation, authorize)?;
    let plan = Plan::observe(
        &review,
        id,
        initial["owner_uid"].as_u64().unwrap_or(0) as u32,
        Mode::parse(initial["mode"].as_str().unwrap_or(""))?,
        &operation,
        authorize,
    )?;
    authorize()?;
    publish(&plan)
}
pub fn run(
    original: &Value,
    sha: &str,
    input: &enzimos_platform::secret::Retained,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<super::backup_setup_coordinator::Finished> {
    enzimos_policy::namespaces::initial()?;
    authorize()?;
    enzimos_policy::backup_setup_plan::validate(original)?;
    let operation = lock()?;
    let discovery = Discovery::observe()?;
    let selection = discovery.select(original["selection_id"].as_str().unwrap())?;
    let review = Review::open(
        &selection,
        original["review_id"].as_str().unwrap(),
        &operation,
        authorize,
    )?;
    let uid = original["owner_uid"].as_u64().unwrap() as u32;
    let plan = Plan::observe(
        &review,
        original["id"].as_str().unwrap(),
        uid,
        Mode::parse(original["mode"].as_str().unwrap())?,
        &operation,
        authorize,
    )?;
    require(
        plan.value()? == *original && plan.digest()? == sha,
        "job-plan-changed",
    )?;
    input.recheck()?;
    let validated = Validated::retain(input.fd()?, uid, authorize)?;
    super::backup_setup_coordinator::run(&plan, sha, &validated, &operation, authorize)
}
