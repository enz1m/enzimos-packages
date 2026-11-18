// SPDX-License-Identifier: MIT
//! One attempt coordinates guarded restoration, publication and selection.
use crate::{
    native_policy_files, operation, recovery_activation_runtime as activation,
    recovery_context::Context,
    recovery_journal::{Journal, Kind},
    recovery_records as records, recovery_stage as stage,
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json};
use std::path::Path;
fn checkpoint(
    journal: &mut Journal,
    id: &str,
    value: &mut Value,
    action: &str,
    lock: &files::Lock,
) -> Result<()> {
    journal.unchanged()?;
    let previous = value.clone();
    value["state"] = json!("running");
    value["action"] = json!(action);
    journal.save(id, value.clone(), Some(&previous), lock)
}
pub fn execute_locked<F: FnMut(&str, &Value) -> Result<()>>(
    id: &str,
    digest: &str,
    flavor: &str,
    lock: &files::Lock,
    mut observer: F,
) -> Result<Value> {
    records::flavor(flavor)?;
    let plan = stage::load_plan(id, digest)?;
    let jobs = Journal::open_independent(Kind::Jobs, false, &plan)?;
    require(
        jobs.records
            .get(id)
            .is_some_and(|v| v["phase"] == "planned" && v["plan"] == plan),
        "exact unstarted recovery plan required",
    )?;
    let mut journal = Journal::open_independent(Kind::Workflows, true, &plan)?;
    require(
        !journal.records.contains_key(id)
            && journal.records.values().all(|v| v["state"] == "complete"),
        "workflow already attempted or uncertain; no replay",
    )?;
    let context = Context::observe(&plan)?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == native_policy_files::observe(&context.source_path.join("usr/lib/enzimos-native"))?,
        "snapshot native policy incompatible with recovery workflow",
    )?;
    context.recheck()?;
    jobs.unchanged()?;
    journal.unchanged()?;
    let mut record = json!({"schema":1,"id":id,"plan_sha256":digest,"flavor":flavor,"boot_id":operation::boot_id()?,"state":"prepared","action":null,"activation_sha256":null});
    journal.save(id, record.clone(), None, lock)?;
    observer("prepared", &record)?;
    checkpoint(&mut journal, id, &mut record, "stage", lock)?;
    observer("stage", &record)?;
    stage::stage_locked(id, digest, lock, |_, _| Ok(()))?;
    checkpoint(&mut journal, id, &mut record, "review", lock)?;
    observer("review", &record)?;
    let review = stage::review_locked(id, digest, lock)?;
    checkpoint(&mut journal, id, &mut record, "prepare-publication", lock)?;
    observer("prepare-publication", &record)?;
    let publication = activation::prepare_locked(id, records::text(&review, "job_sha256")?, lock)?;
    let previous = record.clone();
    record["activation_sha256"] = publication["intent_sha256"].clone();
    journal.save(id, record.clone(), Some(&previous), lock)?;
    checkpoint(&mut journal, id, &mut record, "publish", lock)?;
    observer("publish", &record)?;
    activation::publish_locked(
        id,
        records::text(&record, "activation_sha256")?,
        lock,
        |_| Ok(()),
    )?;
    checkpoint(&mut journal, id, &mut record, "select", lock)?;
    observer("select", &record)?;
    activation::select_locked(
        id,
        records::text(&record, "activation_sha256")?,
        flavor,
        lock,
        |_| Ok(()),
    )?;
    journal.unchanged()?;
    let previous = record.clone();
    record["state"] = json!("complete");
    journal.save(id, record.clone(), Some(&previous), lock)?;
    observer("complete", &record)?;
    Ok(
        json!({"status":"recovery-workflow-disk-defaults-selected","id":id,"flavor":flavor,"boot_confirmed":false,"home_overwritten":false,"authority_overwritten":false,"retirement_enabled":false}),
    )
}
pub fn status_locked(id: &str, plan_sha: &str, _lock: &files::Lock) -> Result<Value> {
    let plan = stage::load_plan(id, plan_sha)?;
    let journal = Journal::open_independent(Kind::Workflows, false, &plan)?;
    let record = journal
        .records
        .get(id)
        .ok_or_else(|| enzimos_platform::Error("workflow missing".into()))?;
    journal.unchanged()?;
    Ok(
        json!({"id":id,"state":if record["state"] == "running" {json!("uncertain")} else {record["state"].clone()},"last_action":record["action"],"automatic_replay":false,"retirement_enabled":false}),
    )
}
