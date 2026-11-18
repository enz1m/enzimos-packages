// SPDX-License-Identifier: MIT
//! Complete online retirement from actual deleted receipt and original actors.
use super::system_jobs::ReferenceView;
use enzimos_platform::{Error, Result, json, require};
use enzimos_policy::{
    operation,
    root_retirement_firmware_publication::finish::Original as Firmware,
    root_retirement_online_boot::Boot,
    root_retirement_online_finish_origin::Original,
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::{Journal, Phase},
    root_retirement_references::Observation,
    storage_runtime::{Guard, TopMount},
};
use serde_json::{Value, json as value};
fn selection(input: &Value) -> Result<&str> {
    super::system_selection::validate(14, input)?;
    json::fields(input, "id")?;
    Ok(input["id"].as_str().unwrap())
}
fn execute(
    guard: &Guard,
    input: &Value,
    refs: &ReferenceView,
    expected: Option<&Value>,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let id = selection(input)?;
    let root = super::root_retirement_stage_coordinator::root_uuid(id)?;
    let lock = operation::lock()?;
    let journal = Journal::observe(guard, &lock, id, Phase::Deleted)?;
    let fingerprint = journal.record()?["plan_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        refs.require_root_target(
            guard.configuration["filesystem_uuid"].as_str().unwrap(),
            &root,
            &fingerprint,
        )
    };
    permission()?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let references =
            Observation::observe_journal_referenced(guard, &lock, refs, &journal, &mut permission)?;
        let inventory = Inventory::observe(guard, &top, &lock, &mut permission)?;
        let origin = Original::observe(
            guard,
            &top,
            &lock,
            &references,
            &inventory,
            &journal,
            &mut permission,
        )?;
        let boot = if journal.record()?.get("coordinator").is_some() {
            Some(Boot::observe_journal(
                guard,
                &lock,
                &references,
                &journal,
                &mut permission,
            )?)
        } else {
            None
        };
        let firmware =
            if boot.is_some() && enzimos_policy::recovery_activation_runtime::efi_guard()? {
                Some(Firmware::observe(
                    guard,
                    &lock,
                    &journal,
                    &inventory,
                    &mut permission,
                )?)
            } else {
                None
            };
        let measured = value!({"filesystem_uuid":guard.configuration["filesystem_uuid"],"plan_sha256":fingerprint,
            "origin":origin.evidence(&mut permission)?,"boot":match &boot {Some(actor)=>actor.evidence(&mut permission)?,None=>Value::Null},
            "firmware":match &firmware {Some(actor)=>actor.evidence(&mut permission)?,None=>Value::Null},"deletion_authorized":false});
        origin.recheck(&mut permission)?;
        match expected {
            None => Ok(measured),
            Some(expected) => {
                require(&measured == expected, "original Root finish review changed")?;
                progress("validating")?;
                let firmware = match firmware {
                    Some(actor) => Some(actor.clear(&inventory, &mut permission)?),
                    None => None,
                };
                let cleanup = match boot {
                    Some(actor) => Some(actor.finish_loaders(
                        &journal,
                        &inventory,
                        firmware,
                        &mut permission,
                    )?),
                    None => None,
                };
                progress("finishing")?;
                enzimos_policy::root_retirement_online_finish_origin::finish(
                    origin,
                    journal,
                    cleanup,
                    &mut permission,
                )
            }
        }
    })();
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => {
            permission()?;
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root finish inspection cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}
pub fn observe(guard: &Guard, input: &Value, refs: &ReferenceView) -> Result<Value> {
    execute(guard, input, refs, None, &mut || Ok(()), &mut |_| Ok(()))
}
pub fn run(
    guard: &Guard,
    input: &Value,
    expected: &Value,
    refs: &ReferenceView,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    execute(guard, input, refs, Some(expected), authorize, progress)
}
