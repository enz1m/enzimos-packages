// SPDX-License-Identifier: MIT
//! Original Root stage context and actual server-held job references.
//! Native provider enablement and fresh installed qualification remain separate.
use super::system_jobs::ReferenceView;
use enzimos_platform::{Error, Result, json, require};
use enzimos_policy::{
    operation,
    root_retirement_online_boot::Boot,
    root_retirement_online_encryption::Source,
    root_retirement_online_image::Image,
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::{Journal, Phase},
    root_retirement_online_stage_targets::Protected,
    root_retirement_references::Observation,
    root_retirement_stage_contract::UefiMode,
    storage_runtime::{Guard, TopMount},
};
use serde_json::Value;
fn selection(input: &Value) -> Result<(&str, &str, &str)> {
    super::system_selection::validate(13, input)?;
    json::fields(input, "id image exit")?;
    Ok((
        enzimos_platform::json::string(&input["id"])?,
        enzimos_platform::json::string(&input["image"])?,
        enzimos_platform::json::string(&input["exit"])?,
    ))
}
pub(crate) fn root_uuid(id: &str) -> Result<String> {
    let raw = id
        .strip_prefix("root-")
        .filter(|raw| super::system_wire::hex(raw, 32))
        .ok_or_else(|| Error("Root stage receipt identity".into()))?;
    let (a, rest) = raw.split_at(8);
    let (b, rest) = rest.split_at(4);
    let (c, rest) = rest.split_at(4);
    let (d, e) = rest.split_at(4);
    let uuid = format!("{a}-{b}-{c}-{d}-{e}");
    enzimos_policy::identity::uuid(&uuid)?;
    Ok(uuid)
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
    let (id, image_id, exit) = selection(input)?;
    let root = root_uuid(id)?;
    let lock = operation::lock()?;
    let journal = Journal::observe(guard, &lock, id, Phase::Prepared)?;
    let original_row = journal.record()?;
    let plan = enzimos_platform::json::string(&original_row["plan_sha256"])?.to_owned();
    refs.require_root_target(
        enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?,
        &root,
        &plan,
    )?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        refs.require_root_target(
            enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?,
            &root,
            &plan,
        )
    };
    permission()?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let original =
            Observation::observe_journal_referenced(guard, &lock, refs, &journal, &mut permission)?;
        let boot = Boot::observe_journal(guard, &lock, &original, &journal, &mut permission)?;
        let inventory = Inventory::observe(guard, &top, &lock, &mut permission)?;
        let image = Image::observe(guard, &lock, &original, &journal, image_id, &mut permission)?;
        let source = Source::observe(guard, &lock, &mut permission)?;
        let protected = Protected::observe(
            guard,
            &top,
            &lock,
            &original,
            &inventory,
            &journal,
            boot,
            &mut permission,
        )?;
        let firmware = if enzimos_policy::recovery_activation_runtime::efi_guard()? {
            Some(
                enzimos_policy::root_retirement_firmware_publication::Original::observe(
                    guard,
                    &lock,
                    &mut permission,
                )?,
            )
        } else {
            None
        };
        let measured = match &firmware {
            Some(firmware) => {
                enzimos_policy::root_retirement_online_stage_publication::measure_one_shot(
                    guard,
                    &lock,
                    &image,
                    &protected,
                    &source,
                    firmware,
                    exit,
                    &mut permission,
                )?
            }
            None => protected.stage_measurement(
                &image,
                &source,
                exit,
                UefiMode::Default,
                &mut permission,
            )?,
        };
        require(
            measured["filesystem_uuid"] == guard.configuration["filesystem_uuid"]
                && measured["plan_sha256"] == plan
                && measured["staged_record"]["id"] == id,
            "original Root stage measurement identity changed",
        )?;
        match expected {
            None => Ok(measured),
            Some(expected) => {
                require(measured == *expected, "job-plan-changed")?;
                let published = match firmware {
                    Some(firmware) => enzimos_policy::root_retirement_online_stage_publication::prepare_and_publish_one_shot(
                        guard, &lock, journal, &image, &protected, &source, firmware, exit,
                        expected, &mut permission, progress,
                    ),
                    None => enzimos_policy::root_retirement_online_stage_publication::prepare_and_publish_default(
                    guard, &lock, journal, &image, &protected, &source, exit, expected, &mut permission, progress,
                ),
                 }?;
                let row = &published["receipt"];
                enzimos_policy::root_retirement_record::validate(row, id)?;
                require(
                    row["schema"] == 2
                        && row["phase"] == "prepared"
                        && row["next_step"] == 0
                        && row["inflight"].is_null()
                        && row["coordinator"]["image"] == image_id
                        && published["coordinator_selected"] == true
                        && published["deletion_authorized"] == false,
                    "actual Root stage publication result differs",
                )?;
                progress("finishing")?;
                Ok(serde_json::json!({"id":id,"image":image_id,
                    "status":"root-retirement-coordinator-staged","reboot_required":true}))
            }
        }
    })();
    // Every borrowed Root filesystem actor ends before the one normal unmount.
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => {
            permission()?;
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root stage inspection cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}
pub(crate) fn observe(guard: &Guard, input: &Value, refs: &ReferenceView) -> Result<Value> {
    execute(guard, input, refs, None, &mut || Ok(()), &mut |_| Ok(()))
}
pub(crate) fn run(
    guard: &Guard,
    input: &Value,
    expected: &Value,
    refs: &ReferenceView,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    execute(guard, input, refs, Some(expected), authorize, progress)
}
