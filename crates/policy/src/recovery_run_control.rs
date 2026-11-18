// SPDX-License-Identifier: MIT
//! System1 stages only an exact existing plan and published native recovery image.
use crate::{
    boot_volume::Volume,
    identity, native_policy_files, operation, recovery_image,
    recovery_journal::{Journal, Kind},
    recovery_records as records, recovery_run_stage,
    transition_idle::Snapshot,
};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
use std::path::Path;
fn selection(body: &Value) -> Result<(&str, &str, &str, &str, &str)> {
    json::fields(body, "id plan_sha256 image flavor exit")?;
    let id = records::text(body, "id")?;
    records::job_id(id)?;
    let digest = records::text(body, "plan_sha256")?;
    identity::sha(digest)?;
    let image = records::text(body, "image")?;
    recovery_image::identifier(image)?;
    let flavor = records::text(body, "flavor")?;
    records::flavor(flavor)?;
    let exit = records::text(body, "exit")?;
    require(matches!(exit, "reboot" | "poweroff"), "recovery exit mode")?;
    Ok((id, digest, image, flavor, exit))
}
pub fn observation(body: &Value) -> Result<Value> {
    crate::namespaces::initial()?;
    let (id, digest, image, _, _) = selection(body)?;
    let idle = Snapshot::planned_run(id)?;
    let job = &idle.records["jobs"][id];
    require(
        job["phase"] == "planned"
            && job["plan"]["plan_sha256"] == digest
            && job["plan"]["storage"] == idle.guard.configuration
            && idle.records["runs"].get(id).is_none(),
        "exact unused recovery run plan required",
    )?;
    let jobs = Journal::open(Kind::Jobs, false)?;
    require(
        jobs.records.get(id) == Some(job),
        "original recovery job inventory differs",
    )?;
    let images = Journal::open(Kind::Images, false)?;
    let image = images
        .records
        .get(image)
        .ok_or_else(|| enzimos_platform::Error("published recovery image missing".into()))?;
    require(
        image["phase"] == "ready"
            && image["inputs"]["identity"]["schema"] == 2
            && image["filesystem_uuid"] == idle.guard.configuration["filesystem_uuid"],
        "ready native recovery image required",
    )?;
    recovery_image::verify_published(image)?;
    let policy = native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?;
    require(
        policy == image["inputs"]["identity"]["policy_files"],
        "recovery image differs from original installed native policy",
    )?;
    let volume = Volume::observe()?;
    require(
        volume.uuid == job["plan"]["boot_uuid"] && image["boot_uuid"] == volume.uuid,
        "original recovery boot volume differs",
    )?;
    let result = value!({"job":job,"image":image,"native_policy":policy,"storage":idle.guard.configuration,
        "root_mount":idle.guard.root_mount_id(),"control_mount":idle.guard.control_mount_id(),
        "boot_uuid":volume.uuid,"boot_mount":volume.unique,
        "receipt_epochs":{"jobs":jobs.evidence()?,"images":images.evidence()?}});
    volume.recheck()?;
    images.unchanged()?;
    jobs.unchanged()?;
    idle.recheck()?;
    Ok(result)
}
pub fn stage<F: FnMut() -> Result<()>>(
    body: &Value,
    expected: &Value,
    mut authorize: F,
) -> Result<Value> {
    crate::namespaces::initial()?;
    let (id, digest, image, flavor, exit) = selection(body)?;
    let lock = operation::lock()?;
    require(
        observation(body)? == *expected,
        "recovery staging plan changed",
    )?;
    // Retain the original ESP through staging, independently of its new entries.
    let volume = Volume::observe()?;
    require(
        volume.uuid == expected["boot_uuid"]
            && volume.unique == expected["boot_mount"].as_u64().unwrap_or(0),
        "recovery staging ESP epoch changed",
    )?;
    let result = recovery_run_stage::stage_authorized(
        id,
        digest,
        flavor,
        image,
        exit,
        false,
        &lock,
        &mut authorize,
    )?;
    volume.recheck()?;
    lock.recheck()?;
    require(
        result["id"] == id
            && result["status"] == "recovery-run-staged"
            && result["replay"] == false
            && matches!(result["uefi_mode"].as_str(), Some("one-shot" | "default"))
            && result["reboot_required"] == true,
        "recovery staging outcome differs; no automatic replay",
    )?;
    Ok(
        value!({"id":result["id"],"status":result["status"],"uefi_mode":result["uefi_mode"],"reboot_required":true}),
    )
}
