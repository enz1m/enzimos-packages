// SPDX-License-Identifier: MIT
//! Activation binds one staged job, exact policy bytes, and a later restored boot.
use crate::{birth, boot_entries, identity, recovery_records as records};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
pub const ASSURANCE: &str = "software-local-staged-boot-not-firmware-or-application-health";
pub fn entry_names(identifier: &str, flavor: &str) -> Result<(String, String)> {
    records::job_id(identifier)?;
    records::flavor(flavor)?;
    Ok((
        format!("enzimos-staged-{identifier}-{flavor}.conf"),
        format!("enzimOS staged {identifier} {flavor}"),
    ))
}
pub fn policy_files(v: &Value, native: bool, image: bool) -> Result<()> {
    let rows = v
        .as_object()
        .ok_or_else(|| Error("recovery policy file set".into()))?;
    let required: &[&str] = match (native, image) {
        (false, false) => &["native.py", "recovery_activation.py", "recovery_stage.py"],
        (false, true) => &[
            "recovery_image.py",
            "native.py",
            "generation_registry.py",
            "recovery-pacman.conf",
        ],
        (true, false) => &[
            "enzimos-policy",
            "enzimos-recovery-run-init",
            "recovery-pacman.conf",
        ],
        (true, true) => &[
            "enzimos-policy",
            "enzimos-recovery-image-init",
            "enzimos-recovery-run-init",
            "recovery-pacman.conf",
        ],
    };
    require(
        rows.len() >= required.len()
            && rows.len() <= 128
            && required.iter().all(|key| rows.contains_key(*key)),
        "incomplete recovery policy file set",
    )?;
    for (name, digest) in rows {
        let valid = if native {
            name.starts_with("enzimos-") && identity::safe_id(name).is_ok() || config_name(name)
        } else {
            let stem = name
                .strip_suffix(".py")
                .or_else(|| name.strip_suffix(".conf"));
            stem.is_some_and(|s| {
                !s.is_empty()
                    && (s.as_bytes()[0].is_ascii_lowercase() || !image && s.starts_with('_'))
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            })
        };
        require(
            valid && name != "recovery-image.json",
            "invalid recovery policy member name",
        )?;
        identity::sha(
            digest
                .as_str()
                .ok_or_else(|| Error("recovery policy member digest".into()))?,
        )?;
    }
    Ok(())
}
fn config_name(name: &str) -> bool {
    name.strip_suffix(".conf").is_some_and(|s| {
        !s.is_empty()
            && s.as_bytes()[0].is_ascii_lowercase()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
    })
}
pub fn validate(v: &Value, identifier: &str) -> Result<()> {
    let text = records::text;
    if v.get("superseded").is_some() {
        json::fields(v, "intent phase selection observations superseded")?;
        let superseded = &v["superseded"];
        json::fields(superseded, "identity legacy_detached retired")?;
        require(
            v["phase"] == "adopted"
                && superseded["legacy_detached"].is_boolean()
                && superseded["retired"].is_boolean(),
            "invalid superseded root record",
        )?;
        let object = &superseded["identity"];
        identity::safe_id(text(object, "path")?)?;
        birth::object(
            object,
            text(object, "path")?,
            object["parent_uuid"].as_str(),
        )?;
    } else {
        json::fields(v, "intent phase selection observations")?;
    }
    let intent = &v["intent"];
    json::fields(
        intent,
        "schema id created_boot job material policy_files bios_before default_before intent_sha256",
    )?;
    let native = match intent["schema"].as_u64() {
        Some(1) => false,
        Some(2) => true,
        _ => return Err(Error("invalid activation schema".into())),
    };
    records::job_id(identifier)?;
    require(intent["id"] == identifier, "activation ID mismatch")?;
    identity::uuid(text(intent, "created_boot")?)?;
    let job = &intent["job"];
    records::job(job, identifier)?;
    require(
        job["phase"] == "staged",
        "activation requires completed staging",
    )?;
    let material = &intent["material"];
    json::fields(
        material,
        "root history package_inventory_sha256 storage_sha256 fstab_sha256",
    )?;
    require(
        material["root"] == job["root"]
            && material["history"] == job["history"]
            && material["package_inventory_sha256"] == job["plan"]["material"]["inventory_sha256"],
        "activation material/job mismatch",
    )?;
    for key in ["package_inventory_sha256", "storage_sha256", "fstab_sha256"] {
        identity::sha(text(material, key)?)?;
    }
    policy_files(&intent["policy_files"], native, false)?;
    let bios = text(intent, "bios_before")?;
    let defaults = text(intent, "default_before")?;
    require(
        bios.len() <= boot_entries::MAX_TEXT && defaults.len() <= boot_entries::MAX_TEXT,
        "activation metadata byte bound",
    )?;
    let menu = boot_entries::menu(bios)?;
    boot_entries::fields(defaults, false)?;
    for flavor in ["linux", "linux-lts"] {
        let (_, title) = entry_names(identifier, flavor)?;
        require(
            menu.entries.iter().all(|e| e.title != title),
            "activation cannot adopt existing BIOS entry",
        )?;
    }
    records::digest(intent, "intent_sha256")?;
    require(
        matches!(
            v["phase"].as_str(),
            Some("prepared" | "published" | "selecting" | "selected" | "adopted")
        ),
        "invalid activation phase",
    )?;
    let selection = &v["selection"];
    if matches!(v["phase"].as_str(), Some("prepared" | "published")) {
        require(selection.is_null(), "premature activation selection")?;
    } else {
        json::fields(
            selection,
            "flavor created_boot efi_observable selection_sha256",
        )?;
        records::flavor(text(selection, "flavor")?)?;
        identity::uuid(text(selection, "created_boot")?)?;
        require(
            selection["efi_observable"].is_boolean(),
            "invalid activation EFI observation",
        )?;
        records::digest(selection, "selection_sha256")?;
    }
    let observations = v["observations"]
        .as_object()
        .ok_or_else(|| Error("activation observations".into()))?;
    require(
        observations
            .keys()
            .all(|k| matches!(k.as_str(), "uefi" | "bios")),
        "invalid activation observation mode",
    )?;
    if !matches!(v["phase"].as_str(), Some("selected" | "adopted")) {
        require(
            observations.is_empty(),
            "unselected activation cannot be confirmed",
        )?;
    }
    if v["phase"] == "adopted" {
        require(
            !observations.is_empty(),
            "adoption requires observed restored boot",
        )?;
    }
    for observation in observations.values() {
        json::fields(
            observation,
            "boot_id kernel root_uuid intent_sha256 assurance",
        )?;
        identity::uuid(text(observation, "boot_id")?)?;
        require(
            observation["boot_id"] != selection["created_boot"]
                && job["plan"]["material"]["kernels"]
                    .as_object()
                    .unwrap()
                    .values()
                    .any(|k| *k == observation["kernel"])
                && observation["root_uuid"] == job["root"]["uuid"]
                && observation["intent_sha256"] == intent["intent_sha256"]
                && observation["assurance"] == ASSURANCE,
            "activation boot observation mismatch",
        )?;
    }
    Ok(())
}
