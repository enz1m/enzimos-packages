// SPDX-License-Identifier: MIT
//! Exact durable recovery contracts, shared by online and independent runtimes.
use crate::{birth, catalog, identity, storage};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub const MAX_JOBS: usize = 16;
pub fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| Error("recovery text field".into()))
}
pub fn job_id(id: &str) -> Result<&str> {
    identity::safe_id(id)?;
    require(id.len() <= 48, "recovery job ID bound")?;
    Ok(id)
}
pub fn fat_uuid(id: &str) -> Result<()> {
    require(
        id.len() == 9
            && id.bytes().enumerate().all(|(i, b)| {
                if i == 4 {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }),
        "invalid FAT recovery boot UUID",
    )
}
pub fn flavor(s: &str) -> Result<()> {
    require(
        matches!(s, "linux" | "linux-lts"),
        "invalid recovery kernel flavor",
    )
}
pub fn digest(v: &Value, key: &str) -> Result<()> {
    let expected = identity::sha(text(v, key)?)?;
    let mut material = v.clone();
    material
        .as_object_mut()
        .ok_or_else(|| Error("recovery digest object".into()))?
        .remove(key);
    require(
        json::fingerprint(&material)? == expected,
        "recovery document digest mismatch",
    )
}
pub fn media_origin(v: &Value) -> Result<()> {
    json::fields(v, "schema boot_id kernel policy_sha256")?;
    require(
        v["schema"].as_u64() == Some(1),
        "invalid installer rescue origin schema",
    )?;
    identity::uuid(text(v, "boot_id")?)?;
    identity::safe_id(text(v, "kernel")?)?;
    identity::sha(text(v, "policy_sha256")?)?;
    Ok(())
}
pub fn plan(v: &Value) -> Result<()> {
    let schema = v["schema"]
        .as_u64()
        .filter(|s| matches!(s, 1 | 2))
        .ok_or_else(|| Error("invalid recovery plan schema".into()))?;
    let fields = "schema id created_boot filesystem_uuid boot_uuid storage protected source_birth generation target_name material plan_sha256";
    json::fields(
        v,
        &if schema == 2 {
            format!("{fields} media_origin")
        } else {
            fields.into()
        },
    )?;
    if schema == 2 {
        media_origin(&v["media_origin"])?;
        require(
            v["created_boot"] == v["media_origin"]["boot_id"],
            "media planning boot mismatch",
        )?;
    }
    let id = job_id(text(v, "id")?)?;
    let filesystem = identity::uuid(text(v, "filesystem_uuid")?)?;
    identity::uuid(text(v, "created_boot")?)?;
    fat_uuid(text(v, "boot_uuid")?)?;
    let target = format!("enzimos-recovered-{id}");
    require(v["target_name"] == target, "recovery target name mismatch")?;
    let config = &v["storage"];
    storage::validate(config)?;
    require(
        config["filesystem_uuid"] == filesystem
            && [
                "root_subvol",
                "home_subvol",
                "authority_subvol",
                "control_subvol",
            ]
            .iter()
            .all(|k| config[*k] != target),
        "recovery storage identity or target conflict",
    )?;
    let protected = &v["protected"];
    json::fields(protected, "home authority control")?;
    let mut uuids = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for role in ["home", "authority", "control"] {
        let obj = &protected[role];
        let parent = obj["parent_uuid"].as_str();
        birth::object(obj, text(config, &format!("{role}_subvol"))?, parent)?;
        require(
            uuids.insert(text(obj, "uuid")?) && ids.insert(obj["id"].as_u64().unwrap()),
            "recovery protected identities overlap",
        )?;
    }
    let source = &v["source_birth"];
    birth::validate(source, text(source, "transaction")?, filesystem)?;
    require(
        source["phase"] == "ready" && source["source"]["path"] == config["root_subvol"],
        "recovery requires completed birth from configured source",
    )?;
    for obj in [
        &source["source"],
        &source["snapshot"]["object"],
        &source["root"],
        &source["history"],
    ] {
        require(
            uuids.insert(text(obj, "uuid")?) && ids.insert(obj["id"].as_u64().unwrap()),
            "recovery protected and source identities overlap",
        )?;
    }
    let material = &v["material"];
    catalog::material(material, text(v, "generation")?)?;
    for key in ["path", "id", "uuid"] {
        require(
            material["root_identity"][key] == source["root"][key],
            "recovery generation/source root mismatch",
        )?;
    }
    require(
        material["inventory_sha256"] == source["inventory_sha256"],
        "recovery generation/source inventory mismatch",
    )?;
    digest(v, "plan_sha256")
}
pub fn job(v: &Value, identifier: &str) -> Result<()> {
    job_id(identifier)?;
    json::fields(v, "plan phase stage_boot root history")?;
    let plan_value = &v["plan"];
    plan(plan_value)?;
    require(
        plan_value["id"] == identifier,
        "recovery job identity mismatch",
    )?;
    let phase = match text(v, "phase")? {
        "planned" => 0,
        "creating" => 1,
        "root-recorded" => 2,
        "staged" => 3,
        _ => return Err(Error("invalid recovery job phase".into())),
    };
    if phase == 0 {
        require(
            v["stage_boot"].is_null(),
            "unstarted recovery has stage boot",
        )?;
    } else {
        identity::uuid(text(v, "stage_boot")?)?;
        require(
            v["stage_boot"] != plan_value["created_boot"]
                || plan_value["schema"].as_u64() == Some(2),
            "recovery requires later independent boot",
        )?;
    }
    if phase < 2 {
        require(
            v["root"].is_null() && v["history"].is_null(),
            "uncreated recovery objects claimed",
        )?;
    } else {
        let target = text(plan_value, "target_name")?;
        birth::object(
            &v["root"],
            target,
            Some(text(
                &plan_value["source_birth"]["snapshot"]["object"],
                "uuid",
            )?),
        )?;
        if phase == 2 {
            require(
                v["history"].is_null(),
                "unfinished recovery history claimed",
            )?;
        } else {
            birth::object(&v["history"], &format!("{target}/.snapshots"), None)?;
            require(
                v["root"]["uuid"] != v["history"]["uuid"] && v["root"]["id"] != v["history"]["id"],
                "recovery root/history identities overlap",
            )?;
        }
    }
    Ok(())
}
pub fn run_entry_names(identifier: &str) -> Result<(String, String)> {
    job_id(identifier)?;
    let digest = json::sha256(identifier.as_bytes());
    let short = &digest[..16];
    Ok((
        format!("enzimos-recovery-run-{short}.conf"),
        format!("enzimOS recovery run {short}"),
    ))
}
pub fn literal_entry(s: &str) -> Result<()> {
    let stem = s
        .strip_suffix(".conf")
        .ok_or_else(|| Error("invalid previous UEFI default".into()))?;
    require(
        !stem.is_empty()
            && stem.len() <= 120
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b)),
        "invalid literal UEFI default",
    )
}
pub fn command_line(s: &str) -> Result<()> {
    require(
        s.len() <= 4096 && s.bytes().all(|b| (32..127).contains(&b)),
        "invalid recovery command line",
    )
}
pub fn run(v: &Value, identifier: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase plan_sha256 flavor image created_boot entry result",
    )?;
    job_id(identifier)?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["id"] == identifier
            && matches!(
                v["phase"].as_str(),
                Some("staged" | "running" | "executed" | "failed" | "complete" | "abandoned")
            ),
        "invalid recovery run identity or phase",
    )?;
    identity::sha(text(v, "plan_sha256")?)?;
    flavor(text(v, "flavor")?)?;
    let image = text(v, "image")?
        .strip_prefix("ri-")
        .ok_or_else(|| Error("invalid recovery image ID".into()))?;
    identity::sha(image)?;
    identity::uuid(text(v, "created_boot")?)?;
    let entry = &v["entry"];
    json::fields(
        entry,
        "uefi_entry uefi_previous uefi_mode bios_title bios_previous bios_own options",
    )?;
    let (uefi, title) = run_entry_names(identifier)?;
    require(
        entry["uefi_entry"] == uefi
            && entry["bios_title"] == title
            && matches!(entry["uefi_mode"].as_str(), Some("one-shot" | "default")),
        "recovery run entry identity mismatch",
    )?;
    let previous = text(entry, "uefi_previous")?;
    literal_entry(previous)?;
    require(previous != uefi, "recovery run cannot restore itself")?;
    let prior = entry["bios_previous"]
        .as_u64()
        .ok_or_else(|| Error("recovery BIOS index".into()))?;
    let own = entry["bios_own"]
        .as_u64()
        .ok_or_else(|| Error("recovery BIOS index".into()))?;
    require(
        prior >= 1 && prior < own && own <= 256,
        "recovery BIOS default bounds",
    )?;
    command_line(text(entry, "options")?)?;
    require(
        v["result"].is_null() || v["result"].is_object(),
        "invalid recovery run result",
    )
}
pub fn workflow(v: &Value, identifier: &str) -> Result<()> {
    json::fields(
        v,
        "schema id plan_sha256 flavor boot_id state action activation_sha256",
    )?;
    job_id(identifier)?;
    require(
        v["schema"].as_u64() == Some(1) && v["id"] == identifier,
        "invalid workflow identity",
    )?;
    identity::sha(text(v, "plan_sha256")?)?;
    identity::uuid(text(v, "boot_id")?)?;
    flavor(text(v, "flavor")?)?;
    require(
        matches!(
            v["state"].as_str(),
            Some("prepared" | "running" | "complete")
        ),
        "invalid workflow state",
    )?;
    require(
        v["action"].is_null()
            || matches!(
                v["action"].as_str(),
                Some("stage" | "review" | "prepare-publication" | "publish" | "select")
            ),
        "invalid workflow action",
    )?;
    if !v["activation_sha256"].is_null() {
        identity::sha(text(v, "activation_sha256")?)?;
    }
    require(
        v["state"] != "prepared" || v["action"].is_null(),
        "prepared workflow advanced",
    )?;
    require(
        v["state"] != "complete" || v["action"] == "select" && !v["activation_sha256"].is_null(),
        "incomplete workflow claimed complete",
    )
}
