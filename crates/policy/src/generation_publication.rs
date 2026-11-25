// SPDX-License-Identifier: MIT
//! Durable generation publication never adopts partial copies or replays writes.
use crate::{boot_entries, boot_options, catalog, identity, recovery_boot, signed_entry};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeMap;
pub(crate) const PHASES: [&str; 11] = [
    "intent",
    "artifacts",
    "ready",
    "linux-entry",
    "lts-entry",
    "bios",
    "published",
    "registry",
    "uefi-selected",
    "bios-selected",
    "complete",
];
pub(crate) fn entries(
    generation: &str,
    material: &Value,
    certificate: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    identity::safe_id(generation)?;
    catalog::material(material, generation)?;
    if let Some(certificate) = certificate {
        identity::sha(certificate)?;
    }
    let mut result = BTreeMap::new();
    for flavor in ["linux", "linux-lts"] {
        let prefix = format!("/enzimos/generations/{generation}");
        let text = format!(
            "title enzimOS {generation} {flavor}\nlinux {prefix}/vmlinuz-{flavor}\ninitrd {prefix}/initramfs-{flavor}.img\noptions {}\n",
            material["options"].as_str().unwrap()
        );
        let text = if let Some(certificate) = certificate {
            let digest = |name: &str| {
                material["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["name"] == name)
                    .unwrap()["sha256"]
                    .as_str()
                    .unwrap()
            };
            let binding = signed_entry::digest(
                digest(&format!("vmlinuz-{flavor}")),
                digest(&format!("initramfs-{flavor}.img")),
                material["options"].as_str().unwrap(),
                certificate,
            )?;
            signed_entry::rewrite(&text, &format!("/enzimos/secure-boot/{binding}.efi"))?
        } else {
            text
        };
        result.insert(
            format!("loader/entries/enzimos-{generation}-{flavor}.conf"),
            text,
        );
    }
    Ok(result)
}
pub(crate) fn bios(generation: &str, material: &Value, before: &str) -> Result<String> {
    catalog::material(material, generation)?;
    let menu = boot_entries::menu(before)?;
    require(
        menu.entries.len() <= 254
            && menu.entries.iter().all(|e| {
                !["linux", "linux-lts"]
                    .iter()
                    .any(|f| e.title == format!("enzimOS {generation} {f}"))
            }),
        "generation cannot adopt existing or excessive BIOS entries",
    )?;
    let mut result = format!("{before}\n");
    for flavor in ["linux", "linux-lts"] {
        let prefix = format!("/enzimos/generations/{generation}");
        result.push_str(&format!("/enzimOS {generation} {flavor}\n    protocol: linux\n    path: boot():{prefix}/vmlinuz-{flavor}\n    module_path: boot():{prefix}/initramfs-{flavor}.img\n    cmdline: {}\n",material["options"].as_str().unwrap()));
    }
    boot_entries::menu(&result)?;
    Ok(result)
}
pub(crate) fn validate(record: &Value, generation: &str) -> Result<()> {
    json::fields(
        record,
        "schema generation phase filesystem_uuid created_boot material bios_before defaults_before certificate_sha256 journal_sha256",
    )?;
    require(
        record["schema"] == 1
            && record["generation"] == generation
            && record["phase"]
                .as_str()
                .is_some_and(|p| PHASES.contains(&p)),
        "generation publication schema, identity or phase",
    )?;
    identity::safe_id(generation)?;
    for name in ["filesystem_uuid", "created_boot"] {
        identity::uuid(
            record[name]
                .as_str()
                .ok_or_else(|| Error("publication UUID type".into()))?,
        )?;
    }
    catalog::material(&record["material"], generation)?;
    let options = record["material"]["options"].as_str().unwrap();
    require(
        boot_options::generation_options(options, generation)? == options
            && !options.split_whitespace().any(|w| {
                [
                    "init=",
                    "rdinit=",
                    "enzimos.staged=",
                    "enzimos.run=",
                    "enzimos.recovery=",
                ]
                .iter()
                .any(|p| w.starts_with(p))
            }),
        "generation options conflict with independent execution",
    )?;
    let before = record["bios_before"]
        .as_str()
        .ok_or_else(|| Error("publication BIOS text type".into()))?;
    bios(generation, &record["material"], before)?;
    let defaults = record["defaults_before"]
        .as_str()
        .ok_or_else(|| Error("publication loader text type".into()))?;
    let fields = boot_entries::fields(defaults, false)?;
    require(
        fields.contains_key("default"),
        "one original loader default required",
    )?;
    recovery_boot::replace_default(
        defaults,
        "default ",
        &format!("enzimos-{generation}-linux.conf"),
    )?;
    let certificate = if record["certificate_sha256"].is_null() {
        None
    } else {
        Some(
            record["certificate_sha256"]
                .as_str()
                .ok_or_else(|| Error("publication certificate type".into()))?,
        )
    };
    entries(generation, &record["material"], certificate)?;
    crate::recovery_records::digest(record, "journal_sha256")
}
pub(crate) fn seal(mut record: Value) -> Result<Value> {
    record
        .as_object_mut()
        .ok_or_else(|| Error("publication record object".into()))?
        .remove("journal_sha256");
    record["journal_sha256"] = value!(json::fingerprint(&record)?);
    validate(&record, record["generation"].as_str().unwrap_or(""))?;
    Ok(record)
}
pub(crate) fn transition(before: Option<&Value>, after: &Value, generation: &str) -> Result<()> {
    validate(after, generation)?;
    if let Some(before) = before {
        validate(before, generation)?;
        let position = PHASES.iter().position(|p| before["phase"] == *p).unwrap();
        require(
            position + 1 < PHASES.len() && after["phase"] == PHASES[position + 1],
            "publication phase cannot replay, skip or resume implicitly",
        )?;
        for (key, value) in before.as_object().unwrap() {
            if !matches!(key.as_str(), "phase" | "journal_sha256") {
                require(after[key] == *value, "publication immutable intent changed")?;
            }
        }
        Ok(())
    } else {
        require(
            after["phase"] == "intent",
            "publication intent must precede any write",
        )
    }
}
