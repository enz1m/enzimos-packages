// SPDX-License-Identifier: MIT
//! Closed boot retirement calculations. Data alone confers no filesystem authority.
use crate::{boot_entries, catalog, identity};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
use std::fmt::Write as _;
pub(crate) const MEMBERS: [&str; 6] = [
    "vmlinuz-linux",
    "vmlinuz-linux-lts",
    "initramfs-linux.img",
    "initramfs-linux-lts.img",
    "READY.json",
    "PUBLISHED.json",
];
pub(crate) fn entry_names(generation: &str) -> Result<([String; 2], [String; 2])> {
    identity::safe_id(generation)?;
    Ok((
        [
            format!("enzimos-{generation}-linux.conf"),
            format!("enzimos-{generation}-linux-lts.conf"),
        ],
        [
            format!("enzimOS {generation} linux"),
            format!("enzimOS {generation} linux-lts"),
        ],
    ))
}
pub(crate) fn without_bios(text: &str, generation: &str) -> Result<String> {
    let menu = boot_entries::menu(text)?;
    let (_, titles) = entry_names(generation)?;
    let chosen = &menu.entries[menu.selected - 1].title;
    require(
        !titles.contains(chosen),
        "BIOS default selects retirement candidate",
    )?;
    require(
        titles
            .iter()
            .all(|t| menu.entries.iter().filter(|e| &e.title == t).count() == 1),
        "both original BIOS entries required",
    )?;
    let kept = menu
        .entries
        .iter()
        .filter(|e| !titles.contains(&e.title))
        .collect::<Vec<_>>();
    let selected = kept
        .iter()
        .position(|e| &e.title == chosen)
        .ok_or_else(|| Error("retained BIOS default missing".into()))?
        + 1;
    let mut rewritten = String::new();
    let mut defaults = 0;
    for line in menu.header.split_inclusive('\n') {
        if line.starts_with("default_entry:") {
            defaults += 1;
            let _ = writeln!(rewritten, "default_entry: {selected}");
        } else {
            rewritten.push_str(line);
        }
    }
    require(defaults == 1, "one original BIOS default required")?;
    for e in kept {
        rewritten.push_str(&e.text);
    }
    let after = boot_entries::menu(&rewritten)?;
    require(
        &after.entries[after.selected - 1].title == chosen,
        "retirement changed selected BIOS title",
    )?;
    Ok(rewritten)
}
pub fn retention(
    data: &Value,
    generation: &str,
    boot: &str,
    running: Option<&str>,
    selected: &BTreeSet<String>,
    pins: &Value,
) -> Result<()> {
    identity::safe_id(generation)?;
    identity::uuid(boot)?;
    catalog::validate(data, data["filesystem_uuid"].as_str().unwrap_or(""))?;
    let rows = enzimos_platform::json::object(&data["generations"])?;
    let candidate = rows
        .get(generation)
        .ok_or_else(|| Error("publisher generation required".into()))?;
    require(
        candidate["state"] == "ready"
            && candidate["created_boot"] != boot
            && running != Some(generation),
        "unfinished/current/this-boot generation protected",
    )?;
    let (entries, titles) = entry_names(generation)?;
    require(
        entries
            .iter()
            .chain(titles.iter())
            .all(|n| !selected.contains(n)),
        "loader default protects retirement candidate",
    )?;
    let pins = pins
        .as_object()
        .ok_or_else(|| Error("complete generation pin map required".into()))?;
    require(
        pins.len() <= crate::generation_pins::MAXIMUM,
        "generation pin bound",
    )?;
    for (id, pin) in pins {
        crate::generation_pins::validate(
            pin,
            id,
            enzimos_platform::json::string(&data["filesystem_uuid"])?,
        )?;
        require(
            pin["generation"] != generation,
            "generation pin protects retirement candidate",
        )?;
    }
    let ordinal = enzimos_platform::json::unsigned(&candidate["ordinal"])?;
    require(
        rows.values()
            .filter(|r| r["state"] == "ready" && r["ordinal"].as_u64().is_some_and(|o| o > ordinal))
            .count()
            >= 2,
        "two newer ready generations must remain",
    )?;
    let retained = rows
        .iter()
        .filter(|(id, r)| id.as_str() != generation && r["state"] == "ready")
        .map(|(_, r)| r)
        .collect::<Vec<_>>();
    let root = &candidate["material"]["root_identity"]["uuid"];
    if !candidate["first_confirmation"].is_null()
        && !retained
            .iter()
            .any(|r| &r["material"]["root_identity"]["uuid"] == root)
    {
        let confirmed = retained
            .iter()
            .filter(|r| !r["first_confirmation"].is_null())
            .map(|r| enzimos_platform::json::string(&r["material"]["root_identity"]["uuid"]))
            .collect::<enzimos_platform::Result<BTreeSet<_>>>()?;
        require(
            confirmed.len() >= 2,
            "last bootable entry of confirmed root protected",
        )?;
    }
    Ok(())
}
pub(crate) fn tombstone(data: &Value, generation: &str, boot: &str) -> Result<Value> {
    identity::uuid(boot)?;
    catalog::validate(data, data["filesystem_uuid"].as_str().unwrap_or(""))?;
    let row = data["generations"]
        .get(generation)
        .ok_or_else(|| Error("original catalog generation absent".into()))?;
    require(
        row["state"] == "ready",
        "ready original catalog member required",
    )?;
    let mut after = data.clone();
    if after.get("retired").is_none() {
        after["retired"] = value!({});
    }
    require(
        after["retired"].get(generation).is_none(),
        "retirement name already consumed",
    )?;
    after["retired"][generation] = value!({"ordinal":row["ordinal"],"material_sha256":json::fingerprint(&row["material"])?,"retired_boot":boot});
    enzimos_platform::json::object_mut(&mut after["generations"])?.remove(generation);
    catalog::validate(
        &after,
        enzimos_platform::json::string(&data["filesystem_uuid"])?,
    )?;
    Ok(after)
}
/// Conservative token matching retains unknown or historical references for
/// explicit review. It cannot turn an unrecognized record into deletion permission.
pub fn mentions(v: &Value, generation: &str) -> Result<bool> {
    identity::safe_id(generation)?;
    let text =
        String::from_utf8(json::canonical(v)?).map_err(|_| Error("reference encoding".into()))?;
    let identifier = |b: u8| b.is_ascii_alphanumeric() || b"._-".contains(&b);
    Ok(text.match_indices(generation).any(|(i, _)| {
        (i == 0 || !identifier(text.as_bytes()[i - 1]))
            && (i + generation.len() == text.len()
                || !identifier(text.as_bytes()[i + generation.len()]))
    }))
}

/// Complete retained-loader cross references. The candidate's own exact two
/// entries are the only exemption; this calculation grants no deletion authority.
pub(crate) fn loader_references(
    texts: &std::collections::BTreeMap<String, String>,
    generation: &str,
    candidate_ukis: &BTreeSet<String>,
) -> Result<()> {
    let (uefi, bios) = entry_names(generation)?;
    let own = uefi.map(|name| format!("loader/entries/{name}"));
    require(
        own.iter().all(|name| texts.contains_key(name)),
        "both original candidate UEFI entries required",
    )?;
    for (name, text) in texts
        .iter()
        .filter(|(name, _)| name.starts_with("loader/entries/"))
    {
        if own.contains(name) {
            continue;
        }
        let fields = boot_entries::fields(text, false)?;
        require(
            !mentions(&value!(fields), generation)?
                && !fields
                    .get("uki")
                    .is_some_and(|u| candidate_ukis.contains(u)),
            "retained UEFI entry protects retirement candidate",
        )?;
    }
    let menu = boot_entries::menu(
        texts
            .get("limine/limine.conf")
            .ok_or_else(|| Error("original BIOS menu required".into()))?,
    )?;
    require(
        bios.iter()
            .all(|title| menu.entries.iter().filter(|e| &e.title == title).count() == 1),
        "both original candidate BIOS entries required",
    )?;
    for entry in &menu.entries {
        if bios.contains(&entry.title) {
            continue;
        }
        require(
            !mentions(
                &value!(boot_entries::fields(&entry.text, true)?),
                generation,
            )?,
            "retained BIOS entry protects retirement candidate",
        )?;
    }
    Ok(())
}
pub(crate) fn file_state(sha: &str) -> Result<String> {
    identity::sha(sha)?;
    json::fingerprint(&value!({"absent":false,"sha256":sha}))
}
/// Legacy immutable intent calculation from observed bytes, never a mutation actor.
/// Actual callers must retain their original files and complete reference actors.
#[expect(
    clippy::too_many_arguments,
    reason = "Each argument is one independently reviewed plan input."
)]
pub fn intent(
    data: &Value,
    generation: &str,
    boot: &str,
    boot_uuid: &str,
    text: &str,
    file_hashes: &std::collections::BTreeMap<String, String>,
    ukis: &std::collections::BTreeMap<String, String>,
    observation: &Value,
    protection: &Value,
) -> Result<(Value, Value)> {
    identity::safe_id(generation)?;
    identity::uuid(boot)?;
    crate::recovery_records::fat_uuid(boot_uuid)?;
    require(
        file_hashes.keys().cloned().collect::<BTreeSet<_>>()
            == MEMBERS
                .iter()
                .map(|v| (*v).into())
                .chain(["uefi-linux".into(), "uefi-linux-lts".into()])
                .collect(),
        "exact original retirement member hash set required",
    )?;
    require(ukis.len() <= 2, "candidate owner UKI bound")?;
    let absent = json::fingerprint(&value!({"absent":true}))?;
    let mut steps = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        let id = format!("uefi-{flavor}");
        steps.push(value!({"id":id,"kind":"uefi-entry","before":file_state(&file_hashes[&id])?,"after":absent}));
    }
    let rewritten = without_bios(text, generation)?;
    steps.push(value!({"id":"bios","kind":"bios-menu","before":file_state(&json::sha256(text.as_bytes()))?,"after":file_state(&json::sha256(rewritten.as_bytes()))?}));
    for (path, sha) in ukis {
        let digest = path
            .strip_prefix("/enzimos/secure-boot/")
            .and_then(|s| s.strip_suffix(".efi"))
            .ok_or_else(|| Error("owned UKI retirement path required".into()))?;
        identity::sha(digest)?;
        steps.push(value!({"id":format!("uki-{digest}"),"kind":"boot-file","before":file_state(sha)?,"after":absent}));
    }
    for name in MEMBERS {
        steps.push(value!({"id":format!("file-{name}"),"kind":"boot-file","before":file_state(&file_hashes[name])?,"after":absent}));
    }
    steps.push(value!({"id":"directory","kind":"boot-directory","before":json::fingerprint(&value!({"absent":false,"members":[]}))?,"after":absent}));
    let after = tombstone(data, generation, boot)?;
    steps.push(value!({"id":"catalog","kind":"catalog","before":json::fingerprint(data)?,"after":json::fingerprint(&after)?}));
    let mut intent = value!({"schema":1,"id":format!("boot-{generation}"),"filesystem_uuid":data["filesystem_uuid"],"boot_uuid":boot_uuid,"created_boot":boot,"observation_sha256":json::fingerprint(observation)?,"protected_sha256":json::fingerprint(protection)?,"steps":steps});
    intent["intent_sha256"] = value!(json::fingerprint(&intent)?);
    crate::retirement_journal::intent(&intent)?;
    Ok((intent, after))
}
