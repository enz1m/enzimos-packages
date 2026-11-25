// SPDX-License-Identifier: MIT
//! Compatibility projection of native measurements. Missing measurements stay null/blocked.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeMap;
/// Collect the boot inventory in the legacy report form.
///
/// # Errors
///
/// As [`crate::boot_inventory::collect`].
pub fn collect() -> Result<Value> {
    view(crate::boot_inventory::collect()?)
}
fn view(native: Value) -> Result<Value> {
    require(
        native["schema"] == 2
            && native["complete"] == false
            && native["execution_available"] == false,
        "native blocked inspection report required",
    )?;
    let original = &native["original_boot_context"];
    let mut blockers: Vec<String> = native["blockers"]
        .as_array()
        .ok_or_else(|| Error("native inspection blockers required".into()))?
        .iter()
        .map(|r| {
            r.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error("native inspection blocker text required".into()))
        })
        .collect::<Result<_>>()?;
    blockers.push("native-compatibility-view-is-not-a-complete-retirement-inventory".into());
    let mut files = BTreeMap::new();
    let mut generations: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    if let Some(artifacts) = original["artifacts"].as_object() {
        for (path, row) in artifacts {
            require(
                row["bytes"].is_u64()
                    && row["sha256"]
                        .as_str()
                        .is_some_and(|s| crate::identity::sha(s).is_ok()),
                "native original artifact measurement required",
            )?;
            let measurement = value!({"bytes":row["bytes"],"sha256":row["sha256"]});
            files.insert(format!("/boot/{path}"), measurement.clone());
            if let Some(relative) = path.strip_prefix("enzimos/generations/") {
                let parts: Vec<_> = relative.split('/').collect();
                require(parts.len() == 2, "native generation artifact path required")?;
                crate::identity::safe_id(parts[0])?;
                generations
                    .entry(parts[0].into())
                    .or_default()
                    .insert(parts[1].into(), measurement);
            }
        }
    }
    let mut uefi = BTreeMap::new();
    let mut bios = Value::Null;
    let mut bios_default = Value::Null;
    if let Some(texts) = original["texts"].as_object() {
        for (path, text) in texts {
            if let Some(name) = path.strip_prefix("loader/entries/") {
                let text = text
                    .as_str()
                    .ok_or_else(|| Error("native loader text required".into()))?;
                match crate::boot_entries::fields(text, false) {
                    Ok(fields) => {
                        uefi.insert(name.to_owned(), value!(fields));
                    }
                    Err(_) => {
                        uefi.insert(name.to_owned(), value!({"unparsed":true}));
                        blockers.push(format!("unparsed-UEFI-entry:{name}"));
                    }
                }
            }
        }
        if let Some(text) = texts.get("limine/limine.conf").and_then(Value::as_str) {
            match crate::boot_entries::menu(text) {
                Ok(menu) => {
                    bios = value!(menu.entries.iter().map(|e| &e.title).collect::<Vec<_>>());
                    bios_default = value!(menu.entries[menu.selected - 1].title);
                }
                Err(_) => blockers.push("native-BIOS-menu-observation-unavailable".into()),
            }
        }
    }
    let markers: Vec<_> = original["command_line"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|s| s.strip_prefix("enzimos.generation="))
        .collect();
    let running = if markers.len() == 1 {
        value!(markers[0])
    } else {
        blockers.push("unambiguous-running-generation-marker-missing".into());
        Value::Null
    };
    let selected = if let Some(loader) = original["texts"]["loader/loader.conf"].as_str() {
        let entries = uefi
            .iter()
            .map(|(name, row)| (name.clone(), value!(row)))
            .collect();
        let variables: BTreeMap<String, Value> =
            serde_json::from_value(original["firmware"]["variables"].clone()).unwrap_or_default();
        match crate::recovery_reference_diagnostic::candidates(loader, &entries, &variables) {
            Ok(names) => value!(names),
            Err(error) => {
                blockers.push(error.to_string());
                Value::Null
            }
        }
    } else {
        Value::Null
    };
    // Each populated family comes from its independent original observer;
    // absence is disclosed rather than silently synthesized as an empty set.
    let families = &native["reference_families"];
    for (family, key) in [
        ("publisher-registry", "publisher_registry"),
        ("root-birth", "root_births"),
        ("root-reference", "root_references"),
        ("recovery-staging", "recovery_staging"),
        ("recovery-image", "recovery_images"),
        ("recovery-reference", "recovery_references"),
    ] {
        if families[key].is_null() {
            blockers.push(format!(
                "{family}-legacy-measurement-unavailable-in-native-compatibility-view"
            ));
        }
    }
    for (key, pending, drift) in [
        (
            "root_births",
            "pending-root-creation",
            "root-birth-identity-drift",
        ),
        (
            "recovery_staging",
            "planned-or-incomplete-recovery-staging",
            "staged-recovery-identity-drift",
        ),
    ] {
        if families[key]["pending"]
            .as_array()
            .is_some_and(|r| !r.is_empty())
        {
            blockers.push(pending.into());
        }
        if families[key]["drift"]
            .as_array()
            .is_some_and(|r| !r.is_empty())
        {
            blockers.push(drift.into());
        }
    }
    for key in ["root_references", "recovery_images", "recovery_references"] {
        if let Some(reasons) = families[key]["blockers"].as_array() {
            for reason in reasons {
                blockers.push(
                    reason
                        .as_str()
                        .ok_or_else(|| Error("original family blocker text required".into()))?
                        .into(),
                );
            }
        }
    }
    for (key, reason) in [
        ("pending_rebinds", "pending-root-rebinding"),
        ("pending_births", "pending-root-creation"),
    ] {
        if families["publisher_registry"][key]
            .as_array()
            .is_some_and(|r| !r.is_empty())
        {
            blockers.push(reason.into());
        }
    }
    if native["process_references"]["legacy"].is_null() {
        blockers.push(
            "process-inode-reference-legacy-measurement-unavailable-in-native-compatibility-view"
                .into(),
        );
    }
    blockers.sort();
    blockers.dedup();
    let mut result = value!({"schema":1,"status":"OBSERVED-retirement-blocked","complete":false,"execution_available":false,
        "boot_id":native["boot_id"],"running_kernel":native["running_kernel"],"running_marker":running,
        "mount_identity":if original.is_object(){value!({"root_uuid":native["source"]["configuration"]["filesystem_uuid"],"root_subvolume":native["source"]["mount"]["root"],"boot_uuid":original["boot_uuid"],"boot_fstype":"vfat"})}else{Value::Null},
        "uefi_entries":uefi,"uefi_default_candidates":selected,"efi_observable":original["firmware"]["observable"],"efi_loader_variables":original["firmware"]["variables"],
        "bios_entries":bios,"bios_default_title":bios_default,"generations":generations,
        "publisher_registry":families["publisher_registry"],"root_births":families["root_births"],"root_references":families["root_references"],"recovery_staging":families["recovery_staging"],"recovery_images":families["recovery_images"],"recovery_references":families["recovery_references"],
        "mount_namespaces":native["mount_namespaces"],"process_references":native["process_references"]["legacy"],"files":files,"blockers":blockers});
    result["observation_sha256"] = value!(json::fingerprint(&result)?);
    Ok(result)
}
