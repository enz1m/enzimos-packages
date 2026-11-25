// SPDX-License-Identifier: MIT
//! Rewrite only completely inventoried boot owners; defaults and artifacts stay bound.
use crate::{boot_entries, boot_options, catalog, identity, recovery_activation, recovery_image};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
pub type Texts = BTreeMap<String, String>;
pub struct RecoveryOwners {
    uefi: BTreeSet<String>,
    bios: BTreeSet<String>,
    ready_image: bool,
}
impl RecoveryOwners {
    /// Runtime callers must also verify every ready image's actual published artifacts.
    pub fn from_records(
        images: &BTreeMap<String, Value>,
        activations: &BTreeMap<String, Value>,
    ) -> Result<Self> {
        require(
            images.len() <= 32 && activations.len() <= 32,
            "rebind auxiliary owner bound",
        )?;
        let mut this = Self {
            uefi: BTreeSet::new(),
            bios: BTreeSet::new(),
            ready_image: false,
        };
        for (id, record) in images {
            recovery_image::validate(record, id)?;
            require(
                record["phase"] == "ready",
                "unfinished recovery image prevents rebind",
            )?;
            let (uefi, bios) = recovery_image::entry_names(id)?;
            require(
                this.uefi.insert(uefi) && this.bios.insert(bios),
                "duplicate recovery image owner",
            )?;
            this.ready_image = true;
        }
        for (id, record) in activations {
            recovery_activation::validate(record, id)?;
            require(
                matches!(
                    record["phase"].as_str(),
                    Some("published" | "selected" | "adopted")
                ),
                "unfinished activation prevents rebind",
            )?;
            for flavor in ["linux", "linux-lts"] {
                let (uefi, bios) = recovery_activation::entry_names(id, flavor)?;
                require(
                    this.uefi.insert(uefi) && this.bios.insert(bios),
                    "duplicate staged boot owner",
                )?;
            }
        }
        Ok(this)
    }
}
fn root(v: &Value) -> Result<()> {
    enzimos_platform::json::fields(v, "path id uuid ownership")?;
    identity::safe_id(text(v, "path")?)?;
    identity::uuid(text(v, "uuid")?)?;
    require(
        v["id"].as_u64().is_some_and(|id| id >= 256) && v["ownership"] == "not-established",
        "rebind cannot establish retirement ownership",
    )
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("rebind text field missing".into()))
}
fn legacy(v: Option<&Value>) -> Result<Vec<(String, String)>> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    let installer = value!({"uefi":["linux.conf","linux-lts.conf"],"bios":["enzimOS linux","enzimOS linux-lts"]});
    let lab = value!({"uefi":["linux.conf","linux-lts.conf"],"bios":["enzimOS encrypted lab linux","enzimOS encrypted lab linux-lts"]});
    require(
        *v == installer || *v == lab,
        "unreviewed legacy ownership declaration",
    )?;
    Ok(v["uefi"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["bios"].as_array().unwrap())
        .map(|(u, b)| (u.as_str().unwrap().into(), b.as_str().unwrap().into()))
        .collect())
}
pub(crate) fn replace_options(body: &str, bios: bool, target: &str) -> Result<String> {
    let fields = boot_entries::fields(body, bios)?;
    let key = if bios { "cmdline" } else { "options" };
    let original = fields
        .get(key)
        .ok_or_else(|| Error("rebind boot options missing".into()))?;
    let replacement = boot_options::root_options(original, target)?;
    let mut result = String::new();
    let mut count = 0;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let field = if bios {
            trimmed.split_once(':').map(|(key, _)| key.trim())
        } else {
            trimmed.find(char::is_whitespace).map(|end| &trimmed[..end])
        };
        if field == Some(key) {
            count += 1;
            let start = line.len() - trimmed.len();
            result.push_str(&line[..start]);
            result.push_str(key);
            result.push_str(if bios { ": " } else { " " });
            result.push_str(&replacement);
            if line.ends_with('\n') {
                result.push('\n');
            }
        } else {
            result.push_str(line);
        }
    }
    require(count == 1, "one owned boot option field required")?;
    Ok(result)
}
fn pair(uefi: &str, bios: &str, kernel: &str, initrd: &str) -> Result<()> {
    let u = boot_entries::fields(uefi, false)?;
    let b = boot_entries::fields(bios, true)?;
    require(
        u.get("linux").map(String::as_str) == Some(kernel)
            && u.get("initrd").map(String::as_str) == Some(initrd)
            && b.get("protocol").map(String::as_str) == Some("linux")
            && b.get("path") == Some(&format!("boot():{kernel}"))
            && b.get("module_path") == Some(&format!("boot():{initrd}"))
            && u.contains_key("options")
            && b.get("cmdline") == u.get("options"),
        "rebind loader resource bindings differ",
    )
}
pub struct Plan {
    pub catalog: Value,
    pub replacements: Texts,
    pub affected: Vec<String>,
}
/// The wrapping callback is an internal signing adapter, never an IPC parameter.
pub fn redirect<F: FnMut(&str) -> Result<String>>(
    before: &Value,
    source: &Value,
    target: &Value,
    files: &Texts,
    declaration: Option<&Value>,
    owners: &RecoveryOwners,
    mut wrap: F,
) -> Result<Plan> {
    root(source)?;
    root(target)?;
    require(
        source["uuid"] != target["uuid"] && source["id"] != target["id"],
        "rebind retained root must be independent",
    )?;
    catalog::validate(before, text(before, "filesystem_uuid")?)?;
    require(
        files.len() <= 128
            && files.contains_key("loader/loader.conf")
            && files.contains_key("limine/limine.conf"),
        "rebind complete boot metadata required",
    )?;
    for (name, body) in files {
        let entry = name
            .strip_prefix("loader/entries/")
            .is_some_and(|n| n.ends_with(".conf") && identity::safe_id(n).is_ok());
        require(
            (entry || matches!(name.as_str(), "loader/loader.conf" | "limine/limine.conf"))
                && body.len() <= boot_entries::MAX_TEXT,
            "rebind boot metadata membership or bytes refused",
        )?;
    }
    let legacy = legacy(declaration)?;
    let mut expected_uefi = owners.uefi.clone();
    let mut expected_bios = owners.bios.clone();
    for (u, b) in &legacy {
        require(
            expected_uefi.insert(u.clone()) && expected_bios.insert(b.clone()),
            "ambiguous legacy owner",
        )?;
    }
    let menu = boot_entries::menu(&files["limine/limine.conf"])?;
    let bios = menu
        .entries
        .iter()
        .map(|entry| (entry.title.clone(), entry.text.clone()))
        .collect::<Texts>();
    if let Some(recovery) = files.get("loader/entries/recovery.conf") {
        require(
            expected_uefi.insert("recovery.conf".into())
                && expected_bios.insert("Independent enzimOS lab recovery".into()),
            "ambiguous independent recovery owner",
        )?;
        let other = bios
            .get("Independent enzimOS lab recovery")
            .ok_or_else(|| Error("independent BIOS recovery absent".into()))?;
        pair(
            recovery,
            other,
            "/enzimos-recovery/kernel",
            "/enzimos-recovery/initrd.img",
        )?;
        let fields = boot_entries::fields(recovery, false)?;
        require(
            fields.get("options").is_some_and(|s| {
                !s.split_whitespace()
                    .any(|word| word.starts_with("root=") || word.starts_with("rootflags="))
            }),
            "independent recovery cannot bind a root",
        )?;
    } else {
        require(owners.ready_image, "independent recovery image absent")?;
    }
    // The recovery environment publishes its own UEFI entry beside the
    // generations; it boots from RAM and never binds a root.
    if let Some(environment) = files.get("loader/entries/enzimos-recovery-env.conf") {
        require(
            expected_uefi.insert("enzimos-recovery-env.conf".into()),
            "ambiguous recovery environment owner",
        )?;
        let fields = boot_entries::fields(environment, false)?;
        require(
            fields.get("linux").map(String::as_str) == Some("/enzimos/recovery-env/vmlinuz")
                && fields.get("initrd").map(String::as_str)
                    == Some("/enzimos/recovery-env/initrd.img")
                && fields.get("options").is_some_and(|s| {
                    !s.split_whitespace()
                        .any(|word| word.starts_with("root=") || word.starts_with("rootflags="))
                }),
            "recovery environment entry must boot its own image without a root",
        )?;
    }
    let mut after = before.clone();
    let mut patches = Texts::new();
    let mut affected = Vec::new();
    let mut redirects = BTreeMap::<String, String>::new();
    for (id, record) in before["generations"].as_object().unwrap() {
        require(
            record["state"] == "ready",
            "pending generation prevents root rebind",
        )?;
        let mut texts = Texts::new();
        for flavor in ["linux", "linux-lts"] {
            let name = format!("enzimos-{id}-{flavor}.conf");
            let title = format!("enzimOS {id} {flavor}");
            require(
                expected_uefi.insert(name.clone()) && expected_bios.insert(title.clone()),
                "ambiguous publisher owner",
            )?;
            texts.insert(
                name.clone(),
                files
                    .get(&format!("loader/entries/{name}"))
                    .ok_or_else(|| Error("publisher UEFI missing".into()))?
                    .clone(),
            );
        }
        require(
            boot_entries::fingerprint_entries(record, &texts, &files["limine/limine.conf"])?
                == record["entry_fingerprints"],
            "publisher fingerprints changed before rebind",
        )?;
        if record["material"]["root_identity"]["uuid"] != source["uuid"] {
            continue;
        }
        require(
            record["material"]["root_identity"] == *source,
            "registered source identity changed",
        )?;
        affected.push(id.clone());
        let updated = &mut after["generations"][id];
        updated["material"]["root_identity"] = target.clone();
        updated["material"]["options"] = value!(boot_options::root_options(
            text(&record["material"], "options")?,
            text(target, "path")?
        )?);
        updated["first_confirmation"] = Value::Null;
        updated["last_confirmation"] = Value::Null;
        for (name, body) in texts {
            let rewritten = replace_options(&body, false, text(target, "path")?)?;
            let wrapped = wrap(&rewritten)?;
            let raw = boot_entries::fields(&rewritten, false)?;
            let signed = boot_entries::fields(&wrapped, false)?;
            require(
                ["linux", "initrd", "options"]
                    .iter()
                    .all(|key| raw.get(*key) == signed.get(*key)),
                "rebind signing adapter changed bindings",
            )?;
            patches.insert(format!("loader/entries/{name}"), wrapped);
        }
        for flavor in ["linux", "linux-lts"] {
            redirects.insert(
                format!("enzimOS {id} {flavor}"),
                text(target, "path")?.into(),
            );
        }
    }
    let observed = files
        .keys()
        .filter_map(|name| name.strip_prefix("loader/entries/").map(String::from))
        .collect::<BTreeSet<_>>();
    require(
        observed == expected_uefi && bios.keys().cloned().collect::<BTreeSet<_>>() == expected_bios,
        "unknown or missing loader entries require review before package changes",
    )?;
    for ((name, title), flavor) in legacy.iter().zip(["linux", "linux-lts"]) {
        let key = format!("loader/entries/{name}");
        pair(
            &files[&key],
            &bios[title],
            &format!("/vmlinuz-{flavor}"),
            &format!("/initramfs-{flavor}.img"),
        )?;
        let fields = boot_entries::fields(&files[&key], false)?;
        if boot_options::subvolume_from_options(&fields["options"])? != text(source, "path")? {
            continue;
        }
        let rewritten = replace_options(&files[&key], false, text(target, "path")?)?;
        let wrapped = wrap(&rewritten)?;
        let raw = boot_entries::fields(&rewritten, false)?;
        let signed = boot_entries::fields(&wrapped, false)?;
        require(
            ["linux", "initrd", "options"]
                .iter()
                .all(|key| raw.get(*key) == signed.get(*key)),
            "rebind legacy signing changed bindings",
        )?;
        patches.insert(key, wrapped);
        redirects.insert(title.clone(), text(target, "path")?.into());
    }
    let mut rewritten = menu.header;
    for entry in menu.entries {
        rewritten.push_str(&if let Some(target) = redirects.get(&entry.title) {
            replace_options(&entry.text, true, target)?
        } else {
            entry.text
        });
    }
    if rewritten != files["limine/limine.conf"] {
        patches.insert("limine/limine.conf".into(), rewritten);
    }
    let mut combined = files.clone();
    combined.extend(patches.clone());
    for id in &affected {
        let texts = ["linux", "linux-lts"]
            .into_iter()
            .map(|flavor| {
                let name = format!("enzimos-{id}-{flavor}.conf");
                (
                    name.clone(),
                    combined[&format!("loader/entries/{name}")].clone(),
                )
            })
            .collect();
        after["generations"][id]["entry_fingerprints"] = boot_entries::fingerprint_entries(
            &after["generations"][id],
            &texts,
            &combined["limine/limine.conf"],
        )?;
    }
    catalog::validate(&after, text(before, "filesystem_uuid")?)?;
    affected.sort();
    Ok(Plan {
        catalog: after,
        replacements: patches,
        affected,
    })
}
