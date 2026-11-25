// SPDX-License-Identifier: MIT
//! Exact staged boot metadata and prefix-ordered publication/selection.
use crate::{
    boot_entries, boot_options, recovery_activation as activation, recovery_records as records,
};
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::collections::BTreeMap;
pub(crate) type Metadata = BTreeMap<String, Option<String>>;
pub(crate) struct Entries {
    pub uefi: BTreeMap<String, String>,
    pub bios: String,
    pub sequence: Vec<String>,
}
pub(crate) fn entries(job: &Value) -> Result<Entries> {
    let plan = &job["plan"];
    let id = records::text(plan, "id")?;
    records::job(job, id)?;
    let options = boot_options::root_options(
        records::text(&plan["material"], "options")?,
        records::text(plan, "target_name")?,
    )?;
    let words = options
        .split_whitespace()
        .filter(|s| !s.starts_with("enzimos.generation="))
        .collect::<Vec<_>>();
    require(
        !words.iter().any(|s| {
            ["enzimos.staged=", "enzimos.recovery=", "init=", "rdinit="]
                .iter()
                .any(|prefix| s.starts_with(prefix))
        }),
        "conflicting staged boot options",
    )?;
    let options = format!("{} enzimos.staged={id}", words.join(" "));
    let prefix = format!(
        "/enzimos/generations/{}",
        records::text(plan, "generation")?
    );
    let mut uefi = BTreeMap::new();
    let mut bios = String::new();
    let mut sequence = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        let (name, title) = activation::entry_names(id, flavor)?;
        uefi.insert(name.clone(),format!("title {title}\nlinux {prefix}/vmlinuz-{flavor}\ninitrd {prefix}/initramfs-{flavor}.img\noptions {options}\n"));
        sequence.push(format!("loader/entries/{name}"));
        bios.push_str(&format!("/{title}\n protocol: linux\n path: boot():{prefix}/vmlinuz-{flavor}\n module_path: boot():{prefix}/initramfs-{flavor}.img\n cmdline: {options}\n"));
    }
    sequence.push("limine/limine.conf".into());
    Ok(Entries {
        uefi,
        bios,
        sequence,
    })
}
pub(crate) fn replace_default(text: &str, prefix: &str, next: &str) -> Result<String> {
    require(
        text.len() <= boot_entries::MAX_TEXT && !next.contains(['\n', '\r', '\0']),
        "boot default replacement bound",
    )?;
    let mut count = 0;
    let mut result = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with(prefix)
            || prefix == "default_entry: " && line.starts_with("default_entry:")
        {
            count += 1;
            result.push_str(prefix);
            result.push_str(next);
            if line.ends_with('\n') {
                result.push('\n');
            }
        } else {
            result.push_str(line);
        }
    }
    require(count == 1, "one literal loader default required")?;
    Ok(result)
}
pub(crate) fn expected(
    intent: &Value,
    entries: &Entries,
    selection: Option<&Value>,
) -> Result<Metadata> {
    let mut result = Metadata::new();
    for (name, text) in &entries.uefi {
        result.insert(format!("loader/entries/{name}"), Some(text.clone()));
    }
    let mut bios = format!(
        "{}\n{}",
        records::text(intent, "bios_before")?.trim_end(),
        entries.bios
    );
    let mut defaults = records::text(intent, "default_before")?.to_owned();
    if let Some(selection) = selection {
        let (name, title) = activation::entry_names(
            records::text(intent, "id")?,
            records::text(selection, "flavor")?,
        )?;
        let number = boot_entries::number(&bios, &title)?;
        defaults = replace_default(&defaults, "default ", &name)?;
        bios = replace_default(&bios, "default_entry: ", &number.to_string())?;
    }
    result.insert("loader/loader.conf".into(), Some(defaults));
    result.insert("limine/limine.conf".into(), Some(bios));
    Ok(result)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Before,
    After,
}
pub(crate) fn classify(
    record: &Value,
    entries: &Entries,
    actual: &Metadata,
) -> Result<BTreeMap<String, State>> {
    let intent = &record["intent"];
    activation::validate(record, records::text(intent, "id")?)?;
    let published = expected(intent, entries, None)?;
    let selected = expected(
        intent,
        entries,
        (!record["selection"].is_null()).then_some(&record["selection"]),
    )?;
    require(
        actual.len() == published.len() && actual.keys().eq(published.keys()),
        "activation metadata member set changed",
    )?;
    let phase = records::text(record, "phase")?;
    let mut states = BTreeMap::new();
    for (name, body) in actual {
        let before = match name.as_str() {
            "loader/loader.conf" => Some(records::text(intent, "default_before")?.to_owned()),
            "limine/limine.conf" => Some(records::text(intent, "bios_before")?.to_owned()),
            _ => None,
        };
        let allowed = if phase == "prepared" {
            body == &before || body == &published[name]
        } else if phase == "selecting" {
            body == &published[name] || body == &selected[name]
        } else {
            body == &selected[name]
        };
        require(allowed, "activation metadata drift; overwrite refused")?;
        states.insert(
            name.clone(),
            if body == &selected[name] {
                State::After
            } else {
                State::Before
            },
        );
    }
    if phase == "prepared" {
        let mut before_seen = false;
        for name in &entries.sequence {
            match states[name] {
                State::Before => before_seen = true,
                State::After => require(!before_seen, "out-of-order staged entry publication")?,
            }
        }
    }
    if phase == "selecting" {
        require(
            !(states["limine/limine.conf"] == State::After
                && states["loader/loader.conf"] == State::Before),
            "out-of-order staged default selection",
        )?;
    }
    Ok(states)
}
pub(crate) fn default_guard(defaults: &str, entries: &Entries) -> Result<String> {
    let fields = boot_entries::fields(defaults, false)?;
    let name = fields
        .get("default")
        .ok_or_else(|| Error("existing UEFI default missing".into()))?;
    records::literal_entry(name)?;
    require(
        !entries.uefi.contains_key(name),
        "cannot adopt an already selected staged entry",
    )?;
    replace_default(defaults, "default ", name)?;
    Ok(name.clone())
}
