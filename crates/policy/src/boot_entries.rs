// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_TEXT: usize = 256 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub title: String,
    pub text: String,
}
pub struct Menu {
    pub header: String,
    pub entries: Vec<Entry>,
    pub selected: usize,
}
pub fn fields(text: &str, bios: bool) -> Result<BTreeMap<String, String>> {
    require(
        text.len() <= MAX_TEXT && !text.contains('\0'),
        "boot entry byte bound",
    )?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let mut line = line.trim();
        if !bios && let Some(source) = line.strip_prefix("# enzimos-source-") {
            line = source;
        }
        if line.is_empty() || line.starts_with(['#', '/']) {
            continue;
        }
        let pair = if bios {
            line.split_once(':')
        } else {
            line.find(char::is_whitespace)
                .map(|i| (&line[..i], &line[i..]))
        };
        let (key, val) = pair.ok_or_else(|| Error("unrecognized boot entry line".into()))?;
        let (key, val) = (key.trim(), val.trim());
        require(
            !key.is_empty() && !val.is_empty() && !result.contains_key(key),
            "duplicate or empty boot field",
        )?;
        result.insert(key.into(), val.into());
    }
    Ok(result)
}
pub fn menu(text: &str) -> Result<Menu> {
    require(
        text.len() <= MAX_TEXT && !text.contains('\0'),
        "invalid BIOS menu",
    )?;
    let mut header = String::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut defaults = Vec::new();
    for line in text.split_inclusive('\n') {
        if let Some(title) = line.strip_prefix('/') {
            let title = title.trim();
            require(
                !title.is_empty() && !title.starts_with('/') && seen.insert(title.to_owned()),
                "nested or duplicate BIOS entry",
            )?;
            require(entries.len() < 256, "BIOS menu entry bound")?;
            entries.push(Entry {
                title: title.into(),
                text: line.into(),
            });
        } else if let Some(entry) = entries.last_mut() {
            entry.text.push_str(line);
        } else {
            header.push_str(line);
        }
        if let Some(raw) = line.strip_prefix("default_entry:") {
            let raw = raw.trim();
            require(
                !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()),
                "ambiguous BIOS default",
            )?;
            defaults.push(
                raw.parse::<usize>()
                    .map_err(|_| Error("BIOS default bound".into()))?,
            );
        }
    }
    require(
        defaults.len() == 1 && defaults[0] > 0 && defaults[0] <= entries.len(),
        "ambiguous BIOS default",
    )?;
    Ok(Menu {
        header,
        entries,
        selected: defaults[0],
    })
}
pub fn number(text: &str, title: &str) -> Result<usize> {
    let m = menu(text)?;
    let found = m
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.title == title)
        .map(|(i, _)| i + 1)
        .collect::<Vec<_>>();
    require(found.len() == 1, "owned BIOS entry missing or ambiguous")?;
    Ok(found[0])
}
pub fn efi_string(body: &[u8]) -> Result<String> {
    require(
        body.len() > 4 && body.len() <= 8192 && (body.len() - 4).is_multiple_of(2),
        "EFI loader string size",
    )?;
    let words = body[4..]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    let mut text =
        String::from_utf16(&words).map_err(|_| Error("EFI loader string encoding".into()))?;
    require(text.ends_with('\0'), "EFI loader string terminator")?;
    text.pop();
    require(
        !text.is_empty() && !text.chars().any(char::is_control) && !text.contains(['/', '\\']),
        "EFI entry identifier",
    )?;
    Ok(text)
}
/// Every entry is measured from actual boot files; certificate/UKI verification
/// belongs to the secure-boot observer and must precede publication/confirmation.
pub fn fingerprint_entries(
    record: &Value,
    uefi: &BTreeMap<String, String>,
    bios: &str,
) -> Result<Value> {
    let generation = record["generation"]
        .as_str()
        .ok_or_else(|| Error("generation identity".into()))?;
    crate::identity::safe_id(generation)?;
    crate::catalog::material(&record["material"], generation)?;
    let m = menu(bios)?;
    let mut result = value!({"uefi":{},"bios":{}});
    for flavor in ["linux", "linux-lts"] {
        let filename = format!("enzimos-{generation}-{flavor}.conf");
        let title = format!("enzimOS {generation} {flavor}");
        let entry = fields(
            uefi.get(&filename)
                .ok_or_else(|| Error("UEFI entry missing".into()))?,
            false,
        )?;
        let row = m
            .entries
            .iter()
            .find(|e| e.title == title)
            .ok_or_else(|| Error("BIOS entry missing".into()))?;
        let legacy = fields(&row.text, true)?;
        let prefix = format!("/enzimos/generations/{generation}");
        require(
            entry.get("linux") == Some(&format!("{prefix}/vmlinuz-{flavor}"))
                && entry.get("initrd") == Some(&format!("{prefix}/initramfs-{flavor}.img"))
                && entry.get("options")
                    == record["material"]["options"]
                        .as_str()
                        .map(std::borrow::ToOwned::to_owned)
                        .as_ref(),
            "UEFI publisher binding changed",
        )?;
        require(
            legacy.get("protocol").is_some_and(|s| s == "linux")
                && legacy.get("path") == Some(&format!("boot():{prefix}/vmlinuz-{flavor}"))
                && legacy.get("module_path")
                    == Some(&format!("boot():{prefix}/initramfs-{flavor}.img"))
                && legacy.get("cmdline") == entry.get("options"),
            "BIOS publisher binding changed",
        )?;
        result["uefi"][&filename] = value!(json::fingerprint(
            &serde_json::to_value(&entry).map_err(|_| Error("entry encoding".into()))?
        )?);
        result["bios"][&title] = value!(json::fingerprint(
            &serde_json::to_value(&legacy).map_err(|_| Error("entry encoding".into()))?
        )?);
    }
    Ok(result)
}
