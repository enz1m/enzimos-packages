// SPDX-License-Identifier: MIT
//! Durable root-redirection bindings; reading one grants no replay authority.
use crate::{catalog, identity, recovery_records};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
/// Validate root rebind record `id`.
///
/// # Errors
///
/// Fails when a field is missing or invalid.
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase filesystem_uuid source target snapshot inventory_sha256 kernels kernel_hashes authority before_files replacements before_catalog after_catalog affected journal_sha256",
    )?;
    identity::safe_id(id)?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["id"] == id
            && matches!(v["phase"].as_str(), Some("prepared" | "complete")),
        "invalid root rebind identity or state",
    )?;
    recovery_records::digest(v, "journal_sha256")?;
    let filesystem = identity::uuid(recovery_records::text(v, "filesystem_uuid")?)?;
    for role in ["source", "target"] {
        let root = &v[role];
        json::fields(root, "path id uuid ownership")?;
        identity::safe_id(recovery_records::text(root, "path")?)?;
        identity::uuid(recovery_records::text(root, "uuid")?)?;
        require(
            root["id"].as_u64().is_some_and(|n| n >= 256) && root["ownership"] == "not-established",
            "root rebind is not retirement ownership",
        )?;
    }
    require(
        v["source"]["uuid"] != v["target"]["uuid"] && v["source"]["id"] != v["target"]["id"],
        "retained rebind root must be independent",
    )?;
    json::fields(&v["snapshot"], "number uuid")?;
    require(
        v["snapshot"]["number"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= i64::MAX as u64),
        "invalid root rebind snapshot number",
    )?;
    identity::uuid(recovery_records::text(&v["snapshot"], "uuid")?)?;
    identity::sha(recovery_records::text(v, "inventory_sha256")?)?;
    json::fields(
        &v["authority"],
        "pubring.gpg gpg.conf approved.trust ownertrust",
    )?;
    for hash in enzimos_platform::json::object(&v["authority"])?.values() {
        identity::sha(
            hash.as_str()
                .ok_or_else(|| Error("rebind authority digest type".into()))?,
        )?;
    }
    json::fields(&v["kernels"], "linux linux-lts")?;
    json::fields(&v["kernel_hashes"], "linux linux-lts")?;
    for flavor in ["linux", "linux-lts"] {
        identity::safe_id(recovery_records::text(&v["kernels"], flavor)?)?;
        identity::sha(recovery_records::text(&v["kernel_hashes"], flavor)?)?;
    }
    require(
        v["kernels"]["linux"] != v["kernels"]["linux-lts"],
        "ambiguous rebind kernel flavors",
    )?;
    catalog::validate(&v["before_catalog"], filesystem)?;
    catalog::validate(&v["after_catalog"], filesystem)?;
    let before = v["before_files"]
        .as_object()
        .ok_or_else(|| Error("root rebind boot metadata object".into()))?;
    let replacements = v["replacements"]
        .as_object()
        .ok_or_else(|| Error("root rebind replacements object".into()))?;
    require(
        before.len() <= 128
            && replacements.keys().all(|name| before.contains_key(name))
            && !replacements.contains_key("loader/loader.conf"),
        "unbound replacement or selected UEFI default change",
    )?;
    for (name, text) in before {
        let entry = name.strip_prefix("loader/entries/").is_some_and(|name| {
            !name.contains('/') && name.ends_with(".conf") && identity::safe_id(name).is_ok()
        });
        require(
            matches!(name.as_str(), "loader/loader.conf" | "limine/limine.conf") || entry,
            "unqualified rebind boot metadata path",
        )?;
        require(
            text.as_str()
                .is_some_and(|s| s.len() <= crate::boot_entries::MAX_TEXT),
            "root rebind metadata byte bound",
        )?;
    }
    for body in replacements.values() {
        require(
            body.as_str()
                .is_some_and(|s| s.len() <= crate::boot_entries::MAX_TEXT),
            "root rebind replacement byte bound",
        )?;
    }
    let affected = v["affected"]
        .as_array()
        .ok_or_else(|| Error("root rebind affected generations".into()))?;
    require(
        affected.len() <= 64,
        "root rebind affected generation bound",
    )?;
    let mut names = std::collections::BTreeSet::new();
    for name in affected {
        require(
            names.insert(name.as_str()),
            "duplicate rebind affected generation",
        )?;
        identity::safe_id(
            name.as_str()
                .ok_or_else(|| Error("root rebind generation name".into()))?,
        )?;
    }
    Ok(())
}
