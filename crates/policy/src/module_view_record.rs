// SPDX-License-Identifier: MIT
//! Interrupted module mounts block another entry; no checkpoint grants replay.
use crate::identity;
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
pub(crate) const MAXIMUM: usize = 32;
pub(crate) fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase boot_id kernel filesystem_uuid inventory_sha256 source runtime alias live",
    )?;
    identity::safe_id(id)?;
    require(
        v["schema"] == 2
            && v["id"] == id
            && matches!(
                v["phase"].as_str(),
                Some(
                    "intent"
                        | "cloned"
                        | "binding-alias"
                        | "alias-mounted"
                        | "binding-live"
                        | "active"
                        | "restoring"
                        | "detaching-live"
                        | "complete"
                        | "uncertain"
                )
            ),
        "module view phase or identity refused",
    )?;
    for key in ["boot_id", "filesystem_uuid"] {
        identity::uuid(
            v[key]
                .as_str()
                .ok_or_else(|| Error("module view UUID missing".into()))?,
        )?;
    }
    identity::safe_id(
        v["kernel"]
            .as_str()
            .ok_or_else(|| Error("module view kernel missing".into()))?,
    )?;
    identity::sha(
        v["inventory_sha256"]
            .as_str()
            .ok_or_else(|| Error("module view inventory digest missing".into()))?,
    )?;
    for key in ["source", "runtime", "alias", "live"] {
        if v[key].is_null() {
            require(key != "source", "module view source missing")?;
            continue;
        }
        json::fields(&v[key], "device inode mount")?;
        require(
            ["device", "inode", "mount"]
                .iter()
                .all(|n| v[key][*n].as_u64().is_some_and(|n| n > 0)),
            "module view retained directory identity refused",
        )?;
    }
    if !matches!(v["phase"].as_str(), Some("intent" | "uncertain")) {
        require(
            !v["runtime"].is_null(),
            "retained runtime directory missing",
        )?;
    }
    if matches!(
        v["phase"].as_str(),
        Some(
            "alias-mounted"
                | "binding-live"
                | "active"
                | "restoring"
                | "detaching-live"
                | "complete"
        )
    ) {
        require(
            !v["alias"].is_null() && v["alias"]["mount"] != v["source"]["mount"],
            "private transaction alias missing",
        )?;
    }
    if matches!(
        v["phase"].as_str(),
        Some("active" | "restoring" | "detaching-live" | "complete")
    ) {
        require(
            ["runtime", "alias", "live"]
                .iter()
                .all(|k| !v[*k].is_null())
                && v["alias"]["device"] == v["source"]["device"]
                && v["alias"]["inode"] == v["source"]["inode"]
                && v["live"]["device"] == v["runtime"]["device"]
                && v["live"]["inode"] == v["runtime"]["inode"]
                && (v["live"]["device"] != v["source"]["device"]
                    || v["live"]["inode"] != v["source"]["inode"])
                && v["live"]["mount"] != v["runtime"]["mount"]
                && v["live"]["mount"] != v["alias"]["mount"],
            "live and transaction module views are not distinct",
        )?;
    }
    Ok(())
}
pub(crate) fn transition(before: Option<&Value>, after: &Value, id: &str) -> Result<()> {
    validate(after, id)?;
    let Some(before) = before else {
        return require(
            after["phase"] == "intent",
            "module view must start with intent",
        );
    };
    validate(before, id)?;
    for key in [
        "schema",
        "id",
        "boot_id",
        "kernel",
        "filesystem_uuid",
        "inventory_sha256",
        "source",
    ] {
        require(before[key] == after[key], "module view intent changed")?;
    }
    for key in ["runtime", "alias", "live"] {
        require(
            before[key].is_null() || before[key] == after[key],
            "module view retained mount changed",
        )?;
    }
    let phase = before["phase"].as_str().unwrap();
    let next = after["phase"].as_str().unwrap();
    require(
        matches!(
            (phase, next),
            ("intent", "cloned")
                | ("cloned", "binding-alias")
                | ("binding-alias", "alias-mounted")
                | ("alias-mounted", "binding-live")
                | ("binding-live", "active")
                | ("active", "restoring")
                | ("restoring", "detaching-live")
                | ("detaching-live", "complete")
        ) || (next == "uncertain" && !matches!(phase, "complete" | "uncertain")),
        "module view cannot replay or skip a checkpoint",
    )
}
