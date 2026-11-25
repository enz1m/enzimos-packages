// SPDX-License-Identifier: MIT
//! Concrete boot-only references from already validated original observations.
//! These calculations do not create filesystem, receipt or deletion actors.
use crate::identity;
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
/// Original caller retains all registry and recovery journal descriptions.
/// Only actual adopted/legacy-detached conclusions stop using staging inputs.
pub(crate) fn protection(records: &Value, generation: &str) -> Result<BTreeSet<String>> {
    identity::safe_id(generation)?;
    json::fields(
        records,
        "boot_publications update_workers module_views authority_refresh births rebinds retirement boot_retirement root_retirement jobs workflows runs images publications activations media",
    )?;
    for map in enzimos_platform::json::object(records)?.values() {
        require(
            map.as_object().is_some_and(|v| v.len() <= 256),
            "complete bounded reference registries required",
        )?;
    }
    let mut protected = BTreeSet::new();
    let jobs = enzimos_platform::json::object(&records["jobs"])?;
    let activations = enzimos_platform::json::object(&records["activations"])?;
    let mut concluded = BTreeSet::new();
    for (id, activation) in activations {
        identity::safe_id(id)?;
        require(
            jobs.get(id) == Some(&activation["intent"]["job"]),
            "activation differs from original staging job",
        )?;
        if activation["phase"] == "adopted" && activation["superseded"]["legacy_detached"] == true {
            require(
                jobs[id]["phase"] == "staged",
                "concluded recovery must retain its original staged job",
            )?;
            concluded.insert(id.clone());
        } else {
            if activation["intent"]["job"]["plan"]["generation"] == generation {
                protected.insert(format!("activation:{id}"));
            }
        }
    }
    for (id, job) in jobs {
        if !concluded.contains(id) && job["plan"]["generation"] == generation {
            protected.insert(format!("staging:{id}"));
        }
    }
    // Unknown or active state is never treated as historical. Original idle
    // admission separately checks every complete schema and filesystem binding.
    for (key, terminal) in [
        ("boot_publications", "complete"),
        ("update_workers", "complete"),
        ("module_views", "complete"),
        ("authority_refresh", "complete"),
        ("rebinds", "complete"),
        ("boot_retirement", "complete"),
    ] {
        for (id, row) in enzimos_platform::json::object(&records[key])? {
            require(
                row["phase"] == terminal,
                "nonterminal original context prevents boot retirement",
            )?;
            identity::safe_id(id)?;
        }
    }
    require(
        enzimos_platform::json::object(&records["retirement"])?.is_empty(),
        "independent retirement journal prevents boot retirement",
    )?;
    for row in enzimos_platform::json::object(&records["root_retirement"])?.values() {
        require(
            matches!(row["phase"].as_str(), Some("complete" | "abandoned")),
            "root retirement prevents boot retirement",
        )?;
    }
    for row in enzimos_platform::json::object(&records["births"])?.values() {
        require(
            matches!(row["phase"].as_str(), Some("ready" | "retired")),
            "unfinished root birth prevents boot retirement",
        )?;
    }
    for row in enzimos_platform::json::object(&records["workflows"])?.values() {
        require(
            row["state"] == "complete",
            "uncertain recovery workflow prevents boot retirement",
        )?;
    }
    for row in enzimos_platform::json::object(&records["runs"])?.values() {
        require(
            matches!(row["phase"].as_str(), Some("complete" | "abandoned")),
            "unfinished recovery run prevents boot retirement",
        )?;
    }
    for row in enzimos_platform::json::object(&records["media"])?.values() {
        require(
            row["phase"] == "complete",
            "unfinished media adoption prevents boot retirement",
        )?;
    }
    for row in enzimos_platform::json::object(&records["images"])?.values() {
        require(
            row["phase"] == "ready",
            "unready independent recovery image prevents boot retirement",
        )?;
    }
    // Current published recovery loaders, including any still-staged recovery,
    // are checked against actual retained ESP entries by loader_references.
    // Completed image publication's old menu/default and completed rebind's
    // old catalogs cannot replay and are historical, not current use edges.
    for (id, publication) in enzimos_platform::json::object(&records["publications"])? {
        let image = records["images"]
            .get(id)
            .ok_or_else(|| Error("orphan recovery publication prevents boot retirement".into()))?;
        crate::recovery_publication::expected_record(publication, image)?;
    }
    Ok(protected)
}
/// Inspect common automatic-discovery naming without granting ownership. Any
/// discovered external image protects the operation until independently joined.
pub(crate) fn external_autodiscovery(names: &BTreeSet<String>) -> Result<()> {
    require(
        names.is_empty(),
        "unowned automatically discovered UKIs prevent complete boot retirement references",
    )
}
