// SPDX-License-Identifier: MIT
//! Print-only resolution is bound to the original independently verified cohort.
use crate::{operation, update_cohort, update_plan::Plan};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
pub fn candidates(body: &str, packages: &[Value]) -> Result<Vec<Value>> {
    require(
        body.len() <= 2 * 1024 * 1024 && !body.contains('\0') && body.lines().count() <= 16384,
        "update resolution output bound",
    )?;
    let allowed = packages
        .iter()
        .map(|row| {
            Ok((
                row["name"]
                    .as_str()
                    .ok_or_else(|| Error("resolution package name missing".into()))?,
                row["version"]
                    .as_str()
                    .ok_or_else(|| Error("resolution package version missing".into()))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    require(
        !allowed.is_empty() && allowed.len() == packages.len() && allowed.len() <= 768,
        "resolution package set ambiguous",
    )?;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.strip_prefix("ENZIMOS_UPGRADE ") else {
            continue;
        };
        let fields = rest.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 2
                && allowed.get(fields[0]) == Some(&fields[1])
                && seen.insert(fields[0]),
            "resolution differs from admitted package identity",
        )?;
        result.push(json!({"name":fields[0],"version":fields[1]}));
    }
    Ok(result)
}
pub fn resolve(plan: &Plan) -> Result<Vec<Value>> {
    plan.recheck_before_mutation()?;
    let body = operation::query(
        "/usr/bin/pacman",
        &[
            "--config",
            update_cohort::CONFIG,
            "-Syu",
            "--noconfirm",
            "--print",
            "--print-format",
            "ENZIMOS_UPGRADE %n %v",
        ],
        Duration::from_secs(120),
        2 * 1024 * 1024,
        &[0],
    )?;
    let result = candidates(
        std::str::from_utf8(&body).map_err(|_| Error("resolution output encoding".into()))?,
        plan.admitted().source().packages_metadata(),
    )?;
    plan.recheck_before_mutation()?;
    Ok(result)
}
