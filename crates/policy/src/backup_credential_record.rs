// SPDX-License-Identifier: MIT
//! Legacy enrollment records and review data never grant execution authority.
use crate::{identity, recovery_records as records};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
pub(crate) const CAPACITY: usize = 8;
pub(crate) const LIMIT: usize = 32768;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    records::text(v, key)
}
pub(crate) fn validate(v: &Value, id: &str) -> Result<()> {
    identity::safe_id(id)?;
    json::fields(
        v,
        "schema id phase repository_binding before_keys new_key created_boot input_identity",
    )?;
    let schema = v["schema"].as_u64();
    require(
        matches!(schema, Some(1 | 2)) && v["id"] == id,
        "credential enrollment schema/filename mismatch",
    )?;
    identity::uuid(text(v, "created_boot")?)?;
    let before = v["before_keys"].as_array().ok_or_else(|| {
        enzimos_platform::Error("credential before-key inventory required".into())
    })?;
    require(
        (1..32).contains(&before.len()),
        "credential before-key inventory bound",
    )?;
    let mut previous: Option<&str> = None;
    for key in before {
        let key = key
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("credential key ID required".into()))?;
        identity::sha(key)?;
        require(
            previous.is_none_or(|p| p < key),
            "credential key inventory must be sorted and unique",
        )?;
        previous = Some(key);
    }
    match v["phase"].as_str() {
        Some("prepared") => require(
            v["new_key"].is_null(),
            "prepared enrollment cannot claim a new key",
        )?,
        Some("complete") => {
            let new = identity::sha(text(v, "new_key")?)?;
            require(
                !before.iter().any(|k| k == new),
                "completed enrollment key already existed",
            )?;
        }
        _ => {
            return Err(enzimos_platform::Error(
                "credential enrollment phase required".into(),
            ));
        }
    }
    let input = &v["input_identity"];
    json::fields(
        input,
        if schema == Some(1) {
            "device inode size mtime_ns ctime_ns"
        } else {
            "filesystem_uuid root_uuid root_id root_path inode size mtime_ns ctime_ns"
        },
    )?;
    for field in [
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        if schema == Some(1) {
            "device"
        } else {
            "root_id"
        },
    ] {
        require(
            input[field].as_u64().is_some_and(|n| n > 0),
            "credential input metadata bound",
        )?;
    }
    require(
        enzimos_platform::json::unsigned(&input["size"])? <= 4096,
        "credential input size bound",
    )?;
    if schema == Some(2) {
        identity::uuid(text(input, "filesystem_uuid")?)?;
        identity::uuid(text(input, "root_uuid")?)?;
        identity::safe_id(text(input, "root_path")?)?;
        require(
            enzimos_platform::json::unsigned(&input["root_id"])? >= 256,
            "credential input subvolume bound",
        )?;
    }
    stable_binding(&v["repository_binding"])?;
    require(
        json::canonical(v)?.len() <= LIMIT,
        "credential enrollment record bound",
    )
}
pub(crate) fn stable_binding(bound: &Value) -> Result<Value> {
    json::fields(bound, "filesystem_uuid mount repository_sha256")?;
    identity::uuid(text(bound, "filesystem_uuid")?)?;
    identity::sha(text(bound, "repository_sha256")?)?;
    require(
        bound["mount"].is_object(),
        "credential repository mount observation required",
    )?;
    // Historical mount observations are not cross-boot repository identities.
    Ok(
        value!({"filesystem_uuid":bound["filesystem_uuid"],"repository_sha256":bound["repository_sha256"]}),
    )
}
fn keys(values: &BTreeMap<String, bool>) -> Result<()> {
    require(
        (1..=32).contains(&values.len()) && values.values().filter(|v| **v).count() == 1,
        "one authenticated current repository key required",
    )?;
    for key in values.keys() {
        identity::sha(key)?;
    }
    Ok(())
}
/// Necessary consistency calculation only. The native review must still retain
/// actual journal, credentials, repository and supervised worker observations.
/// This function cannot complete a journal or construct any retained actor.
pub(crate) fn sole_added_key(
    enrollment: &Value,
    current: &BTreeMap<String, bool>,
    candidate: &BTreeMap<String, bool>,
) -> Result<String> {
    validate(enrollment, text(enrollment, "id")?)?;
    require(
        enrollment["schema"] == 2 && enrollment["phase"] == "prepared",
        "legacy or completed enrollment cannot complete/replay",
    )?;
    keys(current)?;
    keys(candidate)?;
    let before = enrollment["before_keys"]
        .as_array()
        .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
        .iter()
        .map(enzimos_platform::json::string)
        .collect::<Result<BTreeSet<_>>>()?;
    let actual = current.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let next = candidate
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let added = actual.difference(&before).copied().collect::<Vec<_>>();
    require(
        before.is_subset(&actual) && added.len() == 1 && actual == next,
        "credential key outcome ambiguous; no completion",
    )?;
    let new = added[0];
    require(
        candidate.get(new) == Some(&true),
        "candidate does not authenticate sole added key",
    )?;
    Ok(new.into())
}
