// SPDX-License-Identifier: MIT
//! Bounded diagnostic dependency joins. These values never construct execution actors.
use crate::{
    birth_runtime::{self, Records},
    catalog, identity,
};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
const MAX_REFERENCES: usize = 32768;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("root reference text required".into()))
}
fn relative(path: &str) -> Result<()> {
    require(
        !path.is_empty()
            && path.len() <= 4096
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path.split('/').all(|p| !matches!(p, "" | "." | "..")),
        "canonical root reference path required",
    )
}
pub(crate) fn validate_inventory(rows: &Records) -> Result<()> {
    require(rows.len() <= 4096, "root reference inventory bound")?;
    let mut ids = BTreeSet::new();
    let mut uuids = BTreeSet::new();
    for (path, row) in rows {
        enzimos_platform::json::fields(row, "path id uuid parent_uuid")?;
        relative(path)?;
        require(
            row.as_object().is_some_and(|r| r.len() == 4)
                && row["path"] == *path
                && row["id"].as_u64().is_some_and(|id| id >= 256),
            "closed root reference identity required",
        )?;
        let uuid = identity::uuid(text(row, "uuid")?)?;
        if !row["parent_uuid"].is_null() {
            identity::uuid(text(row, "parent_uuid")?)?;
        }
        require(
            ids.insert(row["id"].as_u64().unwrap()) && uuids.insert(uuid),
            "ambiguous root reference identity",
        )?;
    }
    Ok(())
}
fn charge(count: &mut usize, more: usize) -> Result<()> {
    *count = count
        .checked_add(more)
        .ok_or_else(|| Error("root reference count overflow".into()))?;
    require(*count <= MAX_REFERENCES, "root reference work bound")
}
fn edge(
    edges: &mut BTreeMap<String, BTreeSet<String>>,
    source: &str,
    target: &str,
    count: &mut usize,
) -> Result<()> {
    require(
        edges.contains_key(target),
        "root dependency endpoint missing",
    )?;
    if edges
        .get_mut(source)
        .ok_or_else(|| Error("root dependency source missing".into()))?
        .insert(target.into())
    {
        charge(count, 1)?;
    }
    Ok(())
}
pub(crate) fn join(
    catalog: &Value,
    records: &Records,
    inventory: &Records,
    readonly: &Records,
    namespaces: &Value,
) -> Result<Value> {
    let fs = text(catalog, "filesystem_uuid")?;
    catalog::validate(catalog, fs)?;
    validate_inventory(inventory)?;
    validate_inventory(readonly)?;
    require(
        readonly.iter().all(|(p, r)| inventory.get(p) == Some(r)),
        "read-only root reference inventory drift",
    )?;
    require(
        records.len() <= birth_runtime::MAX_RECORDS,
        "root birth reference bound",
    )?;
    for (id, row) in records {
        crate::birth::validate(row, id, fs)?;
    }
    let births = birth_runtime::evaluate(records, inventory, readonly)?;
    let mut blockers: BTreeSet<String> = [
        "independent-recovery-references-unavailable",
        "user-pin-inventory-unavailable",
        "complete-retirement-inventory-not-implemented",
        "retirement-executor-not-implemented",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if !births["pending"].as_array().unwrap().is_empty() {
        blockers.insert("pending-root-creation".into());
    }
    if !births["drift"].as_array().unwrap().is_empty() {
        blockers.insert("root-birth-identity-drift".into());
    }
    let mut resources: BTreeMap<String, Value> = BTreeMap::new();
    let mut by_path: BTreeMap<String, String> = BTreeMap::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut references = 0;
    for (path, row) in inventory {
        let uuid = text(row, "uuid")?.to_owned();
        let origin = &births["resources"][&uuid];
        let valid = origin["publisher_origin_observed"] == true && origin["identity"] == *row;
        by_path.insert(path.clone(), uuid.clone());
        edges.insert(uuid.clone(), BTreeSet::new());
        resources.insert(
            uuid,
            value!({"identity":row,"publisher_origin_observed":valid,
            "birth_transaction":if valid {origin["transaction"].clone()} else {Value::Null},
            "birth_kind":if valid {origin["kind"].clone()} else {Value::Null},
            "container":null,"children":[],"birth_dependencies":[],"generation_roots":[],
            "required_by_generations":[],"mount_references":[],"deletion_authorized":false}),
        );
    }
    for (path, uuid) in &by_path {
        let parts: Vec<_> = path.split('/').collect();
        for n in (1..parts.len()).rev() {
            if let Some(parent) = by_path.get(&parts[..n].join("/")) {
                resources.get_mut(uuid).unwrap()["container"] = value!(parent);
                resources.get_mut(parent).unwrap()["children"]
                    .as_array_mut()
                    .unwrap()
                    .push(value!(uuid));
                edge(&mut edges, parent, uuid, &mut references)?;
                edge(&mut edges, uuid, parent, &mut references)?;
                if resources[uuid]["publisher_origin_observed"] != true {
                    blockers.insert(format!("unowned-nested-subvolume:{path}"));
                }
                break;
            }
        }
    }
    for row in records.values().filter(|r| r["phase"] == "ready") {
        let objects = [&row["root"], &row["snapshot"]["object"], &row["history"]];
        if !objects.iter().all(|r| {
            r["path"]
                .as_str()
                .is_some_and(|p| inventory.get(p) == Some(*r))
        }) {
            continue;
        }
        let root = text(&row["root"], "uuid")?;
        let dependencies = BTreeSet::from([
            text(&row["snapshot"]["object"], "uuid")?.to_owned(),
            text(&row["history"], "uuid")?.to_owned(),
        ]);
        resources.get_mut(root).unwrap()["birth_dependencies"] = value!(dependencies);
        for target in dependencies {
            edge(&mut edges, root, &target, &mut references)?;
        }
    }
    let mut generations = BTreeMap::new();
    for (name, row) in catalog["generations"].as_object().unwrap() {
        let bound = &row["material"]["root_identity"];
        let observed = inventory.get(text(bound, "path")?);
        let valid = observed.is_some_and(|actual| {
            ["path", "id", "uuid"]
                .iter()
                .all(|k| actual[*k] == bound[*k])
        });
        let key = if valid {
            Some(text(observed.unwrap(), "uuid")?.to_owned())
        } else {
            None
        };
        if !valid {
            blockers.insert(format!("generation-root-identity-drift:{name}"));
        }
        if row["state"] != "ready" {
            blockers.insert(format!("pending-generation-publication:{name}"));
        }
        let mut linked = BTreeSet::new();
        if let Some(key) = &key {
            if resources[key]["publisher_origin_observed"] != true {
                blockers.insert(format!("generation-root-origin-not-established:{name}"));
            }
            resources.get_mut(key).unwrap()["generation_roots"]
                .as_array_mut()
                .unwrap()
                .push(value!(name));
            linked.insert(key.clone());
            let mut pending = vec![key.clone()];
            while let Some(source) = pending.pop() {
                for target in &edges[&source] {
                    if linked.insert(target.clone()) {
                        pending.push(target.clone());
                    }
                }
            }
            charge(&mut references, linked.len())?;
            for target in &linked {
                resources.get_mut(target).unwrap()["required_by_generations"]
                    .as_array_mut()
                    .unwrap()
                    .push(value!(name));
            }
        }
        generations.insert(name.clone(),value!({"root_uuid":key,"identity_matches":valid,"state":row["state"],"resources":linked,"deletion_authorized":false}));
    }
    require(
        namespaces.as_object().is_some_and(|r| {
            r.len() == 2 && r.contains_key("namespaces") && r.contains_key("departed_processes")
        }),
        "closed namespace reference observation required",
    )?;
    let views = namespaces["namespaces"]
        .as_array()
        .ok_or_else(|| Error("namespace reference array required".into()))?;
    require(
        views.len() <= 4096 && namespaces["departed_processes"].is_array(),
        "namespace reference bound",
    )?;
    if !namespaces["departed_processes"]
        .as_array()
        .unwrap()
        .is_empty()
    {
        blockers.insert("process-set-changed-during-observation".into());
    }
    let mut seen = BTreeSet::new();
    let mut comparisons = 0usize;
    for view in views {
        let label = text(view, "namespace")?;
        require(seen.insert(label), "duplicate namespace reference")?;
        let mounts = view["mounts"]
            .as_array()
            .ok_or_else(|| Error("namespace mounts required".into()))?;
        require(mounts.len() <= MAX_REFERENCES, "namespace mount bound")?;
        for mount in mounts.iter().filter(|r| r["fstype"] == "btrfs") {
            let path = text(mount, "root")?
                .strip_prefix('/')
                .ok_or_else(|| Error("absolute Btrfs mount root required".into()))?;
            if !path.is_empty() {
                relative(path)?;
            }
            for (target, uuid) in &by_path {
                comparisons += 1;
                require(
                    comparisons <= 1024 * 1024,
                    "namespace/root comparison bound",
                )?;
                if path.is_empty()
                    || path == target
                    || path.starts_with(&format!("{target}/"))
                    || target.starts_with(&format!("{path}/"))
                {
                    charge(&mut references, 1)?;
                    let device = if let Some(device) = mount.get("device") {
                        require(device.is_string(), "actual mount device text required")?;
                        device.clone()
                    } else {
                        let major = mount["major"]
                            .as_u64()
                            .ok_or_else(|| Error("actual mount major required".into()))?;
                        let minor = mount["minor"]
                            .as_u64()
                            .ok_or_else(|| Error("actual mount minor required".into()))?;
                        value!(format!("{major}:{minor}"))
                    };
                    resources.get_mut(uuid).unwrap()["mount_references"].as_array_mut().unwrap().push(value!({"namespace":label,"root":mount["root"],"target":mount["target"],"device":device}));
                }
            }
        }
    }
    let unclaimed: Vec<_> = resources
        .iter()
        .filter(|(_, r)| r["required_by_generations"].as_array().unwrap().is_empty())
        .map(|(id, _)| id)
        .collect();
    Ok(
        value!({"schema":1,"status":"OBSERVED-root-references-retirement-blocked","filesystem_uuid":fs,"complete":false,"execution_available":false,"resources":resources,"generations":generations,"births":births,"unclaimed_resources":unclaimed,"blockers":blockers,"mount_scope":"conservative path overlap across observed Btrfs namespaces; not filesystem-UUID exclusion","scope":"root/birth/containment references only; no loader, recovery, pin or deletion authority"}),
    )
}
