// SPDX-License-Identifier: MIT
//! Bounded pure retirement preview. Caller inventory never grants deletion authority.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
type Names = BTreeSet<String>;
const MAX: usize = 256;
pub const LIMIT: usize = 2 * 1024 * 1024;
fn text(v: &Value) -> Result<&str> {
    v.as_str()
        .ok_or_else(|| Error("lifecycle text required".into()))
}
fn identifier(v: &Value) -> Result<String> {
    let s = text(v)?;
    require(
        !s.is_empty()
            && s.len() <= 80
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid lifecycle identifier",
    )?;
    Ok(s.into())
}
fn names(v: &Value) -> Result<Names> {
    let a = v
        .as_array()
        .ok_or_else(|| Error("bounded lifecycle list required".into()))?;
    require(a.len() <= MAX, "lifecycle list bound")?;
    let n = a.iter().map(identifier).collect::<Result<Names>>()?;
    require(n.len() == a.len(), "duplicate lifecycle reference")?;
    Ok(n)
}
fn index<'a>(v: &'a Value, fields: &str) -> Result<BTreeMap<String, &'a Value>> {
    let a = v
        .as_array()
        .ok_or_else(|| Error("lifecycle rows required".into()))?;
    require(!a.is_empty() && a.len() <= MAX, "lifecycle inventory bound")?;
    let mut rows = BTreeMap::new();
    for row in a {
        json::fields(row, fields)?;
        require(
            rows.insert(identifier(&row["id"])?, row).is_none(),
            "duplicate lifecycle object",
        )?;
    }
    Ok(rows)
}
fn boolean(v: &Value) -> Result<()> {
    require(v.is_boolean(), "lifecycle boolean required")
}
fn visit(
    key: &str,
    deps: &BTreeMap<String, Names>,
    visiting: &mut Names,
    visited: &mut Names,
    post: &mut Vec<String>,
) -> Result<()> {
    require(!visiting.contains(key), "resource dependency cycle")?;
    if visited.contains(key) {
        return Ok(());
    }
    visiting.insert(key.into());
    for dep in &deps[key] {
        visit(dep, deps, visiting, visited, post)?;
    }
    visiting.remove(key);
    visited.insert(key.into());
    post.push(key.into());
    Ok(())
}
fn closure(mut found: Names, deps: &BTreeMap<String, Names>) -> Names {
    let mut todo: Vec<_> = found.iter().cloned().collect();
    while let Some(key) = todo.pop() {
        for dep in &deps[&key] {
            if found.insert(dep.clone()) {
                todo.push(dep.clone());
            }
        }
    }
    found
}
pub fn plan(inventory: &Value, keep_good: usize) -> Result<Value> {
    require(
        (2..=8).contains(&keep_good),
        "retain at least two known-good generations",
    )?;
    json::fields(
        inventory,
        "schema complete boot_id generations resources references",
    )?;
    require(
        inventory["schema"].as_u64() == Some(1) && inventory["complete"] == true,
        "complete lifecycle schema1 required",
    )?;
    let boot = identifier(&inventory["boot_id"])?;
    let generations = index(
        &inventory["generations"],
        "id ordinal role state confirmed owned created_boot resources",
    )?;
    let resources = index(
        &inventory["resources"],
        "id kind owned created_boot dependencies",
    )?;
    let refs = &inventory["references"];
    json::fields(
        refs,
        "running uefi_default uefi_oneshot bios_default recovery pins external_resources mounted_resources",
    )?;
    let mut reference_sets =
        BTreeMap::from([("running", Names::from([identifier(&refs["running"])?]))]);
    for key in [
        "uefi_default",
        "uefi_oneshot",
        "bios_default",
        "recovery",
        "pins",
    ] {
        reference_sets.insert(key, names(&refs[key])?);
    }
    for key in ["uefi_default", "bios_default", "recovery"] {
        require(
            !reference_sets[key].is_empty(),
            "boot selections and independent recovery required",
        )?;
    }
    for set in reference_sets.values() {
        require(
            set.iter().all(|n| generations.contains_key(n)),
            "unknown generation reference",
        )?;
    }
    let external = names(&refs["external_resources"])?;
    let mounted = names(&refs["mounted_resources"])?;
    let protected_refs: Names = external.union(&mounted).cloned().collect();
    require(
        protected_refs.iter().all(|n| resources.contains_key(n)),
        "unknown external resource",
    )?;
    let mut deps = BTreeMap::new();
    for (key, row) in &resources {
        boolean(&row["owned"])?;
        identifier(&row["created_boot"])?;
        require(
            matches!(
                text(&row["kind"])?,
                "boot-artifacts" | "root-subvolume" | "source-snapshot"
            ),
            "unsupported lifecycle resource",
        )?;
        let set = names(&row["dependencies"])?;
        require(
            set.iter().all(|n| resources.contains_key(n)),
            "unknown resource dependency",
        )?;
        deps.insert(key.clone(), set);
    }
    let mut ordinals = BTreeSet::new();
    let mut links = BTreeMap::new();
    let mut roots = BTreeMap::new();
    for (key, row) in &generations {
        let ordinal = row["ordinal"]
            .as_u64()
            .filter(|n| *n < 1 << 63)
            .ok_or_else(|| Error("invalid generation ordinal".into()))?;
        require(ordinals.insert(ordinal), "ambiguous generation ordering")?;
        require(
            matches!(
                text(&row["state"])?,
                "ready" | "pending" | "failed" | "retiring"
            ),
            "unknown generation state",
        )?;
        require(
            matches!(text(&row["role"])?, "system" | "recovery"),
            "unknown generation role",
        )?;
        boolean(&row["owned"])?;
        boolean(&row["confirmed"])?;
        identifier(&row["created_boot"])?;
        let set = names(&row["resources"])?;
        require(
            !set.is_empty() && set.iter().all(|n| resources.contains_key(n)),
            "missing generation resources",
        )?;
        require(
            set.iter().any(|n| resources[n]["kind"] == "boot-artifacts"),
            "generation boot artifacts required",
        )?;
        if row["role"] == "system" {
            let r: Vec<_> = set
                .iter()
                .filter(|n| resources[*n]["kind"] == "root-subvolume")
                .cloned()
                .collect();
            require(r.len() == 1, "system requires one root resource")?;
            roots.insert(key.clone(), r[0].clone());
        }
        links.insert(key.clone(), set);
    }
    require(
        reference_sets["recovery"]
            .iter()
            .all(|n| generations[n]["role"] == "recovery"),
        "independent recovery role required",
    )?;
    require(
        reference_sets["recovery"]
            .iter()
            .any(|n| generations[n]["state"] == "ready" && generations[n]["confirmed"] == true),
        "confirmed usable recovery required",
    )?;
    let mut post = Vec::new();
    let mut visiting = Names::new();
    let mut visited = Names::new();
    for key in resources.keys() {
        visit(key, &deps, &mut visiting, &mut visited, &mut post)?;
    }
    let mut reasons: BTreeMap<String, Names> = generations
        .keys()
        .map(|n| (n.clone(), Names::new()))
        .collect();
    for (reason, set) in &reference_sets {
        for n in set {
            reasons.get_mut(n).unwrap().insert((*reason).into());
        }
    }
    let mut good: Vec<_> = generations
        .iter()
        .filter(|(_, g)| {
            g["role"] == "system"
                && g["owned"] == true
                && g["state"] == "ready"
                && g["confirmed"] == true
        })
        .collect();
    good.sort_by_key(|(_, g)| std::cmp::Reverse(g["ordinal"].as_u64().unwrap()));
    let mut distinct = Names::new();
    let mut retained = Vec::new();
    for (n, _) in good {
        if distinct.insert(roots[n].clone()) {
            retained.push(n);
        }
        if retained.len() == keep_good {
            break;
        }
    }
    require(
        retained.len() >= keep_good,
        "insufficient independently confirmed root generations",
    )?;
    for n in retained {
        reasons
            .get_mut(n)
            .unwrap()
            .insert("recent-known-good-distinct-root".into());
    }
    for (n, row) in &generations {
        let r = reasons.get_mut(n).unwrap();
        if row["owned"] != true {
            r.insert("unowned-generation".into());
        }
        if row["state"] != "ready" {
            r.insert("unfinished-or-failed".into());
        }
        if row["confirmed"] != true {
            r.insert("unconfirmed".into());
        }
        if row["created_boot"] == boot {
            r.insert("created-this-boot".into());
        }
        if links[n]
            .iter()
            .any(|x| protected_refs.contains(x) && resources[x]["kind"] == "boot-artifacts")
        {
            r.insert("externally-referenced-boot-artifacts".into());
        }
    }
    let retire: Names = reasons
        .iter()
        .filter(|(_, r)| r.is_empty())
        .map(|(n, _)| n.clone())
        .collect();
    let claimed = closure(links.values().flatten().cloned().collect(), &deps);
    let mut protected = protected_refs;
    for (n, r) in &resources {
        if r["owned"] != true || r["created_boot"] == boot || !claimed.contains(n) {
            protected.insert(n.clone());
        }
    }
    for (n, set) in &links {
        if !retire.contains(n) {
            protected.extend(set.iter().cloned());
        }
    }
    let protected = closure(protected, &deps);
    let candidates = closure(
        retire
            .iter()
            .flat_map(|n| links[n].iter().cloned())
            .collect(),
        &deps,
    );
    let deletable: Names = candidates.difference(&protected).cloned().collect();
    let ordered: Vec<_> = post
        .into_iter()
        .rev()
        .filter(|n| deletable.contains(n))
        .collect();
    let preserve: Names = resources
        .keys()
        .filter(|n| !deletable.contains(*n))
        .cloned()
        .collect();
    let reasons: BTreeMap<_, _> = reasons.into_iter().filter(|(_, r)| !r.is_empty()).collect();
    Ok(
        value!({"schema":1,"status":"retirement-preview-only","execution_available":false,
        "inventory_sha256":json::fingerprint(inventory)?,"keep_good":keep_good,"retire_generations":retire,
        "delete_resources":ordered,"preserve_resources":preserve,"generation_protection":reasons,
        "required_apply_conditions":["fresh identical complete observation","root authorization and exclusive operation lock",
            "durable independent journal","detach both loader references before deleting artifacts",
            "revalidate references and identities before every destructive step"]}),
    )
}
