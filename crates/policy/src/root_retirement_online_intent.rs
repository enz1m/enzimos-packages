// SPDX-License-Identifier: MIT
//! Target ownership is joined to original online registries and Kernel inventory.
//! A preview is not filesystem protection completeness or deletion authority.
use crate::{
    birth_runtime::Records,
    root_retirement_objects::Targets,
    root_retirement_online_inventory::Inventory,
    root_retirement_references::Observation,
    storage_runtime::{Guard, TopMount},
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};

fn role(identity: &Value, role: &str) -> Result<Value> {
    json::fields(identity, "path id uuid parent_uuid")?;
    let mut target = enzimos_platform::json::object(identity)?.clone();
    target.insert("role".into(), value!(role));
    Ok(Value::Object(target))
}
fn planned(
    original: &Value,
    inventory: &Records,
    root_uuid: &str,
    filesystem: &Value,
    boot: &str,
) -> Result<Value> {
    crate::identity::uuid(root_uuid)?;
    crate::identity::uuid(boot)?;
    let candidates = inventory
        .values()
        .filter(|row| row["uuid"] == root_uuid)
        .collect::<Vec<_>>();
    require(
        candidates.len() == 1,
        "one complete kernel Root identity required",
    )?;
    let root = candidates[0];
    let path = crate::recovery_records::text(root, "path")?;
    crate::identity::safe_id(path)?;
    let records = &original["records"];
    let births = records["births"]
        .as_object()
        .ok_or_else(|| Error("original birth registry missing".into()))?;
    let activations = records["activations"]
        .as_object()
        .ok_or_else(|| Error("original activation registry missing".into()))?;
    let owners = activations
        .iter()
        .filter(|(_, row)| {
            row["phase"] == "adopted" && row["superseded"]["identity"]["uuid"] == root_uuid
        })
        .collect::<Vec<_>>();
    require(
        owners.len() <= 1,
        "ambiguous adopted superseded Root ownership",
    )?;
    let mut descendants = inventory
        .values()
        .filter(|row| {
            row["path"]
                .as_str()
                .is_some_and(|p| p.starts_with(&format!("{path}/")))
        })
        .collect::<Vec<_>>();
    descendants.sort_by(|a, b| {
        // Descendants were selected above by their string path.
        let a = a["path"].as_str().unwrap_or_default();
        let b = b["path"].as_str().unwrap_or_default();
        b.matches('/')
            .count()
            .cmp(&a.matches('/').count())
            .then_with(|| a.cmp(b))
    });
    require(descendants.len() < 64, "bounded complete Root descendants")?;
    let (birth, mut targets) = if let Some((id, activation)) = owners.first() {
        let job = &records["jobs"][*id];
        require(
            activation["superseded"]["identity"] == *root
                && activation["superseded"]["legacy_detached"] == true
                && activation["superseded"]["retired"] == false
                && *job == activation["intent"]["job"]
                && job["phase"] == "staged",
            "actual adopted activation/staged job must own the detached unretired Root",
        )?;
        require(
            descendants.iter().all(|target| {
                births
                    .values()
                    .all(|row| row["root"]["uuid"] != target["uuid"])
            }),
            "superseded descendant has independent publisher ownership",
        )?;
        (
            format!("superseded-{id}"),
            descendants
                .iter()
                .map(|target| role(target, "nested-subvolume"))
                .collect::<Result<Vec<_>>>()?,
        )
    } else {
        let publishers = births
            .iter()
            .filter(|(_, row)| row["root"]["uuid"] == root_uuid)
            .collect::<Vec<_>>();
        require(
            publishers.len() == 1,
            "one original publisher birth must own Root",
        )?;
        let (id, row) = publishers[0];
        let history_path = crate::recovery_records::text(&row["history"], "path")?;
        require(
            row["phase"] == "ready"
                && row["root"] == *root
                && row["filesystem_uuid"] == *filesystem
                && inventory.get(history_path) == Some(&row["history"])
                && history_path == format!("{path}/.snapshots")
                && descendants.len() == 1
                && *descendants[0] == row["history"],
            "exact ready publisher Root/history must have no additional descendants",
        )?;
        (id.clone(), vec![role(&row["history"], "history-store")?])
    };
    targets.push(role(root, "root-subvolume")?);
    let targets = value!(targets);
    let sha =
        json::fingerprint(&value!({"filesystem_uuid":filesystem,"birth":birth,"targets":targets}))?;
    let id = format!("root-{}", root_uuid.replace('-', ""));
    require(
        records["root_retirement"].get(&id).is_none()
            && records["root_retirement"]
                .as_object()
                .is_some_and(|rows| rows.len() < 16),
        "existing Root retirement cannot be adopted or planned again",
    )?;
    let result = value!({"schema":1,"id":id,"phase":"prepared","filesystem_uuid":filesystem,
        "created_boot":boot,"birth":birth,"targets":targets,"next_step":0,"inflight":null,"plan_sha256":sha});
    crate::root_retirement_record::validate(&result, &id)?;
    Ok(result)
}

/// Comparison only. The staging caller supplies its separately retained actual
/// original receipt; this projection never constructs an execution actor.
pub(crate) fn planned_for_receipt(
    original: &Value,
    inventory: &Records,
    receipt: &Value,
) -> Result<Value> {
    let id = crate::recovery_records::text(receipt, "id")?;
    crate::root_retirement_record::validate(receipt, id)?;
    require(
        receipt["schema"] == 1
            && receipt["phase"] == "prepared"
            && receipt.get("coordinator").is_none()
            && original["records"]["root_retirement"][id] == *receipt,
        "staging requires exact original unstaged prepared receipt",
    )?;
    let mut comparison = original.clone();
    comparison["records"]["root_retirement"]
        .as_object_mut()
        .ok_or_else(|| Error("original Root receipt registry missing".into()))?
        .remove(id);
    let root = enzimos_platform::json::array(&receipt["targets"])?
        .last()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
    let expected = planned(
        &comparison,
        inventory,
        crate::recovery_records::text(root, "uuid")?,
        &receipt["filesystem_uuid"],
        crate::recovery_records::text(receipt, "created_boot")?,
    )?;
    require(
        expected == *receipt,
        "prepared Root receipt no longer matches actual original ownership",
    )?;
    Ok(expected)
}

fn mounts_unmentioned(mounts: &[enzimos_platform::mountinfo::Row], targets: &Value) -> Result<()> {
    let rows = targets
        .as_array()
        .filter(|rows| (1..=64).contains(&rows.len()))
        .ok_or_else(|| Error("original mount target bound".into()))?;
    for target in rows {
        let path = crate::recovery_records::text(target, "path")?;
        let root = format!("/{path}");
        for mount in mounts {
            require(
                !(mount.filesystem == "btrfs"
                    && (mount.root == root || mount.root.starts_with(&format!("{root}/")))),
                "Root retirement target is mounted in an observed namespace",
            )?;
        }
    }
    Ok(())
}
pub(crate) fn mount_protection(
    observed: &crate::namespaces::Observation,
    targets: &Value,
) -> Result<()> {
    for view in &observed.views {
        mounts_unmentioned(&view.mounts, targets)?;
    }
    Ok(())
}
fn namespace_measurement(
    observed: &crate::namespaces::Observation,
) -> std::collections::BTreeMap<(u64, u64), &str> {
    observed
        .views
        .iter()
        .map(|view| (view.identity, view.sha.as_str()))
        .collect()
}
/// Refuse unless every observed mount namespace and its complete mount table
/// equal the protected sample. The refusal names what differed (bounded), so a
/// refused positive control shows whether a namespace appeared or left, or
/// which mounts changed, instead of only that something did.
pub(crate) fn unchanged_namespaces(
    current: &crate::namespaces::Observation,
    protected: &crate::namespaces::Observation,
    reason: &str,
) -> Result<()> {
    if namespace_measurement(current) == namespace_measurement(protected) {
        return Ok(());
    }
    Err(Error(format!(
        "{reason} ({})",
        namespace_drift(protected, current)
    )))
}
fn namespace_drift(
    before: &crate::namespaces::Observation,
    after: &crate::namespaces::Observation,
) -> String {
    use crate::namespaces::{Observation, View};
    use std::collections::{BTreeMap, BTreeSet};
    const NAMESPACES: usize = 6;
    const MOUNTS: usize = 4;
    fn index(observed: &Observation) -> BTreeMap<(u64, u64), &View> {
        observed
            .views
            .iter()
            .map(|view| (view.identity, view))
            .collect()
    }
    fn rows(view: &View) -> BTreeSet<(&str, &str, &str, &str)> {
        view.mounts
            .iter()
            .map(|r| {
                (
                    r.target.as_str(),
                    r.filesystem.as_str(),
                    r.root.as_str(),
                    r.options.as_str(),
                )
            })
            .collect()
    }
    fn printable(text: &str, bound: usize) -> String {
        text.chars()
            .take(bound)
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    }
    // Diagnostic only: the PID may have been reused since the sample.
    fn command(pid: u32) -> String {
        std::fs::read(format!("/proc/{pid}/comm"))
            .map(|b| printable(String::from_utf8_lossy(&b).trim(), 16))
            .unwrap_or_default()
    }
    let (before, after) = (index(before), index(after));
    let mut changes = Vec::new();
    for (identity, view) in &after {
        match before.get(identity) {
            None => changes.push(format!(
                "new mnt:[{}] pid {} {}",
                identity.1,
                view.representative,
                command(view.representative)
            )),
            Some(old) if old.sha != view.sha => {
                let (was, now) = (rows(old), rows(view));
                let mut detail = now
                    .difference(&was)
                    .map(|r| format!("+{} {}", printable(r.0, 128), printable(r.1, 32)))
                    .chain(
                        was.difference(&now)
                            .map(|r| format!("-{} {}", printable(r.0, 128), printable(r.1, 32))),
                    )
                    .collect::<Vec<_>>();
                let more = detail.len().saturating_sub(MOUNTS);
                detail.truncate(MOUNTS);
                if more > 0 {
                    detail.push(format!("{more} more"));
                }
                if detail.is_empty() {
                    detail.push("mount IDs, order or propagation".into());
                }
                changes.push(format!("mnt:[{}] {}", identity.1, detail.join(" ")));
            }
            Some(_) => {}
        }
    }
    for (identity, view) in &before {
        if !after.contains_key(identity) {
            changes.push(format!(
                "gone mnt:[{}] pid {}",
                identity.1, view.representative
            ));
        }
    }
    let more = changes.len().saturating_sub(NAMESPACES);
    changes.truncate(NAMESPACES);
    if more > 0 {
        changes.push(format!("{more} more namespaces"));
    }
    changes.join("; ")
}

pub struct Intent<'a> {
    references: Observation<'a>,
    inventory: &'a Inventory<'a>,
    targets: Targets<'a>,
    record: Value,
    protection: Option<Protection<'a>>,
}
struct Protection<'a> {
    boot: crate::root_retirement_online_boot::Boot<'a>,
    namespaces: crate::namespaces::Observation,
}
impl<'a> Intent<'a> {
    pub fn observe(
        guard: &'a Guard,
        top: &'a TopMount,
        lock: &'a files::Lock,
        references: Observation<'a>,
        inventory: &'a Inventory<'a>,
        root_uuid: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        references.require_original_source(guard, lock, authorize)?;
        inventory.require_original_source(guard, top, lock, authorize)?;
        let record = planned(
            references.original(authorize)?,
            inventory.records(authorize)?,
            root_uuid,
            &guard.configuration["filesystem_uuid"],
            &crate::operation::boot_id()?,
        )?;
        let targets = Targets::observe(guard, top, lock, &record["targets"], authorize)?;
        let this = Self {
            references,
            inventory,
            targets,
            record,
            protection: None,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    /// Join original loader actors and a complete namespace mount sample.
    /// This still supplies no offline deletion or cold receipt authority.
    pub fn protect(
        mut self,
        boot: crate::root_retirement_online_boot::Boot<'a>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        self.recheck(authorize)?;
        boot.protect(&self.targets, authorize)?;
        let namespaces = crate::namespaces::observe()?;
        mount_protection(&namespaces, &self.targets.rows(authorize)?)?;
        self.protection = Some(Protection { boot, namespaces });
        self.recheck(authorize)?;
        Ok(self)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.references.recheck(authorize)?;
        self.inventory.recheck(authorize)?;
        self.targets.recheck(authorize)?;
        let root = enzimos_platform::json::array(&self.record["targets"])?
            .last()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["uuid"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?;
        require(
            planned(
                self.references.original(authorize)?,
                self.inventory.records(authorize)?,
                root,
                &self.record["filesystem_uuid"],
                &crate::operation::boot_id()?,
            )? == self.record,
            "original Root target ownership/intent changed",
        )?;
        self.references
            .require_target_references(&self.targets, &self.record, authorize)?;
        if let Some(protection) = &self.protection {
            protection.boot.protect(&self.targets, authorize)?;
            let current = crate::namespaces::observe()?;
            mount_protection(&current, &self.targets.rows(authorize)?)?;
            unchanged_namespaces(
                &current,
                &protection.namespaces,
                "original Root namespace mount observations changed",
            )?;
        }
        self.targets.recheck(authorize)
    }
    /// Stable plan measurement excludes transient inspection mount IDs and
    /// namespace representatives. Actual retained actors still recheck in full.
    pub fn measurement(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let protection = self
            .protection
            .as_ref()
            .ok_or_else(|| Error("complete original Root protection required".into()))?;
        let original = self.references.original(authorize)?;
        let root = enzimos_platform::json::array(&self.record["targets"])?
            .last()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["uuid"]
            .clone();
        let result = value!({"filesystem_uuid":self.record["filesystem_uuid"],"plan_sha256":self.record["plan_sha256"],
            "root_uuid":root,"birth":self.record["birth"],"targets":self.record["targets"],
            "source_sha256":json::fingerprint(&original["source"])?,
            "reference_sha256":json::fingerprint(original)?,
            "loader_sha256":json::fingerprint(&protection.boot.evidence(authorize)?)?,
            "target_epoch_sha256":json::fingerprint(&self.targets.planning_evidence(authorize)?)?});
        self.recheck(authorize)?;
        Ok(result)
    }
    /// Consume one fully protected intent into one fresh prepared receipt. No
    /// existing row, uncertain attempt or offline deletion actor is adopted.
    pub fn prepare(
        mut self,
        expected: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
        progress: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<Value> {
        require(
            self.measurement(authorize)? == *expected,
            "job-plan-changed",
        )?;
        self.recheck(authorize)?;
        let mut protection = self
            .protection
            .take()
            .ok_or_else(|| Error("original Root protection missing".into()))?;
        let targets = &self.targets;
        let inventory = self.inventory;
        let record = &self.record;
        let mut original_barrier = || {
            authorize()?;
            targets.recheck(authorize)?;
            inventory.recheck(authorize)?;
            protection.boot.root_receipt_barrier(targets, authorize)?;
            let current = crate::namespaces::observe()?;
            mount_protection(&current, &targets.rows(authorize)?)?;
            unchanged_namespaces(
                &current,
                &protection.namespaces,
                "original Root mount snapshot changed during receipt creation",
            )?;
            authorize()
        };
        let mut registry =
            self.references
                .begin_root_receipt(targets, record, &mut original_barrier)?;
        original_barrier()?;
        protection
            .boot
            .bind_root_receipt(&registry, record, targets, authorize)?;
        progress("finishing")?;
        let mut barrier = || {
            self.references.root_receipt_barrier(authorize)?;
            protection.boot.root_receipt_barrier(targets, authorize)?;
            targets.recheck(authorize)?;
            inventory.recheck(authorize)?;
            let current = crate::namespaces::observe()?;
            mount_protection(&current, &targets.rows(authorize)?)?;
            unchanged_namespaces(
                &current,
                &protection.namespaces,
                "original Root mount snapshot changed during receipt publication",
            )?;
            authorize()
        };
        registry.publish(&json::canonical(record)?, &mut barrier)?;
        barrier()?;
        self.references
            .verify_new_root_receipt(&registry, record, authorize)?;
        protection
            .boot
            .verify_new_root_receipt(&registry, record, targets, authorize)?;
        targets.recheck(authorize)?;
        inventory.recheck(authorize)?;
        Ok(value!({"id":record["id"],"status":"root-retirement-prepared","deleted":false}))
    }
    /// Comparison data; publishing requires an independent complete protection gate.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = value!({"record":self.record,"targets":self.targets.evidence(authorize)?,
            "filesystem_protection_complete":self.protection.is_some(),"execution_authorized":false});
        self.recheck(authorize)?;
        Ok(result)
    }
}

/// Standalone Root preparation uses the complete original backend inventory;
/// it supplies no job exemption and creates no offline deletion authority.
pub fn prepare_locked(
    guard: &Guard,
    lock: &files::Lock,
    root_uuid: &str,
    plan_sha256: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::uuid(root_uuid)?;
    crate::identity::sha(plan_sha256)?;
    authorize()?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let references = Observation::observe(guard, lock, authorize)?;
        let boot =
            crate::root_retirement_online_boot::Boot::observe(guard, lock, &references, authorize)?;
        let inventory = crate::root_retirement_online_inventory::Inventory::observe(
            guard, &top, lock, authorize,
        )?;
        let intent = Intent::observe(
            guard, &top, lock, references, &inventory, root_uuid, authorize,
        )?
        .protect(boot, authorize)?;
        let expected = intent.measurement(authorize)?;
        require(
            expected["root_uuid"] == root_uuid && expected["plan_sha256"] == plan_sha256,
            "reviewed original Root retirement plan changed",
        )?;
        intent.prepare(&expected, authorize, progress)
    })();
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root preparation cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}

/// Standalone preview uses the same complete retained context as preparation.
/// A diagnostic refusal never constructs a receipt or deletion authority.
pub fn plan_locked(
    guard: &Guard,
    lock: &files::Lock,
    root_uuid: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::uuid(root_uuid)?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    let mut top = TopMount::open_retained(guard)?;
    let outcome = (|| {
        let references = Observation::observe(guard, lock, authorize)?;
        let inventory = Inventory::observe(guard, &top, lock, authorize)?;
        require(
            inventory
                .records(authorize)?
                .values()
                .filter(|row| row["uuid"] == root_uuid)
                .count()
                == 1,
            "Root is not uniquely present in the observed subvolume inventory",
        )?;
        let candidate = planned(
            references.original(authorize)?,
            inventory.records(authorize)?,
            root_uuid,
            &guard.configuration["filesystem_uuid"],
            &crate::operation::boot_id()?,
        );
        let mut result = value!({"status":"root-retirement-plan","root_uuid":root_uuid,"retirable":false,"protection":[],"targets":[],"offline_coordinator_required":false});
        match candidate {
            Err(error) => {
                result["protection"] = value!([error.0]);
                // Retain the original family and complete inventory through the
                // diagnostic. A changing source/authorization still refuses.
                references.recheck(authorize)?;
            }
            Ok(candidate) => {
                result["targets"] = candidate["targets"].clone();
                let boot = crate::root_retirement_online_boot::Boot::observe(
                    guard,
                    lock,
                    &references,
                    authorize,
                )?;
                let checked = Intent::observe(
                    guard, &top, lock, references, &inventory, root_uuid, authorize,
                )
                .and_then(|intent| intent.protect(boot, authorize))
                .and_then(|intent| intent.measurement(authorize));
                match checked {
                    Ok(measurement) => {
                        result["retirable"] = value!(true);
                        result["plan_sha256"] = measurement["plan_sha256"].clone();
                    }
                    Err(error) => result["protection"] = value!([error.0]),
                }
            }
        }
        inventory.require_original_source(guard, &top, lock, authorize)?;
        guard.recheck()?;
        lock.recheck()?;
        authorize()?;
        Ok(result)
    })();
    let cleanup = top.close();
    match (outcome, cleanup) {
        (Ok(result), Ok(())) => {
            guard.recheck()?;
            lock.recheck()?;
            authorize()?;
            Ok(result)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error(format!(
            "{}; original Root preview cleanup refused: {}",
            error.0, cleanup.0
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROOT: &str = "22222222-2222-4222-8222-222222222222";
    const FS: &str = "11111111-1111-4111-8111-111111111111";
    const BOOT: &str = "33333333-3333-4333-8333-333333333333";
    fn object(path: &str, id: u64) -> Value {
        value!({"path":path,"id":id,"uuid":if id == 400 {ROOT.to_owned()} else {format!("{id:08x}-4444-4444-8444-444444444444")},"parent_uuid":null})
    }
    fn fixture() -> (Value, Records) {
        let root = object("old-root", 400);
        let history = object("old-root/.snapshots", 401);
        let original = value!({"records":{"births":{"birth9":{"phase":"ready","filesystem_uuid":FS,
            "root":root,"history":history}},"activations":{},"jobs":{},"root_retirement":{}}});
        (
            original,
            Records::from([
                ("old-root".into(), root),
                ("old-root/.snapshots".into(), history),
            ]),
        )
    }

    fn adopted() -> (Value, Records) {
        let (mut original, mut inventory) = fixture();
        original["records"]["births"] = value!({});
        let job = value!({"phase":"staged","root":object("restored",900)});
        original["records"]["jobs"]["job9"] = job.clone();
        original["records"]["activations"]["job9"] = value!({"phase":"adopted","intent":{"job":job},
            "superseded":{"identity":inventory["old-root"],"legacy_detached":true,"retired":false}});
        for (path, id) in [
            ("old-root/a", 402),
            ("old-root/a/deep", 403),
            ("old-root/b", 404),
        ] {
            inventory.insert(path.into(), object(path, id));
        }
        (original, inventory)
    }
    #[test]
    fn adopted_plan_refuses_missing_ambiguous_root_and_overfull_nested_inventory() {
        let (original, mut inventory) = adopted();
        let mut duplicate = inventory.clone();
        let mut same = duplicate["old-root"].clone();
        same["path"] = value!("alias");
        duplicate.insert("alias".into(), same);
        assert!(planned(&original, &duplicate, ROOT, &value!(FS), BOOT).is_err());
        let mut missing = inventory.clone();
        missing.remove("old-root");
        assert!(planned(&original, &missing, ROOT, &value!(FS), BOOT).is_err());
        for n in 0..64 {
            let path = format!("old-root/n{n}");
            inventory.insert(path.clone(), object(&path, 1000 + n));
        }
        assert!(planned(&original, &inventory, ROOT, &value!(FS), BOOT).is_err());
    }
}
