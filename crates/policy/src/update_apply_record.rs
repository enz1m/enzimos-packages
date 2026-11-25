// SPDX-License-Identifier: MIT
//! Ordered apply evidence never authorizes automatic replay or cleanup.
use crate::{identity, storage};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
pub(crate) const MAXIMUM: usize = 128;
/// Terminal phase for an apply that failed before changing the system
/// (during resolution or staging). It ends the record so the global lock,
/// backups and recovery are not blocked by an apply that never mutated.
pub(crate) const FAILED: &str = "failed-before-change";
const FAILED_AFTER: [&str; 3] = ["intent", "resolved", "stage-recorded"];
/// Terminal phase for an apply that stopped after its fallback snapshot (and
/// possibly the `old-<id>` fallback generation) existed but before the root
/// rebind, the first change to the running system. The fallback stays as an
/// ordinary root/generation for later retirement; nothing else changed.
pub(crate) const FAILED_FALLBACK: &str = "failed-after-fallback";
pub(crate) const FAILED_FALLBACK_RESULT: &str = "failed-fallback-kept";
const FAILED_FALLBACK_AFTER: [&str; 2] = ["fallback-born", "fallback-published"];
/// Finished records: completed, or failed before changing the running system.
pub fn finished(record: &Value) -> bool {
    record["phase"] == "complete" || record["phase"] == FAILED || record["phase"] == FAILED_FALLBACK
}
/// Whether an unfinished apply may end as `failed-after-fallback`: it stopped
/// after the fallback existed and before any rebind record was created.
pub(crate) fn fallback_only(record: &Value) -> bool {
    FAILED_FALLBACK_AFTER.contains(&record["phase"].as_str().unwrap_or(""))
}
pub const STEPS: [&str; 12] = [
    "resolved",
    "stage-recorded",
    "fallback-born",
    "fallback-published",
    "rebound",
    "view-entered",
    "worker-starting",
    "worker-complete",
    "view-restored",
    "transaction-recorded",
    "new-published",
    "complete",
];
pub fn plan(plan: &Value) -> Result<()> {
    json::fields(
        plan,
        match plan["schema"].as_u64() {
            Some(1) => {
                "schema operation boot_id storage inventory_sha256 current_kernels target_kernels options authority cohort_sha256 implementation_sha256"
            }
            Some(2) => {
                "schema operation boot_id storage inventory_sha256 current_kernels target_kernels options authority cohort_sha256 implementation_sha256 implementation_image"
            }
            _ => return Err(Error("native apply plan version".into())),
        },
    )?;
    require(
        matches!(plan["schema"].as_u64(), Some(1 | 2)) && plan["operation"] == "update-apply",
        "native apply plan schema",
    )?;
    if plan["schema"] == 2 {
        crate::update_actor::image_path(text(plan, "implementation_image")?)?;
    }
    identity::uuid(text(plan, "boot_id")?)?;
    storage::validate(&plan["storage"])?;
    for name in ["inventory_sha256", "cohort_sha256", "implementation_sha256"] {
        identity::sha(text(plan, name)?)?;
    }
    for name in ["current_kernels", "target_kernels"] {
        json::fields(&plan[name], "linux linux-lts")?;
        identity::safe_id(text(&plan[name], "linux")?)?;
        identity::safe_id(text(&plan[name], "linux-lts")?)?;
        require(
            plan[name]["linux"] != plan[name]["linux-lts"],
            "apply kernel flavors overlap",
        )?;
    }
    json::fields(
        &plan["authority"],
        "ownertrust pubring.gpg gpg.conf approved.trust",
    )?;
    for name in ["ownertrust", "pubring.gpg", "gpg.conf", "approved.trust"] {
        identity::sha(text(&plan["authority"], name)?)?;
    }
    let options = text(plan, "options")?;
    require(
        crate::update_plan::options(options, text(&plan["storage"], "root_subvol")?)? == options,
        "apply options are not canonical live root options",
    )
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| Error(format!("apply {key} string required")))
}
fn seal(mut record: Value) -> Result<Value> {
    enzimos_platform::json::object_mut(&mut record)?.remove("journal_sha256");
    record["journal_sha256"] = value!(json::fingerprint(&record)?);
    Ok(record)
}
pub fn initial(id: &str, document: &Value, actor: &Value) -> Result<Value> {
    let mut body = value!({"schema":1,"id":id,"boot_id":document["boot_id"],"filesystem_uuid":document["storage"]["filesystem_uuid"],"actor":actor,"phase":"intent","plan":document,"steps":[],"result":null});
    if document["schema"] == 2 {
        body["schema"] = value!(2);
        body["actor_image"] = document["implementation_image"].clone();
    }
    let record = seal(body)?;
    validate(&record, id)?;
    Ok(record)
}
pub fn validate(record: &Value, id: &str) -> Result<()> {
    identity::safe_id(id)?;
    require(
        id.strip_prefix("api-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }),
        "fresh canonical apply identifier required",
    )?;
    json::fields(
        record,
        match record["schema"].as_u64() {
            Some(1) => {
                "schema id boot_id filesystem_uuid actor phase plan steps result journal_sha256"
            }
            Some(2) => {
                "schema id boot_id filesystem_uuid actor phase plan steps result journal_sha256 actor_image"
            }
            _ => return Err(Error("apply record version".into())),
        },
    )?;
    require(
        matches!(record["schema"].as_u64(), Some(1 | 2)) && record["id"] == id,
        "apply record schema or identifier",
    )?;
    plan(&record["plan"])?;
    require(
        record["schema"] == record["plan"]["schema"],
        "apply record and plan versions differ",
    )?;
    if record["schema"] == 2 {
        crate::update_actor::image_path(text(record, "actor_image")?)?;
        require(
            record["actor_image"] == record["plan"]["implementation_image"],
            "apply original actor image role differs",
        )?;
    }

    require(
        record["boot_id"] == record["plan"]["boot_id"]
            && record["filesystem_uuid"] == record["plan"]["storage"]["filesystem_uuid"],
        "apply boot or filesystem binding differs",
    )?;
    json::fields(&record["actor"], "pid start_ticks executable_sha256")?;
    require(
        record["actor"]["pid"]
            .as_u64()
            .is_some_and(|p| p > 1 && p <= i32::MAX as u64)
            && record["actor"]["start_ticks"]
                .as_u64()
                .is_some_and(|ticks| ticks > 0)
            && record["actor"]["executable_sha256"] == record["plan"]["implementation_sha256"],
        "apply actor identity refused",
    )?;
    identity::sha(text(&record["actor"], "executable_sha256")?)?;
    let steps = record["steps"]
        .as_array()
        .ok_or_else(|| Error("apply evidence array required".into()))?;
    let shortcut =
        record["phase"] == "complete" && record["result"] == "up-to-date-no-new-generation";
    let failed = record["phase"] == FAILED;
    let failed_fallback = record["phase"] == FAILED_FALLBACK;
    let failed_steps;
    let expected: &[&str] = if shortcut {
        &["resolved", "complete"]
    } else if failed || failed_fallback {
        let (range, terminal) = if failed {
            (1..=FAILED_AFTER.len(), FAILED)
        } else {
            (4..=5, FAILED_FALLBACK)
        };
        require(range.contains(&steps.len()), "apply failure evidence count")?;
        failed_steps = STEPS[..steps.len() - 1]
            .iter()
            .copied()
            .chain([terminal])
            .collect::<Vec<_>>();
        &failed_steps
    } else {
        &STEPS
    };
    require(steps.len() <= expected.len(), "apply evidence count")?;
    for (index, step) in steps.iter().enumerate() {
        json::fields(step, "phase sha256")?;
        require(
            step["phase"] == expected[index],
            "apply evidence skipped or reordered",
        )?;
        identity::sha(text(step, "sha256")?)?;
    }
    require(
        record["phase"]
            == steps
                .last()
                .map_or("intent", |row| row["phase"].as_str().unwrap())
            && if record["phase"] == "complete" {
                steps.len() == expected.len()
                    && (shortcut || record["result"] == "prepared-not-rebooted")
            } else if failed {
                record["result"] == "failed-no-change"
            } else if failed_fallback {
                record["result"] == FAILED_FALLBACK_RESULT
            } else {
                record["result"].is_null()
            },
        "apply terminal evidence differs",
    )?;
    require(
        seal(record.clone())? == *record,
        "apply journal digest mismatch",
    )
}
pub fn advance(
    previous: &Value,
    phase: &str,
    evidence: &Value,
    result: Option<&str>,
) -> Result<Value> {
    let id = text(previous, "id")?;
    validate(previous, id)?;
    require(!finished(previous), "completed apply cannot replay")?;
    require(
        phase != FAILED || FAILED_AFTER.contains(&previous["phase"].as_str().unwrap_or("")),
        "an apply that changed the system cannot be marked unchanged",
    )?;
    require(
        phase != FAILED_FALLBACK || fallback_only(previous),
        "only an apply stopped before its rebind can end with its fallback kept",
    )?;
    let mut current = previous.clone();
    enzimos_platform::json::array_mut(&mut current["steps"])?
        .push(value!({"phase":phase,"sha256":json::fingerprint(evidence)?}));
    current["phase"] = value!(phase);
    current["result"] = value!(result);
    let current = seal(current)?;
    transition(previous, &current, id)?;
    Ok(current)
}
pub fn transition(previous: &Value, current: &Value, id: &str) -> Result<()> {
    validate(previous, id)?;
    validate(current, id)?;
    require(!finished(previous), "completed apply cannot replay")?;
    for key in [
        "schema",
        "id",
        "boot_id",
        "filesystem_uuid",
        "actor",
        "plan",
    ] {
        require(
            previous[key] == current[key],
            "immutable apply intent changed",
        )?;
    }
    let before = enzimos_platform::json::array(&previous["steps"])?;
    let after = enzimos_platform::json::array(&current["steps"])?;
    require(
        after.len() == before.len() + 1 && after[..before.len()] == before[..],
        "apply evidence rewritten or replayed",
    )
}
pub fn worker_binding(record: &Value, request: &Value) -> Result<()> {
    let id = text(request, "id")?;
    validate(record, id)?;
    crate::update_worker_record::execution_request(request)?;
    let consistent = if record["schema"] == 1 {
        request["schema"] == 2
    } else {
        request["schema"] == 3 && record["actor_image"] == request["caller_image"]
    };
    require(
        consistent,
        "worker caller role/version differs from original apply intent",
    )?;
    require(
        record["phase"] == "worker-starting"
            && record["boot_id"] == request["boot_id"]
            && record["filesystem_uuid"] == request["filesystem_uuid"]
            && record["actor"] == request["caller"],
        "worker differs from the original fresh apply intent",
    )
}
