// SPDX-License-Identifier: MIT
//! Sealed worker requests bind retained resources; neither records nor failures replay.
use crate::{identity, module_view_record};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
pub(crate) const MAXIMUM: usize = 32;
pub const EXECUTABLE: &str = "/usr/lib/enzimos-native/enzimos-update-worker";
pub const CONFIG: &str = "/etc/enzimos/update-pacman.conf";
pub const RUNTIME_SECONDS: u64 = 1400;
pub const STOP_SECONDS: u64 = 10;
pub fn process(value: &Value) -> Result<()> {
    json::fields(value, "pid start_ticks executable_sha256")?;
    require(
        value["pid"]
            .as_u64()
            .is_some_and(|n| n > 1 && n < i32::MAX as u64)
            && value["start_ticks"].as_u64().is_some_and(|n| n > 0),
        "worker caller identity refused",
    )?;
    identity::sha(
        value["executable_sha256"]
            .as_str()
            .ok_or_else(|| Error("worker caller executable hash missing".into()))?,
    )?;
    Ok(())
}
pub fn directory(value: &Value) -> Result<()> {
    json::fields(value, "device inode mount")?;
    require(
        ["device", "inode", "mount"]
            .iter()
            .all(|key| value[*key].as_u64().is_some_and(|n| n > 0)),
        "worker retained directory identity refused",
    )
}
pub fn request(value: &Value) -> Result<()> {
    let schema = value["schema"]
        .as_u64()
        .ok_or_else(|| Error("worker request schema required".into()))?;
    json::fields(
        value,
        match schema {
            1 => {
                "schema id boot_id filesystem_uuid caller module_view boot_stage config_sha256 cohort_sha256"
            }
            2 => {
                "schema id boot_id filesystem_uuid caller module_view boot_stage config_sha256 cohort_sha256 descriptors"
            }
            3 => {
                "schema id boot_id filesystem_uuid caller caller_image module_view boot_stage config_sha256 cohort_sha256 descriptors"
            }
            _ => return Err(Error("worker request schema refused".into())),
        },
    )?;
    require(matches!(schema, 1..=3), "worker request schema refused")?;
    let id = value["id"]
        .as_str()
        .ok_or_else(|| Error("worker generation missing".into()))?;
    identity::safe_id(id)?;
    for key in ["boot_id", "filesystem_uuid"] {
        identity::uuid(
            value[key]
                .as_str()
                .ok_or_else(|| Error("worker UUID missing".into()))?,
        )?;
    }
    process(&value["caller"])?;
    if schema == 3 {
        crate::update_actor::image_path(
            value["caller_image"]
                .as_str()
                .ok_or_else(|| Error("worker caller image role".into()))?,
        )?;
    }

    let view = &value["module_view"];
    let view_id = view["id"]
        .as_str()
        .ok_or_else(|| Error("worker module view missing".into()))?;
    module_view_record::validate(view, view_id)?;
    require(
        view["phase"] == "active"
            && view["boot_id"] == value["boot_id"]
            && view["filesystem_uuid"] == value["filesystem_uuid"],
        "worker requires exact active module view",
    )?;
    directory(&value["boot_stage"])?;
    require(
        value["boot_stage"] != view["alias"]
            && value["boot_stage"] != view["runtime"]
            && value["boot_stage"] != view["source"],
        "worker resource roles overlap",
    )?;
    for key in ["config_sha256", "cohort_sha256"] {
        identity::sha(
            value[key]
                .as_str()
                .ok_or_else(|| Error("worker input digest missing".into()))?,
        )?;
    }
    if schema >= 2 {
        json::fields(&value["descriptors"], "modules boot_stage operation_lock")?;
        let mut unique = std::collections::BTreeSet::new();
        for key in ["modules", "boot_stage", "operation_lock"] {
            let fd = value["descriptors"][key]
                .as_u64()
                .ok_or_else(|| Error("worker caller descriptor missing".into()))?;
            require(
                fd < 1_048_576 && unique.insert(fd),
                "worker caller descriptor bound or repeated role",
            )?;
        }
    }
    Ok(())
}
pub fn execution_request(value: &Value) -> Result<()> {
    request(value)?;
    require(
        matches!(value["schema"].as_u64(), Some(2 | 3)),
        "worker execution requires closed description-bound request version",
    )
}
/// Closed wire role only; recipients still pin the actual kernel task and image.
pub fn caller_image(value: &Value) -> Result<&'static str> {
    execution_request(value)?;
    if value["schema"] == 2 {
        Ok(crate::update_actor::POLICY)
    } else {
        crate::update_actor::image_path(enzimos_platform::json::string(&value["caller_image"])?)
    }
}
pub fn unit(id: &str) -> Result<String> {
    identity::safe_id(id)?;
    Ok(format!("enzimos-update-worker-{id}.service"))
}
pub fn arguments(id: &str) -> Result<Vec<String>> {
    identity::safe_id(id)?;
    Ok(vec![EXECUTABLE.into(), "serve".into(), id.into()])
}
pub fn socket_path(id: &str) -> Result<std::path::PathBuf> {
    identity::safe_id(id)?;
    let digest = json::sha256(id.as_bytes());
    Ok(std::path::PathBuf::from(format!(
        "/run/enzimos/update-workers/{}/request.sock",
        digest.get(..32).unwrap_or(&digest)
    )))
}
pub fn validate(value: &Value, id: &str) -> Result<()> {
    json::fields(
        value,
        "schema id phase request request_sha256 supervisor invocation exit_code",
    )?;
    require(
        value["schema"].as_u64() == Some(1) && value["id"] == id && value["request"]["id"] == id,
        "worker record schema or generation refused",
    )?;
    request(&value["request"])?;
    require(
        value["request_sha256"] == json::sha256(&json::canonical(&value["request"])?),
        "worker request digest mismatch",
    )?;
    let phase = value["phase"]
        .as_str()
        .ok_or_else(|| Error("worker record phase missing".into()))?;
    require(
        matches!(
            phase,
            "intent"
                | "starting"
                | "handed-off"
                | "running"
                | "stopping"
                | "complete"
                | "failed"
                | "uncertain"
        ),
        "worker record phase refused",
    )?;
    if !value["supervisor"].is_null() {
        process(&value["supervisor"])?;
    }
    let invocation = &value["invocation"];
    require(
        invocation.is_null()
            || invocation.as_str().is_some_and(|s| {
                s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
        "worker invocation refused",
    )?;
    require(
        value["exit_code"].is_null() || value["exit_code"].as_u64().is_some_and(|n| n <= 255),
        "worker exit code refused",
    )?;
    if matches!(phase, "handed-off" | "running" | "stopping" | "complete") {
        require(
            !value["supervisor"].is_null() && !invocation.is_null(),
            "worker ownership missing",
        )?;
    }
    require(
        phase != "complete" || value["exit_code"].as_u64() == Some(0),
        "worker completion requires success",
    )?;
    Ok(())
}
/// Validate every service checkpoint before a caller advances its private snapshot.
pub fn history(before: &Value, checkpoints: &[Value], id: &str) -> Result<Value> {
    validate(before, id)?;
    execution_request(&before["request"])?;
    require(
        before["phase"] == "starting" && checkpoints.len() == 4,
        "worker completion history must cover every checkpoint",
    )?;
    let mut prior = before;
    for (next, phase) in checkpoints
        .iter()
        .zip(["handed-off", "running", "stopping", "complete"])
    {
        require(
            next["phase"] == phase,
            "worker completion history order refused",
        )?;
        transition(Some(prior), next, id)?;
        prior = next;
    }
    require(
        prior["exit_code"] == 0,
        "worker history lacks successful completion",
    )?;
    Ok(prior.clone())
}
pub fn transition(before: Option<&Value>, after: &Value, id: &str) -> Result<()> {
    validate(after, id)?;
    let Some(before) = before else {
        return require(
            after["phase"] == "intent"
                && after["supervisor"].is_null()
                && after["invocation"].is_null()
                && after["exit_code"].is_null(),
            "worker must persist initial intent before service start",
        );
    };
    validate(before, id)?;
    let old = enzimos_platform::json::string(&before["phase"])?;
    let new = enzimos_platform::json::string(&after["phase"])?;
    let order = [
        "intent",
        "starting",
        "handed-off",
        "running",
        "stopping",
        "complete",
    ];
    let terminal = matches!(old, "complete" | "failed" | "uncertain");
    let normal = order.windows(2).any(|pair| pair == [old, new]);
    require(
        !terminal && (normal || matches!(new, "failed" | "uncertain")),
        "worker replay or skipped checkpoint refused",
    )?;
    for key in ["schema", "id", "request", "request_sha256"] {
        require(
            before[key] == after[key],
            "worker immutable request changed",
        )?;
    }
    for key in ["supervisor", "invocation"] {
        require(
            before[key].is_null() || before[key] == after[key],
            "worker owner changed",
        )?;
    }
    require(
        after["exit_code"].is_null()
            || matches!(new, "stopping" | "complete" | "failed" | "uncertain"),
        "worker exit recorded before stop checkpoint",
    )
}
