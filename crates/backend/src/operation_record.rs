// SPDX-License-Identifier: MIT
//! Durable operation states bind a server-made plan and never replay uncertainty.
use super::{
    system_selection,
    system_wire::{OPERATIONS, hex},
};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
pub const MAX_DOCUMENT: usize = 8192;
pub const PROGRESS: [&str; 7] = [
    "planned",
    "queued",
    "validating",
    "capturing",
    "transferring",
    "finishing",
    "completed",
];
fn invalid() -> Error {
    Error("job-record-invalid".into())
}
// System1 job_store's historical canonical bytes include a terminal newline.
// This differs from native policy receipts and must preserve their own digests.
pub fn canonical(body: &Value) -> Result<Vec<u8>> {
    let mut bytes = json::canonical(body)?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub fn seal(body: &Value) -> Result<String> {
    Ok(json::sha256(&canonical(body)?))
}
pub fn destination_name(path: &str, id: &str) -> Result<String> {
    enzimos_platform::delivery_name::restored(path, id)
}

pub fn validate(body: &Value) -> Result<()> {
    json::fields(
        body,
        "schema request_id owner_uid operation state progress plan plan_sha256 result",
    )
    .map_err(|_| invalid())?;
    require(
        body["schema"].as_u64() == Some(3)
            && body["request_id"].as_str().is_some_and(|s| hex(s, 32))
            && body["owner_uid"]
                .as_u64()
                .is_some_and(|n| n < u32::MAX as u64)
            && body["operation"]
                .as_str()
                .is_some_and(|s| OPERATIONS.contains(&s)),
        "job-record-invalid",
    )?;
    let state = body["state"].as_str().ok_or_else(invalid)?;
    require(
        matches!(
            state,
            "planned" | "queued" | "running" | "completed" | "cancelled" | "uncertain"
        ) && body["progress"]
            .as_str()
            .is_some_and(|s| PROGRESS.contains(&s)),
        "job-record-invalid",
    )?;
    require(
        body["plan"].is_object()
            && canonical(body)?.len() <= MAX_DOCUMENT
            && body["plan_sha256"].as_str().is_some_and(|s| hex(s, 64))
            && body["plan_sha256"] == seal(&body["plan"])?,
        "job-plan-invalid",
    )?;
    let operation = body["operation"].as_str().unwrap();
    let schema = OPERATIONS.iter().position(|s| *s == operation).unwrap() as u64 + 3;
    if !matches!(schema, 3 | 5) {
        system_selection::validate(schema, &body["plan"]["selection"])?;
    }
    if operation == "own-file-restore" {
        let plan = &body["plan"];
        let selection = &plan["selection"];
        let name = destination_name(
            selection["path"].as_str().ok_or_else(invalid)?,
            selection["id"].as_str().ok_or_else(invalid)?,
        )?;
        require(
            plan["uid"] == body["owner_uid"]
                && plan["uid"]
                    .as_u64()
                    .is_some_and(|n| (1000..(1 << 31)).contains(&n))
                && plan["account"].is_object()
                && plan["account"]["uid"] == body["owner_uid"]
                && plan["filename"] == name,
            "job-plan-invalid",
        )?;
    }
    if state == "completed" {
        require(body["progress"] == "completed", "job-result-invalid")?;
        super::operation_result::validate(body)?;
    } else {
        require(
            body["result"].is_null() && body["progress"] != "completed",
            "job-result-invalid",
        )?;
    }
    require(
        match state {
            "planned" | "queued" => body["progress"] == state,
            "running" => matches!(
                body["progress"].as_str(),
                Some("validating" | "capturing" | "transferring" | "finishing")
            ),
            _ => true,
        },
        "job-record-invalid",
    )
}
pub fn initial(id: &str, uid: u32, operation: &str, plan: Value) -> Result<Value> {
    let digest = seal(&plan)?;
    let body = value!({"schema":3,"request_id":id,"owner_uid":uid,"operation":operation,"state":"planned",
        "progress":"planned","plan":plan,"plan_sha256":digest,"result":null});
    validate(&body)?;
    Ok(body)
}
pub fn transition(before: &Value, after: &Value) -> Result<()> {
    validate(before)?;
    validate(after)?;
    for key in [
        "schema",
        "request_id",
        "owner_uid",
        "operation",
        "plan",
        "plan_sha256",
    ] {
        require(before[key] == after[key], "job-plan-changed")?;
    }
    let a = before["state"].as_str().unwrap();
    let b = after["state"].as_str().unwrap();
    require(
        matches!(
            (a, b),
            ("planned", "queued" | "cancelled")
                | ("queued", "running" | "cancelled" | "uncertain")
                | ("running", "running" | "completed" | "uncertain")
        ),
        "job-transition-refused",
    )?;
    if a == "running" && b == "running" {
        let index = |body: &Value| {
            PROGRESS
                .iter()
                .position(|s| body["progress"] == *s)
                .unwrap()
        };
        require(index(after) >= index(before), "job-transition-refused")?;
    }
    if matches!(b, "uncertain" | "cancelled") {
        require(
            before["progress"] == after["progress"],
            "job-transition-refused",
        )?;
    }
    Ok(())
}
pub fn public(body: &Value) -> Result<Value> {
    validate(body)?;
    let mut result = serde_json::Map::new();
    for name in [
        "schema",
        "request_id",
        "operation",
        "state",
        "progress",
        "plan_sha256",
        "result",
    ] {
        result.insert(name.into(), body[name].clone());
    }
    Ok(Value::Object(result))
}
