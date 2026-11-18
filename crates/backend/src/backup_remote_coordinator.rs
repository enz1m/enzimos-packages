// SPDX-License-Identifier: MIT
//! Reviewed original remote copy inputs through actual kernel closure and receipt.
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_policy::{
    backup_configuration::Configuration,
    backup_destination::Destination,
    backup_remote_completion::Replication,
    backup_remote_copy_context::{Context, Direction},
    storage_runtime::Guard,
};
use serde_json::{Value, json as value};
fn selection<'a>(role: &str, selected: &'a Value) -> Result<(Direction, &'a str, Option<&'a str>)> {
    let direction = match role {
        "remote-replicate" => Direction::Replicate,
        "remote-retrieve" => Direction::Retrieve,
        _ => return Err(Error("closed remote copy role required".into())),
    };
    json::fields(
        selected,
        if direction == Direction::Replicate {
            "snapshot"
        } else {
            "id snapshot"
        },
    )?;
    let snapshot = selected["snapshot"].as_str().unwrap_or("");
    enzimos_policy::identity::sha(snapshot)?;
    let receipt = if direction == Direction::Retrieve {
        let id = selected["id"].as_str().unwrap_or("");
        enzimos_policy::identity::safe_id(id)?;
        Some(id)
    } else {
        None
    };
    Ok((direction, snapshot, receipt))
}
fn measurement(original: &Value, role: &str, selected: &Value) -> Result<Value> {
    let mut stable = original.clone();
    // This field is a fresh internal worker nonce. Public selection, receipt ID,
    // original descriptor epochs, mounts, pins and vendor images remain bound.
    stable
        .as_object_mut()
        .ok_or_else(|| Error("original remote context required".into()))?
        .remove("id");
    Ok(value!({"schema":1,"operation":role,"selection":selected,
        "boot_id":original["remote"]["boot_id"],"context_sha256":json::fingerprint(&stable)?,
        "remote_authenticated":false,"copy_complete":false,"worker_closed":false,"receipt_complete":false}))
}
fn measure(
    context: &Context<'_, '_>,
    role: &str,
    selected: &Value,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let idle = enzimos_policy::transition_idle::Snapshot::online()?;
    require(
        idle.guard.backup_root_binding()? == context.evidence(authorize)?["source"],
        "remote review transition source changed",
    )?;
    let result = measurement(context.evidence(authorize)?, role, selected)?;
    context.recheck(authorize)?;
    Ok(result)
}
pub fn observe(guard: &Guard, role: &str, selected: &Value) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let (direction, snapshot, receipt) = selection(role, selected)?;
    let lock = enzimos_policy::operation::lock()?;
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, guard)?;
    let context = Context::observe(
        guard,
        &lock,
        &destination,
        direction,
        snapshot,
        &"0".repeat(32),
        receipt,
        &mut || Ok(()),
    )?;
    measure(&context, role, selected, &mut || Ok(()))
}
pub fn run(
    guard: &Guard,
    role: &str,
    selected: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let (direction, snapshot, receipt) = selection(role, selected)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, guard)?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        configuration.recheck()
    };
    progress("validating")?;
    let context = Context::observe(
        guard,
        &lock,
        &destination,
        direction,
        snapshot,
        &files::random_hex(16)?,
        receipt,
        &mut permission,
    )?;
    require(
        measure(&context, role, selected, &mut permission)? == *expected,
        "job-plan-changed",
    )?;
    let replication = if direction == Direction::Replicate {
        Some(Replication::prepare(&context, &mut permission)?)
    } else {
        None
    };
    progress("transferring")?;
    let closed = super::backup_remote_client::launch(&context, &|| {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        configuration.recheck()
    })?;
    closed.require_context(&context, &mut permission)?;
    progress("finishing")?;
    let result = if let Some(replication) = replication {
        replication.complete(closed, &context, &mut permission)?
    } else {
        closed.complete_retrieval(&context, &mut permission)?
    };
    permission()?;
    if direction == Direction::Replicate {
        // Clean up the remote repository by the same policy; the closed result
        // fields stay as they are and the outcome is published as status.
        enzimos_policy::backup_restic_runtime::remote_retention::after_copy_locked(
            guard,
            &lock,
            result["remote_snapshot"].as_str(),
            &mut permission,
        );
        permission()?;
    }
    // The helper receipt exposes additional safety facts; System1 keeps its
    // historical closed result fields for existing consumers and durable jobs.
    Ok(if direction == Direction::Replicate {
        value!({"status":result["status"],"source_snapshot":result["source_snapshot"],
            "remote_snapshot":result["remote_snapshot"],"repository_id":result["repository_id"]})
    } else {
        value!({"id":result["id"],"status":result["status"],"remote_snapshot":result["remote_snapshot"],
            "local_snapshot":result["local_snapshot"],"automatic_retry":false})
    })
}
