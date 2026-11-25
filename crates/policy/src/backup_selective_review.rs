// SPDX-License-Identifier: MIT
//! Server review data; no stage/worker/export is created during planning.
use crate::{
    backup_configuration::Configuration, backup_destination::Destination,
    backup_selective_context::Context, storage_runtime::Guard,
};
use enzimos_platform::{Result, json};
use serde_json::{Value, json as value};
/// Review document of a file export for `selection`.
///
/// # Errors
///
/// Fails when the selection is invalid or its context cannot be observed.
pub fn observe(guard: &Guard, selection: &Value) -> Result<Value> {
    observe_kind(guard, selection, false)
}
/// Review document of a tree export for `selection`.
///
/// # Errors
///
/// Fails when the selection is invalid or its context cannot be observed.
pub fn observe_tree(guard: &Guard, selection: &Value) -> Result<Value> {
    observe_kind(guard, selection, true)
}
fn observe_kind(guard: &Guard, selection: &Value, tree: bool) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::backup_selective_request::selection(selection)?;
    let lock = crate::operation::lock()?;
    // Borrowed when mounted, otherwise one reviewed temporary owned mount.
    let attached = || -> Result<()> {
        guard.recheck()?;
        lock.recheck()
    };
    crate::backup_destination_attach::with_destination(guard, &lock, &attached, || {
        let configuration = Configuration::open()?;
        let destination = Destination::open(&configuration, guard)?;
        let observer = if tree {
            Context::observe_tree
        } else {
            Context::observe
        };
        let context = observer(
            guard,
            &lock,
            selection,
            &destination,
            &"0".repeat(32),
            &mut || Ok(()),
        )?;
        measure(&context, &mut || Ok(()))
    })
}
/// Measure the review document for `context`.
///
/// # Errors
///
/// Fails when the context changed or `authorize` fails.
pub fn measure(
    context: &Context<'_, '_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    context.recheck(authorize)?;
    let idle = crate::transition_idle::Snapshot::online()?;
    enzimos_platform::require(
        idle.guard.backup_root_binding()? == context.guard().backup_root_binding()?,
        "selective review transition source changed",
    )?;
    let mut original = context.evidence(authorize)?.clone();
    crate::backup_selective_export::preflight(
        context.guard(),
        enzimos_platform::json::string(&original["selection"]["id"])?,
    )?;
    // Server-generated job IDs differ between plan observation and execution;
    // selection and all actual original input observations remain bound.
    enzimos_platform::json::object_mut(&mut original)?.remove("id");
    // The plan and the job may each own a separate temporary mount of the same
    // destination; bind the repository, not one mount epoch.
    crate::backup_destination::stable_context(&mut original)?;
    let mut review = value!({"schema":1,"operation":context.kind().operation(),"selection":original["selection"],
        "boot_id":original["boot_id"],"export_exists":false,"context_sha256":json::fingerprint(&original)?});
    if context.kind() == crate::backup_selective_request::Kind::Tree {
        review["tree"] = context.query_tree(authorize)?;
    }
    context.recheck(authorize)?;
    Ok(review)
}
