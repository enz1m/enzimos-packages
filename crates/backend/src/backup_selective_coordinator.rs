// SPDX-License-Identifier: MIT
//! Original stored System1 plan through exclusive stage and actual worker closure.
use enzimos_platform::{Result, require};
use enzimos_policy::{
    backup_configuration::Configuration, backup_destination::Destination,
    backup_selective_context::Context, backup_selective_export::Staging, backup_selective_review,
    storage_runtime::Guard,
};
use serde_json::Value;
pub fn run(
    guard: &Guard,
    id: &str,
    selection: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    run_kind(guard, id, selection, expected, authorize, progress, false)
}
pub fn run_tree(
    guard: &Guard,
    id: &str,
    selection: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    run_kind(guard, id, selection, expected, authorize, progress, true)
}
fn run_kind(
    guard: &Guard,
    id: &str,
    selection: &Value,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
    tree: bool,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    enzimos_policy::backup_selective_request::selection(selection)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    // Borrowed when mounted, otherwise one reviewed temporary owned mount,
    // closed after the export is published.
    let attached = || -> Result<()> {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    enzimos_policy::backup_destination_attach::with_destination(guard, &lock, &attached, || {
        let configuration = Configuration::open()?;
        let destination = Destination::open(&configuration, guard)?;
        let mut permission = || {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            configuration.recheck()
        };
        progress("validating")?;
        let observer = if tree {
            Context::observe_tree
        } else {
            Context::observe
        };
        let context = observer(guard, &lock, selection, &destination, id, &mut permission)?;
        require(
            backup_selective_review::measure(&context, &mut permission)? == *expected,
            "job-plan-changed",
        )?;
        let stage = Staging::enter(&context, &mut permission)?;
        progress("transferring")?;
        let closed = super::backup_selective_client::launch(&context, &|| {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            configuration.recheck()
        })?;
        closed.recheck()?;
        if tree {
            closed.require_tree(&expected["tree"])?;
        }
        permission()?;
        progress("finishing")?;
        let completed = stage.publish(closed, &mut permission)?;
        permission()?;
        completed.system_result(&mut permission)
    })
}
