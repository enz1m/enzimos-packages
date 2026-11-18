// SPDX-License-Identifier: MIT
//! One owned caller connects actual capture, transfer, retirement and publication.
//! Run on a blocking thread outside Tokio; evidence never reconstructs authority.
use enzimos_platform::{Result, files, json, require};
use enzimos_policy::{
    backup_archive_inputs::Inputs, backup_attempt::Attempt, backup_completion,
    backup_configuration::Configuration, backup_destination::Destination, backup_inventory_stage,
    backup_readonly_trees, backup_source_capture, backup_source_inventory::Inventory,
    backup_transfer_context::Context, storage_runtime::Guard,
};
use serde_json::{Value, json as value};

/// All inputs are retained original actors; callers cannot supply a source path,
/// credentials, backup arguments, worker identity or a reconstructed receipt.
/// The review is freshly measured under the owned lock before the first durable
/// attempt/capture; it cannot invoke an adapter that reacquires that same lock.
/// Settings "Back up now": the destination is borrowed when mounted, otherwise
/// this job owns one reviewed temporary mount (see `attached`).
pub fn run(
    guard: &Guard,
    id: &str,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let summary = attached(guard, &lock, id, Some(expected), authorize, progress)?;
    eprintln!("enzimos-backup: cleanup");
    // The System1 result keeps its closed fields; the cleanup outcome is
    // published as backup status instead.
    enzimos_policy::backup_restic_runtime::retention::after_backup_attached(
        guard,
        &lock,
        summary["snapshot_id"].as_str(),
        authorize,
    );
    Ok(value!({"snapshot_id":summary["snapshot_id"]}))
}
/// One capture with the configured destination available. A mounted
/// destination is borrowed and never unmounted; otherwise the attached drive
/// is reviewed against its pin and this call owns one temporary mount that it
/// closes before terminal publication. `expected: None` (standalone command)
/// measures the review under this same lock and destination first.
pub(crate) fn attached(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    expected: Option<&Value>,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::backup_destination_attach::attach(guard, lock, authorize, |active| {
        let mut body = |scope: Option<&dyn crate::backup_destination_scope::Closure>| {
            let measured;
            let expected = match expected {
                Some(expected) => expected,
                None => {
                    measured = measure(guard, lock)?;
                    authorize()?;
                    &measured
                }
            };
            execute_locked(guard, lock, id, expected, authorize, progress, scope)
        };
        let Some(active) = active else {
            eprintln!("enzimos-backup: destination borrowed");
            return body(None);
        };
        eprintln!("enzimos-backup: destination attached (owned temporary mount)");
        let scope = crate::backup_destination_scope::Owned::new(active);
        match body(Some(&scope)) {
            Ok(result) => {
                let closed = scope.finish()?;
                closed.recheck()?;
                Ok(result)
            }
            Err(error) => Err(scope.failed(error)),
        }
    })
}
/// Fresh review of the current borrowed or owned destination (standalone use).
fn measure(guard: &Guard, lock: &files::Lock) -> Result<Value> {
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, guard)?;
    destination.require_writable()?;
    let inventory = Inventory::observe(&configuration, guard)?;
    enzimos_policy::backup_create_review::measure(
        guard,
        lock,
        &configuration,
        &inventory,
        &destination,
    )
}
fn execute_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
    scope: Option<&dyn crate::backup_destination_scope::Closure>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    authorize()?;
    lock.recheck()?;
    guard.recheck()?;
    let configuration = Configuration::open()?;
    let destination = Destination::open(&configuration, guard)?;
    destination.require_writable()?;
    if let Some(scope) = scope {
        scope.require_destination(&destination)?;
    }
    let inventory = Inventory::observe(&configuration, guard)?;
    require(
        enzimos_policy::backup_create_review::measure(
            guard,
            lock,
            &configuration,
            &inventory,
            &destination,
        )? == *expected,
        "job-plan-changed",
    )?;
    authorize()?;
    inventory.recheck()?;
    destination.require_writable()?;
    let attempt = Attempt::begin(guard, &lock)?;
    let mut boundary = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        configuration.recheck()?;
        if let Some(scope) = scope {
            scope.recheck()?;
        }
        Ok(())
    };
    progress("capturing")?;
    let capture = backup_source_capture::capture(&inventory, &attempt, lock, id, &mut boundary)?;
    let stage = backup_inventory_stage::stage(&capture, lock, id, &mut boundary)?;
    progress("transferring")?;
    let finished = {
        let inputs = Inputs::observe(&capture, &stage)?;
        let context = Context::observe(&inputs, lock, &destination, &mut boundary)?;
        let trees = backup_readonly_trees::Prepared::prepare(&inputs, lock, id, &mut boundary)?;
        super::backup_transfer_client::launch(&context, trees, &|| {
            boundary_authorize(guard, lock, &configuration, authorize)?;
            if let Some(scope) = scope {
                scope.recheck()?;
            }
            Ok(())
        })?
    };
    // Drop the input/context borrows before consuming either captured actor.
    // These three owned actors exist only after actual original PID/cgroup closure.
    finished.evidence()?;
    let (observation, request, descriptors) = finished.into_parts();
    let closed = observation.close(&request, &descriptors)?;
    closed.recheck()?;
    progress("finishing")?;
    // Timings of each finishing step go to the journal (stderr), so a slow
    // step is visible without a debugger.
    let mut step = std::time::Instant::now();
    let mut timed = |name: &str| {
        eprintln!(
            "enzimos-backup: finishing {name} {} ms",
            step.elapsed().as_millis()
        );
        step = std::time::Instant::now();
    };
    let retired_stage = stage.retire(&closed, &mut boundary)?;
    timed("stage-retired");
    let retired_source = capture.retire(&retired_stage, &closed, &mut boundary)?;
    timed("source-retired");
    // The complete worker/retirement proofs contain no destination descriptors.
    // Release the consumer's original destination before one actual owner close.
    // Its typed normal-close proof remains through terminal publication.
    destination.recheck()?;
    let retained_destination = if let Some(scope) = scope {
        drop(destination);
        scope.close()?;
        scope.recheck()?;
        None
    } else {
        Some(destination)
    };
    timed("destination-closed");
    let publication = backup_completion::Prepared::enter(
        &attempt,
        &retired_source,
        &retired_stage,
        &closed,
        &mut boundary,
    )?
    .publish(&mut boundary)?;
    timed("published");
    let receipt = publication.evidence()?;
    let snapshot = receipt["snapshot_id"].as_str().unwrap_or("");
    require(
        snapshot.len() == 64,
        "original terminal full snapshot ID required",
    )?;
    enzimos_policy::identity::sha(snapshot)?;
    // Keep every original proof alive until the terminal result has been checked.
    let result = publication.summary()?;
    if let Some(destination) = &retained_destination {
        destination.recheck()?;
    }
    if let Some(scope) = scope {
        scope.recheck()?;
    }
    json::canonical(&result)?;
    Ok(result)
}
fn boundary_authorize(
    guard: &Guard,
    lock: &files::Lock,
    configuration: &Configuration,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    configuration.recheck()
}
