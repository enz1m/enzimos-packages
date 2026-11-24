// SPDX-License-Identifier: MIT
//! One owned caller connects actual capture, transfer, retirement and publication.
//! Run on a blocking thread outside Tokio; evidence never reconstructs authority.
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_policy::{
    backup_archive_inputs::Inputs,
    backup_attempt::Attempt,
    backup_completion,
    backup_configuration::{Configuration, SourceScope},
    backup_destination::Destination,
    backup_inventory_stage, backup_readonly_trees,
    backup_restic_runtime::remote_share as share,
    backup_running::Run,
    backup_share_destination::{self as primary, ShareScope},
    backup_source_capture,
    backup_source_inventory::Inventory,
    backup_transfer_context::Context,
    storage_runtime::Guard,
};
use serde_json::{Value, json as value};

/// All inputs are retained original actors; callers cannot supply a source path,
/// credentials, backup arguments, worker identity or a reconstructed receipt.
/// The review is freshly measured under the owned lock before the first durable
/// attempt/capture; it cannot invoke an adapter that reacquires that same lock.
/// Settings "Back up now": the destination is borrowed when mounted, otherwise
/// this job owns one reviewed temporary mount (see `attached`). Without a
/// backup drive the backup goes straight into the ready NAS share (see
/// `shared`). The outcome is recorded as the backup run status, like a
/// scheduled run.
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
    let lock = enzimos_policy::operation::lock().inspect_err(|error| {
        enzimos_policy::backup_run_status::record_outcome(Some(&error.0));
    })?;
    let target = primary::primary().unwrap_or(primary::DRIVE);
    let mut running = Run::begin(target);
    let created = if target == primary::SHARE {
        shared(
            guard,
            &lock,
            id,
            Some(expected),
            authorize,
            &mut tracked(&mut running, target, progress),
        )
    } else {
        attached(
            guard,
            &lock,
            id,
            Some(expected),
            authorize,
            &mut tracked(&mut running, target, progress),
        )
    };
    enzimos_policy::backup_run_status::record_outcome(created.as_ref().err().map(|e| e.0.as_str()));
    let summary = created?;
    // The System1 result keeps its closed fields; the cleanup and copy
    // outcomes are published as backup status instead.
    after_backup(
        guard,
        &lock,
        summary["snapshot_id"].as_str(),
        authorize,
        &mut running,
        target,
    );
    Ok(value!({"snapshot_id":summary["snapshot_id"]}))
}
/// Report each capture phase as the running backup's phase too.
pub(crate) fn tracked<'a>(
    running: &'a mut Run,
    target: &'a str,
    progress: &'a mut dyn FnMut(&str) -> Result<()>,
) -> impl FnMut(&str) -> Result<()> + 'a {
    move |phase| {
        running.phase(phase, target);
        progress(phase)
    }
}
/// After a successful backup: clean up by policy, then copy the new snapshot
/// to the NAS share when one is set up. A backup that went into the share is
/// only cleaned up there. Neither step fails the backup; both outcomes are
/// published as backup status.
pub(crate) fn after_backup(
    guard: &Guard,
    lock: &files::Lock,
    created: Option<&str>,
    authorize: &dyn Fn() -> Result<()>,
    running: &mut Run,
    target: &str,
) -> Value {
    eprintln!("enzimos-backup: cleanup");
    if target == primary::SHARE {
        let cleanup = enzimos_policy::backup_restic_runtime::remote_retention::after_copy_locked(
            guard,
            lock,
            created,
            &mut || authorize(),
        );
        return value!({"cleanup":cleanup});
    }
    let cleanup = enzimos_policy::backup_restic_runtime::retention::after_backup_attached(
        guard, lock, created, authorize,
    );
    let mut result = value!({"cleanup":cleanup});
    if let Some(snapshot) =
        created.filter(|_| enzimos_policy::backup_restic_runtime::remote_share::copy_ready())
    {
        running.phase("copying", primary::SHARE);
        result["remote_copy"] =
            crate::backup_remote_coordinator::copy_after_backup(guard, lock, snapshot, authorize);
    }
    result
}
/// One capture straight into the NAS share (no backup drive is set up).
/// `expected: None` (standalone command) measures the review under this same
/// lock first. Share failures carry their public `remote-share-*` code; the
/// detail goes to the journal.
pub(crate) fn shared(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    expected: Option<&Value>,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    let outcome = (|| {
        let measured;
        let expected = match expected {
            Some(expected) => expected,
            None => {
                let scope = ShareScope::open()?;
                let inventory = Inventory::observe(&scope, guard)?;
                measured = enzimos_policy::backup_create_review::measure_share(
                    guard, lock, &scope, &inventory,
                )?;
                authorize()?;
                &measured
            }
        };
        execute_share_locked(guard, lock, id, expected, authorize, progress)
    })();
    outcome.map_err(|error| {
        // A share that stopped answering explains a failed transfer better
        // than the worker's closed control channel does.
        let error = if share::code(&error).is_none() {
            eprintln!(
                "enzimos-backup: share backup failed: {}",
                enzimos_policy::diagnostic::bounded(&error.0)
            );
            match ShareScope::open().and_then(|scope| primary::reachable(&scope)) {
                Err(unreachable) if share::code(&unreachable).is_some() => unreachable,
                _ => error,
            }
        } else {
            error
        };
        match share::code(&error) {
            Some(code) => {
                eprintln!(
                    "enzimos-backup: share backup refused: {}",
                    enzimos_policy::diagnostic::bounded(&error.0)
                );
                Error(code.into())
            }
            None => error,
        }
    })
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
/// The share counterpart of `execute_locked`: the same capture, staging,
/// worker transfer, retirement and publication, with the pinned NAS share
/// repository as the transfer target and the share configuration as the
/// capture scope.
fn execute_share_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    expected: &Value,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    authorize()?;
    lock.recheck()?;
    guard.recheck()?;
    let scope = ShareScope::open()?;
    let inventory = Inventory::observe(&scope, guard)?;
    require(
        enzimos_policy::backup_create_review::measure_share(guard, lock, &scope, &inventory)?
            == *expected,
        "job-plan-changed",
    )?;
    primary::reachable(&scope)?;
    authorize()?;
    inventory.recheck()?;
    let attempt = Attempt::begin(guard, lock)?;
    let mut boundary = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        SourceScope::recheck(&scope)
    };
    progress("capturing")?;
    let capture = backup_source_capture::capture(&inventory, &attempt, lock, id, &mut boundary)?;
    let stage = backup_inventory_stage::stage(&capture, lock, id, &mut boundary)?;
    progress("transferring")?;
    let finished = {
        let inputs = Inputs::observe(&capture, &stage)?;
        let context = Context::observe_share(&inputs, lock, &mut boundary)?;
        let trees = backup_readonly_trees::Prepared::prepare(&inputs, lock, id, &mut boundary)?;
        super::backup_transfer_client::launch(&context, trees, &|| {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            SourceScope::recheck(&scope)
        })?
    };
    finished.evidence()?;
    let (observation, request, descriptors) = finished.into_parts();
    let closed = observation.close(&request, &descriptors)?;
    closed.recheck()?;
    progress("finishing")?;
    let retired_stage = stage.retire(&closed, &mut boundary)?;
    let retired_source = capture.retire(&retired_stage, &closed, &mut boundary)?;
    let publication = backup_completion::Prepared::enter(
        &attempt,
        &retired_source,
        &retired_stage,
        &closed,
        &mut boundary,
    )?
    .publish(&mut boundary)?;
    let receipt = publication.evidence()?;
    let snapshot = receipt["snapshot_id"].as_str().unwrap_or("");
    require(
        snapshot.len() == 64,
        "original terminal full snapshot ID required",
    )?;
    enzimos_policy::identity::sha(snapshot)?;
    let result = publication.summary()?;
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
