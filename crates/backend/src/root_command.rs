// SPDX-License-Identifier: MIT
//! Closed standalone Root selectors. No caller JSON, paths, credentials, worker
//! ownership or authorization evidence is accepted. Fresh native measurements
//! precede the same retained execution actors used by the System1 providers.
//! `--system-backup-create` (test/maintenance) runs the native provider's own
//! backup-create plan and job sequence; `--backup-candidates` prints the
//! passive candidate inventory that setup selection tokens come from.
//! `--system-query backups|backup-points|snapshots|history` (test/maintenance) answers the
//! System1 query of that name through the native provider.
use enzimos_platform::{Error, Result, files};
use enzimos_policy::{identity, operation, storage_runtime::Guard};
use serde_json::{Value, json as value};
use std::ffi::OsString;
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    ProvisionPlan(Value),
    ProvisionApply(Value, String, i32),
    ExportReview(bool, Value),
    Export(bool, Value, String),
    DeliveryReview(Value),
    Delivery(Value, String),
    CredentialReview(String),
    CredentialComplete(String, String),
    Replicate(String),
    Retrieve(String, String),
    Schedule(bool),
    RotationReview(String),
    RotationAdvance(String, String, String),
    RemoteRotationReview,
    RemoteRotationAdvance(String, String),
    /// Test/maintenance: the exact System1 `backup-create` provider sequence.
    SystemBackupCreate,
    /// The passive `backup-candidates` inventory (selection tokens for setup).
    Candidates,
    /// Test/maintenance: one System1 backup query through the native provider.
    SystemQuery(&'static str),
}
fn id(s: &str) -> Result<String> {
    Ok(identity::safe_id(s)?.into())
}
fn sha(s: &str) -> Result<String> {
    Ok(identity::sha(s)?.into())
}
fn action(s: &str) -> Result<String> {
    enzimos_platform::require(
        matches!(s, "abandon" | "switch" | "discard"),
        "closed rotation action required",
    )?;
    Ok(s.into())
}
pub fn parse(args: &[OsString]) -> Result<Option<Command>> {
    let Some(first) = args.get(1) else {
        return Ok(None);
    };
    let first = first
        .to_str()
        .ok_or_else(|| Error("Root command argument encoding".into()))?;
    if !matches!(
        first,
        "--provision-plan"
            | "--provision-apply"
            | "--file-export-review"
            | "--tree-export-review"
            | "--file-export"
            | "--tree-export"
            | "--delivery-review"
            | "--delivery-deliver"
            | "--credential-review"
            | "--credential-complete"
            | "--remote-replicate"
            | "--remote-retrieve"
            | "--backup-enable"
            | "--backup-disable"
            | "--rotation-review"
            | "--rotation-advance"
            | "--remote-rotation-review"
            | "--remote-rotation-advance"
            | "--system-backup-create"
            | "--backup-candidates"
            | "--system-query"
    ) {
        return Ok(None);
    }
    let parts = args[1..]
        .iter()
        .map(|s| {
            s.to_str()
                .ok_or_else(|| Error("Root command argument encoding".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let command = match parts.as_slice() {
        ["--provision-plan", selected, candidate, mode, uid] => {
            Command::ProvisionPlan(provision_selection(selected, candidate, mode, uid)?)
        }
        [
            "--provision-apply",
            selected,
            candidate,
            mode,
            uid,
            digest,
            input,
        ] => Command::ProvisionApply(
            provision_selection(selected, candidate, mode, uid)?,
            sha(digest)?,
            inherited_descriptor(input)?,
        ),
        [
            role @ ("--file-export-review" | "--tree-export-review"),
            selected,
            snapshot,
            path,
        ] => Command::ExportReview(
            *role == "--tree-export-review",
            export_selection(selected, snapshot, path)?,
        ),
        [
            role @ ("--file-export" | "--tree-export"),
            selected,
            snapshot,
            path,
            digest,
        ] => Command::Export(
            *role == "--tree-export",
            export_selection(selected, snapshot, path)?,
            sha(digest)?,
        ),
        ["--delivery-review", selected, grant] => {
            Command::DeliveryReview(delivery_selection(selected, grant)?)
        }
        ["--delivery-deliver", selected, grant, digest] => {
            Command::Delivery(delivery_selection(selected, grant)?, sha(digest)?)
        }
        ["--credential-review", selected] => Command::CredentialReview(id(selected)?),
        ["--credential-complete", selected, digest] => {
            Command::CredentialComplete(id(selected)?, sha(digest)?)
        }
        ["--remote-replicate", snapshot] => Command::Replicate(sha(snapshot)?),
        ["--remote-retrieve", selected, snapshot] => {
            Command::Retrieve(id(selected)?, sha(snapshot)?)
        }
        ["--backup-enable"] => Command::Schedule(true),
        ["--backup-disable"] => Command::Schedule(false),
        ["--rotation-review", selected] => Command::RotationReview(id(selected)?),
        ["--rotation-advance", selected, digest, next] => {
            Command::RotationAdvance(id(selected)?, sha(digest)?, action(next)?)
        }
        ["--remote-rotation-review"] => Command::RemoteRotationReview,
        ["--system-backup-create"] => Command::SystemBackupCreate,
        ["--backup-candidates"] => Command::Candidates,
        ["--system-query", "backups"] => Command::SystemQuery("backups"),
        ["--system-query", "backup-points"] => Command::SystemQuery("backup-points"),
        ["--system-query", "snapshots"] => Command::SystemQuery("snapshots"),
        ["--system-query", "history"] => Command::SystemQuery("history"),
        ["--remote-rotation-advance", digest, next] => {
            Command::RemoteRotationAdvance(sha(digest)?, action(next)?)
        }
        _ => return Err(Error("exact closed Root command arguments required".into())),
    };
    Ok(Some(command))
}
pub fn execute(command: Command) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let guard = Guard::observe()?;
    let permission = || {
        operation::root_only()?;
        enzimos_policy::namespaces::initial()?;
        guard.recheck()
    };
    permission()?;
    let mut progress = |_: &str| Ok(());
    match command {
        Command::ProvisionPlan(selection) => provision(&selection, None, &permission),
        Command::ProvisionApply(selection, digest, input) => {
            provision(&selection, Some((&digest, input)), &permission)
        }
        Command::ExportReview(tree, selection) => {
            let expected = export_observation(&guard, tree, &selection)?;
            permission()?;
            review_result(expected)
        }
        Command::Export(tree, selection, digest) => {
            let expected = export_observation(&guard, tree, &selection)?;
            require_review(&expected, &digest)?;
            permission()?;
            let runner = if tree {
                crate::backup_selective_coordinator::run_tree
            } else {
                crate::backup_selective_coordinator::run
            };
            runner(
                &guard,
                &files::random_hex(16)?,
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
        Command::DeliveryReview(selection) => {
            let expected = enzimos_policy::delivery_control::observation(&selection)?;
            permission()?;
            review_result(expected)
        }
        Command::Delivery(selection, digest) => {
            let expected = enzimos_policy::delivery_control::observation(&selection)?;
            require_review(&expected, &digest)?;
            permission()?;
            enzimos_policy::delivery_control::deliver(&selection, &expected, &mut || permission())
        }
        Command::CredentialReview(id) => {
            credential(&guard, "credential-review", &id, None, &permission)
        }
        Command::CredentialComplete(id, digest) => credential(
            &guard,
            "credential-complete",
            &id,
            Some(&digest),
            &permission,
        ),
        Command::Replicate(snapshot) => {
            let selection = value!({"snapshot":snapshot});
            let expected =
                crate::backup_remote_coordinator::observe(&guard, "remote-replicate", &selection)?;
            permission()?;
            crate::backup_remote_coordinator::run(
                &guard,
                "remote-replicate",
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
        Command::Retrieve(id, snapshot) => {
            let selection = value!({"id":id,"snapshot":snapshot});
            let expected =
                crate::backup_remote_coordinator::observe(&guard, "remote-retrieve", &selection)?;
            permission()?;
            crate::backup_remote_coordinator::run(
                &guard,
                "remote-retrieve",
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
        Command::Schedule(enabled) => {
            let expected = enzimos_policy::backup_schedule::observation(enabled)?;
            permission()?;
            enzimos_policy::backup_schedule::set(
                enabled,
                &files::random_hex(16)?,
                &expected,
                permission,
            )
        }
        Command::RotationReview(id) => {
            let selection = value!({"id":id});
            let expected = enzimos_policy::backup_rotation_review::observe(&guard, &selection)?;
            permission()?;
            crate::backup_rotation_coordinator::review(
                &guard,
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
        Command::RotationAdvance(id, digest, next) => {
            let selection = value!({"id":id,"review_sha256":digest,"action":next});
            let expected =
                enzimos_policy::backup_rotation_review::observe_advance(&guard, &selection)?;
            permission()?;
            crate::backup_rotation_coordinator::advance(
                &guard,
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
        Command::RemoteRotationReview => {
            let selection = value!({"rotation":"remote"});
            let expected =
                enzimos_policy::backup_remote_rotation_review::observe(&guard, &selection)?;
            permission()?;
            crate::backup_remote_rotation_coordinator::review(
                &guard,
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
        Command::Candidates => {
            // Same passive discovery as the System1 query: no mount or token use.
            let inventory = enzimos_policy::backup_candidates::Discovery::observe()?.inventory()?;
            permission()?;
            Ok(inventory)
        }
        Command::SystemQuery(name) => {
            use crate::system_provider::Provider;
            let native = crate::system_provider::Native::open()?;
            // A query blocks on D-Bus futures (the backup timer) from this
            // thread; only a multi-thread runtime drives them meanwhile.
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(|_| Error("system query runtime unavailable".into()))?;
            let _entered = runtime.enter();
            let result = native.query(name)?;
            permission()?;
            Ok(result)
        }
        Command::SystemBackupCreate => {
            // Test and maintenance use: what Settings "Back up now" runs, minus
            // the bus caller. The native provider plans exactly as System1 does
            // (server-measured, no selection), then its job entry verifies the
            // stored plan again and runs the same coordinator, retention and
            // destination lifetime. Nothing is recorded in the job ledger.
            use crate::system_provider::Provider;
            let native = crate::system_provider::Native::open()?;
            let id = files::random_hex(16)?;
            let plan = native.plan("backup-create", &Value::Null, &id, 0)?;
            permission()?;
            let mut commit = || permission();
            let mut phases = |phase: &str| {
                eprintln!("enzimos-backup: {phase}");
                Ok(())
            };
            let result = native.run(&plan, &mut phases, &mut commit)?;
            permission()?;
            Ok(value!({"request_id":id,"result":result}))
        }
        Command::RemoteRotationAdvance(digest, next) => {
            let selection = remote_advance_selection(&digest, &next)?;
            let expected =
                enzimos_policy::backup_remote_rotation_review::observe_advance(&guard, &selection)?;
            permission()?;
            crate::backup_remote_rotation_coordinator::advance(
                &guard,
                &selection,
                &expected,
                &permission,
                &mut progress,
            )
        }
    }
}
fn inherited_descriptor(s: &str) -> Result<i32> {
    let fd = s
        .parse::<i32>()
        .map_err(|_| Error("canonical input descriptor required".into()))?;
    enzimos_platform::require(
        fd >= 3 && fd.to_string() == s,
        "canonical input descriptor required",
    )?;
    Ok(fd)
}
fn provision_selection(selected: &str, candidate: &str, mode: &str, uid: &str) -> Result<Value> {
    let owner = uid
        .parse::<u32>()
        .map_err(|_| Error("ordinary setup owner required".into()))?;
    enzimos_platform::require(
        (1000..i32::MAX as u32).contains(&owner) && owner.to_string() == uid,
        "canonical ordinary setup owner required",
    )?;
    let mode = enzimos_policy::backup_setup_plan::Mode::parse(mode)?;
    Ok(
        value!({"id":id(selected)?,"selection_id":sha(candidate)?,"mode":mode.name(),"owner_uid":owner}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn provision(
    selection: &Value,
    apply: Option<(&str, i32)>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    use enzimos_policy::{
        backup_candidates::Discovery,
        backup_mount_review::{self, Review},
        backup_secret_input::Validated,
        backup_setup_plan::{Mode, Plan},
    };
    use std::{
        fs::File,
        os::fd::{AsFd, FromRawFd},
    };
    let lock = enzimos_policy::operation::lock()?;
    let discovery = Discovery::observe()?;
    let candidate = discovery.select(selection["selection_id"].as_str().unwrap())?;
    let id = selection["id"].as_str().unwrap();
    let permission = || {
        lock.recheck()?;
        discovery.recheck()?;
        authorize()
    };
    permission()?;
    if apply.is_none() {
        backup_mount_review::review(&candidate, id, &lock, &permission)?;
    }
    // Apply opens the actual durable mount review, then measures a NEW typed
    // plan. No decoded plan, prior grant, input path or worker receipt is adopted.
    let review = Review::open(&candidate, id, &lock, &permission)?;
    let plan = Plan::observe(
        &review,
        id,
        selection["owner_uid"].as_u64().unwrap() as u32,
        Mode::parse(selection["mode"].as_str().unwrap())?,
        &lock,
        &permission,
    )?;
    if let Some((digest, input)) = apply {
        enzimos_platform::require(plan.digest()? == digest, "standalone setup review changed")?;
        enzimos_platform::require(
            unsafe { libc::fcntl(input, libc::F_GETFD) } >= 0,
            "setup input descriptor unavailable",
        )?;
        let input = unsafe { File::from_raw_fd(input) };
        let validated = Validated::retain(
            input.as_fd(),
            selection["owner_uid"].as_u64().unwrap() as u32,
            &permission,
        )?;
        let finished =
            crate::backup_setup_coordinator::run(&plan, digest, &validated, &lock, &permission)?;
        permission()?;
        Ok(finished.result().clone())
    } else {
        let original = plan.value()?;
        permission()?;
        Ok(value!({"schema":1,"plan_sha256":plan.digest()?,"plan":original}))
    }
}

// These are selection data only. Every execution constructs fresh original
// descriptor-backed observations, then the coordinator checks them again under
// its operation lock. A digest never reconstructs a grant or worker witness.
fn export_selection(selected: &str, snapshot: &str, path: &str) -> Result<Value> {
    let selection = value!({"id":id(selected)?,"snapshot":sha(snapshot)?,"path":path});
    enzimos_policy::backup_selective_request::selection(&selection)?;
    Ok(selection)
}
fn delivery_selection(selected: &str, grant: &str) -> Result<Value> {
    Ok(value!({"id":id(selected)?,"grant_sha256":sha(grant)?}))
}
fn export_observation(guard: &Guard, tree: bool, selection: &Value) -> Result<Value> {
    if tree {
        enzimos_policy::backup_selective_review::observe_tree(guard, selection)
    } else {
        enzimos_policy::backup_selective_review::observe(guard, selection)
    }
}
fn review_result(observation: Value) -> Result<Value> {
    Ok(
        value!({"schema":1,"review_sha256":enzimos_platform::json::fingerprint(&observation)?,
               "observation":observation}),
    )
}
fn require_review(observation: &Value, digest: &str) -> Result<()> {
    sha(digest)?;
    enzimos_platform::require(
        enzimos_platform::json::fingerprint(observation)? == digest,
        "standalone review changed; fresh review required",
    )
}

fn remote_advance_selection(digest: &str, next: &str) -> Result<Value> {
    let selection = value!({"rotation":"remote","review_sha256":digest,"action":next});
    enzimos_policy::backup_remote_rotation_review::advance_selection(&selection)?;
    Ok(selection)
}

fn credential(
    guard: &Guard,
    role: &str,
    id: &str,
    digest: Option<&str>,
    permission: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    let selection = match digest {
        Some(digest) => value!({"id":id,"review_sha256":digest}),
        None => value!({"id":id}),
    };
    let expected = enzimos_policy::backup_credential_review::observe(guard, role, id)?;
    permission()?;
    crate::backup_credential_coordinator::run(
        guard,
        role,
        &files::random_hex(16)?,
        &selection,
        &expected,
        permission,
        &mut |_| Ok(()),
    )
}
