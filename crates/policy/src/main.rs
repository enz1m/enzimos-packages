// SPDX-License-Identifier: MIT
//! Fixed native policy entry point; covered operations retain one global lock.
use enzimos_platform::{Error, Result, json, require};
use enzimos_policy::{
    fallback, media_origin, operation, recovery_activation_runtime as activation,
    recovery_adoption, recovery_confirmation, recovery_image_build, recovery_image_publish,
    recovery_plan, recovery_run_stage, recovery_stage as stage, recovery_workflow as workflow,
};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, io::Write};
fn flags(args: &[String], expected: &[&str]) -> Result<BTreeMap<String, String>> {
    require(
        args.len() == expected.len() * 2,
        "exact native policy options required",
    )?;
    let mut result = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let name = pair[0]
            .strip_prefix("--")
            .ok_or_else(|| Error("native policy option syntax".into()))?;
        require(
            expected.contains(&name)
                && pair[1].len() <= 4096
                && !pair[1].contains('\0')
                && result.insert(name.to_owned(), pair[1].clone()).is_none(),
            "unknown or duplicate native policy option",
        )?;
    }
    require(
        expected.iter().all(|s| result.contains_key(*s)),
        "missing native policy option",
    )?;
    Ok(result)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn run(args: &[String]) -> Result<Value> {
    require(
        args.len() >= 2 && args.len() <= 16,
        "native policy command required",
    )?;
    if args == ["delivery-copy-worker", "--fd3"] {
        use std::os::fd::FromRawFd;
        require(
            // SAFETY: F_GETFD takes no pointers; it only checks that descriptor 3 is open.
            unsafe { libc::fcntl(3, libc::F_GETFD) } >= 0,
            "delivery worker channel unavailable",
        )?;
        // SAFETY: The parent passed descriptor 3 to this worker alone, checked open above, and it
        // is adopted once.
        let file = unsafe { std::fs::File::from_raw_fd(3) };
        enzimos_policy::delivery_copy_worker::entry(
            enzimos_platform::fd_packet::Packet::from_file(file)?,
        )?;
        return Ok(Value::Null);
    }
    let scope = args[0].as_str();
    let action = args[1].as_str();
    let rest = &args[2..];
    let expected: &[&str] = match (scope, action) {
        ("desktop", "setup" | "setup-everyday") => &["root"],
        ("desktop", "crash-reports" | "gaming-check") => &[],
        ("memory", "condition" | "run") => &[],
        ("backup-recovery", "save") => {
            &["descriptor", "directory", "name", "backup-filesystem-uuid"]
        }
        ("backup-recovery", "print") => &["descriptor", "document-fd"],
        ("generation" | "root-ownership", "status") => &[],
        ("generation", "pin") => &["id", "generation"],
        ("generation", "pins") => &[],
        ("lifecycle", "plan") if rest.len() == 2 => &["inventory"],
        ("lifecycle", "plan") => &["inventory", "keep-good"],
        ("authority", "check" | "refresh" | "refresh-auto" | "hook") => &[],
        ("secure-boot", "sign") => &["source"],
        ("secure-boot", "status" | "create-key" | "enroll-db" | "enable" | "abandon") => &[],
        ("secure-boot", "build-uki") => &["kernel", "initrd", "options", "destination"],
        ("deferred", "status" | "resume") => &[],
        ("maintenance", "trim" | "scrub") => &[],
        ("deferred", "clear") => &["action"],
        ("delivery", "grant") => &["id", "export", "uid"],
        ("delivery", "cancel") => &["id", "grant-sha256"],
        ("delivery", "status") => &["id"],
        ("fallback", "create") => &["id"],
        ("update", "plan" | "apply") => &[],
        ("backup", "capture-stage-review" | "init" | "retain") => &[],
        ("backup-setup", "reset-uncertain") => &[],
        ("backup", "restore-system" | "restore-complete") => &["snapshot", "target-uuid"],
        ("backup-complete", "boot") => &["stage-uuid"],
        ("backup-complete", "prepare") => &[
            "stage-uuid",
            "root-uuid",
            "home-uuid",
            "boot-uuid",
            "luks-uuid",
        ],
        ("backup-remote", "init" | "check" | "retain") => &[],
        ("backup-rotation", "prepare") => &["id"],
        ("backup-credentials", "enroll") => &["id"],
        ("home-history", "create" | "create-auto") => &[],
        ("home-retention", "plan") => &[],
        ("generation", "confirm-current") => &[],
        ("boot-inventory", "collect" | "collect-native") => &[],
        ("boot-retire", "plan") => &["generation"],
        ("boot-retire", "resume-review") => &["id"],
        ("boot-retire", "resume") => &["id", "review-sha256"],
        ("boot-retire", "status" | "auto") => &[],
        ("boot-retire", "retire") => &["generation", "plan-sha256"],
        ("root-retire", "stage") => &["id", "image", "exit"],
        ("root-retire", "plan") => &["root-uuid"],
        ("root-retire", "finish" | "delete" | "abandon") => &["id"],
        ("root-retire", "prepare") => &["root-uuid", "plan-sha256"],
        ("root-retire", "status" | "auto") => &[],
        ("system", "status") => &[],
        ("root-rebind", "status") => &[],
        ("root-rebind", "resume") => &["transaction"],
        ("recovery-image" | "recovery-stage", "status") => &[],
        ("recovery-publication", "review") => &["id"],
        ("recovery-publication", "resume") => &["id", "journal-sha256"],
        ("recovery-image", "confirm-current") => &[],
        ("recovery-image", "build" | "first-boot") => &["kernel", "options"],
        ("recovery-image", "publish") => &["options"],
        ("recovery-stage", "stage" | "review") => &["id", "plan-sha256"],
        ("recovery-stage", "prepare") => &["id", "birth", "generation"],
        ("recovery-run", "stage") => &["id", "plan-sha256", "flavor", "image", "exit", "automatic"],
        ("recovery-activation", "prepare") => &["id", "job-sha256"],
        ("recovery-activation", "publish") => &["id", "intent-sha256"],
        ("recovery-activation", "select") => &["id", "intent-sha256", "flavor"],
        ("recovery-workflow", "execute") => &["id", "plan-sha256", "flavor"],
        ("recovery-workflow", "status") => &["id", "plan-sha256"],
        ("media-origin", "init" | "show") => &[],
        ("recovery-activation", "confirm-current") => &[],
        ("recovery-activation", "adopt") => &["id", "intent-sha256"],
        ("recovery-run", "finish") => &["id"],
        _ => return Err(Error("unknown native policy command".into())),
    };
    let mut options = flags(rest, expected)?;
    if (scope, action) == ("lifecycle", "plan") {
        options
            .entry("keep-good".into())
            .or_insert_with(|| "2".into());
    }
    if scope == "backup-recovery" {
        use std::os::fd::FromRawFd;
        #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
        fn descriptor(s: &str) -> Result<i32> {
            let fd = s
                .parse::<i32>()
                .map_err(|_| Error("recovery descriptor required".into()))?;
            require(
                // SAFETY: F_GETFD takes no pointers; it only checks that the number is open.
                fd >= 3 && fd.to_string() == s && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
                "canonical inherited recovery descriptor required",
            )?;
            Ok(fd)
        }
        let input = descriptor(&options["descriptor"])?;
        if action == "print" {
            let output = descriptor(&options["document-fd"])?;
            require(input != output, "distinct recovery descriptors required")?;
            return enzimos_policy::backup_recovery_print::render(
                // SAFETY: The caller passed this canonical inherited descriptor, checked open
                // above, and it is adopted once.
                unsafe { std::fs::File::from_raw_fd(input) },
                // SAFETY: The caller passed this canonical inherited descriptor, checked open
                // above, and it is adopted once. It differs from `input`.
                unsafe { std::fs::File::from_raw_fd(output) },
            );
        }
        return enzimos_policy::backup_recovery_save::save(
            // SAFETY: The caller passed this canonical inherited descriptor, checked open above,
            // and it is adopted once.
            unsafe { std::fs::File::from_raw_fd(input) },
            std::path::Path::new(&options["directory"]),
            &options["name"],
            &options["backup-filesystem-uuid"],
        );
    }
    if (scope, action) == ("root-ownership", "status") {
        return enzimos_policy::birth_runtime::status();
    }
    if scope == "memory" {
        return enzimos_policy::memory::launch(action);
    }
    if scope == "desktop" {
        return match action {
            "setup" | "setup-everyday" => enzimos_policy::desktop_setup::configure(
                std::path::Path::new(&options["root"]),
                action == "setup-everyday",
            ),
            "crash-reports" => enzimos_policy::desktop_crash_reports::read(),
            "gaming-check" => enzimos_policy::desktop_gaming_check::check(),
            _ => Err(Error("fixed desktop action required".into())),
        };
    }
    if (scope, action) == ("generation", "status") {
        let lock = operation::lock()?;
        let transaction = enzimos_policy::catalog::Transaction::begin()?;
        let births = enzimos_policy::birth_runtime::Store::open(false)?;
        require(
            births.configuration() == &transaction.config,
            "generation/birth source changed",
        )?;
        let rebinds = enzimos_policy::root_rebind_runtime::status()?;
        births.recheck()?;
        transaction.recheck()?;
        lock.recheck()?;
        let pending_births: Vec<_> = births
            .records
            .iter()
            .filter(|(_, r)| !matches!(r["phase"].as_str(), Some("ready" | "retired")))
            .map(|(id, _)| id.clone())
            .collect();
        return Ok(
            value!({"status":"publisher-registry-only","catalog":transaction.data,
            "pending_rebinds":rebinds["pending"],"pending_births":pending_births,"retirement_enabled":true,
            "root_ownership_established":false,"independent_recovery_confirmation_available":false}),
        );
    }
    if (scope, action) == ("lifecycle", "plan") {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let keep = options["keep-good"]
            .parse::<usize>()
            .map_err(|_| Error("canonical keep-good required".into()))?;
        require(
            keep.to_string() == options["keep-good"],
            "canonical keep-good required",
        )?;
        // This unprivileged input is preview data only, never a storage actor.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&options["inventory"])?;
        let m = file.metadata()?;
        require(
            m.is_file() && m.size() <= enzimos_policy::lifecycle::LIMIT as u64,
            "bounded regular preview inventory required",
        )?;
        let bytes = enzimos_platform::files::read_file(
            &file,
            enzimos_policy::lifecycle::LIMIT,
            None,
            false,
        )?;
        return enzimos_policy::lifecycle::plan(
            &json::decode(&bytes, enzimos_policy::lifecycle::LIMIT)?,
            keep,
        );
    }
    if scope == "boot-inventory" {
        return if action == "collect-native" {
            enzimos_policy::boot_inventory::collect()
        } else {
            enzimos_policy::boot_inventory_legacy::collect()
        };
    }
    if scope == "delivery" {
        operation::root_only()?;
        return match action {
            "grant" => {
                let uid = options["uid"]
                    .parse::<u32>()
                    .map_err(|_| Error("ordinary delivery UID required".into()))?;
                require(
                    uid.to_string() == options["uid"],
                    "canonical delivery UID required",
                )?;
                let selection = value!({"id":options["id"],"export":options["export"],"uid":uid});
                let observed = enzimos_policy::delivery_grant::observation(&selection)?;
                let mut result = enzimos_policy::delivery_grant::grant(
                    &selection,
                    &observed,
                    &mut operation::root_only,
                )?;
                result["status"] = value!("explicit-admin-delivery-granted");
                Ok(result)
            }
            "cancel" => {
                let selection = value!({"id":options["id"],"grant_sha256":options["grant-sha256"]});
                let observed = enzimos_policy::delivery_cancel::observation(&selection)?;
                let mut result = enzimos_policy::delivery_cancel::cancel(
                    &selection,
                    &observed,
                    &mut operation::root_only,
                )?;
                enzimos_platform::json::object_mut(&mut result)?.remove("grant_id");
                result["id"] = value!(options["id"]);
                Ok(result)
            }
            "status" => enzimos_policy::delivery_cancel::status(&options["id"]),
            _ => unreachable!(),
        };
    }
    if (scope, action) == ("system", "status") {
        return enzimos_policy::system_query::system();
    }
    if (scope, action) == ("home-history", "create") {
        return enzimos_policy::home_history_create::create(None, || Ok(()));
    }
    if (scope, action) == ("home-history", "create-auto") {
        return enzimos_policy::home_history_auto::create();
    }
    if scope == "secure-boot" && matches!(action, "sign" | "build-uki") {
        secure_options(action, &options)?;
    }
    if (scope, action) == ("root-rebind", "status") {
        return enzimos_policy::root_rebind_runtime::status();
    }
    if (scope, action) == ("authority", "hook") {
        return enzimos_policy::authority_hook_proxy::request();
    }
    if (scope, action) == ("authority", "refresh-auto") {
        return match enzimos_policy::deferred::admit("authority")? {
            enzimos_policy::deferred::Admission::Entered(lock) => {
                enzimos_policy::authority_publish::refresh_locked(&lock)
            }
            enzimos_policy::deferred::Admission::Deferred(_) => {
                Ok(value!({"status":"authority-refresh-deferred-to-next-boot"}))
            }
        };
    }
    if scope == "maintenance" {
        return enzimos_policy::maintenance::maintain(action);
    }
    if (scope, action) == ("secure-boot", "create-key") {
        return enzimos_policy::secure_boot::create_key();
    }
    if (scope, action) == ("secure-boot", "abandon") {
        // The ordinary lock refuses while an enablement is unfinished.
        let lock = operation::lock_for_enable_abandon()?;
        return enzimos_policy::signed_entry::enable::abandon_locked(&lock);
    }
    if (scope, action) == ("boot-retire", "auto") {
        // Lock contention exits 75 so the timer's service retries later.
        let Some(lock) = operation::try_lock()? else {
            return Ok(value!({"status":"operation-lock-busy","retry":true}));
        };
        let guard = enzimos_policy::storage_runtime::Guard::observe()?;
        let result =
            enzimos_policy::generation_retention::retain_locked(&guard, &lock, &mut || {
                guard.recheck()?;
                lock.recheck()
            })?;
        // A stopped run left a retirement journal for review: report failure so
        // the unit (and the journal) show it instead of a silent success.
        if !result["stopped"].is_null() {
            write_value(&result)?;
            return Err(Error(
                "generation retention stopped; a retirement journal needs review".into(),
            ));
        }
        return Ok(result);
    }
    if (scope, action) == ("root-retire", "auto") {
        // Same contract as boot-retire auto: lock contention exits 75.
        let Some(lock) = operation::try_lock()? else {
            return Ok(value!({"status":"operation-lock-busy","retry":true}));
        };
        let guard = enzimos_policy::storage_runtime::Guard::observe()?;
        let result =
            enzimos_policy::root_retirement_auto::retain_locked(&guard, &lock, &mut || {
                guard.recheck()?;
                lock.recheck()
            })?;
        if !result["stopped"].is_null() {
            write_value(&result)?;
            return Err(Error(
                "root retention stopped; a root retirement receipt needs review".into(),
            ));
        }
        return Ok(result);
    }
    // The one-attempt first-boot image build starts alongside other boot-time
    // policy units; it waits for them instead of failing on a held lock.
    let lock = if (scope, action) == ("recovery-image", "first-boot") {
        operation::lock_wait(std::time::Duration::from_secs(900))?
    } else {
        operation::lock()?
    };
    match (scope, action) {
        ("boot-retire", "resume") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::boot_retirement_continuation::resume_locked(
                &guard,
                &lock,
                &options["id"],
                &options["review-sha256"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
                &mut |_| Ok(()),
            )
        }
        ("boot-retire", "resume-review") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::boot_retirement_continuation::review_locked(
                &guard,
                &lock,
                &options["id"],
            )
        }
        ("root-retire", "prepare") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::root_retirement_online_intent::prepare_locked(
                &guard,
                &lock,
                &options["root-uuid"],
                &options["plan-sha256"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
                &mut |phase| write_value(&value!({"phase":phase})),
            )
        }
        ("root-retire", "status") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            let rows = enzimos_policy::control_registry::read(
                &guard,
                "root-retirements",
                16,
                enzimos_policy::root_retirement_record::validate,
            )?;
            let result = rows
                .into_iter()
                .map(|(id, row)| {
                    (
                        id,
                        value!({"phase":row["phase"],"next_step":row["next_step"],
                            "inflight":row["inflight"],"staged":row.get("coordinator").is_some()}),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            guard.recheck()?;
            lock.recheck()?;
            Ok(value!(result))
        }
        ("root-retire", "delete") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::root_retirement_online_delete::delete_locked(
                &guard,
                &lock,
                &options["id"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("root-retire", "abandon") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::root_retirement_online_delete::abandon_locked(
                &guard,
                &lock,
                &options["id"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("root-retire", "finish") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::root_retirement_online_finish_origin::finish_locked(
                &guard,
                &lock,
                &options["id"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("boot-retire", "plan") => {
            enzimos_policy::identity::safe_id(&options["generation"])?;
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            let mut authorize = || {
                guard.recheck()?;
                lock.recheck()
            };
            let context = enzimos_policy::boot_retirement_context::Context::observe(
                &guard,
                &lock,
                &options["generation"],
                &mut authorize,
            )?;
            context.preview_plan(&mut authorize)
        }
        ("root-retire", "plan") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::root_retirement_online_intent::plan_locked(
                &guard,
                &lock,
                &options["root-uuid"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("boot-retire", "status") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::boot_retirement_cli::status_locked(&guard, &lock)
        }
        ("boot-retire", "retire") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::boot_retirement_cli::retire_locked(
                &guard,
                &lock,
                &options["generation"],
                &options["plan-sha256"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
                &mut |phase| write_value(&value!({"phase":phase})),
            )
        }
        ("root-retire", "stage") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::root_retirement_cli_stage::stage_locked(
                &guard,
                &lock,
                &options["id"],
                &options["image"],
                &options["exit"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
                &mut |phase| write_value(&value!({"phase":phase})),
            )
        }
        ("backup", "restore-system" | "restore-complete") => {
            enzimos_policy::backup_restic_runtime::system_restore::stage_auto_locked(
                &lock,
                &options["snapshot"],
                &options["target-uuid"],
                action == "restore-complete",
            )
        }
        ("backup-complete", "boot") => {
            enzimos_policy::backup_restic_runtime::system_restore::boot_complete::publish_locked(
                &lock,
                &options["stage-uuid"],
            )
        }
        ("backup-complete", "prepare") => {
            let luks = match options["luks-uuid"].as_str() {
                "none" => None,
                value => Some(value),
            };
            enzimos_policy::backup_restic_runtime::system_restore::complete::prepare_locked(
                &lock,
                &options["stage-uuid"],
                &options["root-uuid"],
                &options["home-uuid"],
                &options["boot-uuid"],
                luks,
            )
        }
        ("backup-rotation", "prepare") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::backup_rotation_prepare::prepare_locked(
                &guard,
                &lock,
                &options["id"],
                &mut operation::root_only,
                &mut |_| Ok(()),
            )
        }
        ("backup-setup", "reset-uncertain") => {
            enzimos_policy::backup_setup_reset::reset_locked(&lock)
        }
        ("backup", "retain") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::backup_restic_runtime::retention::retain_attached_locked(&guard, &lock)
        }
        ("backup-credentials", "enroll") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::backup_restic_runtime::enrollment::enroll_locked(
                &guard,
                &lock,
                &options["id"],
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("secure-boot", "enroll-db") => {
            enzimos_policy::secure_owner_source::enrollment::enroll_locked(&lock)
        }
        ("secure-boot", "enable") => enzimos_policy::signed_entry::enable::enable_locked(&lock),
        ("secure-boot", "status") => {
            let mut status = enzimos_policy::secure_boot::firmware()?;
            status["configured"] = value!(enzimos_policy::secure_boot::configured()?);
            lock.recheck()?;
            Ok(status)
        }
        ("backup-remote", "retain") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            Ok(
                enzimos_policy::backup_restic_runtime::remote_retention::after_copy_locked(
                    &guard,
                    &lock,
                    None,
                    &mut || {
                        guard.recheck()?;
                        lock.recheck()
                    },
                ),
            )
        }
        ("backup-remote", "check") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::backup_restic_runtime::remote_check::check_locked(
                &guard,
                &lock,
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("backup-remote", "init") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::backup_remote_initialize::initialize_locked(&guard, &lock, &mut || {
                guard.recheck()?;
                lock.recheck()
            })
        }
        ("backup", "init") => {
            let guard = enzimos_policy::storage_runtime::Guard::observe()?;
            enzimos_policy::backup_destination::initialize::initialize_locked(
                &guard,
                &lock,
                &mut || {
                    guard.recheck()?;
                    lock.recheck()
                },
            )
        }
        ("backup", "capture-stage-review") => enzimos_policy::backup_capture_runtime::stage_review(
            &lock,
            &mut |phase| write_value(&value!({"phase":phase})),
            &mut || lock.recheck(),
        ),
        ("home-retention", "plan") => enzimos_policy::home_retention::observation(),
        ("generation", "pins") => enzimos_policy::generation_pins::status_locked(&lock),
        ("generation", "pin") => enzimos_policy::generation_pins::pin_locked(
            &options["id"],
            &options["generation"],
            &lock,
        ),
        ("generation", "confirm-current") => {
            enzimos_policy::generation_confirmation::confirm_locked(&lock)
        }
        ("update", "apply") => {
            enzimos_policy::update_apply_runtime::apply_locked_with_progress(&lock, &mut |phase| {
                write_value(&value!({"phase":phase}))
            })
        }
        ("update", "plan") => Ok(enzimos_policy::update_plan::Plan::observe_locked(&lock)?
            .document()
            .clone()),
        ("secure-boot", "sign") => enzimos_policy::secure_artifacts::sign_locked(
            std::path::Path::new(&options["source"]),
            None,
            &lock,
        ),
        ("secure-boot", "build-uki") => enzimos_policy::secure_artifacts::build_uki_locked(
            std::path::Path::new(&options["kernel"]),
            std::path::Path::new(&options["initrd"]),
            &options["options"],
            std::path::Path::new(&options["destination"]),
            &lock,
        ),
        ("authority", "check") => enzimos_policy::authority_check::check_locked(&lock),
        ("authority", "refresh") => enzimos_policy::authority_publish::refresh_locked(&lock),
        ("deferred", "status") => enzimos_policy::deferred_runtime::status(),
        ("deferred", "resume") => enzimos_policy::deferred_runtime::resume(),
        ("deferred", "clear") => {
            Ok(value!({"cleared":enzimos_policy::deferred_runtime::clear(&options["action"])?}))
        }
        ("fallback", "create") => fallback::create_locked(&options["id"], &lock, |_, _| Ok(())),
        ("root-rebind", "resume") => {
            enzimos_policy::root_rebind_runtime::resume_locked(&options["transaction"], &lock)
        }
        ("recovery-publication", "review") => {
            enzimos_policy::recovery_publication_runtime::review_locked(&options["id"], &lock)
        }
        ("recovery-publication", "resume") => {
            enzimos_policy::recovery_publication_runtime::resume_locked(
                &options["id"],
                &options["journal-sha256"],
                &lock,
            )
        }
        ("recovery-stage", "status") => stage::status_locked(&lock),
        ("recovery-image", "status") => enzimos_policy::recovery_image::status_locked(&lock),
        ("recovery-image", "confirm-current") => recovery_confirmation::confirm_locked(&lock),
        ("recovery-image", "build") => {
            recovery_image_build::build_locked(&options["kernel"], &options["options"], &lock)
        }
        ("recovery-image", "first-boot") => {
            recovery_image_build::first_boot_locked(&options["kernel"], &options["options"], &lock)
        }
        ("recovery-image", "publish") => {
            recovery_image_publish::publish_locked(&options["options"], &lock)
        }
        ("recovery-stage", "prepare") => recovery_plan::prepare_locked(
            &options["id"],
            &options["birth"],
            &options["generation"],
            &lock,
        ),
        ("recovery-run", "stage") => {
            let automatic = match options["automatic"].as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(Error("automatic must be true or false".into())),
            };
            recovery_run_stage::stage_locked(
                &options["id"],
                &options["plan-sha256"],
                &options["flavor"],
                &options["image"],
                &options["exit"],
                automatic,
                &lock,
            )
        }
        ("recovery-stage", "stage") => stage::stage_locked(
            &options["id"],
            &options["plan-sha256"],
            &lock,
            |_, _| Ok(()),
        ),
        ("recovery-stage", "review") => {
            stage::review_locked(&options["id"], &options["plan-sha256"], &lock)
        }
        ("recovery-activation", "prepare") => {
            activation::prepare_locked(&options["id"], &options["job-sha256"], &lock)
        }
        ("recovery-activation", "publish") => {
            activation::publish_locked(&options["id"], &options["intent-sha256"], &lock, |_| Ok(()))
        }
        ("recovery-activation", "select") => activation::select_locked(
            &options["id"],
            &options["intent-sha256"],
            &options["flavor"],
            &lock,
            |_| Ok(()),
        ),
        ("recovery-workflow", "execute") => workflow::execute_locked(
            &options["id"],
            &options["plan-sha256"],
            &options["flavor"],
            &lock,
            |_, _| Ok(()),
        ),
        ("recovery-workflow", "status") => {
            workflow::status_locked(&options["id"], &options["plan-sha256"], &lock)
        }
        ("media-origin", "init") => media_origin::initialize(),
        ("media-origin", "show") => media_origin::current(),
        ("recovery-activation", "confirm-current") => recovery_confirmation::confirm_locked(&lock),
        ("recovery-activation", "adopt") => {
            recovery_adoption::adopt_locked(&options["id"], &options["intent-sha256"], &lock)
        }
        ("recovery-run", "finish") => recovery_confirmation::finish_locked(&options["id"], &lock),
        _ => unreachable!(),
    }
}
/// Exit status of one command: 75 is work deferred by a busy operation lock
/// (units with `RestartForceExitStatus=75` retry it), 2 a failure.
fn exit_code(result: &Result<Value>, recovery: bool) -> i32 {
    match result {
        Ok(value)
            if (value["status"] == "deferred" && value["owed_after_reboot"] == true)
                || value["status"] == "operation-lock-busy" =>
        {
            75
        }
        Ok(value) if value["status"] == "memory-policy-disabled" => 1,
        Ok(_) => 0,
        Err(_) if recovery => 1,
        Err(_) => 2,
    }
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (getrlimit, prctl, setrlimit)."
)]
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let recovery_action = if args.first().is_some_and(|s| s == "backup-recovery") {
        args.get(1)
            .map(String::as_str)
            .filter(|s| matches!(*s, "save" | "print"))
    } else {
        None
    };
    let result = (|| -> Result<Value> {
        let mut caller = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `caller` is a writable rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut caller) } == 0 {
            let _ = enzimos_policy::desktop_gaming_check::CALLER_NOFILE
                .set((caller.rlim_cur, caller.rlim_max));
        }
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        require(
            // SAFETY: `core` is a valid rlimit that outlives the call.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0
                // SAFETY: This prctl option takes no pointers.
                && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "native policy process protection unavailable",
        )?;
        let descriptors = libc::rlimit {
            rlim_cur: 4096,
            rlim_max: 4096,
        };
        require(
            // SAFETY: `descriptors` is a valid rlimit that outlives the call.
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &descriptors) } == 0,
            "native policy retained descriptor budget unavailable",
        )?;
        run(&args)
    })();
    let code = exit_code(&result, recovery_action.is_some());
    let output = match result {
        Ok(value) => value,
        Err(error) => match recovery_action {
            Some("print") => value!({"schema":1,"status":"recovery-print-document-not-ready",
                "reason":"Save a private recovery file or retry printing.","confirmation_recorded":false}),
            Some("save") => value!({"schema":1,"status":"recovery-file-not-saved",
                "reason":error.to_string(),"confirmation_recorded":false}),
            _ => value!({"error":error.to_string()}),
        },
    };
    let write = write_value(&output);
    std::process::exit(if write.is_err() { 2 } else { code });
}
fn write_value(output: &Value) -> Result<()> {
    let mut bytes = json::canonical(output)?;
    bytes.push(b'\n');
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.flush()?;
    Ok(())
}
fn secure_options(action: &str, options: &BTreeMap<String, String>) -> Result<()> {
    if action == "sign" {
        require(
            matches!(
                options["source"].as_str(),
                "/boot/EFI/systemd/systemd-bootx64.efi"
                    | "/boot/EFI/BOOT/BOOTX64.EFI"
                    | "/boot/EFI/enzimos/refind_x64.efi"
                    | "/boot/EFI/enzimos/select-entry.efi"
            ),
            "initial signing source outside fixed boot-loader registry",
        )
    } else {
        let flavor = options["kernel"]
            .strip_prefix("/boot/vmlinuz-")
            .filter(|f| matches!(*f, "linux" | "linux-lts"))
            .ok_or_else(|| Error("initial UKI kernel outside fixed dual-kernel registry".into()))?;
        require(
            options["initrd"] == format!("/boot/initramfs-{flavor}.img")
                && options["destination"]
                    .strip_prefix("/boot/enzimos/secure-boot/")
                    .and_then(|s| s.strip_suffix(".efi"))
                    .is_some_and(|s| enzimos_policy::identity::sha(s).is_ok())
                && !options["options"].is_empty()
                && options["options"].len() <= 4096
                && options["options"].bytes().all(|b| (32..127).contains(&b)),
            "initial UKI paths, pairing or options refused",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_busy_operation_lock_defers_and_real_failures_still_fail() {
        let busy = Ok(value!({"status":"operation-lock-busy","retry":true}));
        assert_eq!(exit_code(&busy, false), 75);
        let owed = Ok(value!({"status":"deferred","owed_after_reboot":true}));
        assert_eq!(exit_code(&owed, false), 75);
        assert_eq!(exit_code(&Ok(value!({"snapshot":66})), false), 0);
        let busy_error = Err(Error(enzimos_policy::operation::BUSY.into()));
        assert_eq!(exit_code(&busy_error, false), 2);
        assert_eq!(exit_code(&Err(Error("snapper failed".into())), false), 2);
        assert_eq!(exit_code(&Err(Error("x".into())), true), 1);
    }
}
