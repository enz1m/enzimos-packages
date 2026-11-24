// SPDX-License-Identifier: MIT
//! Root command entry for the same original supervised capture/transfer path.
//! Borrow existing mounts or own one configured mount through normal closure.
use enzimos_platform::{Result, files};
use enzimos_policy::{
    backup_admission::OptIn,
    backup_configuration::{Configuration, SourceScope},
    backup_credential::Credential,
    backup_running::Run,
    backup_share_destination::{self as primary, ShareScope},
    deferred::{self, Admission},
    operation,
    storage_runtime::Guard,
};
use serde_json::{Value, json as value};
/// Run a backup and record how it ended; without a backup drive it goes into
/// the ready NAS share. A scheduled run with the backup drive
/// unplugged is not a failure: it is recorded as waiting for the drive (the
/// backup starts when the drive is connected) and exits successfully. A backup
/// is recorded as `ok` as soon as it is published, before cleanup and the copy
/// to the NAS share, so neither can turn it into a failure.
pub fn create(automatic: bool) -> Result<Value> {
    let mut created = false;
    let result = create_inner(automatic, &mut created);
    settle(result, created, automatic, &mut |error| {
        enzimos_policy::backup_run_status::record_outcome(Some(error));
    })
}
/// The run status a finished run still owes: a published backup is already
/// recorded as `ok`, so a later cleanup, copy or recheck error leaves it.
fn settle(
    result: Result<Value>,
    created: bool,
    automatic: bool,
    record_failure: &mut dyn FnMut(&str),
) -> Result<Value> {
    use enzimos_policy::backup_run_status as run;
    match result {
        Ok(result) => Ok(result),
        Err(error) if created => Err(error),
        Err(error) => {
            record_failure(&error.0);
            if automatic && run::is_absent(&error.0) {
                Ok(value!({"status":"waiting-for-drive"}))
            } else {
                Err(error)
            }
        }
    }
}
fn create_inner(automatic: bool, created: &mut bool) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    // A revoked or absent opt-in returns before source capture, vendor reads,
    // repository access or any daemon start.
    let marker = if automatic {
        match OptIn::open()? {
            Some(marker) => Some(marker),
            None => {
                enzimos_policy::deferred_runtime::clear("backup")?;
                return Ok(value!({"status":"disabled-no-source-scan"}));
            }
        }
    } else {
        None
    };
    let lock = if automatic {
        match deferred::admit("backup")? {
            Admission::Entered(lock) => lock,
            Admission::Deferred(_) => {
                return Ok(
                    value!({"status":"deferred","action":"automatic-backup","reason":"operation-lock-busy","owed_after_reboot":true}),
                );
            }
        }
    } else {
        operation::lock()?
    };
    if let Some(marker) = &marker {
        marker.recheck()?;
    }
    let guard = Guard::observe()?;
    match primary::primary() {
        Some(primary::SHARE) => return create_share(&guard, &lock, marker.as_ref(), created),
        Some(_) => {}
        None => {
            return Err(enzimos_platform::Error(
                enzimos_policy::backup_destination_attach::NOT_CONFIGURED.into(),
            ));
        }
    }
    let configuration = Configuration::open()?;
    let pin = enzimos_policy::backup_admission::StoredPin::open(&configuration, &guard)?;
    let credential = Credential::open()?;
    let confirmation = if let Some(marker) = &marker {
        marker.verify_stored(&configuration, &pin)?;
        Some(enzimos_policy::backup_recovery_confirmation::Stored::open(
            &configuration,
            &pin,
            &credential,
        )?)
    } else {
        None
    };
    let permission = || {
        operation::root_only()?;
        enzimos_policy::namespaces::initial()?;
        lock.recheck()?;
        guard.recheck()?;
        configuration.recheck()?;
        pin.recheck()?;
        credential.recheck()?;
        if let Some(marker) = &marker {
            marker.verify_stored(&configuration, &pin)?;
        }
        if let Some(confirmation) = &confirmation {
            confirmation.recheck()?;
        }
        Ok(())
    };
    permission()?;
    let mut running = Run::begin("drive");
    // Borrow an existing mount, or own one reviewed temporary mount of the
    // configured drive; the same path Settings "Back up now" uses.
    let mut result = crate::backup_create_coordinator::attached(
        &guard,
        &lock,
        &files::random_hex(16)?,
        None,
        &permission,
        &mut crate::backup_create_coordinator::tracked(
            &mut running,
            primary::DRIVE,
            &mut |phase| {
                eprintln!("enzimos-backup: {phase}");
                Ok(())
            },
        ),
    )
    .inspect_err(|_| crate::backup_create_coordinator::failed_cleanup(&guard, &lock))?;
    *created = true;
    enzimos_policy::backup_run_status::record_outcome(None);
    permission()?;
    let after = crate::backup_create_coordinator::after_backup(
        &guard,
        &lock,
        result["snapshot_id"].as_str(),
        &permission,
        &mut running,
        primary::DRIVE,
    );
    result["cleanup"] = after["cleanup"].clone();
    if !after["remote_copy"].is_null() {
        result["remote_copy"] = after["remote_copy"].clone();
    }
    permission()?;
    Ok(result)
}
/// A backup straight into the NAS share of a setup without a backup drive. A
/// scheduled run requires an opt-in bound to this share configuration and
/// pin; there is no drive recovery-copy confirmation to verify.
fn create_share(
    guard: &Guard,
    lock: &files::Lock,
    marker: Option<&OptIn>,
    created: &mut bool,
) -> Result<Value> {
    let scope = ShareScope::open()?;
    let pin = primary::pin(guard)?;
    let permission = || {
        operation::root_only()?;
        enzimos_policy::namespaces::initial()?;
        lock.recheck()?;
        guard.recheck()?;
        SourceScope::recheck(&scope)?;
        if let Some(marker) = marker {
            marker.verify_share(scope.public_bytes()?, &pin)?;
        }
        Ok(())
    };
    permission()?;
    let mut running = Run::begin(primary::SHARE);
    let mut result = crate::backup_create_coordinator::shared(
        guard,
        lock,
        &files::random_hex(16)?,
        None,
        &permission,
        &mut crate::backup_create_coordinator::tracked(
            &mut running,
            primary::SHARE,
            &mut |phase| {
                eprintln!("enzimos-backup: {phase}");
                Ok(())
            },
        ),
    )
    .inspect_err(|_| crate::backup_create_coordinator::failed_cleanup(guard, lock))?;
    *created = true;
    enzimos_policy::backup_run_status::record_outcome(None);
    permission()?;
    let after = crate::backup_create_coordinator::after_backup(
        guard,
        lock,
        result["snapshot_id"].as_str(),
        &permission,
        &mut running,
        primary::SHARE,
    );
    result["cleanup"] = after["cleanup"].clone();
    permission()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enzimos_platform::Error;

    fn settled(
        result: Result<Value>,
        created: bool,
        automatic: bool,
    ) -> (Result<Value>, Vec<String>) {
        let mut recorded = Vec::new();
        let result = settle(result, created, automatic, &mut |error| {
            recorded.push(error.to_owned());
        });
        (result, recorded)
    }
    #[test]
    fn an_error_after_the_backup_was_published_keeps_the_ok_run_status() {
        let (result, recorded) =
            settled(Err(Error("remote-share-unreachable: x".into())), true, true);
        assert!(result.is_err());
        assert!(recorded.is_empty());
    }
    #[test]
    fn an_unplugged_drive_waits_on_schedule_and_fails_by_hand() {
        let absent = || Err(Error("backup-destination-absent".into()));
        let (result, recorded) = settled(absent(), false, true);
        assert_eq!(result.unwrap(), value!({"status":"waiting-for-drive"}));
        assert_eq!(recorded, ["backup-destination-absent"]);
        let (result, recorded) = settled(absent(), false, false);
        assert!(result.is_err());
        assert_eq!(recorded, ["backup-destination-absent"]);
    }
    #[test]
    fn a_failure_before_publication_is_recorded() {
        let (result, recorded) = settled(Err(Error("job-plan-changed".into())), false, true);
        assert!(result.is_err());
        assert_eq!(recorded, ["job-plan-changed"]);
    }
}
