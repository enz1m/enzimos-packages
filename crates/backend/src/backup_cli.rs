// SPDX-License-Identifier: MIT
//! Root command entry for the same original supervised capture/transfer path.
//! Borrow existing mounts or own one configured mount through normal closure.
use enzimos_platform::{Result, files};
use enzimos_policy::{
    backup_admission::OptIn,
    backup_configuration::Configuration,
    backup_credential::Credential,
    deferred::{self, Admission},
    operation,
    storage_runtime::Guard,
};
use serde_json::{Value, json as value};
/// Run a backup and record how it ended. A scheduled run with the backup drive
/// unplugged is not a failure: it is recorded as waiting for the drive (the
/// backup starts when the drive is connected) and exits successfully.
pub fn create(automatic: bool) -> Result<Value> {
    use enzimos_policy::backup_run_status as run;
    match create_inner(automatic) {
        Ok(result) => {
            let skipped = matches!(
                result["status"].as_str(),
                Some("disabled-no-source-scan" | "deferred")
            );
            if !skipped {
                let _ = run::record("ok", None);
            }
            Ok(result)
        }
        Err(error) if run::is_absent(&error.0) => {
            let _ = run::record("waiting-for-drive", Some(&error.0));
            if automatic {
                Ok(value!({"status":"waiting-for-drive"}))
            } else {
                Err(error)
            }
        }
        Err(error) => {
            let _ = run::record("failed", Some(&error.0));
            Err(error)
        }
    }
}
fn create_inner(automatic: bool) -> Result<Value> {
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
    // Borrow an existing mount, or own one reviewed temporary mount of the
    // configured drive; the same path Settings "Back up now" uses.
    let mut result = crate::backup_create_coordinator::attached(
        &guard,
        &lock,
        &files::random_hex(16)?,
        None,
        &permission,
        &mut |phase| {
            eprintln!("enzimos-backup: {phase}");
            Ok(())
        },
    )?;
    permission()?;
    eprintln!("enzimos-backup: cleanup");
    // Clean up old backups by policy, with the destination attached again.
    let created = result["snapshot_id"].as_str().map(str::to_owned);
    result["cleanup"] = enzimos_policy::backup_restic_runtime::retention::after_backup_attached(
        &guard,
        &lock,
        created.as_deref(),
        &permission,
    );
    permission()?;
    Ok(result)
}
