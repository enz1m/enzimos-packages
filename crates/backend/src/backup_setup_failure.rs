// SPDX-License-Identifier: MIT
//! Failure settlement of one setup attempt: step-tagged errors, bounded journal
//! lines, and rollback of this run's own publications only when provably safe.
//!
//! Configuration and credential are published before the provision worker
//! because the worker must prove that the *stored* credential opens the
//! repository it just created (init, config/header readback, key list, metadata
//! check) before the destination pin is bound. If anything fails before that
//! pin exists and before repository creation was entered on the device, the
//! publications refer to a repository that provably does not exist; they are
//! retracted so no configuration is left behind and a fresh review can start.
use enzimos_platform::{Error, Result};
use std::path::Path;

/// Prefix of an error whose rollback was proven (see `settle`).
pub(crate) const ROLLED_BACK: &str = "setup-rolled-back: ";
/// The failure was settled by a proven rollback; a new review can start.
pub(crate) fn proven_rollback(error: &Error) -> bool {
    error.0.starts_with(ROLLED_BACK)
}
/// Prefix an error with the fixed setup step that produced it.
pub(crate) fn step<T>(name: &'static str, result: Result<T>) -> Result<T> {
    result.map_err(|error| Error(format!("{name}: {}", error.0)))
}
pub(crate) fn log(line: &str) {
    eprintln!(
        "enzimos-system-backend: backup setup: {}",
        enzimos_policy::diagnostic::bounded(line)
    );
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Facts {
    /// Repository creation was entered on the destination device.
    pub repository_entered: bool,
    /// Anything is still mounted at or below /backup-repository.
    pub destination_mounted: bool,
    /// The destination pin (`backup-destination.json`) or opt-in exists.
    pub pin_present: bool,
    /// Partial publication files (drafts) that this run cannot attribute.
    pub drafts_present: bool,
    /// A setup-mount or private-area intent is not terminal (it would block
    /// the next attempt, so the rollback is not complete).
    pub intents_unfinished: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Retract,
    Retain(&'static str),
}
pub(crate) fn decide(facts: Facts) -> Decision {
    if facts.destination_mounted {
        Decision::Retain("/backup-repository is still mounted")
    } else if facts.pin_present {
        Decision::Retain("destination pin or schedule opt-in exists")
    } else if facts.repository_entered {
        Decision::Retain("repository creation was entered; the drive may hold a partial repository")
    } else if facts.drafts_present {
        Decision::Retain("unattributed publication drafts exist")
    } else if facts.intents_unfinished {
        Decision::Retain("a setup mount intent was not settled")
    } else {
        Decision::Retract
    }
}
fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn unfinished(directory: &Path) -> Result<bool> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let bytes = std::fs::read(entry?.path())?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Error("setup intent unreadable".into()))?;
        if !matches!(v["phase"].as_str(), Some("complete" | "rolled-back")) {
            return Ok(true);
        }
    }
    Ok(false)
}
/// The proof `enzimos-policy backup-setup reset-uncertain` leaves after it
/// retracted one setup request (Root-private, in the control directory).
pub(crate) fn reset_proof() -> Result<Option<serde_json::Value>> {
    use enzimos_platform::{files, require};
    use std::os::unix::fs::MetadataExt;
    let control = files::directory(Path::new(enzimos_policy::operation::CONTROL), Some(0))?;
    let Some(file) = files::optional_relative(
        &control,
        Path::new(enzimos_policy::backup_setup_reset::RESET_PROOF),
    )?
    else {
        return Ok(None);
    };
    let m = file.metadata()?;
    require(
        m.is_file() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "setup reset proof is not Root-private",
    )?;
    let bytes = files::read_file(&file, 4096, Some(0), true)?;
    Ok(Some(enzimos_platform::json::decode(&bytes, 4096)?))
}
/// Whether a reset proof settles this `uncertain` enrollment as rolled back:
/// it names this exact request and plan, and the live facts allow the same
/// retraction an in-process rollback requires.
pub(crate) fn reset_settles(
    record: &serde_json::Value,
    proof: Option<&serde_json::Value>,
    facts: Facts,
) -> bool {
    record["state"] == "uncertain"
        && record["plan"]["operation"] == "backup-initial-setup"
        && proof.is_some_and(|p| {
            p["schema"] == 1
                && p["retracted"] == true
                && p["request_id"] == record["request_id"]
                && p["plan_sha256"] == record["plan_sha256"]
        })
        && decide(facts) == Decision::Retract
}
/// Live facts from the kernel mount table and the fixed publication names.
pub(crate) fn observe(repository_entered: bool) -> Result<Facts> {
    let rows = enzimos_policy::storage_runtime::rows()?;
    let control = Path::new(enzimos_policy::operation::CONTROL);
    let etc = Path::new("/etc/enzimos");
    Ok(Facts {
        repository_entered,
        destination_mounted: rows.iter().any(|row| {
            row.target == "/backup-repository" || row.target.starts_with("/backup-repository/")
        }),
        pin_present: exists(&control.join("backup-destination.json"))?
            || exists(&control.join("backup.enabled"))?,
        drafts_present: exists(&etc.join(".backup-setup-config"))?
            || exists(&etc.join(".backup-password-input"))?,
        intents_unfinished: unfinished(&control.join("backup-setup-mounts"))?
            || unfinished(&control.join("backup-setup-areas"))?,
    })
}
/// Log the failure, then retract only when `decide` allows it. Returns the
/// original error; settlement never turns a failure into success. A proven
/// rollback is marked with `ROLLED_BACK` so the job ledger can say so.
pub(crate) fn settle(
    error: Error,
    facts: Result<Facts>,
    retract: impl FnOnce() -> Result<()>,
) -> Error {
    log(&format!("failed at {}", error.0));
    match facts.map(decide) {
        Ok(Decision::Retract) => match retract() {
            Ok(()) => {
                log(
                    "rolled back this attempt's configuration, credential and setup intent; \
                     no repository was created; a new review can start",
                );
                return Error(format!("{ROLLED_BACK}{}", error.0));
            }
            Err(retraction) => log(&format!(
                "rollback of this attempt's publications failed ({}); \
                 run `enzimos-policy backup-setup reset-uncertain` as root",
                retraction.0
            )),
        },
        Ok(Decision::Retain(reason)) => log(&format!(
            "publications retained ({reason}); inspect, then run \
             `enzimos-policy backup-setup reset-uncertain` as root"
        )),
        Err(observation) => log(&format!(
            "publications retained; failure state unobservable ({})",
            observation.0
        )),
    }
    error
}
