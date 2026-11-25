// SPDX-License-Identifier: MIT
//! The backup run in progress, for Settings: its phase and target.
//!
//! Every backup run (System1 job, schedule, drive plug-in) holds the operation
//! lock and records itself in a Root-private runtime file that names its owner
//! process. `read` reports `null` when no run is recorded, when the owner has
//! exited, or when the record is from another boot, so a crashed or killed run
//! never shows as running. Recording is best effort and never fails a backup.
use crate::operation;
use enzimos_platform::{Result, files, json, process_identity, require};
use serde_json::{Value, json as value};
use std::path::{Path, PathBuf};

const DIRECTORY: &str = "/run/enzimos";
const NAME: &str = "backup-running.json";
const LIMIT: usize = 1024;
/// Closed phase vocabulary of the `running` status field.
pub(crate) const PHASES: [&str; 5] = [
    "preparing",
    "capturing",
    "transferring",
    "finishing",
    "copying",
];
/// Where the running phase writes: the backup drive or the NAS share.
pub(crate) const TARGETS: [&str; 2] = ["drive", "share"];

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
/// Start time of `pid`, a process running as `uid`.
fn owner_identity(pid: u32, uid: u32) -> Option<u64> {
    let body = files::read_kernel_owned(Path::new(&format!("/proc/{pid}/stat")), 8192, uid).ok()?;
    let text = std::str::from_utf8(&body).ok()?;
    process_identity::parse_stat(text, pid)
        .ok()
        .map(|stat| stat.start_ticks)
}

#[derive(Clone)]
struct Store {
    directory: PathBuf,
    owner: u32,
}
impl Store {
    fn system() -> Self {
        Self {
            directory: PathBuf::from(DIRECTORY),
            owner: 0,
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.join(NAME)
    }
    fn load(&self) -> Option<Value> {
        files::read_optional(&self.path(), LIMIT, Some(self.owner), true)
            .ok()
            .flatten()
            .and_then(|bytes| json::decode(&bytes, LIMIT).ok())
    }
    fn write(&self, record: &Value) -> Result<()> {
        files::atomic_bounded(
            &self.path(),
            &json::canonical(record)?,
            0o600,
            Some(self.owner),
            true,
            LIMIT,
        )
    }
    fn read(&self) -> Value {
        let Some(record) = self.load() else {
            return Value::Null;
        };
        let Ok(boot) = operation::boot_id() else {
            return Value::Null;
        };
        project(&record, &boot, &|pid, start| {
            owner_identity(pid, self.owner) == Some(start)
        })
    }
}

impl Store {
    fn foreign(&self, own: u32) -> bool {
        let Some(record) = self.load() else {
            return false;
        };
        let Ok(boot) = operation::boot_id() else {
            return true;
        };
        !project(&record, &boot, &|pid, start| {
            pid != own && owner_identity(pid, self.owner) == Some(start)
        })
        .is_null()
    }
}
/// Validate a stored record and reduce it to the public `running` field.
fn project(record: &Value, boot: &str, alive: &dyn Fn(u32, u64) -> bool) -> Value {
    let valid = (|| -> Result<(u32, u64)> {
        json::fields(record, "schema boot_id pid start_ticks since phase target")?;
        let pid = record["pid"].as_u64().unwrap_or(0);
        let start = record["start_ticks"].as_u64().unwrap_or(0);
        require(
            record["schema"] == 1
                && (1..=i32::MAX as u64).contains(&pid)
                && start > 0
                && record["since"].is_u64()
                && record["phase"]
                    .as_str()
                    .is_some_and(|phase| PHASES.contains(&phase))
                && record["target"]
                    .as_str()
                    .is_some_and(|target| TARGETS.contains(&target)),
            "backup running record",
        )?;
        Ok((pid as u32, start))
    })();
    match valid {
        Ok((pid, start)) if record["boot_id"] == boot && alive(pid, start) => {
            value!({"since":record["since"],"phase":record["phase"],"target":record["target"]})
        }
        _ => Value::Null,
    }
}

/// Whether a live process other than this one records a backup run in this
/// boot. An unreadable boot identity counts as a foreign run.
#[must_use]
pub(crate) fn foreign() -> bool {
    Store::system().foreign(std::process::id())
}
/// The current backup run, or `null` when idle (see the module documentation).
#[must_use]
pub fn read() -> Value {
    Store::system().read()
}

/// The recorded run of this process; dropping it clears the record.
pub struct Run {
    store: Store,
    record: Option<Value>,
}
impl Run {
    /// Record a run starting now in the `preparing` phase.
    #[must_use]
    pub fn begin(target: &str) -> Self {
        Self::begin_in(Store::system(), target)
    }
    fn begin_in(store: Store, target: &str) -> Self {
        let pid = std::process::id();
        let record = (|| -> Result<Value> {
            let start = owner_identity(pid, store.owner)
                .ok_or_else(|| enzimos_platform::Error("backup run owner identity".into()))?;
            let record = value!({"schema":1,"boot_id":operation::boot_id()?,"pid":pid,
                "start_ticks":start,"since":now(),"phase":"preparing","target":target});
            require(
                TARGETS.contains(&target),
                "closed backup running target required",
            )?;
            store.write(&record)?;
            Ok(record)
        })();
        Self {
            store,
            record: record.ok(),
        }
    }
    /// Move to `phase` writing to `target`; unknown phases are ignored.
    pub fn phase(&mut self, phase: &str, target: &str) {
        let Some(record) = &mut self.record else {
            return;
        };
        if !PHASES.contains(&phase) || !TARGETS.contains(&target) {
            return;
        }
        if record["phase"] == phase && record["target"] == target {
            return;
        }
        record["phase"] = value!(phase);
        record["target"] = value!(target);
        let _ = self.store.write(record);
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        let Some(record) = &self.record else {
            return;
        };
        // Only this run's own record is removed; a later run's record stays.
        let owned = self.store.load().is_some_and(|stored| {
            stored["pid"] == record["pid"] && stored["start_ticks"] == record["start_ticks"]
        });
        if owned {
            let _ = std::fs::remove_file(self.store.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base =
            std::env::var_os("ENZIMOS_TEST_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .unwrap();
        let store = Store {
            directory: temp.path().to_owned(),
            owner: temp.path().metadata().unwrap().uid(),
        };
        (temp, store)
    }
    fn record(boot: &str) -> Value {
        value!({"schema":1,"boot_id":boot,"pid":42,"start_ticks":7,"since":1700000000,
            "phase":"transferring","target":"drive"})
    }
    const BOOT: &str = "00000000-0000-4000-8000-000000000001";

    #[test]
    fn running_field_has_the_fixed_public_shape() {
        assert_eq!(
            project(&record(BOOT), BOOT, &|pid, start| pid == 42 && start == 7),
            value!({"since":1700000000,"phase":"transferring","target":"drive"})
        );
    }
    #[test]
    fn dead_owner_reused_pid_or_previous_boot_reads_as_idle() {
        assert_eq!(project(&record(BOOT), BOOT, &|_, _| false), Value::Null);
        assert_eq!(
            project(&record(BOOT), BOOT, &|pid, start| pid == 42 && start == 8),
            Value::Null
        );
        let other = "00000000-0000-4000-8000-000000000002";
        assert_eq!(project(&record(other), BOOT, &|_, _| true), Value::Null);
    }
    #[test]
    fn open_or_unknown_record_fields_read_as_idle() {
        let mut extra = record(BOOT);
        extra["progress"] = value!(0.5);
        assert_eq!(project(&extra, BOOT, &|_, _| true), Value::Null);
        let mut phase = record(BOOT);
        phase["phase"] = value!("uploading");
        assert_eq!(project(&phase, BOOT, &|_, _| true), Value::Null);
        let mut target = record(BOOT);
        target["target"] = value!("cloud");
        assert_eq!(project(&target, BOOT, &|_, _| true), Value::Null);
    }
    #[test]
    fn a_live_run_is_reported_with_its_phase_and_cleared_when_it_ends() {
        let (_temp, store) = store();
        assert_eq!(store.read(), Value::Null);
        let mut run = Run::begin_in(store.clone(), "drive");
        let started = store.read();
        assert_eq!(started["phase"], "preparing");
        assert_eq!(started["target"], "drive");
        assert!(started["since"].as_u64().is_some_and(|s| s > 0));
        run.phase("copying", "share");
        let copying = store.read();
        assert_eq!(copying["phase"], "copying");
        assert_eq!(copying["target"], "share");
        assert_eq!(copying["since"], started["since"]);
        run.phase("uploading", "drive");
        assert_eq!(store.read()["phase"], "copying");
        drop(run);
        assert_eq!(store.read(), Value::Null);
        assert!(!store.path().exists());
    }
    #[test]
    fn only_a_live_run_of_another_process_is_foreign() {
        let (_temp, store) = store();
        assert!(!store.foreign(std::process::id()));
        let run = Run::begin_in(store.clone(), "share");
        assert!(!store.foreign(std::process::id()));
        assert!(store.foreign(1));
        drop(run);
        assert!(!store.foreign(1));
    }
    #[test]
    fn ending_a_run_keeps_a_record_owned_by_another_process() {
        let (_temp, store) = store();
        let run = Run::begin_in(store.clone(), "drive");
        let mut foreign = store.load().unwrap();
        foreign["pid"] = value!(1);
        store.write(&foreign).unwrap();
        drop(run);
        assert!(store.path().exists());
    }
}
