// SPDX-License-Identifier: MIT
//! enzimOS home history: previous versions service and maintenance commands.
//!
//! - no arguments: the D-Bus activated `org.enzimos.History1` service
//! - `guard`: before a new snapshot, make room by removing the oldest home
//!   history snapshots; exits 1 (skip the snapshot) when there is still no room.
//!   While the operation lock is held it removes nothing and records no room
//!   check, so the snapshot run retries; a running backup's own snapshot holds
//!   the space anyway
//! - `prune`: drop skipped folders (build output, caches, exclusions) from home
//!   history snapshots not pruned yet
//! - `measure`: refresh the space measurement shown in Settings
//! - `is-backup-drive UUID`: exit 0 for the configured backup drive (udev)
//! - `attached UUID`: the backup drive was connected; start an owed backup
use enzimos_system_backend::history::{self, measure, prune, store::Store};
use std::path::Path;
use std::time::Duration;

/// The configured backup drive's filesystem UUID, if backups are set up.
fn backup_drive() -> Option<String> {
    let bytes = std::fs::read("/etc/enzimos/backup.json")
        .ok()
        .filter(|b| b.len() <= 32768)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value["destination_uuid"].as_str().map(str::to_owned)
}

/// A drive was connected: start the scheduled backup if it is this drive and a
/// backup is owed (waiting for the drive, failed, or none in 20 hours).
fn attached(uuid: &str) -> i32 {
    if backup_drive().as_deref() != Some(uuid)
        || !Path::new("/var/lib/enzimos-control/backup.enabled").exists()
    {
        return 0;
    }
    let status = enzimos_policy::backup_run_status::read();
    let now = history::store::now();
    let recent = status["last_success"]
        .as_i64()
        .is_some_and(|t| now - t < 20 * 3600);
    let owed = matches!(
        status["state"].as_str(),
        Some("waiting-for-drive" | "failed")
    ) || !recent;
    if !owed {
        return 0;
    }
    eprintln!("enzimos-history: backup drive connected; starting the owed backup");
    let started = std::process::Command::new("/usr/bin/systemctl")
        .args(["--no-block", "start", "enzimos-backup.service"])
        .status();
    i32::from(!started.is_ok_and(|s| s.success()))
}

fn run(command: &str) -> enzimos_platform::Result<i32> {
    let store = Store::default();
    let snapshots = enzimos_platform::fsview::open_directory(Path::new(history::SNAPSHOTS))?;
    match command {
        "guard" => {
            enzimos_policy::home_history_auto::forget_room_check()?;
            if enzimos_policy::operation::busy()? {
                return Ok(0);
            }
            let _lock = store.lock(Duration::from_secs(120))?;
            let list = history::list(&snapshots)?;
            let room = prune::guard(&store, &list, prune::delete_snapshot, || {
                prune::free_percent(Path::new(history::HOME_ROOT)).map(|f| f.0)
            })?;
            if room {
                enzimos_policy::home_history_auto::record_room_check()?;
            } else {
                eprintln!("enzimos-history: the disk is too full for a new home history snapshot");
            }
            Ok(i32::from(!room))
        }
        "prune" => {
            let _lock = store.lock(Duration::from_secs(120))?;
            let list = history::list(&snapshots)?;
            let outcome = prune::prune_pending(&store, &snapshots, &list)?;
            eprintln!(
                "enzimos-history: pruned {} entries from {} snapshots ({} kept)",
                outcome.removed, outcome.snapshots, outcome.kept
            );
            Ok(0)
        }
        "measure" => {
            let list = history::list(&snapshots)?;
            measure::measure(&store, &list, Duration::from_secs(30 * 60))?;
            Ok(0)
        }
        _ => Err(enzimos_platform::Error(
            "usage: enzimos-history [guard|prune|measure]".into(),
        )),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => history::service::serve().await.map(|()| 0),
        [command, uuid] if command == "is-backup-drive" => {
            Ok(i32::from(backup_drive().as_deref() != Some(uuid.as_str())))
        }
        [command, uuid] if command == "attached" => Ok(attached(uuid)),
        [command] => tokio::task::block_in_place(|| run(command)),
        _ => Err(enzimos_platform::Error(
            "usage: enzimos-history [guard|prune|measure]".into(),
        )),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("enzimos-history: {}", error.0);
            std::process::exit(2);
        }
    }
}
