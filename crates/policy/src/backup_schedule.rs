// SPDX-License-Identifier: MIT
//! Fixed daily opt-in; disabling never waits for or cancels a running capture.
use crate::{
    backup_admission::{Document, Repository},
    backup_configuration::{self, Configuration},
    backup_credential::Credential,
    backup_destination::Destination,
    backup_recovery_confirmation::Confirmation,
    operation,
    settings_command::Command,
    storage_runtime::Guard,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{os::unix::fs::MetadataExt, path::Path};
const TIMER: &str = "enzimos-backup.timer";

struct Marker<'a> {
    storage: &'a Guard,
    document: Option<Document>,
}
impl<'a> Marker<'a> {
    fn open(storage: &'a Guard) -> Result<Self> {
        storage.recheck()?;
        let metadata = storage.control().metadata()?;
        require(
            metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o7777 == 0o700,
            "private original schedule control required",
        )?;
        let document =
            Document::optional(&Path::new(operation::CONTROL).join("backup.enabled"), 0)?;
        let this = Self { storage, document };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        self.storage.recheck()?;
        if let Some(document) = &self.document {
            document.recheck()?;
            require(
                document.mount() == self.storage.control_mount_id(),
                "schedule left original control mount",
            )?;
        } else {
            require(
                files::optional_relative(self.storage.control(), Path::new("backup.enabled"))?
                    .is_none(),
                "schedule marker appeared after review",
            )?;
        }
        self.storage.recheck()
    }
    fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"enabled":self.document.is_some(),"marker":self.document.as_ref().map(Document::evidence).transpose()?,
            "control_mount":self.storage.control_mount_id()}),
        )
    }
    fn admit(&self, binding: &Value) -> Result<()> {
        self.recheck()?;
        if let Some(document) = &self.document {
            require(
                json::decode(document.bytes()?, backup_configuration::LIMIT)? == *binding,
                "existing opt-in differs; disable and review before re-enabling",
            )?;
        }
        Ok(())
    }
    fn publish(&mut self, binding: &Value) -> Result<()> {
        self.admit(binding)?;
        if self.document.is_none() {
            let published = files::atomic_relative_retained(
                self.storage.control(),
                Path::new("backup.enabled"),
                &json::canonical(binding)?,
                0o600,
                Some(0),
                false,
                backup_configuration::LIMIT,
            )?;
            let document =
                Document::optional(&Path::new(operation::CONTROL).join("backup.enabled"), 0)?
                    .ok_or_else(|| Error("published original schedule marker missing".into()))?;
            document.matches(&published)?;
            self.document = Some(document);
        }
        self.admit(binding)
    }
    fn revoke(&mut self, id: &str) -> Result<Option<Document>> {
        self.recheck()?;
        let retired = self
            .document
            .take()
            .map(|document| document.retire_schedule(id))
            .transpose()?;
        self.recheck()?;
        Ok(retired)
    }
}
fn activity(bytes: &[u8]) -> Result<&str> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("backup timer activity encoding".into()))?
        .trim_end_matches('\n');
    require(
        matches!(
            text,
            "active"
                | "inactive"
                | "activating"
                | "deactivating"
                | "failed"
                | "reloading"
                | "maintenance"
        ),
        "backup timer activity differs",
    )?;
    Ok(text)
}
fn timer(command: &Command) -> Result<Value> {
    let unit =
        crate::home_history_control::parse(&command.run(&["is-enabled", TIMER], &[0, 1], 4096)?)?;
    let bytes = command.run(
        &["show", "--property=ActiveState", "--value", TIMER],
        &[0],
        4096,
    )?;
    Ok(value!({"unit":unit,"activity":activity(&bytes)?}))
}
fn review(
    configuration: &Configuration,
    destination: &Destination<'_>,
    repository: &Repository<'_, '_>,
    confirmation: &Confirmation<'_, '_, '_>,
) -> Result<Value> {
    let binding =
        crate::backup_binding::schedule(configuration.public_bytes()?, repository.public_bytes()?)?;
    Ok(
        value!({"binding":binding,"configuration":configuration.evidence()?,"destination":destination.stable_evidence()?,
        "destination_pin":repository.evidence()?,"recovery":confirmation.review_evidence()?}),
    )
}
/// Review of a schedule for a setup without a backup drive: the share
/// configuration and repository pin it binds. The share is not contacted.
fn review_share(
    storage: &Guard,
    scope: &crate::backup_share_destination::ShareScope,
) -> Result<Value> {
    let binding = crate::backup_share_destination::schedule_binding(scope, storage)?;
    Ok(
        value!({"binding":binding,"share":crate::backup_configuration::SourceScope::evidence(scope)?,
        "share_pin":crate::backup_share_destination::pin(storage)?}),
    )
}
fn share_primary() -> bool {
    crate::backup_share_destination::primary() == Some(crate::backup_share_destination::SHARE)
}
fn observed(marker: &Marker<'_>, command: &Command, approval: Option<Value>) -> Result<Value> {
    Ok(
        value!({"marker":marker.evidence()?,"timer":timer(command)?,"provider":command.evidence()?,"approval":approval}),
    )
}
pub fn observation(enabled: bool) -> Result<Value> {
    crate::namespaces::initial()?;
    let storage = Guard::observe()?;
    let marker = Marker::open(&storage)?;
    let command = Command::open("/usr/bin/systemctl")?;
    let approval = if enabled && share_primary() {
        let idle = Snapshot::online()?;
        let scope = crate::backup_share_destination::ShareScope::open()?;
        let approval = review_share(&storage, &scope)?;
        marker.admit(&approval["binding"])?;
        idle.recheck()?;
        Some(approval)
    } else if enabled {
        let measure = || -> Result<Value> {
            let idle = Snapshot::online()?;
            let configuration = Configuration::open()?;
            let destination = Destination::open(&configuration, &storage)?;
            let repository = Repository::open(&destination)?;
            let credential = Credential::open()?;
            let confirmation = Confirmation::open(&configuration, &repository, &credential)?;
            let approval = review(&configuration, &destination, &repository, &confirmation)?;
            marker.admit(&approval["binding"])?;
            idle.recheck()?;
            Ok(approval)
        };
        // Planning checks the configured repository the same way as enabling:
        // borrowed when mounted, otherwise in one temporary owned mount. When
        // the operation lock is already held (the enabling step verifying its
        // own plan inside its attached destination, or another operation) the
        // current destination is measured as it is.
        Some(match operation::try_lock()? {
            Some(lock) => {
                let attached = || -> Result<()> {
                    storage.recheck()?;
                    lock.recheck()
                };
                crate::backup_destination_attach::with_destination(
                    &storage, &lock, &attached, measure,
                )?
            }
            None => measure()?,
        })
    } else {
        None
    };
    observed(&marker, &command, approval)
}
pub fn set<F: FnMut() -> Result<()>>(
    enabled: bool,
    id: &str,
    expected: &Value,
    mut authorize: F,
) -> Result<Value> {
    crate::namespaces::initial()?;
    operation::root_only()?;
    let storage = Guard::observe()?;
    let schedule_lock = files::Lock::acquire(
        &Path::new(operation::CONTROL).join("backup-schedule.lock"),
        0,
    )?;
    let command = Command::open("/usr/bin/systemctl")?;
    let mut marker = Marker::open(&storage)?;
    if enabled && share_primary() {
        let operation = operation::lock()?;
        let idle = Snapshot::online()?;
        let scope = crate::backup_share_destination::ShareScope::open()?;
        let approval = review_share(&storage, &scope)?;
        marker.admit(&approval["binding"])?;
        require(
            observed(&marker, &command, Some(approval.clone()))? == *expected,
            "backup schedule plan changed",
        )?;
        let mut boundary = || -> Result<()> {
            authorize()?;
            operation.recheck()?;
            schedule_lock.recheck()?;
            idle.recheck()?;
            require(
                review_share(&storage, &scope)? == approval,
                "backup schedule approval changed",
            )?;
            marker.recheck()?;
            command.recheck()
        };
        boundary()?;
        // As for a drive: stop first, enable without --now.
        command.run(&["stop", TIMER], &[0], 65536)?;
        boundary()?;
        marker.publish(&approval["binding"])?;
        authorize()?;
        operation.recheck()?;
        schedule_lock.recheck()?;
        idle.recheck()?;
        require(
            review_share(&storage, &scope)? == approval,
            "backup approval changed before timer enable",
        )?;
        marker.admit(&approval["binding"])?;
        command.run(&["enable", TIMER], &[0], 65536)?;
        let after = timer(&command)?;
        require(
            after["unit"]["state"] == "enabled" && after["activity"] == "inactive",
            "backup schedule outcome differs; no automatic replay",
        )?;
        marker.admit(&approval["binding"])?;
        operation.recheck()?;
        idle.recheck()?;
    } else if enabled {
        let operation = operation::lock()?;
        // The configured repository is checked in a borrowed mount or in one
        // reviewed temporary mount owned for this call and closed after it.
        let attached = || -> Result<()> {
            storage.recheck()?;
            schedule_lock.recheck()?;
            operation.recheck()
        };
        crate::backup_destination_attach::with_destination(
            &storage,
            &operation,
            &attached,
            || {
                let idle = Snapshot::online()?;
                let configuration = Configuration::open()?;
                let destination = Destination::open(&configuration, &storage)?;
                let repository = Repository::open(&destination)?;
                let credential = Credential::open()?;
                let confirmation = Confirmation::open(&configuration, &repository, &credential)?;
                let approval = review(&configuration, &destination, &repository, &confirmation)?;
                marker.admit(&approval["binding"])?;
                require(
                    observed(&marker, &command, Some(approval.clone()))? == *expected,
                    "backup schedule plan changed",
                )?;
                let mut boundary = || -> Result<()> {
                    authorize()?;
                    operation.recheck()?;
                    schedule_lock.recheck()?;
                    idle.recheck()?;
                    require(
                        review(&configuration, &destination, &repository, &confirmation)?
                            == approval,
                        "backup schedule approval changed",
                    )?;
                    marker.recheck()?;
                    command.recheck()
                };
                boundary()?;
                // Persistent timers may trigger immediately when started. Stop first;
                // enable intentionally has no --now and never starts the backup service.
                command.run(&["stop", TIMER], &[0], 65536)?;
                boundary()?;
                marker.publish(&approval["binding"])?;
                authorize()?;
                operation.recheck()?;
                schedule_lock.recheck()?;
                idle.recheck()?;
                require(
                    review(&configuration, &destination, &repository, &confirmation)? == approval,
                    "backup approval changed before timer enable",
                )?;
                marker.admit(&approval["binding"])?;
                command.run(&["enable", TIMER], &[0], 65536)?;
                let after = timer(&command)?;
                require(
                    after["unit"]["state"] == "enabled" && after["activity"] == "inactive",
                    "backup schedule outcome differs; no automatic replay",
                )?;
                marker.admit(&approval["binding"])?;
                confirmation.recheck()?;
                operation.recheck()?;
                idle.recheck()?;
                Ok(())
            },
        )?;
    } else {
        require(
            observed(&marker, &command, None)? == *expected,
            "backup disable plan changed",
        )?;
        authorize()?;
        schedule_lock.recheck()?;
        marker.recheck()?;
        command.recheck()?;
        let retired = marker.revoke(id)?;
        // No long capture lock and no credential/configuration/source discovery.
        authorize()?;
        schedule_lock.recheck()?;
        marker.recheck()?;
        if let Some(retired) = &retired {
            retired.recheck()?;
        }
        command.run(&["disable", "--now", TIMER], &[0], 65536)?;
        let after = timer(&command)?;
        require(
            after["unit"]["state"] == "disabled" && after["activity"] == "inactive",
            "backup disable outcome differs; no automatic replay",
        )?;
        marker.recheck()?;
        if let Some(retired) = &retired {
            retired.recheck()?;
        }
    }
    command.recheck()?;
    schedule_lock.recheck()?;
    storage.recheck()?;
    Ok(
        value!({"enabled":enabled,"status":if enabled {"local-backup-schedule-enabled-next-boot"} else {"local-backup-schedule-disabled"},"immediate_backup_started":false}),
    )
}
