// SPDX-License-Identifier: MIT
//! Where a backup is written: the backup drive, or the NAS share in setups
//! without a drive.
//!
//! A configured drive (`/etc/enzimos/backup.json`) is always the primary
//! destination; a ready NAS share then receives copies of its snapshots. Only
//! without a drive does a ready share (configuration, both passwords and the
//! pinned repository) receive the backup itself. The share then also decides
//! the capture scope: system and home, without the drive's additional sources.
use crate::{
    backup_configuration::SourceScope, backup_source_layout::Dataset, control_record::Observation,
    settings_file, storage_runtime::Guard,
};
use enzimos_platform::{Result, json};
use serde_json::Value;
use std::path::Path;

/// The backup drive is the primary destination.
pub const DRIVE: &str = "drive";
/// The NAS share is the primary destination (no backup drive is set up).
pub const SHARE: &str = "share";
const CONFIGURATION: &str = "/etc/enzimos/backup-remote.json";

/// The primary destination for a drive configuration that exists or not and
/// a share that is ready or not.
#[must_use]
pub fn choose(drive_configured: bool, share_ready: bool) -> Option<&'static str> {
    match (drive_configured, share_ready) {
        (true, _) => Some(DRIVE),
        (false, true) => Some(SHARE),
        (false, false) => None,
    }
}

/// The current primary destination; metadata only, no secret bytes are read.
#[must_use]
pub fn primary() -> Option<&'static str> {
    choose(
        Path::new(crate::backup_configuration::PATH).exists(),
        crate::backup_restic_runtime::remote_share::copy_ready(),
    )
}

/// The NAS share configuration as the capture scope of a share backup.
pub struct ShareScope {
    original: settings_file::Config,
}
impl ShareScope {
    /// Observe the share configuration; it must be a valid SMB endpoint.
    ///
    /// # Errors
    /// An absent, unprotected or invalid configuration.
    pub fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        let original = settings_file::Config::open(CONFIGURATION, 32768)?;
        crate::backup_remote_endpoint::validate(&json::decode(&original.body, 32768)?)?;
        original.recheck()?;
        Ok(Self { original })
    }
    /// The exact public configuration bytes.
    ///
    /// # Errors
    /// As for [`SourceScope::recheck`].
    pub fn public_bytes(&self) -> Result<&[u8]> {
        self.original.recheck()?;
        Ok(&self.original.body)
    }
}
/// The share repository pin in the Root control directory.
///
/// # Errors
/// An absent, unprotected or invalid pin.
pub fn pin(guard: &Guard) -> Result<Value> {
    let pin = Observation::open(
        guard.control(),
        Path::new("backup-remote-pin.json"),
        32768,
        guard.control_mount_id(),
    )?;
    crate::backup_remote_record::pin(pin.value()?)?;
    Ok(pin.value()?.clone())
}
/// The schedule opt-in binding of a setup without a backup drive.
///
/// # Errors
/// A pin that does not name the current share configuration.
pub(crate) fn schedule_binding(scope: &ShareScope, guard: &Guard) -> Result<Value> {
    crate::backup_binding::schedule_share(scope.public_bytes()?, &pin(guard)?)
}
/// Whether the NAS answers on the SMB port; nothing is mounted and no
/// password is read. A backup checks this before it captures anything.
///
/// # Errors
/// `remote-share-unreachable` with the reason.
pub fn reachable(scope: &ShareScope) -> Result<()> {
    let endpoint =
        crate::backup_remote_endpoint::endpoint(&json::decode(scope.public_bytes()?, 32768)?)?;
    enzimos_platform::remote_mount_child::reachable(&endpoint)
}
impl SourceScope for ShareScope {
    fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    fn datasets(&self) -> Result<Vec<Dataset>> {
        self.original.recheck()?;
        Ok(crate::backup_source_layout::base())
    }
    fn evidence(&self) -> Result<Value> {
        self.original.evidence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drive_stays_primary_and_a_ready_share_serves_only_without_one() {
        assert_eq!(choose(true, true), Some(DRIVE));
        assert_eq!(choose(true, false), Some(DRIVE));
        assert_eq!(choose(false, true), Some(SHARE));
        assert_eq!(choose(false, false), None);
    }
}
