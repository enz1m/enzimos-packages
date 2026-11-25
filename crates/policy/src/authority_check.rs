// SPDX-License-Identifier: MIT
//! Read-only authority review operates on private copies of the mounted ring.
use crate::{authority_build, authority_mount, operation, transition_idle};
use enzimos_platform::{Result, files};
use serde_json::Value;
use std::path::Path;
/// Check the package authority against the installed keyring while `_lock` is held.
///
/// # Errors
///
/// Fails when a build or comparison step fails.
pub fn check_locked(_lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    let snapshot = transition_idle::Snapshot::online()?;
    let mounted = authority_mount::Authority::observe(&snapshot.guard)?;
    let parent = Path::new("/run/enzimos/authority-builds");
    files::ensure_directory(parent, 0o700, 0)?;
    let name = format!("check-{}", files::random_hex(16)?);
    snapshot.recheck()?;
    let prepared = authority_build::build(
        Path::new(authority_mount::PATH),
        Path::new("/usr/share/pacman/keyrings"),
        &parent.join(name),
        0,
    )?;
    mounted.recheck(&snapshot.guard)?;
    prepared.recheck()?;
    snapshot.recheck()?;
    Ok(prepared.summary)
}
