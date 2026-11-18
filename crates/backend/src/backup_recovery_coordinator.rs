// SPDX-License-Identifier: MIT
//! System1 recovery password export and copy confirmation under the operation
//! lock. Export authenticates the stored credential against the configured
//! repository: an existing fixed-path mount is borrowed, otherwise this call
//! owns one reviewed mount and closes it before the reply is sent.
use enzimos_platform::{Result, files};
use enzimos_policy::{backup_restic_runtime::recovery_export, operation, storage_runtime::Guard};
use serde_json::Value;
use std::fs::File;

pub(crate) fn export(
    guard: &Guard,
    uid: u32,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<(Value, File)> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    authorize()?;
    let lock = operation::lock()?;
    let permission = || {
        authorize()?;
        lock.recheck()?;
        guard.recheck()
    };
    recovery_export::export_locked(
        guard,
        &lock,
        uid,
        &mut |body| mounted(guard, &lock, &permission, body),
        &permission,
    )
}
pub(crate) fn confirm(
    guard: &Guard,
    uid: u32,
    ticket: &str,
    assertion: &str,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    authorize()?;
    let lock = operation::lock()?;
    let permission = || {
        authorize()?;
        lock.recheck()?;
        guard.recheck()
    };
    recovery_export::confirm_locked(guard, &lock, uid, ticket, assertion, &permission)
}
/// Run `body` with the configured destination mounted at its fixed path, as
/// the backup command does: borrow the one existing mount, or own one mount of
/// the configured drive whose readonly review matches the stored pin.
fn mounted(
    guard: &Guard,
    lock: &files::Lock,
    permission: &dyn Fn() -> Result<()>,
    body: &mut dyn FnMut() -> Result<String>,
) -> Result<String> {
    enzimos_policy::backup_destination_attach::with_destination(guard, lock, permission, body)
}
