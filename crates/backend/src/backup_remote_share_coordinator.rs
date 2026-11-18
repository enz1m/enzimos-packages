// SPDX-License-Identifier: MIT
//! System1 NAS share setup, test and removal under the operation lock.
//! Callers see only the fixed public codes; the reason is journaled without
//! secret bytes (none ever reach an error text).
use enzimos_platform::{Error, Result, secret::Retained};
use enzimos_policy::{
    backup_restic_runtime::remote_share::{self, Repository},
    operation,
    storage_runtime::Guard,
};
use serde_json::Value;

pub(crate) fn run(
    guard: &Guard,
    request: &Value,
    share: Option<&Retained>,
    repository: Option<&Retained>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    authorize()?;
    let lock = operation::lock()?;
    let mut permission = || authorize();
    let result = match (request.get("share"), request["action"].as_str()) {
        (Some(selection), _) => {
            let share = share.ok_or_else(|| Error("wire-signature".into()))?;
            let source = match (remote_share::local_backup_configured(), repository) {
                (true, None) => Repository::Local,
                (false, Some(input)) => Repository::Entered(input),
                (true, Some(_)) => {
                    return Err(Error("remote-repository-password-not-expected".into()));
                }
                (false, None) => return Err(Error("remote-repository-password-required".into())),
            };
            remote_share::setup_locked(guard, &lock, selection, share, source, &mut permission)
        }
        (None, Some("test")) => remote_share::test_locked(guard, &lock, &mut permission),
        (None, Some("remove")) => remote_share::remove_locked(guard, &lock, &mut permission),
        _ => Err(Error("operation-unavailable".into())),
    };
    result.map_err(|error| {
        eprintln!(
            "enzimos-system-backend: NAS share {} refused: {}",
            request["action"].as_str().unwrap_or("setup"),
            enzimos_policy::diagnostic::bounded(&error.0)
        );
        remote_share::code(&error).map_or(error, |code| Error(code.into()))
    })
}
