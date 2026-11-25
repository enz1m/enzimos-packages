// SPDX-License-Identifier: MIT
//! Public closed SMB share syntax, not an execution or credential actor.
//!
//! `/etc/enzimos/backup-remote.json` names the NAS share that holds the remote
//! Restic repository: `{"schema":2,"server":"nas.local","share":"backups",
//! "folder":"enzimos/laptop","user":"ann"}` plus an optional `"domain"`. The
//! share password is `/etc/enzimos/backup-remote.share-password` and the
//! repository password `/etc/enzimos/backup-remote.password` (both Root-only).
//! Recovery opens the same repository as `smb://server/share/folder`.
use enzimos_platform::{Error, Result, json, remote_restic::Endpoint, require};
use serde_json::Value;
/// Status and refusal for a NAS backup still configured for SFTP, which the
/// OS no longer uses: the share has to be set up again.
pub(crate) const RECONFIGURE: &str = "remote-backup-reconfigure-as-smb: the NAS backup is set up for SFTP, which is no longer supported; set it up again as an SMB share";
/// Whether this is a pre-SMB (SFTP) remote configuration.
pub(crate) fn sftp(v: &Value) -> bool {
    v.is_object()
        && (v["schema"] == 1
            || ["address", "port", "path", "host_key_sha256"]
                .iter()
                .any(|key| v.get(*key).is_some()))
}
/// # Errors
/// An SFTP configuration ([`RECONFIGURE`]), unknown or missing fields, or a
/// server, share, folder, user or domain outside the closed SMB syntax.
pub(crate) fn validate(v: &Value) -> Result<()> {
    endpoint(v).map(|_| ())
}
/// The validated share endpoint.
///
/// # Errors
/// As [`validate`].
pub(crate) fn endpoint(v: &Value) -> Result<Endpoint> {
    require(!sftp(v), RECONFIGURE)?;
    let domain = v.get("domain").is_some();
    json::fields(
        v,
        if domain {
            "schema server share folder user domain"
        } else {
            "schema server share folder user"
        },
    )?;
    require(v["schema"].as_u64() == Some(2), "remote backup schema")?;
    let text = |key: &str| {
        v[key]
            .as_str()
            .ok_or_else(|| Error(format!("remote backup {key} required")))
    };
    Endpoint::new(
        text("server")?,
        text("share")?,
        text("folder")?,
        text("user")?,
        if domain { Some(text("domain")?) } else { None },
    )
}
