// SPDX-License-Identifier: MIT
//! Shared detached package signatures from retained regular-file descriptors.
use crate::authority;
use enzimos_platform::{Error, Result, files, mount_identity, process, require};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
    time::Duration,
};
pub fn status(body: &[u8], success: bool) -> Result<String> {
    require(body.len() <= 65536, "package signature status bound")?;
    let text =
        std::str::from_utf8(body).map_err(|_| Error("package signature status encoding".into()))?;
    let mut signer = None;
    let mut trusted = false;
    let mut bad = false;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields = rest.split_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("VALIDSIG") => {
                require(
                    matches!(fields.len(), 10 | 11) && signer.is_none(),
                    "package signature identity count or shape",
                )?;
                authority::fingerprint(fields[1])?;
                // Current Arch/package wire uses v4 OpenPGP fingerprints. Weak
                // hashes are never admitted merely because a key is trusted.
                require(
                    fields[5] == "4"
                        && matches!(fields[8], "8" | "9" | "10" | "11" | "12" | "14")
                        && fields[9] == "00",
                    "package signature version, digest or class refused",
                )?;
                let primary = if fields.len() == 11 {
                    fields[10]
                } else {
                    fields[1]
                };
                authority::fingerprint(primary)?;
                signer = Some(primary.to_owned());
            }
            Some("TRUST_FULLY" | "TRUST_ULTIMATE") => trusted = true,
            Some(
                "BADSIG" | "ERRSIG" | "REVKEYSIG" | "EXPKEYSIG" | "EXPSIG" | "NO_PUBKEY"
                | "FAILURE" | "ERROR",
            ) => bad = true,
            _ => (),
        }
    }
    require(
        success && trusted && !bad,
        "package signature not currently authorized",
    )?;
    signer.ok_or_else(|| Error("package signature lacks one valid signer".into()))
}
fn directory_identity(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn verify(archive: &File, signature: &File, home: &Path) -> Result<String> {
    let owner = unsafe { libc::geteuid() };
    let directory = files::directory(home, Some(owner))?;
    let identity = directory_identity(&directory)?;
    let mount = mount_identity::id(directory.as_fd(), true)?;
    require(
        identity.2 == owner && identity.4 & 0o7777 == 0o700,
        "private current package verification authority required",
    )?;
    for (file, bound) in [(archive, 2 * 1024u64 * 1024 * 1024), (signature, 65536)] {
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.len() > 0
                && m.len() <= bound
                && m.mode() & 0o022 == 0,
            "protected bounded package or signature descriptor required",
        )?;
    }
    let before = [
        files::identity(&archive.metadata()?),
        files::identity(&signature.metadata()?),
    ];
    let result = process::run_with_fds(
        "/usr/bin/gpg",
        &[
            "--no-options",
            "--trust-model",
            "direct",
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
            "--no-auto-check-trustdb",
            "--homedir",
            "@fd-dir:2",
            "--status-fd",
            "1",
            "--verify",
            "@fd:1",
            "@fd:0",
        ],
        &[],
        Duration::from_secs(30),
        65536,
        &[archive.as_fd(), signature.as_fd(), directory.as_fd()],
    )?;
    let named = files::directory(home, Some(owner))?;
    require(
        directory_identity(&directory)? == identity
            && directory_identity(&named)? == identity
            && mount_identity::id(directory.as_fd(), true)? == mount
            && mount_identity::id(named.as_fd(), true)? == mount
            && [
                files::identity(&archive.metadata()?),
                files::identity(&signature.metadata()?),
            ] == before,
        "package verification descriptors or authority directory changed",
    )?;
    status(&result.stdout, result.status.success())
}
