// SPDX-License-Identifier: MIT
//! Independently parse machine-readable deployed refs and effective remote policy.
use crate::flatpak_plan::Source;
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
fn sections(bytes: &[u8]) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    require(
        !bytes.is_empty() && bytes.len() <= 512 * 1024 && !bytes.contains(&0),
        "Flatpak state text bound",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|_| Error("Flatpak state encoding".into()))?;
    let mut output = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut section = None::<String>;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            require(
                line.ends_with(']') && line.len() > 2 && output.len() < 128,
                "Flatpak state section bound",
            )?;
            let name = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
                .ok_or_else(|| Error("Flatpak state section bound".into()))?;
            require(
                !name.chars().any(char::is_control)
                    && output.insert(name.into(), BTreeMap::new()).is_none(),
                "duplicate Flatpak state section",
            )?;
            section = Some(name.into());
        } else {
            let (key, contents) = line
                .split_once('=')
                .ok_or_else(|| Error("Flatpak state key shape".into()))?;
            let key = key.trim();
            let contents = contents.trim();
            require(
                !key.is_empty() && key.len() <= 128 && !key.chars().any(char::is_control),
                "Flatpak state key bound",
            )?;
            let rows = output
                .get_mut(
                    section
                        .as_deref()
                        .ok_or_else(|| Error("Flatpak state key outside section".into()))?,
                )
                .ok_or_else(|| Error("Flatpak state section missing".into()))?;
            require(
                rows.len() < 1024 && rows.insert(key.into(), contents.into()).is_none(),
                "duplicate Flatpak state key",
            )?;
        }
    }
    Ok(output)
}
/// The installation's repository names exactly `sources`, each with its reviewed
/// address, collection and signature checks.
///
/// # Errors
/// Any other remote, a missing one, or a changed signing or routing setting.
pub fn remote(bytes: &[u8], sources: &[Source]) -> Result<()> {
    let sections = sections(bytes)?;
    let names = sources
        .iter()
        .map(|s| format!("remote \"{}\"", s.name()))
        .collect::<BTreeSet<_>>();
    require(
        !sources.is_empty()
            && names.len() == sources.len()
            && sections.keys().all(|s| s == "core" || names.contains(s)),
        "installed Flatpak repository contains an unreviewed remote",
    )?;
    let core = sections
        .get("core")
        .ok_or_else(|| Error("installed Flatpak core missing".into()))?;
    require(
        core.get("repo_version").is_some_and(|s| s == "1") && !core.contains_key("parent"),
        "installed Flatpak external parent refused",
    )?;
    for source in sources {
        let remote = sections
            .get(&format!("remote \"{}\"", source.name()))
            .ok_or_else(|| Error("installed reviewed remote missing".into()))?;
        require(
            remote.get("url").is_some_and(|s| s == source.url())
                && remote
                    .get("collection-id")
                    .is_some_and(|s| s == source.collection())
                && remote.get("gpg-verify").is_some_and(|s| s == "true")
                && remote.get("xa.disable").is_none_or(|s| s == "false")
                && remote.get("xa.noenumerate").is_none_or(|s| s == "false")
                // Absent when flatpak 1.18 imports the packaged remotes.d entry.
                && remote.get("url-is-set").is_none_or(|s| s == "true")
                && remote
                    .get("xa.authenticator-install")
                    .is_none_or(|s| s == "false")
                && !remote.keys().any(|s| {
                    s.starts_with("xa.authenticator-name")
                        || s.starts_with("xa.authenticator-options.")
                        || matches!(
                            s.as_str(),
                            "xa.filter"
                                | "signature-lookaside"
                                | "xa.signature-lookaside"
                                | "gpgkeypath"
                                | "metalink"
                        )
                }),
            "installed Flatpak signing or routing policy differs",
        )?;
    }
    Ok(())
}
/// Installed apps as listed, each from the remote `expected` assigns it.
///
/// # Errors
/// Another app set, origin, architecture or branch, or a malformed commit.
pub fn deployments(
    bytes: &[u8],
    expected: &BTreeMap<String, Source>,
) -> Result<BTreeMap<String, Value>> {
    require(
        bytes.len() <= 256 * 1024 && !bytes.contains(&0),
        "installed Flatpak listing bound",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("installed Flatpak listing encoding".into()))?;
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        let fields = line.split('\t').map(str::trim).collect::<Vec<_>>();
        require(
            fields.len() == 5
                && rows.len() < 128
                && crate::flatpak_plan::app_id(fields[0])
                && fields[1] == "x86_64"
                && fields[2] == "stable"
                && expected
                    .get(fields[0])
                    .is_some_and(|source| fields[3] == source.name()),
            "installed Flatpak app identity or origin differs",
        )?;
        // flatpak 1.18 `list` shortens the active commit to 12 hex digits; the
        // caller resolves the full commit from the deployment's `active` link.
        require(
            (12..=64).contains(&fields[4].len())
                && fields[4]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "installed Flatpak commit prefix",
        )?;
        require(rows.insert(fields[0].into(), value!({"ref":format!("app/{}/x86_64/stable",fields[0]),"commit":fields[4],"origin":fields[3]})).is_none(), "installed Flatpak app duplicated")?;
    }
    require(
        rows.keys().eq(expected.keys()) && !rows.is_empty(),
        "installed Flatpak app set differs",
    )?;
    Ok(rows)
}
pub fn metadata(bytes: &[u8], app: &str) -> Result<()> {
    let sections = sections(bytes)?;
    let application = sections
        .get("Application")
        .ok_or_else(|| Error("deployed Flatpak application metadata missing".into()))?;
    require(
        application.get("name").is_some_and(|s| s == app),
        "deployed Flatpak metadata identifies another application",
    )?;
    let runtime = application
        .get("runtime")
        .ok_or_else(|| Error("deployed Flatpak runtime metadata missing".into()))?
        .split('/')
        .collect::<Vec<_>>();
    require(
        runtime.len() == 3
            && crate::flatpak_plan::app_id(runtime[0])
            && runtime[1] == "x86_64"
            && !runtime[2].is_empty()
            && runtime[2].len() <= 64
            && runtime[2]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "deployed Flatpak runtime metadata shape",
    )
}
