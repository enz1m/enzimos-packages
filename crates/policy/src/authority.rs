// SPDX-License-Identifier: MIT
//! Arch package authority uses five independent pinned master contexts, never key discovery.
use enzimos_platform::{Error, Result, require};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
/// Fingerprints of the five Arch master signing keys.
pub const MASTERS: [&str; 5] = [
    "2AC0A42EFB0B5CBC7A0402ED4DC95B6D7BE9892E",
    "3572FA2A1B067F22C58AF155F8B821B42A6FDCD7",
    "69E6471E3AE065297529832E6BA0F5A2037F4F41",
    "99B6618472A3B3B814185BAED7D3D823B88BDB9B",
    "D8AFDDA07A5B6EDFA7D8CCDAD6D055F927843F1C",
];
/// GnuPG configuration of an authority home.
pub const CONFIG: &str =
    "trust-model direct\nno-auto-key-retrieve\nauto-key-locate clear\nno-autostart\n";
/// Files that make up an authority home.
pub const FILES: [&str; 4] = ["pubring.gpg", "trustdb.gpg", "gpg.conf", "approved.trust"];
pub(crate) const MINIMUM_APPROVED: usize = 10;
/// Require an uppercase 40-digit hex fingerprint.
///
/// # Errors
///
/// Fails for any other form.
pub fn fingerprint(s: &str) -> Result<&str> {
    require(
        s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
        "invalid package authority fingerprint",
    )?;
    Ok(s)
}
pub(crate) fn revoked(body: &str) -> Result<BTreeSet<String>> {
    require(
        body.len() <= 8 * 1024 * 1024 && !body.contains('\0'),
        "authority revocation list bound",
    )?;
    let mut result = BTreeSet::new();
    for value in body.split_whitespace() {
        require(
            result.len() < 65536 && result.insert(fingerprint(value)?.into()),
            "duplicate or excessive authority revocation",
        )?;
    }
    Ok(result)
}
fn rows(body: &str) -> Result<Vec<Vec<&str>>> {
    require(
        body.len() <= 8 * 1024 * 1024 && !body.contains('\0'),
        "authority listing byte bound",
    )?;
    let mut result = Vec::new();
    for line in body.lines() {
        require(
            result.len() < 65536 && line.len() <= 65536,
            "authority listing row bound",
        )?;
        let row = line.split(':').collect::<Vec<_>>();
        require(
            !matches!(row[0], "sec" | "ssb") && row.len() <= 64,
            "private key material or invalid authority listing",
        )?;
        result.push(row);
    }
    Ok(result)
}
fn usable(row: &[&str]) -> bool {
    row.len() > 11 && !matches!(row[1], "r" | "e" | "d" | "i") && !row[11].contains('D')
}
fn arch_uid(s: &str) -> bool {
    let Some((name, email)) = s.split_once('<') else {
        return false;
    };
    let Some(local) = email.strip_suffix("@archlinux.org>") else {
        return false;
    };
    !name.contains(['<', '>', '\r', '\n'])
        && !local.is_empty()
        && local
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"<>@".contains(&b))
}
/// Primary key fingerprints and UIDs in a GnuPG colon listing.
///
/// # Errors
///
/// Fails when the listing is malformed or repeats a key.
pub fn identities(body: &str) -> Result<BTreeSet<(String, String)>> {
    let mut result = BTreeSet::new();
    let mut primary = None;
    let mut waiting = false;
    let mut valid = false;
    let mut seen = BTreeSet::new();
    for row in rows(body)? {
        match row[0] {
            "pub" => {
                require(!waiting, "primary fingerprint missing")?;
                waiting = true;
                primary = None;
                valid = usable(&row);
            }
            "fpr" if waiting => {
                require(row.len() > 9, "primary fingerprint missing")?;
                let fp = fingerprint(row[9])?;
                require(
                    seen.insert(fp.to_owned()),
                    "duplicate primary package authority key",
                )?;
                primary = Some(fp.to_owned());
                waiting = false;
            }
            "uid" => {
                require(
                    !waiting && row.len() > 9,
                    "package authority UID before fingerprint",
                )?;
                if valid && matches!(row[1], "f" | "u") && arch_uid(row[9]) {
                    let fp = primary
                        .as_ref()
                        .ok_or_else(|| Error("package authority primary missing".into()))?;
                    result.insert((fp.clone(), row[9].into()));
                }
            }
            "sub" => require(!waiting, "primary fingerprint missing before subkey")?,
            _ => (),
        }
    }
    require(!waiting, "primary fingerprint missing")?;
    Ok(result)
}
pub(crate) fn masters_usable(body: &str, now: u64) -> Result<()> {
    let mut keys = BTreeMap::new();
    let mut pending = None;
    for row in rows(body)? {
        if row[0] == "pub" {
            require(pending.is_none(), "master fingerprint missing")?;
            pending = Some(row);
        } else if row[0] == "fpr" && pending.is_some() {
            require(row.len() > 9, "master fingerprint missing")?;
            require(
                keys.insert(
                    fingerprint(row[9])?.to_owned(),
                    pending
                        .take()
                        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                )
                .is_none(),
                "duplicate master fingerprint",
            )?;
        }
    }
    require(pending.is_none(), "master fingerprint missing")?;
    for master in MASTERS {
        let row = keys.get(master).ok_or_else(|| {
            Error("a pinned Arch master key is unavailable; review required".into())
        })?;
        require(
            usable(row) && row[11].contains('c'),
            "a pinned Arch master key is revoked or disabled; review required",
        )?;
        require(
            row[6].is_empty() || row[6].parse::<u64>().is_ok_and(|expiry| expiry > now),
            "a pinned Arch master key is expired; review required",
        )?;
    }
    Ok(())
}
/// Master keys trusted by all five master contexts, excluding `revoked`.
///
/// # Errors
///
/// Fails without exactly five contexts or when a master key is revoked.
pub fn quorum(
    listings: &BTreeMap<String, String>,
    revoked: &BTreeSet<String>,
) -> Result<Vec<String>> {
    require(
        listings.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == MASTERS.into_iter().collect(),
        "exactly five pinned master contexts required",
    )?;
    for revoked in revoked {
        fingerprint(revoked)?;
    }
    let mut votes: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (master, listing) in listings {
        require(
            !revoked.contains(master),
            "a pinned Arch master key is revoked; review required",
        )?;
        for identity in identities(listing)? {
            votes.entry(identity).or_default().insert(master.clone());
        }
    }
    Ok(votes
        .into_iter()
        .filter_map(|((fp, _), masters)| {
            (masters.len() >= 3 && !revoked.contains(&fp) && !MASTERS.contains(&fp.as_str()))
                .then_some(fp)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}
pub(crate) fn trusted_local(body: &str, arch: &BTreeSet<String>) -> Result<Vec<String>> {
    require(body.len() <= 2 * 1024 * 1024, "local ownertrust bound")?;
    let mut result = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for line in body
        .lines()
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
    {
        let fields = line.split(':').collect::<Vec<_>>();
        require(
            fields.len() == 3
                && fields[2].is_empty()
                && seen.insert(fingerprint(fields[0])?.to_owned())
                && matches!(fields[1], "1" | "2" | "3" | "4" | "5" | "6"),
            "invalid or duplicate local ownertrust",
        )?;
        if matches!(fields[1], "5" | "6") && !arch.contains(fields[0]) {
            result.insert(fields[0].to_owned());
        }
    }
    Ok(result.into_iter().collect())
}
/// Fingerprints in a GnuPG colon listing.
///
/// # Errors
///
/// Fails when a fingerprint row is missing.
pub fn fingerprints(body: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for row in rows(body)? {
        if row[0] == "fpr" {
            require(row.len() > 9, "key fingerprint missing")?;
            result.insert(fingerprint(row[9])?.into());
        }
    }
    Ok(result)
}
/// GnuPG ownertrust text giving `keys` full trust.
///
/// # Errors
///
/// Fails when the output would exceed its bound.
pub fn trust(keys: impl IntoIterator<Item = String>) -> Result<String> {
    let mut result = String::new();
    for key in keys.into_iter().collect::<BTreeSet<_>>() {
        fingerprint(&key)?;
        require(result.len() < 2 * 1024 * 1024, "ownertrust output bound")?;
        let _ = writeln!(result, "{key}:5:");
    }
    Ok(result)
}
