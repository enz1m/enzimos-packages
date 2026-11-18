// SPDX-License-Identifier: MIT
//! Closed offline application selection and the two signed remotes it may name:
//! Flathub, and the enzimOS repository with its pinned key and app fleet.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
pub const COLLECTION: &str = "org.flathub.Stable";
pub const URL: &str = "https://dl.flathub.org/repo/";
/// The enzimOS repository's OSTree collection.
pub const ENZIMOS_COLLECTION: &str = "org.enzimos.Apps";
/// Placeholder until the repository host exists; installs come from the medium.
pub const ENZIMOS_URL: &str = "https://flatpak.enzimos.invalid/repo/";
/// The enzimOS repository signing key (OpenPGP v4 fingerprint).
pub const ENZIMOS_FINGERPRINT: &str = "02AF25420A1609EAC4CB4E5FA9E4B8C18CB3F476";
/// The apps the enzimOS remote may install from the medium.
pub const ENZIMOS_APPS: [&str; 7] = [
    "org.enzimos.Calculator",
    "io.enz.Messages",
    "io.github.enzui.Music",
    "org.enzimos.Photos",
    "io.github.enzui.Remote",
    "io.github.enzui.Reader",
    "io.github.enzui.Calendar",
];
/// A reviewed remote that offline media may install from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// Flathub, the origin of runtimes and third-party apps.
    Flathub,
    /// The enzimOS repository of enzUI apps.
    Enzimos,
}
impl Source {
    /// The remote name in a Flatpak installation.
    pub fn name(self) -> &'static str {
        match self {
            Self::Flathub => "flathub",
            Self::Enzimos => "enzimos",
        }
    }
    /// The reviewed remote address.
    pub fn url(self) -> &'static str {
        match self {
            Self::Flathub => URL,
            Self::Enzimos => ENZIMOS_URL,
        }
    }
    /// The reviewed collection ID.
    pub fn collection(self) -> &'static str {
        match self {
            Self::Flathub => COLLECTION,
            Self::Enzimos => ENZIMOS_COLLECTION,
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Flathub => "Flathub",
            Self::Enzimos => "enzimOS Apps",
        }
    }
    /// Flathub's key is whatever its published definition carries; the enzimOS key is pinned.
    fn fingerprint(self) -> Option<&'static str> {
        match self {
            Self::Flathub => None,
            Self::Enzimos => Some(ENZIMOS_FINGERPRINT),
        }
    }
    fn admits(self, app: &str) -> bool {
        match self {
            Self::Flathub => true,
            Self::Enzimos => ENZIMOS_APPS.contains(&app),
        }
    }
}
pub fn repository(bytes: &[u8]) -> Result<()> {
    require(
        !bytes.is_empty() && bytes.len() <= 64 * 1024 && !bytes.contains(&0),
        "sideload repository configuration bound",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("sideload repository configuration encoding".into()))?;
    let mut section = false;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            require(
                line == "[core]" && !section,
                "sideload repository external remote or repeated section",
            )?;
            section = true;
            continue;
        }
        let (name, contents) = line
            .split_once('=')
            .ok_or_else(|| Error("sideload repository configuration field".into()))?;
        require(
            section
                && matches!(name, "repo_version" | "mode" | "indexed-deltas")
                && fields.insert(name, contents).is_none(),
            "sideload repository external parent or unsupported policy",
        )?;
    }
    require(
        fields.get("repo_version") == Some(&"1")
            && fields.get("mode") == Some(&"archive-z2")
            && fields
                .get("indexed-deltas")
                .is_none_or(|v| *v == "true" || *v == "false"),
        "sideload repository must use the closed immutable create-usb archive format",
    )
}

pub fn app_id(name: &str) -> bool {
    let parts = name.split('.').collect::<Vec<_>>();
    name.len() <= 255
        && parts.len() >= 3
        && parts.iter().enumerate().all(|(i, part)| {
            !part.is_empty()
                && (part.as_bytes()[0].is_ascii_alphabetic() || part.as_bytes()[0] == b'_')
                && part.bytes().all(|c| {
                    c.is_ascii_alphanumeric() || c == b'_' || (i + 1 == parts.len() && c == b'-')
                })
        })
}
pub fn applications(source: Source, bytes: &[u8], declared: &Value) -> Result<Vec<String>> {
    require(
        bytes.len() <= 64 * 1024 && !bytes.contains(&0),
        "offline application list bound",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("offline application list encoding".into()))?;
    let mut seen = BTreeSet::new();
    let mut apps = Vec::new();
    for line in text.lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        require(
            app_id(name) && apps.len() < 128 && seen.insert(name.to_owned()),
            "invalid, duplicated or excessive offline application ID",
        )?;
        require(
            source.admits(name),
            "offline application is not admitted from this remote",
        )?;
        apps.push(name.into());
    }
    require(
        !apps.is_empty() && value!(apps) == *declared,
        "offline application list differs from admitted media declaration",
    )?;
    Ok(apps)
}
pub fn remote(source: Source, bytes: &[u8]) -> Result<Value> {
    require(
        !bytes.is_empty() && bytes.len() <= 128 * 1024 && !bytes.contains(&0),
        "offline remote policy bound",
    )?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error("offline remote policy encoding".into()))?;
    let mut section = false;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            require(
                line == "[Flatpak Repo]" && !section,
                "remote policy has an unknown or repeated section",
            )?;
            section = true;
            continue;
        }
        require(section, "remote field outside its section")?;
        let (key, contents) = line
            .split_once('=')
            .ok_or_else(|| Error("remote policy field shape".into()))?;
        require(
            matches!(
                key,
                "Title"
                    | "Url"
                    | "Homepage"
                    | "Comment"
                    | "Description"
                    | "Icon"
                    | "GPGKey"
                    | "CollectionID"
                    | "DefaultBranch"
            ) && !contents.is_empty()
                && !contents.chars().any(char::is_control)
                && !contents.contains('\\')
                && fields.insert(key.to_owned(), contents.to_owned()).is_none(),
            "remote policy contains duplicate or unsupported signing/routing policy",
        )?;
    }
    require(
        fields.get("Title").is_some_and(|s| s == source.title())
            && fields.get("Url").is_some_and(|s| s == source.url())
            // Flathub's definition omits its collection; ours must name it.
            && fields.get("CollectionID").map_or(source == Source::Flathub, |s| s == source.collection())
            && fields.get("DefaultBranch").is_none_or(|s| s == "stable"),
        "remote is not the reviewed stable repository",
    )?;
    let encoded = fields
        .get("GPGKey")
        .ok_or_else(|| Error("remote signing key missing".into()))?;
    require(encoded.len() <= 96 * 1024, "remote signing key bound")?;
    let key = openssl::base64::decode_block(encoded)
        .map_err(|_| Error("remote signing key base64 encoding".into()))?;
    require(
        key.len() >= 32
            && key.len() <= 64 * 1024
            && openssl::base64::encode_block(&key) == *encoded,
        "remote signing key is empty, truncated or noncanonical",
    )?;
    let fingerprint = public_packets(&key)?;
    require(
        source
            .fingerprint()
            .is_none_or(|pinned| pinned == fingerprint),
        "remote signing key is not the reviewed key",
    )?;
    Ok(
        value!({"schema":1,"remote":source.name(),"url":source.url(),"collection":source.collection(),"gpg_key_sha256":json::sha256(&key),"gpg_fingerprint":fingerprint,"policy_sha256":json::sha256(bytes),"gpg_verify":true}),
    )
}
// Public-key exports may carry user IDs, signatures, attributes and public
// subkeys. Secret keys, literal data, compressed packets and partial lengths
// are outside this bounded immutable signing-policy format. Returns the
// primary key's v4 fingerprint.
fn public_packets(mut bytes: &[u8]) -> Result<String> {
    let mut primary = 0;
    let mut fingerprint = String::new();
    let mut count = 0;
    while !bytes.is_empty() {
        count += 1;
        require(
            count <= 128 && bytes[0] & 0x80 != 0,
            "remote signing packet count or header",
        )?;
        let first = bytes[0];
        bytes = &bytes[1..];
        let (tag, size) = if first & 0x40 != 0 {
            require(!bytes.is_empty(), "remote signing packet length absent")?;
            let n = bytes[0];
            bytes = &bytes[1..];
            let size = match n {
                0..=191 => n as usize,
                192..=223 => {
                    require(!bytes.is_empty(), "remote signing packet length truncated")?;
                    let size = ((n as usize - 192) << 8) + bytes[0] as usize + 192;
                    bytes = &bytes[1..];
                    size
                }
                255 => {
                    require(bytes.len() >= 4, "remote signing packet length truncated")?;
                    let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                    bytes = &bytes[4..];
                    size
                }
                _ => return Err(Error("partial signing packet length refused".into())),
            };
            (first & 63, size)
        } else {
            let length_bytes = match first & 3 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(Error("indeterminate signing packet length refused".into())),
            };
            require(
                bytes.len() >= length_bytes,
                "remote signing packet length truncated",
            )?;
            let size = bytes[..length_bytes]
                .iter()
                .fold(0usize, |n, b| (n << 8) | *b as usize);
            bytes = &bytes[length_bytes..];
            ((first >> 2) & 15, size)
        };
        require(
            matches!(tag, 2 | 6 | 13 | 14 | 17)
                && size > 0
                && size <= bytes.len()
                && (count != 1 || tag == 6),
            "remote signing packet type, order or extent refused",
        )?;
        if tag == 6 {
            primary += 1;
            let body = &bytes[..size];
            require(
                body[0] == 4 && size <= 0xffff,
                "remote signing key must be an OpenPGP v4 key",
            )?;
            let mut framed = vec![0x99, (size >> 8) as u8, size as u8];
            framed.extend_from_slice(body);
            fingerprint = openssl::sha::sha1(&framed)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
        }
        bytes = &bytes[size..];
    }
    require(
        primary == 1,
        "exactly one primary remote signing key required",
    )?;
    Ok(fingerprint)
}
