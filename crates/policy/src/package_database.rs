// SPDX-License-Identifier: MIT
//! Bounded repository database inspection shared by delivery and native apply.
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
};
struct Pread<'a> {
    file: &'a File,
    offset: u64,
    bytes: u64,
}
impl Read for Pread<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .bytes
            .saturating_sub(self.offset)
            .min(buffer.len() as u64) as usize;
        let count = self.file.read_at(&mut buffer[..remaining], self.offset)?;
        self.offset += count as u64;
        Ok(count)
    }
}
/// Verify that the database archive `file` lists exactly `packages`.
///
/// # Errors
///
/// Fails when the archive is unsafe or its entries differ.
pub fn verify(file: &File, packages: &[Value]) -> Result<()> {
    let metadata = file.metadata()?;
    require(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0
            && metadata.len() > 0
            && metadata.len() <= 32 * 1024 * 1024,
        "protected bounded database archive required",
    )?;
    require(
        !packages.is_empty() && packages.len() <= 768,
        "database package count bound",
    )?;
    for row in packages {
        require(
            ["name", "version", "file"].iter().all(|key| {
                row[*key].as_str().is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 256
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
                        && value != "."
                        && value != ".."
                })
            }) && row["bytes"].as_u64().is_some_and(|bytes| bytes > 0)
                && row["sha256"].as_str().is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }),
            "database expected package identity malformed",
        )?;
    }
    let before = files::identity(&file.metadata()?);
    // Consume concatenated gzip members and tar zero padding rather than
    // accepting the first apparent end marker and hiding later records.
    let decoder = flate2::read::MultiGzDecoder::new(Pread {
        file,
        offset: 0,
        bytes: metadata.len(),
    });
    let mut archive = tar::Archive::new(decoder.take(16 * 1024 * 1024));
    archive.set_ignore_zeros(true);
    let expected = packages
        .iter()
        .map(|p| (p["name"].as_str().unwrap_or(""), p))
        .collect::<BTreeMap<_, _>>();
    require(
        !expected.is_empty() && expected.len() == packages.len() && !expected.contains_key(""),
        "database expected package set ambiguous",
    )?;
    let (mut seen, mut total) = (BTreeSet::new(), 0);
    for (index, item) in archive.entries()?.enumerate() {
        require(index < 3 * packages.len(), "database member bound")?;
        let mut item = item?;
        require(
            !item.header().entry_type().is_symlink() && !item.header().entry_type().is_hard_link(),
            "database links forbidden",
        )?;
        if item.header().entry_type().is_dir() {
            let path = item.path()?;
            require(
                path.components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
                    && path.components().count() == 1,
                "invalid database directory member",
            )?;
            continue;
        }
        let name = item.path()?.to_string_lossy().into_owned();
        let directory = name.strip_suffix("/desc").unwrap_or("");
        require(
            item.header().entry_type().is_file()
                && name.ends_with("/desc")
                && name.matches('/').count() == 1
                && !directory.is_empty()
                && directory != "."
                && directory != ".."
                && item.size() > 0
                && item.size() <= 256 * 1024,
            "invalid database member",
        )?;
        total += item.size();
        require(total <= 8 * 1024 * 1024, "database expanded byte bound")?;
        let mut body = String::new();
        item.read_to_string(&mut body)?;
        let fields = enzimos_platform::alpm_sections::parse(body.as_bytes())?;
        let name = fields
            .get("%NAME%")
            .filter(|v| v.len() == 1)
            .ok_or_else(|| Error("database package set mismatch".into()))?[0];
        let row = expected
            .get(name)
            .ok_or_else(|| Error("database package set mismatch".into()))?;
        require(
            directory
                .strip_prefix(&format!("{name}-"))
                .is_some_and(|version| {
                    crate::package_archive::version_matches(
                        version,
                        row["version"].as_str().unwrap_or(""),
                    )
                }),
            "database directory differs from package identity",
        )?;
        require(seen.insert(name.to_owned()), "database duplicate package")?;
        for (field, v) in [
            (
                "%VERSION%",
                row["version"].as_str().unwrap_or("").to_owned(),
            ),
            ("%FILENAME%", row["file"].as_str().unwrap_or("").to_owned()),
            ("%CSIZE%", row["bytes"].to_string()),
            (
                "%SHA256SUM%",
                row["sha256"].as_str().unwrap_or("").to_owned(),
            ),
        ] {
            require(
                fields
                    .get(field)
                    .is_some_and(|values| values.len() == 1 && values[0] == v),
                "database/channel identity mismatch",
            )?;
        }
    }
    require(
        archive.into_inner().limit() > 0 && files::identity(&file.metadata()?) == before,
        "database expanded bound or retained archive changed",
    )?;
    require(
        seen.len() == expected.len(),
        "database missing channel package",
    )
}
