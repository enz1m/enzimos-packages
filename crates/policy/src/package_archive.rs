// SPDX-License-Identifier: MIT
//! Bounded package identity inspection without extraction or shared-offset changes.
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
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
pub fn metadata(body: &str) -> Result<Value> {
    require(
        body.len() <= 256 * 1024 && !body.contains('\0'),
        "package metadata byte bound",
    )?;
    let mut fields = BTreeMap::<&str, Vec<&str>>::new();
    for line in body.lines() {
        if let Some((key, value)) = line.split_once(" = ") {
            fields.entry(key).or_default().push(value);
        }
    }
    let one = |key| -> Result<&str> {
        Ok(fields
            .get(key)
            .filter(|v| v.len() == 1)
            .ok_or_else(|| Error("package identity field count".into()))?[0])
    };
    let name = one("pkgname")?;
    let version = one("pkgver")?;
    let arch = one("arch")?;
    require(
        name.len() <= 128
            && name
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"@+_.-".contains(&b)),
        "invalid package name",
    )?;
    require(
        version.len() <= 256
            && version
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+_:~-".contains(&b)),
        "invalid package version",
    )?;
    require(
        matches!(arch, "any" | "x86_64"),
        "package architecture refused",
    )?;
    Ok(json!({"name":name,"version":version}))
}
/// Validates the complete bounded archive and returns its unique package identity.
///
/// # Errors
/// Rejects changed files, unsafe member paths, duplicate metadata, invalid
/// compression or archive data, and archives exceeding the admission bounds.
pub fn identity(file: &File) -> Result<Value> {
    Ok(inspect(file, None)?.0)
}
/// ALPM container names allow full versions both with and without an epoch;
/// metadata version comparisons themselves remain exact.
pub fn version_matches(container: &str, version: &str) -> bool {
    container == version
        || version.split_once(':').is_some_and(|(epoch, body)| {
            !epoch.is_empty()
                && epoch.bytes().all(|byte| byte.is_ascii_digit())
                && !body.is_empty()
                && container == body
        })
}
pub fn filename_matches(filename: &str, name: &str, version: &str) -> bool {
    filename
        .strip_prefix(&format!("{name}-"))
        .is_some_and(|tail| {
            ["-x86_64.pkg.tar.zst", "-any.pkg.tar.zst"]
                .iter()
                .any(|suffix| {
                    tail.strip_suffix(suffix)
                        .is_some_and(|container| version_matches(container, version))
                })
        })
}
/// The release comes from one actual regular kernel image, never a package name.
pub fn kernel_release(file: &File, flavor: &str) -> Result<String> {
    require(
        matches!(flavor, "linux" | "linux-lts"),
        "unsupported update kernel flavor",
    )?;
    inspect(file, Some(flavor))?
        .1
        .ok_or_else(|| Error("kernel package lacks its unique module image".into()))
}
fn inspect(file: &File, flavor: Option<&str>) -> Result<(Value, Option<String>)> {
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= 2 * 1024u64 * 1024 * 1024
            && before.mode() & 0o022 == 0,
        "protected bounded package archive required",
    )?;
    let decoder = zstd::stream::read::Decoder::new(Pread {
        file,
        offset: 0,
        bytes: before.len(),
    })?;
    let mut archive = tar::Archive::new(decoder.take(4 * 1024u64 * 1024 * 1024));
    // Padding must not hide another metadata entry or a concatenated archive.
    archive.set_ignore_zeros(true);
    let mut identity = None;
    let mut kernel = None;
    for (index, item) in archive.entries()?.enumerate() {
        require(index < 100000, "package member count bound")?;
        let mut item = item?;
        require(
            item.path()?.components().all(|part| {
                matches!(
                    part,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            }),
            "unsafe package archive member path",
        )?;
        let path = item.path()?;
        let normalized = path
            .components()
            .filter(|part| !matches!(part, std::path::Component::CurDir))
            .collect::<Vec<_>>();
        if normalized
            == [std::path::Component::Normal(std::ffi::OsStr::new(
                ".PKGINFO",
            ))]
        {
            require(
                identity.is_none()
                    && item.header().entry_type().is_file()
                    && item.size() <= 256 * 1024,
                "duplicate or invalid package metadata entry",
            )?;
            let mut body = String::new();
            item.read_to_string(&mut body)?;
            let parsed = metadata(&body)?;
            if let Some(flavor) = flavor {
                require(
                    parsed["name"] == flavor && body.lines().any(|line| line == "arch = x86_64"),
                    "kernel archive metadata differs from admitted flavor or architecture",
                )?;
            }
            identity = Some(parsed);
        } else if flavor.is_some()
            && normalized.len() == 5
            && normalized[0] == std::path::Component::Normal(std::ffi::OsStr::new("usr"))
            && normalized[1] == std::path::Component::Normal(std::ffi::OsStr::new("lib"))
            && normalized[2] == std::path::Component::Normal(std::ffi::OsStr::new("modules"))
            && normalized[4] == std::path::Component::Normal(std::ffi::OsStr::new("vmlinuz"))
        {
            require(
                kernel.is_none()
                    && item.header().entry_type().is_file()
                    && item.size() > 0
                    && item.size() <= enzimos_platform::stream_copy::STREAM_BOUND,
                "kernel module image count, type or size differs",
            )?;
            let release = normalized[3]
                .as_os_str()
                .to_str()
                .ok_or_else(|| Error("kernel release path encoding".into()))?;
            kernel = Some(crate::identity::safe_id(release)?.to_owned());
        }
    }
    require(
        archive.into_inner().limit() > 0,
        "package expanded byte bound exhausted",
    )?;
    require(
        files::identity(&file.metadata()?) == files::identity(&before),
        "package archive changed during inspection",
    )?;
    Ok((
        identity.ok_or_else(|| Error("package lacks .PKGINFO".into()))?,
        kernel,
    ))
}
