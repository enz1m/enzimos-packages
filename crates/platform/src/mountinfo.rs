// SPDX-License-Identifier: MIT
//! Kernel mount records are observations, not filesystem ownership authority.
use crate::{Error, Result, require};
/// One `/proc/<pid>/mountinfo` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Mount ID.
    pub id: u64,
    /// Parent mount ID.
    pub parent: u64,
    /// Device major number.
    pub major: u32,
    /// Device minor number.
    pub minor: u32,
    /// Root of the mount within its filesystem.
    pub root: String,
    /// Mount point.
    pub target: String,
    /// Filesystem type.
    pub filesystem: String,
    /// Per-mount options.
    pub options: String,
    /// Per-superblock options.
    pub filesystem_options: String,
    /// Optional fields such as `shared:N`.
    pub optional: Vec<String>,
}
/// Decode the octal escapes the kernel uses in mountinfo paths.
///
/// # Errors
///
/// Fails on a malformed escape, a disallowed byte, or a result that is not UTF-8.
pub fn unescape(s: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let input = s.as_bytes();
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            bytes.push(input[i]);
            i += 1;
            continue;
        }
        require(
            i + 4 <= input.len()
                && input[i + 1..i + 4]
                    .iter()
                    .all(|b| (b'0'..=b'7').contains(b)),
            "invalid mount path escape",
        )?;
        let n = u16::from(input[i + 1] - b'0') * 64
            + u16::from(input[i + 2] - b'0') * 8
            + u16::from(input[i + 3] - b'0');
        require(n > 0 && n <= 255, "invalid mount path byte")?;
        bytes.push(n as u8);
        i += 4;
    }
    String::from_utf8(bytes).map_err(|_| Error("unsupported mount filename encoding".into()))
}
/// Parse a whole mountinfo body.
///
/// # Errors
///
/// Fails when the body or record count exceeds its bound, a record is malformed, or mount IDs
/// repeat.
pub fn parse(body: &str) -> Result<Vec<Row>> {
    require(
        body.len() <= 2 * 1024 * 1024 && !body.contains('\0'),
        "mount observation byte bound",
    )?;
    let mut rows = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for line in body.lines() {
        require(rows.len() < 4096, "mount observation count")?;
        let (left, right) = line
            .split_once(" - ")
            .ok_or_else(|| Error("invalid mountinfo record".into()))?;
        let left = left.split_whitespace().collect::<Vec<_>>();
        let right = right.split_whitespace().collect::<Vec<_>>();
        require(
            (6..=128).contains(&left.len()) && (3..=16).contains(&right.len()),
            "invalid mountinfo fields",
        )?;
        let parse = |s: &str| {
            s.parse::<u64>()
                .map_err(|_| Error("invalid mountinfo number".into()))
        };
        let id = parse(left[0])?;
        let parent = parse(left[1])?;
        require(id > 0 && ids.insert(id), "duplicate mount identity")?;
        let (major, minor) = left[2]
            .split_once(':')
            .ok_or_else(|| Error("mount device identity".into()))?;
        let major = u32::try_from(parse(major)?).map_err(|_| Error("mount device bound".into()))?;
        let minor = u32::try_from(parse(minor)?).map_err(|_| Error("mount device bound".into()))?;
        let root = unescape(left[3])?;
        let target = unescape(left[4])?;
        require(
            !root.is_empty()
                && target.starts_with('/')
                && root.len() < 4096
                && target.len() < 4096
                && right[0].len() <= 64,
            "mount path/type bound",
        )?;
        rows.push(Row {
            id,
            parent,
            major,
            minor,
            root,
            target,
            filesystem: right[0].into(),
            options: left[5].into(),
            filesystem_options: right[2].into(),
            optional: left[6..].iter().map(|s| (*s).to_owned()).collect(),
        });
    }
    Ok(rows)
}
