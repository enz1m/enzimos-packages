// SPDX-License-Identifier: MIT
//! Bounded newc inventory, one zstd frame, and aligned native descriptor append.
use enzimos_platform::{Error, Result, json, require};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};
pub const MAX_UNPACKED: usize = 768 * 1024 * 1024;
pub const MAX_MEMBERS: usize = 65536;
#[derive(Debug, Clone)]
pub struct Member {
    pub mode: u32,
    pub sha: Option<String>,
    pub link: Option<String>,
}
fn link_path(name: &str, link: &str) -> Result<String> {
    require(
        !link.is_empty() && !link.chars().any(char::is_control),
        "unsafe initramfs link",
    )?;
    let mut parts = if link.starts_with('/') {
        Vec::new()
    } else {
        name.rsplit_once('/').map_or(Vec::new(), |(parent, _)| {
            parent.split('/').collect::<Vec<_>>()
        })
    };
    for part in link.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                require(parts.pop().is_some(), "initramfs link escapes root")?;
            }
            part => parts.push(part),
        }
    }
    path(&parts.join("/"))
}
fn path(raw: &str) -> Result<String> {
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    require(
        !raw.is_empty()
            && raw.len() <= 4096
            && !raw.starts_with('/')
            && raw
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
            && !raw.chars().any(char::is_control),
        "unsafe initramfs member path",
    )?;
    Ok(raw.into())
}
fn read<R: Read>(stream: &mut R, size: usize, total: &mut usize) -> Result<Vec<u8>> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| Error("initramfs unpacked overflow".into()))?;
    require(*total <= MAX_UNPACKED, "initramfs unpacked byte bound")?;
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn padding<R: Read>(stream: &mut R, size: usize, total: &mut usize) -> Result<()> {
    require(
        read(stream, size, total)?.iter().all(|b| *b == 0),
        "nonzero initramfs member padding",
    )
}
fn archive<R: Read>(
    stream: &mut R,
    seen: &mut BTreeMap<String, Member>,
    wanted: &BTreeSet<String>,
    total: &mut usize,
) -> Result<()> {
    for _ in 0..=MAX_MEMBERS {
        let header = read(stream, 110, total)?;
        require(&header[..6] == b"070701", "newc initramfs required")?;
        let mut fields = [0u32; 13];
        for (i, field) in fields.iter_mut().enumerate() {
            let text = std::str::from_utf8(&header[6 + 8 * i..14 + 8 * i])
                .map_err(|_| Error("newc integer encoding".into()))?;
            require(
                text.bytes().all(|b| b.is_ascii_hexdigit()),
                "newc integer syntax",
            )?;
            *field =
                u32::from_str_radix(text, 16).map_err(|_| Error("newc integer overflow".into()))?;
        }
        let mode = fields[1];
        let size = fields[6] as usize;
        let namesize = fields[11] as usize;
        require(
            (1..=4096).contains(&namesize) && fields[2] == 0 && fields[3] == 0 && fields[12] == 0,
            "newc name, owner, or checksum differs",
        )?;
        let name = read(stream, namesize, total)?;
        require(
            name.last() == Some(&0) && !name[..namesize - 1].contains(&0),
            "newc name terminator",
        )?;
        padding(stream, (4 - (110 + namesize) % 4) % 4, total)?;
        let name = std::str::from_utf8(&name[..namesize - 1])
            .map_err(|_| Error("newc member name encoding".into()))?;
        if name == "TRAILER!!!" {
            require(size == 0, "newc trailer carries data")?;
            return Ok(());
        }
        // GNU cpio may emit a harmless explicit root directory.
        if matches!(name, "." | "./") {
            require(
                mode & libc::S_IFMT == libc::S_IFDIR && size == 0,
                "newc root directory differs",
            )?;
            continue;
        }
        let kind = mode & libc::S_IFMT;
        // mkinitcpio emits newc directories with one terminal slash. Preserve
        // the same component checks; files/links and doubled slashes cannot
        // acquire a canonical alias through this directory-only normalization.
        let name = path(if kind == libc::S_IFDIR {
            name.strip_suffix('/').unwrap_or(name)
        } else {
            name
        })?;
        require(
            matches!(
                kind,
                libc::S_IFREG
                    | libc::S_IFDIR
                    | libc::S_IFLNK
                    | libc::S_IFCHR
                    | libc::S_IFBLK
                    | libc::S_IFIFO
            ),
            "newc member kind refused",
        )?;
        require(
            size <= MAX_UNPACKED && (kind == libc::S_IFREG || kind == libc::S_IFLNK || size == 0),
            "newc non-file carries data",
        )?;
        let link = if kind == libc::S_IFLNK {
            require((1..=4096).contains(&size), "newc symlink bound")?;
            let bytes = read(stream, size, total)?;
            let link = String::from_utf8(bytes).map_err(|_| Error("newc link encoding".into()))?;
            require(!link.contains('\0'), "newc link NUL")?;
            Some(link)
        } else {
            None
        };
        let sha = if kind == libc::S_IFREG && wanted.contains(&name) {
            require(
                // libarchive's tar-to-newc conversion emits zero for an
                // independent regular member. Linux only shares archive inodes
                // when c_nlink > 1; those aliases remain refused here.
                size <= crate::recovery_image::MAX_IMAGE as usize && fields[4] <= 1,
                "checked newc regular member bound or hardlink",
            )?;
            Some(json::sha256(&read(stream, size, total)?))
        } else {
            if link.is_none() {
                let mut left = size;
                while left > 0 {
                    let chunk = left.min(1024 * 1024);
                    read(stream, chunk, total)?;
                    left -= chunk;
                }
            }
            None
        };
        padding(stream, (4 - size % 4) % 4, total)?;
        if let Some(previous) = seen.get(&name) {
            require(
                kind == libc::S_IFDIR && previous.mode & libc::S_IFMT == libc::S_IFDIR && size == 0
                    || kind == libc::S_IFLNK && previous.mode == mode && previous.link == link,
                "duplicate initramfs member",
            )?;
        } else {
            require(seen.len() < MAX_MEMBERS, "initramfs member count bound")?;
            seen.insert(name, Member { mode, sha, link });
        }
    }
    Err(Error("newc archive lacks trailer".into()))
}
pub fn inventory(bytes: &[u8], wanted: &BTreeSet<String>) -> Result<BTreeMap<String, Member>> {
    require(
        !bytes.is_empty() && bytes.len() <= crate::recovery_image::MAX_IMAGE as usize,
        "compressed initramfs bound",
    )?;
    let mut raw = Cursor::new(bytes);
    let mut seen = BTreeMap::new();
    let mut total = 0;
    while bytes
        .get(raw.position() as usize..)
        .is_some_and(|s| s.starts_with(b"070701"))
    {
        archive(&mut raw, &mut seen, wanted, &mut total)?;
        while bytes.get(raw.position() as usize) == Some(&0) {
            raw.set_position(raw.position() + 1);
        }
    }
    let position = raw.position() as usize;
    require(
        bytes
            .get(position..)
            .is_some_and(|s| s.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])),
        "one zstd main archive required",
    )?;
    let mut decoder = zstd::stream::read::Decoder::with_buffer(raw)?.single_frame();
    decoder.window_log_max(27)?;
    archive(&mut decoder, &mut seen, wanted, &mut total)?;
    let mut rest = [0u8; 16384];
    loop {
        let n = decoder.read(&mut rest)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n)
            .ok_or_else(|| Error("initramfs padding overflow".into()))?;
        require(
            total <= MAX_UNPACKED && rest[..n].iter().all(|b| *b == 0),
            "unexpected data after initramfs trailer",
        )?;
    }
    let raw = decoder.finish();
    require(
        bytes[raw.position() as usize..].iter().all(|b| *b == 0),
        "data or second frame after compressed initramfs",
    )?;
    for (name, member) in &seen {
        if let Some(link) = &member.link {
            link_path(name, link)?;
        }
        let mut parent = name.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            require(
                seen.get(prefix)
                    .is_none_or(|m| m.mode & libc::S_IFMT == libc::S_IFDIR),
                "initramfs member traverses non-directory or symlink ancestor",
            )?;
            parent = prefix;
        }
    }
    Ok(seen)
}
pub fn newc(name: &str, body: &[u8], mode: u32) -> Result<Vec<u8>> {
    let name = path(name)?;
    require(
        body.len() <= crate::recovery_image::MAX_IMAGE as usize
            && mode & libc::S_IFMT == libc::S_IFREG
            && mode & 0o7000 == 0,
        "newc append regular member required",
    )?;
    // Reserve the complete archive before copying any body. A secret-bearing
    // private append must never leave an unzeroed old allocation after growth.
    let mut output = Vec::with_capacity(body.len() + name.len() + 1024);
    for (name, body, mode) in [(name.as_str(), body, mode), ("TRAILER!!!", &[][..], 0)] {
        output.extend_from_slice(b"070701");
        for field in [
            1,
            mode,
            0,
            0,
            1,
            0,
            body.len() as u32,
            0,
            0,
            0,
            0,
            (name.len() + 1) as u32,
            0,
        ] {
            output.extend_from_slice(format!("{field:08X}").as_bytes());
        }
        output.extend_from_slice(name.as_bytes());
        output.push(0);
        while output.len() % 4 != 0 {
            output.push(0);
        }
        output.extend_from_slice(body);
        while output.len() % 4 != 0 {
            output.push(0);
        }
    }
    while output.len() % 512 != 0 {
        output.push(0);
    }
    Ok(output)
}
pub fn append(base: &[u8], name: &str, body: &[u8], mode: u32) -> Result<Vec<u8>> {
    let archive = newc(name, body, mode)?;
    require(
        base.len().saturating_add(3).saturating_add(archive.len())
            <= crate::recovery_image::MAX_IMAGE as usize,
        "assembled initramfs bound",
    )?;
    let mut output = base.to_vec();
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(&archive);
    Ok(output)
}
/// Secret-bearing copies are zeroed, including the intermediate newc archive.
pub fn append_private(
    base: &[u8],
    name: &str,
    body: &[u8],
    mode: u32,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let archive = zeroize::Zeroizing::new(newc(name, body, mode)?);
    require(
        base.len().saturating_add(3).saturating_add(archive.len())
            <= crate::recovery_image::MAX_IMAGE as usize,
        "private RAM initramfs byte bound",
    )?;
    let mut output = zeroize::Zeroizing::new(base.to_vec());
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(&archive);
    Ok(output)
}
