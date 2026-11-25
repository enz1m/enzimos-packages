// SPDX-License-Identifier: MIT
//! Bounded direct Btrfs Root Tree inventory; no child or decoded execution grant.
//! Linux UAPI: linux/btrfs.h, linux/btrfs_tree.h. Search keys are lexicographic:
//! https://raw.githubusercontent.com/torvalds/linux/master/fs/btrfs/ioctl.c
use crate::{birth_runtime::Records, filesystem, operation, subvolume};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const SEARCH: libc::c_ulong = 0xc0709411;
const LOOKUP: libc::c_ulong = 0xd0009412;
const LAST: u64 = u64::MAX - 255; // BTRFS_LAST_FREE_OBJECTID: -256ULL.
const PAGE: usize = 65536;
const ITEMS: u32 = 128;
const MAX_ITEMS: usize = 16384;
const MAX_ROOTS: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    object: u64,
    kind: u32,
    offset: u64,
}
impl Key {
    fn next(self) -> Option<Self> {
        if self.offset != u64::MAX {
            Some(Self {
                offset: self.offset + 1,
                ..self
            })
        } else if self.kind < 255 {
            Some(Self {
                kind: self.kind + 1,
                offset: 0,
                ..self
            })
        } else if self.object < LAST {
            Some(Self {
                object: self.object + 1,
                kind: 0,
                offset: 0,
            })
        } else {
            None
        }
    }
}
#[repr(C)]
struct SearchKey {
    tree: u64,
    min_object: u64,
    max_object: u64,
    min_offset: u64,
    max_offset: u64,
    min_transid: u64,
    max_transid: u64,
    min_type: u32,
    max_type: u32,
    count: u32,
    unused: u32,
    reserved: [u64; 4],
}
#[repr(C)]
struct Search {
    key: SearchKey,
    size: u64,
    buffer: [u64; PAGE / 8],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Root {
    uuid: String,
    parent: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Link {
    parent: u64,
    directory: u64,
    name: String,
}
struct Tree {
    roots: BTreeMap<u64, Root>,
    back: BTreeMap<u64, Link>,
    forward: BTreeSet<(u64, u64, u64, String)>,
}
fn u64_at(bytes: &[u8], offset: usize, native: bool) -> Result<u64> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| Error("truncated Btrfs inventory integer".into()))?
        .try_into()
        .map_err(|_| enzimos_platform::Error("value out of range".into()))?;
    Ok(if native {
        u64::from_ne_bytes(raw)
    } else {
        u64::from_le_bytes(raw)
    })
}
fn u32_at(bytes: &[u8], offset: usize, native: bool) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error("truncated Btrfs inventory integer".into()))?
        .try_into()
        .map_err(|_| enzimos_platform::Error("value out of range".into()))?;
    Ok(if native {
        u32::from_ne_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}
fn uuid(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            format!(
                "{}{b:02x}",
                if matches!(i, 4 | 6 | 8 | 10) { "-" } else { "" }
            )
        })
        .collect()
}
fn name(bytes: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(bytes).map_err(|_| Error("Btrfs root name encoding".into()))?;
    require(
        !value.is_empty()
            && value.len() <= 255
            && !matches!(value, "." | "..")
            && !value.contains('/')
            && !value.chars().any(char::is_control),
        "canonical Btrfs root reference name",
    )?;
    Ok(value.into())
}
fn path(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 4096
            && !value.starts_with('/')
            && !value.chars().any(char::is_control)
            && value
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | "..")),
        "canonical actual Btrfs root inventory path",
    )
}
impl Tree {
    fn new() -> Self {
        Self {
            roots: BTreeMap::new(),
            back: BTreeMap::new(),
            forward: BTreeSet::new(),
        }
    }
    fn item(&mut self, key: Key, body: &[u8]) -> Result<()> {
        match key.kind {
            132 => {
                require(
                    body.len() >= 439,
                    "complete modern Btrfs root item required",
                )?;
                if u32_at(body, 216, false)? == 0 {
                    return Ok(());
                } // Dead, unlinked roots are not namespace members.
                require(
                    u32_at(body, 216, false)? == 1
                        && u64_at(body, 168, false)? == 256
                        && u64_at(body, 160, false)? == u64_at(body, 239, false)?
                        && body[247..263].iter().any(|b| *b != 0),
                    "live Btrfs root identity/version/reference count ambiguous",
                )?;
                let root = Root {
                    uuid: uuid(&body[247..263]),
                    parent: body[263..279]
                        .iter()
                        .any(|b| *b != 0)
                        .then(|| uuid(&body[263..279])),
                };
                require(
                    self.roots.len() < MAX_ROOTS && self.roots.insert(key.object, root).is_none(),
                    "duplicate or excess live Btrfs root item",
                )?;
            }
            144 | 156 => {
                require(body.len() >= 18, "complete Btrfs root reference required")?;
                let length = u16::from_le_bytes(
                    body[16..18]
                        .try_into()
                        .map_err(|_| enzimos_platform::Error("value out of range".into()))?,
                ) as usize;
                require(
                    body.len() == 18 + length,
                    "Btrfs root reference byte length differs",
                )?;
                let directory = u64_at(body, 0, false)?;
                require(directory >= 256, "Btrfs root reference directory ID")?;
                let name = name(&body[18..])?;
                if key.kind == 144 {
                    require(
                        (key.offset == 5 || (256..=LAST).contains(&key.offset))
                            && self.back.len() < MAX_ROOTS
                            && self
                                .back
                                .insert(
                                    key.object,
                                    Link {
                                        parent: key.offset,
                                        directory,
                                        name,
                                    },
                                )
                                .is_none(),
                        "duplicate, unknown or excess Btrfs root ancestry",
                    )?;
                } else {
                    require(
                        (256..=LAST).contains(&key.offset)
                            && self.forward.len() < MAX_ROOTS
                            && self
                                .forward
                                .insert((key.object, key.offset, directory, name)),
                        "duplicate or excess Btrfs forward root reference",
                    )?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn page(&mut self, bytes: &[u8], count: u32, minimum: Key) -> Result<Option<Key>> {
        require(
            count <= ITEMS && bytes.len() == PAGE,
            "bounded Btrfs search reply required",
        )?;
        let mut cursor = 0usize;
        let mut previous = None;
        for _ in 0..count {
            let header = bytes
                .get(cursor..cursor + 32)
                .ok_or_else(|| Error("truncated Btrfs search header".into()))?;
            let key = Key {
                object: u64_at(header, 8, true)?,
                offset: u64_at(header, 16, true)?,
                kind: u32_at(header, 24, true)?,
            };
            let length = u32_at(header, 28, true)? as usize;
            require(
                (256..=LAST).contains(&key.object)
                    && key.kind <= 255
                    && key >= minimum
                    && previous.is_none_or(|last| key > last),
                "Btrfs search cursor repeated, reversed or outside range",
            )?;
            cursor = cursor
                .checked_add(32)
                .ok_or_else(|| Error("Btrfs search offset overflow".into()))?;
            let body = bytes
                .get(
                    cursor
                        ..cursor
                            .checked_add(length)
                            .ok_or_else(|| Error("Btrfs search item overflow".into()))?,
                )
                .ok_or_else(|| Error("truncated Btrfs search item".into()))?;
            self.item(key, body)?;
            cursor += length;
            previous = Some(key);
        }
        Ok(previous.and_then(Key::next))
    }
    fn complete(&self, top_links: &BTreeMap<u64, Link>) -> Result<()> {
        require(
            self.roots
                .values()
                .map(|root| &root.uuid)
                .collect::<BTreeSet<_>>()
                .len()
                == self.roots.len(),
            "duplicate live Btrfs root UUID",
        )?;
        require(
            self.roots.keys().eq(top_links.keys()),
            "live Btrfs root missing exact namespace ancestry",
        )?;
        for (child, link) in top_links {
            require(
                link.parent == 5 || self.roots.contains_key(&link.parent),
                "unknown live Btrfs parent root",
            )?;
            if link.parent != 5 {
                require(
                    self.forward.contains(&(
                        link.parent,
                        *child,
                        link.directory,
                        link.name.clone(),
                    )),
                    "Btrfs root reference directions disagree",
                )?;
            }
        }
        // Root5's forward references are below the search's minimum object ID;
        // all other forward links must have their actual corresponding backref.
        require(
            self.forward.iter().all(|(parent, child, directory, name)| {
                top_links.get(child).is_some_and(|link| {
                    link.parent == *parent && link.directory == *directory && link.name == *name
                })
            }),
            "unmatched Btrfs forward root reference",
        )
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn directory_path(top: &File, parent: u64, directory: u64) -> Result<String> {
    let mut buffer = [0u64; 512];
    buffer[0] = parent;
    buffer[1] = directory;
    require(
        // SAFETY: `buffer` is the 4096-byte btrfs_ioctl_ino_lookup_args LOOKUP expects, and `top`
        // stays open.
        unsafe { libc::ioctl(top.as_raw_fd(), LOOKUP, buffer.as_mut_ptr()) } == 0,
        "actual Btrfs parent directory lookup unavailable",
    )?;
    require(
        buffer[0] == parent && buffer[1] == directory,
        "actual Btrfs lookup identity changed",
    )?;
    // SAFETY: `buffer` holds 4096 initialized bytes, so the 4080 bytes after its 16-byte header are
    // readable.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(16), 4080) };
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error("unterminated actual Btrfs parent path".into()))?;
    let raw = std::str::from_utf8(&bytes[..end])
        .map_err(|_| Error("Btrfs parent path encoding".into()))?;
    require(
        raw.is_empty() || raw.ends_with('/'),
        "Btrfs parent directory lookup separator",
    )?;
    let result = raw.strip_suffix('/').unwrap_or(raw);
    if !result.is_empty() {
        path(result)?;
    }
    Ok(result.into())
}
fn resolve(
    id: u64,
    links: &BTreeMap<u64, Link>,
    directories: &BTreeMap<u64, String>,
    output: &mut BTreeMap<u64, String>,
    active: &mut BTreeSet<u64>,
) -> Result<String> {
    if id == 5 {
        return Ok(String::new());
    }
    if let Some(value) = output.get(&id) {
        return Ok(value.clone());
    }
    require(
        active.len() < 64 && active.insert(id),
        "cyclic or excess actual Btrfs root ancestry",
    )?;
    let link = links
        .get(&id)
        .ok_or_else(|| Error("missing actual Btrfs root parent".into()))?;
    let parent = resolve(link.parent, links, directories, output, active)?;
    let directory = directories
        .get(&id)
        .ok_or_else(|| Error("actual Btrfs root directory lookup missing".into()))?;
    let result = [parent.as_str(), directory.as_str(), link.name.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    path(&result)?;
    active.remove(&id);
    output.insert(id, result.clone());
    Ok(result)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub(crate) fn query(top: &File) -> Result<Records> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    require(
        std::mem::size_of::<SearchKey>() == 104 && std::mem::offset_of!(Search, buffer) == 112,
        "exact Btrfs direct search ABI",
    )?;
    let original = files::identity(&top.metadata()?);
    let mount = mount_identity::id(top.as_fd(), true)?;
    let filesystem = filesystem::observe(top.as_fd())?;
    let mut minimum = Key {
        object: 256,
        kind: 0,
        offset: 0,
    };
    let mut tree = Tree::new();
    let mut count = 0usize;
    let mut bytes_seen = 0usize;
    loop {
        let mut page = Box::new(Search {
            key: SearchKey {
                tree: 1,
                min_object: minimum.object,
                max_object: LAST,
                min_offset: minimum.offset,
                max_offset: u64::MAX,
                min_transid: 0,
                max_transid: u64::MAX,
                min_type: minimum.kind,
                max_type: 255,
                count: ITEMS,
                unused: 0,
                reserved: [0; 4],
            },
            size: PAGE as u64,
            buffer: [0; PAGE / 8],
        });
        require(
            // SAFETY: `page` is the search_args_v2 buffer SEARCH expects, and `top` stays open.
            unsafe { libc::ioctl(top.as_raw_fd(), SEARCH, &mut *page) } == 0,
            "direct Btrfs search unavailable/truncated; no tool fallback",
        )?;
        require(
            page.size == PAGE as u64 && page.key.count <= ITEMS,
            "direct Btrfs search buffer/count changed",
        )?;
        count += page.key.count as usize;
        bytes_seen += PAGE;
        require(
            count <= MAX_ITEMS && bytes_seen <= MAX_BYTES,
            "complete Btrfs inventory bound exceeded",
        )?;
        // SAFETY: `page.buffer` holds `PAGE` initialized bytes.
        let bytes = unsafe { std::slice::from_raw_parts(page.buffer.as_ptr().cast::<u8>(), PAGE) };
        let Some(next) = tree.page(bytes, page.key.count, minimum)? else {
            break;
        };
        require(next > minimum, "direct Btrfs search failed to advance")?;
        minimum = next;
    }
    tree.complete(&tree.back)?;
    let mut directories = BTreeMap::new();
    for (id, link) in &tree.back {
        directories.insert(*id, directory_path(top, link.parent, link.directory)?);
    }
    let mut paths = BTreeMap::new();
    for id in tree.roots.keys() {
        resolve(
            *id,
            &tree.back,
            &directories,
            &mut paths,
            &mut BTreeSet::new(),
        )?;
    }
    let mut result = Records::new();
    for (id, relative) in &paths {
        // Nonselected user-owned roots remain observations only. Target actors
        // separately require original Root ownership and protected mode.
        let file = files::directory_relative(top, Path::new(relative), None)?;
        let epoch = files::identity(&file.metadata()?);
        require(
            file.metadata()?.ino() == 256
                && mount_identity::id(file.as_fd(), true)? == mount
                && filesystem::observe(file.as_fd())? == filesystem,
            "actual root inventory descriptor crosses filesystem/mount",
        )?;
        let (identity, _) = subvolume::observe(file.as_fd(), relative)?;
        let expected = &tree.roots[id];
        require(
            identity["id"].as_u64() == Some(*id)
                && identity["uuid"] == expected.uuid
                && identity["parent_uuid"].as_str() == expected.parent.as_deref(),
            "actual Btrfs root descriptor differs from Root Tree identity",
        )?;
        let named = files::directory_relative(top, Path::new(relative), None)?;
        require(
            files::identity(&file.metadata()?) == epoch
                && files::identity(&named.metadata()?) == epoch
                && mount_identity::id(named.as_fd(), true)? == mount
                && subvolume::observe(named.as_fd(), relative)?.0 == identity
                && result.insert(relative.clone(), identity).is_none(),
            "actual Btrfs root path replaced or duplicated",
        )?;
    }
    require(
        files::identity(&top.metadata()?) == original
            && mount_identity::id(top.as_fd(), true)? == mount
            && filesystem::observe(top.as_fd())? == filesystem,
        "original Btrfs top changed during direct inventory",
    )?;
    crate::namespaces::initial()?;
    Ok(result)
}
