// SPDX-License-Identifier: MIT
//! Bounded selected-tree listing and tar observations; never extraction authority.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, io::Cursor};
pub(crate) const MAX_ENTRIES: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Node {
    kind: String,
    size: u64,
}
pub(crate) struct Listing {
    pub details: Value,
    nodes: BTreeMap<String, Node>,
}
fn canonical(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && path.split('/').skip(1).all(|p| {
            !p.is_empty()
                && !matches!(p, "." | ".." | ".snapshots")
                && !p.bytes().any(|b| b == 0 || b.is_ascii_control())
        })
}
pub(crate) fn metadata(
    code: Option<i32>,
    bytes: &[u8],
    snapshot: &str,
    path: &str,
) -> Result<Listing> {
    crate::backup_selective_result::file_path(path)?;
    crate::identity::sha(snapshot)?;
    require(
        code == Some(0) && bytes.len() <= crate::backup_selective_result::MAX_METADATA,
        "tree listing failed or bounded out",
    )?;
    let mut header = false;
    let mut nodes = BTreeMap::new();
    let mut raw = BTreeMap::new();
    let mut total = 0u64;
    for line in bytes
        .split(|b| matches!(*b, b'\n' | b'\r'))
        .filter(|b| !b.is_empty())
    {
        require(
            nodes.len() < MAX_ENTRIES || !header,
            "selected tree listing row bound",
        )?;
        let row = json::decode(line, crate::backup_selective_result::MAX_METADATA)?;
        let kind = row
            .get("struct_type")
            .or_else(|| row.get("message_type"))
            .and_then(Value::as_str);
        if kind == Some("snapshot") {
            require(
                !header && row["id"] == snapshot,
                "exact selected tree snapshot required",
            )?;
            header = true;
            continue;
        }
        require(kind == Some("node"), "unexpected tree listing row")?;
        let name = row["path"]
            .as_str()
            .ok_or_else(|| Error("tree node path required".into()))?;
        require(
            canonical(name) && (name == path || name.starts_with(&format!("{path}/"))),
            "tree node outside canonical selection",
        )?;
        let kind = row["type"]
            .as_str()
            .filter(|s| matches!(*s, "dir" | "file" | "symlink"))
            .ok_or_else(|| Error("directory/file/symlink nodes only".into()))?;
        let size = if kind == "file" {
            match row.get("size") {
                None => 0,
                Some(n) => n
                    .as_u64()
                    .ok_or_else(|| Error("integral tree file size required".into()))?,
            }
        } else {
            0
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| Error("tree content size overflow".into()))?;
        require(
            total <= crate::backup_selective_result::MAX_FILE
                && !nodes.contains_key(name)
                && nodes.len() < MAX_ENTRIES,
            "tree count/content bound or duplicate",
        )?;
        nodes.insert(
            name.into(),
            Node {
                kind: kind.into(),
                size,
            },
        );
        raw.insert(name.to_owned(), row);
    }
    require(
        header && !nodes.is_empty() && nodes.get(path).is_some_and(|n| n.kind == "dir"),
        "selected tree requires one directory root",
    )?;
    let rows = raw.into_values().collect::<Vec<_>>();
    Ok(Listing {
        details: value!({"path":path,"size":total,"entries":nodes.len(),"node_sha256":json::fingerprint(&Value::Array(rows))?}),
        nodes,
    })
}
pub(crate) fn verify_tar(bytes: &[u8], path: &str, listing: &Listing) -> Result<()> {
    require(
        (1024..=crate::backup_selective_result::MAX_FILE as usize).contains(&bytes.len()),
        "selected tree tar bound",
    )?;
    let mut cursor = Cursor::new(bytes);
    let mut observed = BTreeMap::new();
    let mut count = 0;
    {
        let mut archive = tar::Archive::new(&mut cursor);
        for member in archive.entries()? {
            count += 1;
            require(count <= MAX_ENTRIES + 1, "tree tar member bound")?;
            let member = member?;
            let raw = member.path_bytes();
            let mut name =
                std::str::from_utf8(&raw).map_err(|_| Error("tree tar path encoding".into()))?;
            while name.starts_with("./") || name.starts_with('/') {
                name = if name.starts_with("./") {
                    &name[2..]
                } else {
                    &name[1..]
                };
            }
            name = name.trim_end_matches('/');
            let kind = member.header().entry_type();
            let kind = if kind.is_dir() {
                "dir"
            } else if kind.is_file() {
                "file"
            } else if kind.is_symlink() {
                "symlink"
            } else {
                return Err(Error("special/hardlink tree tar member refused".into()));
            };
            if matches!(name, "" | ".") {
                require(kind == "dir", "tree tar root must be a directory")?;
                continue;
            }
            require(
                canonical(&format!("/{name}")) && !observed.contains_key(name),
                "duplicate or noncanonical tree tar member",
            )?;
            let size = if kind == "file" { member.size() } else { 0 };
            observed.insert(
                name.to_owned(),
                Node {
                    kind: kind.into(),
                    size,
                },
            );
        }
    }
    let tail = cursor.position() as usize;
    require(
        tail <= bytes.len() && bytes[tail..].iter().all(|b| *b == 0),
        "tree tar contains trailing unobserved data",
    )?;
    let parent = path.rsplit_once('/').unwrap().0;
    let absolute = listing
        .nodes
        .iter()
        .map(|(k, v)| (k.trim_start_matches('/').to_owned(), v.clone()))
        .collect::<BTreeMap<_, _>>();
    let relative = listing
        .nodes
        .iter()
        .map(|(k, v)| (k[parent.len() + 1..].to_owned(), v.clone()))
        .collect::<BTreeMap<_, _>>();
    let inside = listing
        .nodes
        .iter()
        .filter(|(k, _)| k.as_str() != path)
        .map(|(k, v)| (k[path.len() + 1..].to_owned(), v.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut without_absolute = absolute.clone();
    without_absolute.remove(path.trim_start_matches('/'));
    let mut without_relative = relative.clone();
    without_relative.remove(&path[parent.len() + 1..]);
    require(
        [
            absolute,
            relative,
            inside,
            without_absolute,
            without_relative,
        ]
        .contains(&observed),
        "tree tar differs from authenticated listing",
    )
}
