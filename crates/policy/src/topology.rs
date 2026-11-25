// SPDX-License-Identifier: MIT
//! Boot-local storage observation. Never opens a block device or grants ownership.
use crate::identity;
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
pub type Device = (u32, u32);
const MAX_NODES: usize = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub path: PathBuf,
    pub dependencies: Vec<Device>,
    pub disk_sequence: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    pub nodes: BTreeMap<Device, Node>,
    pub leaves: BTreeSet<Device>,
}
impl Graph {
    pub fn json(&self) -> Value {
        json!({"nodes":self.nodes.iter().map(|(device,n)|json!({"device":[device.0,device.1],"path":n.path,"dependencies":n.dependencies.iter().map(|d|[d.0,d.1]).collect::<Vec<_>>(),"disk_sequence":n.disk_sequence})).collect::<Vec<_>>(),"leaves":self.leaves.iter().map(|d|[d.0,d.1]).collect::<Vec<_>>()})
    }
}
fn text(path: &Path) -> Result<String> {
    let b = files::read_kernel(path, 4096)?;
    require(b.is_ascii(), "storage topology encoding")?;
    Ok(String::from_utf8(b).unwrap().trim().to_owned())
}
fn positive(s: &str) -> Result<u64> {
    require(
        !s.is_empty()
            && s.len() <= 20
            && !s.starts_with('0')
            && s.bytes().all(|b| b.is_ascii_digit()),
        "invalid kernel sequence",
    )?;
    s.parse()
        .map_err(|_| Error("invalid kernel sequence".into()))
}
fn device(path: &Path) -> Result<Device> {
    let s = text(&path.join("dev"))?;
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| Error("invalid sysfs device identity".into()))?;
    require(
        [a, b]
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())),
        "invalid sysfs device identity",
    )?;
    Ok((
        a.parse()
            .map_err(|_| Error("device number overflow".into()))?,
        b.parse()
            .map_err(|_| Error("device number overflow".into()))?,
    ))
}
fn resolve(path: &Path) -> Result<PathBuf> {
    let p = std::fs::canonicalize(path)?;
    require(
        p.starts_with("/sys/devices"),
        "block topology escaped device tree",
    )?;
    files::directory(&p, Some(0))?;
    Ok(p)
}
fn directory(path: &Path) -> Result<Vec<std::ffi::OsString>> {
    let _held = files::directory(path, Some(0))?;
    let mut names = Vec::new();
    for e in std::fs::read_dir(path)? {
        require(names.len() < MAX_NODES, "storage topology node bound")?;
        names.push(e?.file_name());
    }
    names.sort();
    Ok(names)
}
pub fn kernel_node(d: Device) -> Result<Node> {
    let p = resolve(&Path::new("/sys/dev/block").join(format!("{}:{}", d.0, d.1)))?;
    require(device(&p)? == d, "sysfs block identity changed")?;
    let partition = p.join("partition");
    let (dependencies, sequence) = match std::fs::symlink_metadata(&partition) {
        Ok(_) => {
            require(
                positive(&text(&partition)?)? <= u64::from(u32::MAX),
                "invalid partition number",
            )?;
            (
                vec![device(
                    p.parent()
                        .ok_or_else(|| Error("missing partition disk".into()))?,
                )?],
                None,
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut children = Vec::new();
            for name in directory(&p.join("slaves"))? {
                children.push(device(&resolve(&p.join("slaves").join(name))?)?);
            }
            children.sort();
            children.dedup();
            (children, Some(positive(&text(&p.join("diskseq"))?)?))
        }
        Err(e) => return Err(e.into()),
    };
    require(
        !dependencies.is_empty() || !p.starts_with("/sys/devices/virtual"),
        "unsupported virtual storage leaf",
    )?;
    Ok(Node {
        path: p,
        dependencies,
        disk_sequence: sequence,
    })
}
pub fn walk<F: FnMut(Device) -> Result<Node>>(roots: &[Device], mut reader: F) -> Result<Graph> {
    require(
        !roots.is_empty() && roots.len() <= MAX_NODES,
        "storage root bound",
    )?;
    let mut graph = Graph {
        nodes: BTreeMap::new(),
        leaves: BTreeSet::new(),
    };
    let mut active = BTreeSet::new();
    fn visit<F: FnMut(Device) -> Result<Node>>(
        d: Device,
        g: &mut Graph,
        active: &mut BTreeSet<Device>,
        reader: &mut F,
    ) -> Result<()> {
        require(!active.contains(&d), "cyclic storage topology")?;
        if g.nodes.contains_key(&d) {
            return Ok(());
        }
        require(
            g.nodes.len() + active.len() < MAX_NODES,
            "storage topology node bound",
        )?;
        active.insert(d);
        let n = reader(d)?;
        require(
            n.dependencies.len() <= MAX_NODES && n.path.is_absolute(),
            "invalid topology node",
        )?;
        for child in &n.dependencies {
            visit(*child, g, active, reader)?;
        }
        if n.dependencies.is_empty() {
            g.leaves.insert(d);
        }
        active.remove(&d);
        g.nodes.insert(d, n);
        Ok(())
    }
    for d in roots {
        visit(*d, &mut graph, &mut active, &mut reader)?;
    }
    Ok(graph)
}
pub fn observe(roots: &[Device]) -> Result<Graph> {
    require(
        enzimos_platform::process_identity::effective_uid() == 0,
        "root authorization required",
    )?;
    require(
        std::fs::read_link("/proc/self/ns/mnt")? == std::fs::read_link("/proc/1/ns/mnt")?,
        "initial mount namespace required",
    )?;
    let before = walk(roots, kernel_node)?;
    require(
        walk(roots, kernel_node)? == before,
        "storage topology changed during observation",
    )?;
    Ok(before)
}
pub(crate) fn btrfs_roots(uuid: &str) -> Result<Vec<Device>> {
    identity::uuid(uuid)?;
    let base = Path::new("/sys/fs/btrfs").join(uuid);
    require(
        text(&base.join("metadata_uuid"))? == uuid && text(&base.join("temp_fsid"))? == "0",
        "unsupported filesystem identity",
    )?;
    let ids = directory(&base.join("devinfo"))?;
    let names = directory(&base.join("devices"))?;
    require(
        !ids.is_empty() && ids.len() == names.len(),
        "incomplete Btrfs inventory",
    )?;
    for id in ids {
        positive(
            id.to_str()
                .ok_or_else(|| Error("invalid Btrfs device ID".into()))?,
        )?;
        let p = base.join("devinfo").join(id);
        for (key, expected) in [
            ("fsid", uuid),
            ("missing", "0"),
            ("in_fs_metadata", "1"),
            ("replace_target", "0"),
        ] {
            require(
                text(&p.join(key))? == expected,
                "incomplete Btrfs membership",
            )?;
        }
    }
    let mut roots = Vec::new();
    for name in names {
        roots.push(device(&resolve(&base.join("devices").join(name))?)?);
    }
    roots.sort();
    require(
        roots.windows(2).all(|pair| pair[0] != pair[1]),
        "duplicate Btrfs membership",
    )?;
    Ok(roots)
}
pub fn mounted_btrfs(uuid: &str) -> Result<Graph> {
    let roots = btrfs_roots(uuid)?;
    let result = observe(&roots)?;
    require(
        btrfs_roots(uuid)? == roots,
        "Btrfs membership changed during observation",
    )?;
    Ok(result)
}
