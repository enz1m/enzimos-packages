// SPDX-License-Identifier: MIT
//! Fixed installer answer labels identify hints; original block/signature epochs are retained.
//! No mounting, filesystem repair, secret reads or disk writes occur here.
use crate::{block, identity, settings_command::Command, topology};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Clone, Copy)]
pub enum Label {
    Answers,
    Testcheck,
}
impl Label {
    pub fn name(self) -> &'static str {
        match self {
            Self::Answers => "ENZIMOS_ANSWERS",
            Self::Testcheck => "ENZIMOS_TESTCHECK",
        }
    }
}
const LIMIT: usize = 512 * 1024;
// libblkid derives this identifier from the ISO volume date. It is a hint,
// never a substitute for the retained block, signature and topology epochs.
fn iso_uuid(uuid: &str) -> Result<()> {
    let b = uuid.as_bytes();
    require(
        b.len() == 22
            && b.iter().enumerate().all(|(i, c)| {
                if [4, 7, 10, 13, 16, 19].contains(&i) {
                    *c == b'-'
                } else {
                    c.is_ascii_digit()
                }
            })
            && b.iter().any(|c| c.is_ascii_digit() && *c != b'0'),
        "ISO answer volume identifier shape",
    )
}
fn number(v: &Value) -> Result<topology::Device> {
    let s = v
        .as_str()
        .ok_or_else(|| Error("answer device number missing".into()))?;
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| Error("answer device number shape".into()))?;
    let a = a
        .parse::<u32>()
        .map_err(|_| Error("answer device major".into()))?;
    let b = b
        .parse::<u32>()
        .map_err(|_| Error("answer device minor".into()))?;
    require(
        a > 0 && a <= 0xfff && b <= 0xfffff && s == format!("{a}:{b}"),
        "canonical answer device number required",
    )?;
    Ok((a, b))
}
fn selected(rows: &[Value], label: Label, mounted: bool) -> Result<Value> {
    let candidates = rows
        .iter()
        .filter(|r| r["label"] == label.name())
        .collect::<Vec<_>>();
    require(
        candidates.len() == 1,
        "one uniquely labelled answer volume required",
    )?;
    let row = candidates[0];
    require(
        (matches!(row["type"].as_str(), Some("disk" | "part"))
            && matches!(row["fstype"].as_str(), Some("ext4" | "vfat" | "iso9660")))
            || (row["type"] == "rom" && row["fstype"] == "iso9660" && row["ro"] == true),
        "unsupported installer answer volume",
    )?;
    let path = Path::new(row["name"].as_str().unwrap_or(""));
    require(
        path.parent() == Some(Path::new("/dev"))
            && path.file_name().is_some_and(|n| {
                let b = n.as_encoded_bytes();
                !b.is_empty()
                    && b[0].is_ascii_alphanumeric()
                    && b.iter()
                        .all(|n| n.is_ascii_alphanumeric() || b"._-".contains(n))
            }),
        "canonical answer device path required",
    )?;
    number(&row["maj:min"])?;
    if row["type"] == "rom" {
        let basename = path.file_name().unwrap().as_encoded_bytes();
        let digits = basename.strip_prefix(b"sr").unwrap_or_default();
        require(
            !digits.is_empty()
                && digits.iter().all(u8::is_ascii_digit)
                && (digits.len() == 1 || digits[0] != b'0'),
            "canonical optical answer device required",
        )?;
    }
    let uuid = row["uuid"]
        .as_str()
        .ok_or_else(|| Error("answer volume UUID required".into()))?;
    match row["fstype"].as_str().unwrap() {
        "ext4" => {
            identity::uuid(uuid)?;
        }
        "vfat" => crate::recovery_records::fat_uuid(uuid)?,
        "iso9660" => iso_uuid(uuid)?,
        _ => unreachable!(),
    }
    require(
        rows.iter().filter(|r| r["uuid"] == uuid).count() == 1,
        "duplicate answer filesystem UUID refused",
    )?;
    let points = row["mountpoints"]
        .as_array()
        .ok_or_else(|| Error("answer mount hints missing".into()))?;
    require(
        points
            .iter()
            .all(|p| p.is_null() || (mounted && p == "/run/enzimos-answers"))
            && (!mounted
                || points
                    .iter()
                    .filter(|p| **p == "/run/enzimos-answers")
                    .count()
                    == 1),
        "answer volume already mounted elsewhere",
    )?;
    let mut row = row.clone();
    row["mountpoints"] = Value::Null;
    Ok(row)
}
fn signature(bytes: &[u8], alias: &str, row: &Value) -> Result<Value> {
    require(bytes.len() <= 4096, "answer signature output bound")?;
    let text = std::str::from_utf8(bytes).map_err(|_| Error("answer signature encoding".into()))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| Error("answer signature field shape".into()))?;
        require(
            ["DEVNAME", "TYPE", "UUID", "LABEL", "USAGE"].contains(&key)
                && fields.insert(key, val).is_none(),
            "unknown/duplicate answer signature field",
        )?;
    }
    require(
        fields.len() == 5
            && fields.get("DEVNAME") == Some(&alias)
            && fields.get("USAGE") == Some(&"filesystem")
            && fields.get("TYPE").copied() == row["fstype"].as_str()
            && fields.get("UUID").copied() == row["uuid"].as_str()
            && fields.get("LABEL").copied() == row["label"].as_str(),
        "answer signature differs from selected label, UUID or filesystem",
    )?;
    Ok(value!({"type":fields["TYPE"],"uuid":fields["UUID"],"label":fields["LABEL"]}))
}
fn inventory(vendor: &Command) -> Result<Vec<Value>> {
    crate::backup_candidates::rows(&vendor.run_timeout(
        &[
            "--json",
            "--bytes",
            "--list",
            "--paths",
            "--output",
            "NAME,MAJ:MIN,TYPE,FSTYPE,UUID,SIZE,RO,MOUNTPOINTS,MODEL,LABEL",
        ],
        &[0],
        LIMIT,
        Duration::from_secs(15),
    )?)
}
pub struct Device {
    label: Label,
    path: PathBuf,
    parent: File,
    file: File,
    inode: files::FileIdentity,
    mount: u64,
    block: Value,
    row: Value,
    signature: Value,
    graph: topology::Graph,
    lsblk: Command,
    blkid: Command,
}
impl Device {
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub fn observe(label: Label) -> Result<Self> {
        crate::namespaces::initial()?;
        crate::operation::root_only()?;
        let lsblk = Command::open("/usr/bin/lsblk")?;
        let row = selected(&inventory(&lsblk)?, label, false)?;
        let path = PathBuf::from(row["name"].as_str().unwrap());
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let name = CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        require(
            raw >= 0,
            "original answer volume block description unavailable",
        )?;
        let file = unsafe { File::from_raw_fd(raw) };
        let block = block::observe(file.as_fd())?;
        let device = number(&row["maj:min"])?;
        require(
            (
                block["major"].as_u64().unwrap() as u32,
                block["minor"].as_u64().unwrap() as u32,
            ) == device
                && block["bytes"] == row["size"]
                && block["read_only"] == row["ro"],
            "selected answer volume differs from original block",
        )?;
        let graph = topology::observe(&[device])?;
        require(
            graph.leaves.len() == 1,
            "answer volume must have one independent physical ancestry",
        )?;
        let blkid = Command::open("/usr/bin/blkid")?;
        let sig = query(&blkid, &file, &row)?;
        let this = Self {
            label,
            path,
            parent,
            mount: mount_identity::id(file.as_fd(), true)?,
            inode: files::identity(&file.metadata()?),
            file,
            block,
            row,
            signature: sig,
            graph,
            lsblk,
            blkid,
        };
        this.recheck(false)?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub fn recheck(&self, mounted: bool) -> Result<()> {
        crate::namespaces::initial()?;
        crate::operation::root_only()?;
        let name = CString::new(self.path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "original answer device name disappeared")?;
        let named = unsafe { File::from_raw_fd(raw) };
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        require(
            parent.metadata()?.dev() == self.parent.metadata()?.dev()
                && parent.metadata()?.ino() == self.parent.metadata()?.ino()
                && files::identity(&named.metadata()?) == self.inode
                && files::identity(&self.file.metadata()?) == self.inode
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && block::observe(self.file.as_fd())? == self.block
                && topology::observe(&[number(&self.row["maj:min"])?])? == self.graph,
            "original answer volume block/media epoch changed",
        )?;
        require(
            selected(&inventory(&self.lsblk)?, self.label, mounted)? == self.row
                && query(&self.blkid, &self.file, &self.row)? == self.signature,
            "original answer volume signature or unique selection changed",
        )
    }
    pub fn descriptor(&self, mounted: bool) -> Result<BorrowedFd<'_>> {
        self.recheck(mounted)?;
        Ok(self.file.as_fd())
    }
    pub fn filesystem(&self) -> &str {
        self.row["fstype"].as_str().unwrap()
    }
    pub fn uuid(&self) -> &str {
        self.row["uuid"].as_str().unwrap()
    }
    pub fn number(&self) -> topology::Device {
        number(&self.row["maj:min"]).unwrap()
    }
    pub fn independent(&self, other: &topology::Graph) -> Result<()> {
        require(
            self.graph.leaves.is_disjoint(&other.leaves),
            "answer volume overlaps installation medium or target",
        )
    }
    pub fn evidence(&self, mounted: bool) -> Result<Value> {
        self.recheck(mounted)?;
        Ok(
            value!({"label":self.label.name(),"path":self.path,"block":self.block,"inode":self.inode,"mount":self.mount,"signature":self.signature,"graph":self.graph.json()}),
        )
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (lseek).")]
fn query(vendor: &Command, file: &File, row: &Value) -> Result<Value> {
    let position = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) };
    require(position >= 0, "answer block description offset unavailable")?;
    let before = block::observe(file.as_fd())?;
    let (bytes, aliases) = vendor.descriptor_query(
        &[
            "--probe",
            "--output",
            "export",
            "--match-tag",
            "TYPE",
            "--match-tag",
            "UUID",
            "--match-tag",
            "LABEL",
            "--match-tag",
            "USAGE",
            "--",
            "@fd:0",
        ],
        4096,
        Duration::from_secs(15),
        &[file.as_fd()],
    )?;
    require(
        aliases.len() == 1
            && block::observe(file.as_fd())? == before
            && unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) } == position,
        "answer signature changed original block or offset",
    )?;
    signature(&bytes, &aliases[0], row)
}
