// SPDX-License-Identifier: MIT
//! Discovery hints never grant mount/format authority; selections retain original block devices.
use crate::{
    block, identity, operation, settings_command::Command, storage_runtime::Guard, topology,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use unicode_general_category::{GeneralCategory as Category, get_general_category};
const LIMIT: usize = 512 * 1024;
pub fn rows(bytes: &[u8]) -> Result<Vec<Value>> {
    let v = json::decode(bytes, LIMIT)?;
    json::fields(&v, "blockdevices")?;
    let rows = v["blockdevices"]
        .as_array()
        .ok_or_else(|| Error("backup device inventory list required".into()))?;
    require(rows.len() <= 128, "backup device inventory count bound")?;
    let mut paths = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    for row in rows {
        json::fields(
            row,
            "name maj:min type fstype uuid size ro mountpoints model label",
        )?;
        let path = row["name"]
            .as_str()
            .ok_or_else(|| Error("backup device path required".into()))?;
        require(
            path.starts_with("/dev/")
                && (6..=261).contains(&path.len())
                && path.as_bytes()[5].is_ascii_alphanumeric()
                && path[5..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
                && path[1..].split('/').all(|p| !matches!(p, "" | "." | ".."))
                && paths.insert(path),
            "invalid/duplicate backup device path",
        )?;
        let number = device_number(
            row["maj:min"]
                .as_str()
                .ok_or_else(|| Error("backup device number required".into()))?,
        )?;
        require(numbers.insert(number), "duplicate backup device number")?;
        let kind = row["type"]
            .as_str()
            .ok_or_else(|| Error("backup device kind required".into()))?;
        require(
            !kind.is_empty()
                && kind.len() <= 32
                && kind
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid backup device kind",
        )?;
        require(
            row["size"].as_u64().is_some_and(|n| n < 1u64 << 63) && row["ro"].is_boolean(),
            "invalid backup device size/state",
        )?;
        for key in ["fstype", "uuid", "model", "label"] {
            require(
                row[key].is_null() || row[key].as_str().is_some_and(|s| s.len() <= 1024),
                "backup display metadata bound",
            )?;
        }
        require(
            row["mountpoints"].as_array().is_some_and(|r| {
                r.len() <= 16
                    && r.iter().all(|s| {
                        s.is_null() || s.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 4096)
                    })
            }),
            "backup mount hints bound",
        )?;
    }
    Ok(rows.clone())
}
fn device_number(s: &str) -> Result<topology::Device> {
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| Error("backup device number shape".into()))?;
    require(
        [a, b]
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())),
        "backup device number bound",
    )?;
    let a = a
        .parse::<u32>()
        .map_err(|_| Error("backup major overflow".into()))?;
    let b = b
        .parse::<u32>()
        .map_err(|_| Error("backup minor overflow".into()))?;
    require(
        a <= 0xfff && b <= 0xfffff,
        "Linux block device number bound",
    )?;
    Ok((a, b))
}
pub fn label(s: Option<&str>) -> String {
    s.unwrap_or("")
        .chars()
        .filter(|c| {
            !matches!(
                get_general_category(*c),
                Category::Control
                    | Category::Format
                    | Category::Surrogate
                    | Category::PrivateUse
                    | Category::Unassigned
                    | Category::LineSeparator
                    | Category::ParagraphSeparator
            )
        })
        .collect::<String>()
        .trim()
        .chars()
        .take(128)
        .collect()
}
fn reason(row: &Value, rows: &[Value]) -> Option<&'static str> {
    let uuid = row["uuid"].as_str().filter(|s| identity::uuid(s).is_ok());
    if !matches!(row["type"].as_str(), Some("disk" | "part")) {
        Some("unsupported-device-type")
    } else if row["fstype"] != "btrfs" || uuid.is_none() {
        Some("existing-btrfs-required")
    } else if rows.iter().filter(|r| r["uuid"] == row["uuid"]).count() != 1 {
        Some("duplicate-filesystem-uuid")
    } else if row["mountpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str().is_some_and(|s| !s.is_empty()))
    {
        Some("already-mounted")
    } else if row["ro"] == true {
        Some("read-only")
    } else {
        None
    }
}
fn selection_token(row: &Value, source: &Value, boot: &str, evidence: &Value) -> Result<String> {
    identity::uuid(boot)?;
    json::fingerprint(
        &value!({"schema":1,"boot_id":boot,"source":source,"path":row["name"],"filesystem_uuid_hint":row["uuid"],"device":evidence["device"],"topology":evidence["topology"]}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open_device(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let name =
        std::ffi::CString::new(name.as_bytes()).map_err(|_| Error("backup device name".into()))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, "backup device unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
struct Device {
    path: PathBuf,
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32),
    parent_mount: u64,
    file: File,
    inode: files::FileIdentity,
    mount: u64,
    observed: Value,
    graph: topology::Graph,
}
fn shape(f: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = f.metadata()?;
    require(
        m.uid() == 0 && m.is_dir() && m.mode() & 0o022 == 0,
        "protected backup device parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Device {
    fn open(row: &Value, protected: &topology::Graph) -> Result<Self> {
        let path = Path::new(enzimos_platform::json::string(&row["name"])?);
        let parent = files::directory(
            path.parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let file = open_device(
            &parent,
            path.file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        )?;
        let inode = files::identity(&file.metadata()?);
        let observed = block::observe(file.as_fd())?;
        let number = device_number(enzimos_platform::json::string(&row["maj:min"])?)?;
        require(
            observed["major"] == number.0
                && observed["minor"] == number.1
                && observed["bytes"] == row["size"]
                && observed["read_only"] == row["ro"]
                && observed["read_only"] == false,
            "backup device inventory changed or readonly",
        )?;
        let graph = topology::observe(&[number])?;
        require(
            graph.leaves.is_disjoint(&protected.leaves),
            "backup device overlaps system disk",
        )?;
        let this = Self {
            path: path.into(),
            parent_shape: shape(&parent)?,
            parent_mount: mount_identity::id(parent.as_fd(), true)?,
            parent,
            file,
            inode,
            mount: 0,
            observed,
            graph,
        };
        let this = Self {
            mount: mount_identity::id(this.file.as_fd(), true)?,
            ..this
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        let parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let named = open_device(
            &self.parent,
            self.path
                .file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        )?;
        require(
            shape(&parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&named.metadata()?) == self.inode
                && files::identity(&self.file.metadata()?) == self.inode
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && block::observe(self.file.as_fd())? == self.observed
                && block::observe(named.as_fd())? == self.observed
                && topology::observe(&[(
                    enzimos_platform::json::unsigned(&self.observed["major"])? as u32,
                    enzimos_platform::json::unsigned(&self.observed["minor"])? as u32,
                )])? == self.graph,
            "original backup device changed or replaced",
        )
    }
    fn evidence(&self) -> Value {
        value!({"device":self.observed,"topology":self.graph.json()})
    }
}
pub struct Discovery {
    guard: Guard,
    vendor: Command,
    boot: String,
    source: topology::Graph,
    source_members: Vec<topology::Device>,
    devices: Vec<Value>,
}
impl Discovery {
    pub fn observe() -> Result<Self> {
        let guard = Guard::observe()?;
        let vendor = Command::open("/usr/bin/lsblk")?;
        let boot = operation::boot_id()?;
        let source = topology::mounted_btrfs(enzimos_platform::json::string(
            &guard.configuration["filesystem_uuid"],
        )?)?;
        let uuid = enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?;
        let source_members = topology::btrfs_roots(uuid)?;
        let devices = source_runtime_hints(Self::read(&vendor)?, uuid, &source_members)?;
        let this = Self {
            guard,
            vendor,
            boot,
            source,
            source_members,
            devices,
        };
        this.recheck()?;
        Ok(this)
    }
    fn read(vendor: &Command) -> Result<Vec<Value>> {
        rows(&vendor.run_timeout(
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
    fn read_current(&self) -> Result<Vec<Value>> {
        let uuid = enzimos_platform::json::string(&self.guard.configuration["filesystem_uuid"])?;
        require(
            topology::btrfs_roots(uuid)? == self.source_members,
            "backup source members changed",
        )?;
        source_runtime_hints(Self::read(&self.vendor)?, uuid, &self.source_members)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.vendor.recheck()?;
        require(
            operation::boot_id()? == self.boot
                && topology::mounted_btrfs(enzimos_platform::json::string(
                    &self.guard.configuration["filesystem_uuid"],
                )?)? == self.source,
            "system storage changed during backup discovery",
        )
    }
    fn token(&self, row: &Value, device: &Device) -> Result<String> {
        selection_token(row, &self.source.json(), &self.boot, &device.evidence())
    }
    pub fn inventory(&self) -> Result<Value> {
        self.recheck()?;
        let mut candidates = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        for row in &self.devices {
            require(
                Instant::now() < deadline,
                "backup discovery deadline exhausted",
            )?;
            let mut candidate = value!({"model":label(row["model"].as_str()),"label":label(row["label"].as_str()),"bytes":row["size"],"filesystem_uuid_hint":row["uuid"].as_str().filter(|s|identity::uuid(s).is_ok()),"selection_id":null,"filesystem_verified":false,"state":"unavailable","reason":reason(row,&self.devices)});
            if candidate["reason"].is_null() {
                match Device::open(row, &self.source) {
                    Ok(device) => {
                        candidate["selection_id"] = value!(self.token(row, &device)?);
                        candidate["state"] = value!("needs-filesystem-verification");
                        device.recheck()?;
                    }
                    Err(_) => candidate["reason"] = value!("identity-or-independence-unavailable"),
                }
            }
            candidates.push(candidate);
        }
        self.recheck()?;
        require(
            self.read_current()? == self.devices,
            "backup inventory changed during discovery",
        )?;
        self.recheck()?;
        Ok(
            value!({"schema":1,"candidates":candidates,"mounting_supported":false,"formatting_supported":false,"credential_enrollment_supported":false}),
        )
    }
    pub fn select(&self, token: &str) -> Result<Selection<'_>> {
        identity::sha(token)?;
        self.recheck()?;
        require(
            self.read_current()? == self.devices,
            "backup inventory changed before selection",
        )?;
        let mut found = None;
        let deadline = Instant::now() + Duration::from_secs(30);
        for row in &self.devices {
            require(
                Instant::now() < deadline,
                "backup selection deadline exhausted",
            )?;
            if reason(row, &self.devices).is_some() {
                continue;
            }
            if let Ok(device) = Device::open(row, &self.source)
                && self.token(row, &device)? == token
            {
                require(found.is_none(), "ambiguous backup selection")?;
                found = Some(Selection {
                    discovery: self,
                    row: row.clone(),
                    device,
                    inventory_checked: std::sync::Mutex::new(None),
                });
            }
        }
        let selected =
            found.ok_or_else(|| Error("backup selection unavailable or changed".into()))?;
        selected.recheck()?;
        Ok(selected)
    }
}
/// Only the independently verified system filesystem's hints may gain excluded
/// runtime aliases. Destination/device identities and persistent mountpoints
/// remain exact; a candidate mounted under /run is still unavailable.
fn source_runtime_hints(
    mut rows: Vec<Value>,
    source_uuid: &str,
    members: &[topology::Device],
) -> Result<Vec<Value>> {
    for row in &mut rows {
        if row["uuid"] != source_uuid {
            continue;
        }
        let number = device_number(
            row["maj:min"]
                .as_str()
                .ok_or_else(|| Error("source member number missing".into()))?,
        )?;
        if !members.contains(&number) {
            continue;
        }
        let points = row["mountpoints"]
            .as_array()
            .ok_or_else(|| Error("source mount hints missing".into()))?;
        let mut kept = points
            .iter()
            .filter(|v| {
                !v.as_str()
                    .is_some_and(crate::backup_source_layout::runtime_mount)
            })
            .cloned()
            .collect::<Vec<_>>();
        if kept.is_empty() {
            kept.push(Value::Null);
        }
        row["mountpoints"] = value!(kept);
    }
    Ok(rows)
}
/// The public (lsblk) inventory may differ from the original only by the owned
/// destination mount on the selected device. The kernel records that mount's
/// source as the retained descriptor path (`/proc/self/fd/N`, never a fresh
/// pathname lookup), which lsblk cannot attribute to the device; the selected
/// row therefore shows either the owned target or still no mountpoint. Kernel
/// identity (unique mount ID, UUID, single member, owned stack) is checked by
/// the caller; every other row and field must be unchanged.
fn attached_inventory(original: &[Value], current: &[Value], selected: &str) -> Result<()> {
    let mut expected = original.to_vec();
    let matches = expected
        .iter_mut()
        .filter(|row| row["name"] == selected)
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        "unique original attached device required",
    )?;
    let row = matches
        .into_iter()
        .next()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
    require(
        row["mountpoints"]
            .as_array()
            .is_some_and(|rows| rows.iter().all(Value::is_null)),
        "original selected device already mounted",
    )?;
    let observed = current
        .iter()
        .filter(|r| r["name"] == selected)
        .map(|r| r["mountpoints"].clone())
        .collect::<Vec<_>>();
    if observed == [value!(["/backup-repository"])] {
        row["mountpoints"] = value!(["/backup-repository"]);
    }
    if expected == current {
        return Ok(());
    }
    // Name the first difference (device names and mountpoints only).
    let detail = if expected.len() != current.len() {
        format!("{} devices, expected {}", current.len(), expected.len())
    } else {
        expected
            .iter()
            .zip(current)
            .find(|(a, b)| a != b)
            .map(|(a, b)| {
                let field = a
                    .as_object()
                    .and_then(|o| o.keys().find(|k| a[k.as_str()] != b[k.as_str()]).cloned())
                    .unwrap_or_else(|| "fields".into());
                format!(
                    "{} {field}: {} -> {}",
                    a["name"].as_str().unwrap_or("?"),
                    a[field.as_str()],
                    b[field.as_str()]
                )
            })
            .unwrap_or_default()
    };
    Err(Error(format!(
        "backup inventory changed beyond the exact owned setup mount ({})",
        crate::diagnostic::bounded(&detail)
    )))
}
// Kernel ownership must be checked by the caller before and after this public
// inventory comparison. A UUID alone never permits a source mountpoint change.
fn area_inventory(
    original: &[Value],
    current: &[Value],
    source_uuid: &str,
    members: &[topology::Device],
) -> Result<Vec<Value>> {
    let mut normalized = current.to_vec();
    for row in &mut normalized {
        if row["uuid"] != source_uuid {
            continue;
        }
        let number = device_number(
            row["maj:min"]
                .as_str()
                .ok_or_else(|| Error("source member number missing".into()))?,
        )?;
        if !members.contains(&number) {
            continue;
        }
        let before = original
            .iter()
            .find(|r| r["name"] == row["name"])
            .ok_or_else(|| Error("source member was not in original inventory".into()))?;
        require(
            before["mountpoints"]
                .as_array()
                .is_some_and(|r| !r.iter().any(|v| v == "/backup-repository")),
            "original source already claimed the backup area; no adoption",
        )?;
        let points = row["mountpoints"]
            .as_array()
            .ok_or_else(|| Error("source mountpoint inventory missing".into()))?;
        require(
            points
                .iter()
                .filter(|v| **v == "/backup-repository")
                .count()
                <= 1,
            "source area mountpoint repeated",
        )?;
        let mut remaining: Vec<Value> = points
            .iter()
            .filter(|v| **v != "/backup-repository")
            .cloned()
            .collect();
        if remaining.is_empty() && before["mountpoints"] == value!([null]) {
            remaining.push(Value::Null);
        }
        row["mountpoints"] = Value::Array(remaining);
    }
    Ok(normalized)
}
pub struct Selection<'a> {
    discovery: &'a Discovery,
    row: Value,
    device: Device,
    /// Last successful public (lsblk) inventory comparison while attached.
    inventory_checked: std::sync::Mutex<Option<Instant>>,
}
/// While a destination is attached, the kernel identity of the held device and
/// the owned mount is checked at every boundary; the public lsblk inventory
/// (one process per check) at most this often. Long copies and backups call
/// their boundary many times per second.
const ATTACHED_INVENTORY_INTERVAL: Duration = Duration::from_secs(5);
impl Selection<'_> {
    pub fn recheck(&self) -> Result<()> {
        self.discovery.recheck()?;
        self.device.recheck()?;
        require(
            self.discovery.read_current()? == self.discovery.devices,
            "backup inventory changed during selection",
        )?;
        self.device.recheck()?;
        self.discovery.recheck()
    }
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.device.file.as_fd())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.device.evidence())
    }
    pub(crate) fn recheck_device(&self) -> Result<()> {
        self.discovery.recheck()?;
        self.device.recheck()?;
        self.discovery.recheck()
    }
    pub(crate) fn recheck_area(&self, area: &crate::backup_private_area::Core) -> Result<()> {
        self.discovery.recheck()?;
        self.device.recheck()?;
        area.uncovered()?;
        require(
            self.discovery.guard.configuration["filesystem_uuid"] == area.source_uuid(),
            "owned private area belongs to another original source",
        )?;
        let current = self.discovery.read_current()?;
        require(
            area_inventory(
                &self.discovery.devices,
                &current,
                area.source_uuid(),
                area.source_members(),
            )? == self.discovery.devices,
            "inventory changed beyond original private source area",
        )?;
        area.uncovered()?;
        self.device.recheck()?;
        self.discovery.recheck()
    }
    pub(crate) fn descriptor_area(
        &self,
        area: &crate::backup_private_area::Core,
    ) -> Result<BorrowedFd<'_>> {
        self.recheck_area(area)?;
        Ok(self.device.file.as_fd())
    }
    pub(crate) fn evidence_area(&self, area: &crate::backup_private_area::Core) -> Result<Value> {
        self.recheck_area(area)?;
        Ok(self.device.evidence())
    }
    pub(crate) fn recheck_attached(&self, mount: &crate::backup_setup_mount::Owned) -> Result<()> {
        self.discovery.recheck()?;
        self.device.recheck()?;
        mount.recheck_kernel()?;
        require(
            mount.device() == &self.device.evidence(),
            "owned mount selected device changed",
        )?;
        let mut checked = self
            .inventory_checked
            .lock()
            .map_err(|_| Error("attached inventory state poisoned".into()))?;
        if checked.is_some_and(|at| at.elapsed() < ATTACHED_INVENTORY_INTERVAL) {
            drop(checked);
            mount.recheck_kernel()?;
            self.device.recheck()?;
            return self.discovery.recheck();
        }
        attached_inventory(
            &self.discovery.devices,
            &area_inventory(
                &self.discovery.devices,
                &self.discovery.read_current()?,
                mount.source_uuid(),
                mount.source_members(),
            )?,
            enzimos_platform::json::string(&self.row["name"])?,
        )?;
        mount.recheck_kernel()?;
        self.device.recheck()?;
        self.discovery.recheck()?;
        *checked = Some(Instant::now());
        Ok(())
    }
    pub(crate) fn guard(&self) -> &Guard {
        &self.discovery.guard
    }
    pub fn token(&self) -> Result<String> {
        self.recheck()?;
        self.discovery.token(&self.row, &self.device)
    }
    pub fn uuid_hint(&self) -> &str {
        self.row["uuid"].as_str().unwrap()
    }
}
