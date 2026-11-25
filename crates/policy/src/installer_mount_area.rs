// SPDX-License-Identifier: MIT
//! A boot-local private bind area at the legacy answer path. Root propagation is unchanged.
//! Creating it is explicit and one-shot; observation grants no disk execution or replay.
use crate::{namespaces, operation, storage_runtime};
use enzimos_platform::{Error, Result, files, json, mount_identity, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub const ROOT: &str = "/run/enzimos-answers";
const STORE: &str = "/run/enzimos-install-native";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Answers,
    Storage,
    Target,
}
impl Role {
    fn root(self) -> &'static str {
        match self {
            Self::Answers => ROOT,
            Self::Storage => "/run/enzimos-install-native/mounts",
            Self::Target => "/mnt/enzimos",
        }
    }
    fn relative(self) -> &'static str {
        match self {
            Self::Answers => "enzimos-answers",
            Self::Storage => "enzimos-install-native/mounts",
            Self::Target => "enzimos",
        }
    }
    fn filesystem_root(self) -> String {
        if self == Self::Target {
            "/mnt/enzimos".into()
        } else {
            format!("/{}", self.relative())
        }
    }
    fn parent(self) -> &'static str {
        if self == Self::Target { "/mnt" } else { "/run" }
    }
    fn parent_target(self) -> &'static str {
        if self == Self::Target { "/" } else { "/run" }
    }
    fn filesystem(self) -> &'static str {
        if self == Self::Target {
            "overlay"
        } else {
            "tmpfs"
        }
    }
    fn magic(self) -> libc::c_long {
        if self == Self::Target {
            0x794c7630
        } else {
            0x01021994
        }
    }
    fn receipt(self) -> &'static str {
        match self {
            Self::Answers => "answer-area.json",
            Self::Storage => "storage-area.json",
            Self::Target => "target-area.json",
        }
    }
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, private: bool) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && (!private || m.mode() & 0o7777 == 0o700),
        "protected original answer area directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn empty(file: &File) -> Result<()> {
    require(
        files::directory_is_empty(file)?,
        "answer area must be empty; no automatic adoption",
    )
}
fn row_role(rows: &[mountinfo::Row], id: u64, private: bool, role: Role) -> Result<mountinfo::Row> {
    let candidates = rows
        .iter()
        .filter(|r| r.target == role.root())
        .collect::<Vec<_>>();
    require(
        candidates.len() == 1
            && (role == Role::Storage
                || !rows
                    .iter()
                    .any(|r| r.target.starts_with(&format!("{}/", role.root())))),
        "one unshadowed answer area required",
    )?;
    let r = candidates[0];
    let flags = r
        .options
        .split(',')
        .collect::<std::collections::BTreeSet<_>>();
    require(
        r.id == id
            && r.filesystem == role.filesystem()
            && r.root == role.filesystem_root()
            && r.major == 0
            && flags.contains("rw")
            && !flags.contains("ro")
            && (!private
                || (r.optional.is_empty()
                    && ["nodev", "nosuid", "noexec"]
                        .iter()
                        .all(|n| flags.contains(n)))),
        "original private answer area kernel mount differs",
    )?;
    Ok(r.clone())
}
pub fn validate_mount(rows: &[mountinfo::Row], id: u64) -> Result<mountinfo::Row> {
    row_role(rows, id, true, Role::Answers)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn magic(file: &File, role: Role) -> Result<()> {
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0 && stat.f_type == role.magic(),
        "answer area requires actual live tmpfs",
    )
}
fn origin(
    row: &mountinfo::Row,
    parent: &mountinfo::Row,
    device: u64,
    parent_device: u64,
) -> Result<()> {
    require(
        row.parent == parent.id
            && (row.major, row.minor) == (parent.major, parent.minor)
            && device == parent_device,
        "private installer bind left its original parent filesystem",
    )
}
pub struct Area {
    role: Role,
    file: File,
    shape: Shape,
    mount: u64,
    row: mountinfo::Row,
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    parent_row: mountinfo::Row,
}
impl Area {
    /// Capture the actual configured kernel area; receipts are never authority.
    pub fn observe() -> Result<Self> {
        Self::observe_role(Role::Answers)
    }
    pub fn observe_storage() -> Result<Self> {
        Self::observe_role(Role::Storage)
    }
    pub fn observe_target() -> Result<Self> {
        Self::observe_role(Role::Target)
    }
    fn observe_role(role: Role) -> Result<Self> {
        namespaces::initial()?;
        let parent = files::directory(Path::new(role.parent()), Some(0))?;
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        let rows = storage_runtime::rows()?;
        let parent_normal = mount_identity::id(parent.as_fd(), false)?;
        let parent_row = rows
            .iter()
            .find(|r| {
                r.id == parent_normal
                    && r.target == role.parent_target()
                    && r.filesystem == role.filesystem()
                    && r.root == "/"
            })
            .ok_or_else(|| Error("original live answer parent unavailable".into()))?
            .clone();
        let file = files::directory(Path::new(role.root()), Some(0))?;
        magic(&parent, role)?;
        magic(&file, role)?;
        if role != Role::Storage {
            empty(&file)?;
        }
        let mount = mount_identity::id(file.as_fd(), true)?;
        require(
            mount != parent_mount,
            "answer area must have its own kernel mount identity",
        )?;
        let this = Self {
            role,
            shape: shape(&file, true)?,
            row: row_role(&rows, mount_identity::id(file.as_fd(), false)?, true, role)?,
            mount,
            file,
            parent_shape: shape(&parent, false)?,
            parent,
            parent_mount,
            parent_row,
        };
        origin(
            &this.row,
            &this.parent_row,
            this.shape.0,
            this.parent_shape.0,
        )?;
        this.recheck()?;
        Ok(this)
    }
    /// Retain and check the underlying area even while its one owned volume covers it.
    pub fn recheck_covered(&self) -> Result<()> {
        let role = self.role;
        namespaces::initial()?;
        let parent = files::directory(Path::new(role.parent()), Some(0))?;
        let rows = storage_runtime::rows()?;
        require(
            shape(&self.parent, false)? == self.parent_shape
                && shape(&parent, false)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount
                && shape(&self.file, true)? == self.shape
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && rows
                    .iter()
                    .filter(|r| r.id == self.row.id)
                    .collect::<Vec<_>>()
                    == vec![&self.row]
                && rows
                    .iter()
                    .filter(|r| r.id == self.parent_row.id)
                    .collect::<Vec<_>>()
                    == vec![&self.parent_row],
            "original answer area or parent changed",
        )?;
        magic(&self.file, role)?;
        if self.role != Role::Storage {
            empty(&self.file)
        } else {
            Ok(())
        }
    }
    pub fn recheck(&self) -> Result<()> {
        let role = self.role;
        self.recheck_covered()?;
        let named = files::directory(Path::new(role.root()), Some(0))?;
        require(
            shape(&named, true)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && row_role(
                    &storage_runtime::rows()?,
                    mount_identity::id(named.as_fd(), false)?,
                    true,
                    role,
                )? == self.row,
            "named original answer area changed",
        )
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub fn binding(&self) -> &mountinfo::Row {
        &self.row
    }
    pub fn parent_mount(&self) -> u64 {
        self.parent_mount
    }
}
/// Explicit fresh boot preparation, before answer discovery/mounting. Failed
/// intent is retained; this function never adopts or completes an earlier one.
pub fn create(lock: &files::Lock) -> Result<Value> {
    create_role(lock, Role::Answers)
}
pub fn create_storage(lock: &files::Lock) -> Result<Value> {
    create_role(lock, Role::Storage)
}
pub fn create_target(lock: &files::Lock) -> Result<Value> {
    create_role(lock, Role::Target)
}
fn create_role(lock: &files::Lock, role: Role) -> Result<Value> {
    namespaces::initial()?;
    lock.recheck()?;
    let parent = files::directory(Path::new(role.parent()), Some(0))?;
    magic(&parent, role)?;
    let parent_shape = shape(&parent, false)?;
    let parent_mount = mount_identity::id(parent.as_fd(), true)?;
    let rows = storage_runtime::rows()?;
    let parent_normal = mount_identity::id(parent.as_fd(), false)?;
    let parent_row = rows
        .iter()
        .find(|r| {
            r.id == parent_normal
                && r.target == role.parent_target()
                && r.filesystem == role.filesystem()
                && r.root == "/"
        })
        .ok_or_else(|| Error("original live tmpfs parent required".into()))?
        .clone();
    require(
        !rows
            .iter()
            .any(|r| r.target == role.root() || r.target.starts_with(&format!("{}/", role.root()))),
        "answer area already mounted; fresh preparation required",
    )?;
    let stub = files::ensure_directory_relative(&parent, Path::new(role.relative()), 0o700, 0)?;
    let stub_shape = shape(&stub, true)?;
    empty(&stub)?;
    require(
        mount_identity::id(stub.as_fd(), true)? == parent_mount,
        "answer stub left original tmpfs",
    )?;
    let store = files::ensure_directory(Path::new(STORE), 0o700, 0)?;
    let store_shape = shape(&store, true)?;
    let run = files::directory(Path::new("/run"), Some(0))?;
    magic(&run, Role::Answers)?;
    magic(&store, Role::Answers)?;
    let run_shape = shape(&run, false)?;
    let store_mount = mount_identity::id(run.as_fd(), true)?;
    let run_normal = mount_identity::id(run.as_fd(), false)?;
    let run_row = rows
        .iter()
        .find(|r| {
            r.id == run_normal && r.target == "/run" && r.root == "/" && r.filesystem == "tmpfs"
        })
        .ok_or_else(|| Error("original live intent tmpfs required".into()))?
        .clone();
    require(
        mount_identity::id(store.as_fd(), true)? == store_mount,
        "private area intent left original live tmpfs",
    )?;
    let mut body = value!({"schema":1,"phase":"preparing","boot":operation::boot_id()?,"underlying":stub_shape,"parent_mount":parent_mount});
    let bytes = json::canonical(&body)?;
    let receipt = files::atomic_relative_retained(
        &store,
        Path::new(role.receipt()),
        &bytes,
        0o600,
        Some(0),
        false,
        65536,
    )?;
    let original = files::identity(&receipt.metadata()?);
    let checkpoint = || -> Result<()> {
        namespaces::initial()?;
        lock.recheck()?;
        let named_store = files::directory(Path::new(STORE), Some(0))?;
        let named_parent = files::directory(Path::new(role.parent()), Some(0))?;
        let named = files::open_relative(&store, Path::new(role.receipt()))?;
        let named_run = files::directory(Path::new("/run"), Some(0))?;
        require(
            shape(&run, false)? == run_shape
                && shape(&named_run, false)? == run_shape
                && mount_identity::id(run.as_fd(), true)? == store_mount
                && mount_identity::id(named_run.as_fd(), true)? == store_mount
                && storage_runtime::rows()?
                    .iter()
                    .filter(|r| r.id == run_row.id)
                    .collect::<Vec<_>>()
                    == vec![&run_row]
                && shape(&parent, false)? == parent_shape
                && shape(&named_parent, false)? == parent_shape
                && mount_identity::id(parent.as_fd(), true)? == parent_mount
                && mount_identity::id(named_parent.as_fd(), true)? == parent_mount
                && shape(&store, true)? == store_shape
                && shape(&named_store, true)? == store_shape
                && mount_identity::id(store.as_fd(), true)? == store_mount
                && mount_identity::id(named_store.as_fd(), true)? == store_mount
                && files::identity(&receipt.metadata()?) == original
                && files::identity(&named.metadata()?) == original
                && files::read_file(&receipt, 65536, Some(0), true)? == bytes
                && storage_runtime::rows()?
                    .iter()
                    .filter(|r| r.id == parent_row.id)
                    .collect::<Vec<_>>()
                    == vec![&parent_row],
            "original answer-area intent, store or parent changed",
        )
    };
    checkpoint()?;
    let named_stub = files::directory(Path::new(role.root()), Some(0))?;
    require(
        shape(&named_stub, true)? == stub_shape
            && mount_identity::id(named_stub.as_fd(), true)? == parent_mount,
        "original named answer stub changed before bind",
    )?;
    empty(&stub)?;
    // Prepare only a detached clone of the retained empty stub. Protection and
    // propagation are set while detached and normalized after attachment below
    // a shared parent, before admission. The original parent is unchanged.
    let detached = crate::private_bind::Detached::prepare(&stub, &checkpoint)?;
    let mount = detached.unique();
    let named_stub = files::directory(Path::new(role.root()), Some(0))?;
    require(
        shape(&named_stub, true)? == stub_shape
            && mount_identity::id(named_stub.as_fd(), true)? == parent_mount,
        "original named answer stub changed before attachment",
    )?;
    let _owned_mount = detached.attach(&stub, &checkpoint)?;
    // Once attached, only the actual retained clone may be admitted. Failure
    // keeps the durable intent; Drop never guesses ownership or unmounts it.
    let area = Area::observe_role(role)?;
    area.recheck()?;
    checkpoint()?;
    require(
        area.mount == mount && area.shape == stub_shape,
        "completed answer bind differs from original creation",
    )?;
    body["phase"] = value!("ready");
    body["mount"] = value!(mount);
    let r = area.binding();
    body["row"] = value!({"id":r.id,"parent":r.parent,"device":[r.major,r.minor],"root":r.root,"target":r.target,
        "filesystem":r.filesystem,"options":r.options,"filesystem_options":r.filesystem_options,"optional":r.optional});
    let complete = files::atomic_replace_original(
        &store,
        Path::new(role.receipt()),
        &json::canonical(&body)?,
        0o600,
        Some(0),
        65536,
        &receipt,
    )?;
    let named = files::open_relative(&store, Path::new(role.receipt()))?;
    let named_store = files::directory(Path::new(STORE), Some(0))?;
    let named_run = files::directory(Path::new("/run"), Some(0))?;
    require(
        files::identity(&named.metadata()?) == files::identity(&complete.metadata()?)
            && files::read_file(&complete, 65536, Some(0), true)? == json::canonical(&body)?
            && shape(&store, true)? == store_shape
            && shape(&named_store, true)? == store_shape
            && mount_identity::id(store.as_fd(), true)? == store_mount
            && mount_identity::id(named_store.as_fd(), true)? == store_mount
            && shape(&run, false)? == run_shape
            && shape(&named_run, false)? == run_shape
            && mount_identity::id(run.as_fd(), true)? == store_mount
            && mount_identity::id(named_run.as_fd(), true)? == store_mount
            && storage_runtime::rows()?
                .iter()
                .filter(|r| r.id == run_row.id)
                .collect::<Vec<_>>()
                == vec![&run_row],
        "answer area completion readback differs",
    )?;
    area.recheck()?;
    lock.recheck()?;
    Ok(
        value!({"schema":1,"private_area_ready":true,"path":role.root(),"mount":mount,"installed_qualification":false}),
    )
}
