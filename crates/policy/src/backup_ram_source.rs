// SPDX-License-Identifier: MIT
//! Original RAM root and independently mounted control for data staging only.
//! This actor cannot supply the live-system Guard or authorize boot publication.
use crate::{filesystem, operation, storage_configuration, storage_runtime, subvolume, topology};
use enzimos_platform::{Result, files, mount_identity, mountinfo, require};
use serde_json::Value;
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original RAM source directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn flags(file: &File) -> Result<i32> {
    let f = enzimos_platform::files::status_flags(&file);
    require(
        f >= 0 && f & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY,
        "original RAM source description flags",
    )?;
    Ok(f)
}
fn ram_type(kind: libc::c_long) -> bool {
    matches!(kind, 0x01021994 | 0x858458f6)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn ram(file: &File) -> Result<()> {
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut status: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `status` is a writable `libc::statfs` and `file` keeps the descriptor open.
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut status) } == 0 && ram_type(status.f_type),
        "independent RAM recovery root required",
    )
}
pub(crate) struct Source {
    configuration: storage_configuration::Configuration,
    root: File,
    root_shape: Shape,
    root_flags: i32,
    root_mount: u64,
    root_row: mountinfo::Row,
    control: File,
    control_shape: Shape,
    control_flags: i32,
    control_mount: u64,
    control_row: mountinfo::Row,
    filesystem: Value,
    object: Value,
    topology: topology::Graph,
    namespaces: Vec<(u64, u64)>,
}
impl Source {
    pub(crate) fn observe() -> Result<Self> {
        operation::root_only()?;
        let namespaces = crate::namespaces::initial()?;
        let configuration = storage_configuration::Configuration::open()?;
        let root = files::directory(Path::new("/"), Some(0))?;
        ram(&root)?;
        let root_shape = shape(&root)?;
        let root_flags = flags(&root)?;
        let root_mount = mount_identity::id(root.as_fd(), true)?;
        let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
        let control_shape = shape(&control)?;
        require(
            control_shape.1 == 256 && control_shape.2 & 0o7777 == 0o700,
            "private independently mounted control subvolume required",
        )?;
        let control_flags = flags(&control)?;
        let control_mount = mount_identity::id(control.as_fd(), true)?;
        let rows = storage_runtime::rows()?;
        require(
            !rows.iter().any(|r| {
                r.target == "/home"
                    || r.target.starts_with("/home/")
                    || r.target.starts_with("/var/lib/enzimos-control/")
            }),
            "RAM restore refuses mounted live home",
        )?;
        let root_rows = rows.iter().filter(|r| r.target == "/").collect::<Vec<_>>();
        let control_rows = rows
            .iter()
            .filter(|r| r.target == operation::CONTROL)
            .collect::<Vec<_>>();
        require(
            root_rows.len() == 1 && control_rows.len() == 1,
            "RAM root/control missing or shadowed",
        )?;
        let root_row = root_rows[0].clone();
        let control_row = control_rows[0].clone();
        require(
            matches!(root_row.filesystem.as_str(), "tmpfs" | "rootfs" | "ramfs")
                && root_row.id == mount_identity::id(root.as_fd(), false)?,
            "actual RAM root mount differs",
        )?;
        let name = enzimos_platform::json::string(&configuration.value()["control_subvol"])?;
        require(
            control_row.filesystem == "btrfs"
                && control_row.root == format!("/{name}")
                && control_row.id == mount_identity::id(control.as_fd(), false)?,
            "RAM control mount differs from configured identity",
        )?;
        crate::backup_destination::writable(&control_row)?;
        let filesystem = filesystem::observe(control.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == configuration.value()["filesystem_uuid"],
            "RAM control filesystem mismatch",
        )?;
        let (object, readonly) = subvolume::observe(control.as_fd(), name)?;
        require(!readonly, "RAM control subvolume readonly")?;
        let topology = topology::mounted_btrfs(enzimos_platform::json::string(
            &configuration.value()["filesystem_uuid"],
        )?)?;
        let this = Self {
            configuration,
            root,
            root_shape,
            root_flags,
            root_mount,
            root_row,
            control,
            control_shape,
            control_flags,
            control_mount,
            control_row,
            filesystem,
            object,
            topology,
            namespaces,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn configuration(&self) -> &Value {
        self.configuration.value()
    }
    pub(crate) fn control(&self) -> &File {
        &self.control
    }
    pub(crate) fn control_mount_id(&self) -> u64 {
        self.control_mount
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        operation::root_only()?;
        require(
            crate::namespaces::initial()? == self.namespaces,
            "original RAM source namespaces changed",
        )?;
        self.configuration.recheck()?;
        let root = files::directory(Path::new("/"), Some(0))?;
        let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
        for original in [&self.root, &root] {
            ram(original)?;
            require(
                shape(original)? == self.root_shape
                    && mount_identity::id(original.as_fd(), true)? == self.root_mount,
                "original RAM root replaced or covered",
            )?;
        }
        for original in [&self.control, &control] {
            require(
                shape(original)? == self.control_shape
                    && mount_identity::id(original.as_fd(), true)? == self.control_mount
                    && filesystem::observe(original.as_fd())? == self.filesystem
                    && subvolume::observe(
                        original.as_fd(),
                        enzimos_platform::json::string(&self.configuration()["control_subvol"])?,
                    )? == (self.object.clone(), false),
                "original RAM control replaced/changed",
            )?;
        }
        require(
            flags(&self.root)? == self.root_flags && flags(&self.control)? == self.control_flags,
            "RAM source shared flags changed",
        )?;
        let rows = storage_runtime::rows()?;
        require(
            rows.iter().filter(|r| r.target == "/").collect::<Vec<_>>() == [&self.root_row]
                && rows
                    .iter()
                    .filter(|r| r.target == operation::CONTROL)
                    .collect::<Vec<_>>()
                    == [&self.control_row]
                && !rows.iter().any(|r| {
                    r.target == "/home"
                        || r.target.starts_with("/home/")
                        || r.target.starts_with("/var/lib/enzimos-control/")
                }),
            "RAM root/control/home mount state changed",
        )?;
        require(
            topology::mounted_btrfs(enzimos_platform::json::string(
                &self.configuration()["filesystem_uuid"],
            )?)? == self.topology,
            "RAM protected filesystem disk topology changed",
        )
    }
}
