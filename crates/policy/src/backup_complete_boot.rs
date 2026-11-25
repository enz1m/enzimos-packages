// SPDX-License-Identifier: MIT
//! Complete boot preparation admits actual RAM recovery and original replacements.
//! All restored execution stays in private child namespaces and an owned cgroup.
use super::{Source, Target};
use crate::{
    backup_admission, backup_configuration, backup_destination, backup_ram_quiet,
    backup_ram_source,
    control_record::Observation,
    filesystem, operation,
    recovery_devices::Block,
    settings_command::{BootTool, Command},
    storage_runtime, subvolume,
};
use enzimos_platform::{
    Error, Result, files, json, mount_identity, mountinfo, process,
    recovery_boot_child::{Context, Tool},
    recovery_boot_group::Group,
    require,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
const ESP: &str = "/restore-boot";
const KEYS: &str = "/run/enzimos-recovery-keys";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected complete boot directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn boot_uuid(layout: &Value) -> Result<String> {
    let rows = layout["fstab"]
        .as_str()
        .ok_or_else(|| Error("complete boot fstab required".into()))?
        .lines()
        .filter(|line| line.split_whitespace().nth(1) == Some("/boot"))
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        "one fresh EFI filesystem identity required",
    )?;
    let uuid = rows[0]
        .strip_prefix("UUID=")
        .and_then(|s| {
            s.strip_suffix(" /boot vfat fmask=0177,dmask=0077 0 2")
                .or_else(|| s.strip_suffix(" /boot vfat umask=0077 0 2"))
        })
        .ok_or_else(|| Error("complete boot fstab options differ".into()))?;
    crate::recovery_records::fat_uuid(uuid)?;
    Ok(uuid.into())
}

struct Esp {
    directory: File,
    shape: Shape,
    mount: u64,
    row: mountinfo::Row,
    block: Block,
    flags: i32,
}
impl Esp {
    fn observe(uuid: &str) -> Result<Self> {
        let block = Block::by_uuid(uuid, true)?;
        let directory = files::directory(Path::new(ESP), Some(0))?;
        let shape = shape(&directory)?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        require(
            shape.2 & 0o7777 == 0o700 && files::directory_names(&directory, 1)?.is_empty(),
            "explicit private empty EFI filesystem required",
        )?;
        let normal = mount_identity::id(directory.as_fd(), false)?;
        let rows = storage_runtime::rows()?;
        let matching = rows.iter().filter(|r| r.target == ESP).collect::<Vec<_>>();
        require(
            matching.len() == 1
                && matching[0].id == normal
                && matching[0].filesystem == "vfat"
                && matching[0].root == "/",
            "original complete EFI mount required",
        )?;
        let row = matching[0].clone();
        crate::backup_destination::writable(&row)?;
        let dev = block.file.metadata()?.rdev();
        require(
            (row.major, row.minor) == (libc::major(dev), libc::minor(dev)),
            "EFI mount differs from original UUID-selected device",
        )?;
        require(
            !rows.iter().any(|r| {
                r.target.starts_with("/restore-boot/")
                    || (r.id != row.id
                        && (r.major, r.minor, r.root.as_str()) == (row.major, row.minor, "/"))
            }),
            "nested or aliased complete EFI mount refused",
        )?;
        let flags = enzimos_platform::files::status_flags(&directory);
        require(
            flags >= 0 && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY,
            "EFI original description role",
        )?;
        let this = Self {
            directory,
            shape,
            mount,
            row,
            block,
            flags,
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        self.block.recheck()?;
        let named = files::directory(Path::new(ESP), Some(0))?;
        for file in [&self.directory, &named] {
            require(
                shape(file)? == self.shape && mount_identity::id(file.as_fd(), true)? == self.mount,
                "original EFI filesystem replaced/covered/changed",
            )?;
        }
        require(
            enzimos_platform::files::status_flags(&self.directory) == self.flags,
            "EFI shared flags changed",
        )?;
        let rows = storage_runtime::rows()?;
        require(
            rows.iter().filter(|r| r.target == ESP).collect::<Vec<_>>() == [&self.row]
                && !rows.iter().any(|r| {
                    r.target.starts_with("/restore-boot/")
                        || (r.id != self.row.id
                            && (r.major, r.minor, r.root.as_str())
                                == (self.row.major, self.row.minor, "/"))
                }),
            "original EFI mount changed or gained alias",
        )
    }
    fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"mount_id":self.row.id,"unique_mount_id":self.mount,"device":format!("{}:{}",self.row.major,self.row.minor),"root":"/","target":ESP,"fstype":"vfat"}),
        )
    }
}
struct Input {
    file: File,
    epoch: files::FileIdentity,
    mount: u64,
    bytes: Vec<u8>,
}
impl Input {
    fn open(parent: &File, name: &str, limit: usize) -> Result<Self> {
        let file = files::open_relative(parent, Path::new(name))?;
        let m = file.metadata()?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original protected complete boot input required",
        )?;
        let bytes = files::read_file(&file, limit, Some(0), true)?;
        Ok(Self {
            epoch: files::identity(&m),
            file,
            mount,
            bytes,
        })
    }
    fn recheck(&self, parent: &File, name: &str) -> Result<()> {
        let named = files::open_relative(parent, Path::new(name))?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && enzimos_platform::files::status_flags(&self.file)
                    & (libc::O_ACCMODE | libc::O_PATH)
                    == libc::O_RDONLY,
            "original complete boot input changed/replaced",
        )
    }
}
struct Keys {
    directory: File,
    shape: Shape,
    mount: u64,
    inputs: BTreeMap<String, Input>,
}
impl Keys {
    fn observe() -> Result<Self> {
        let directory = files::directory(Path::new(KEYS), Some(0))?;
        let shape = shape(&directory)?;
        require(
            shape.2 & 0o7777 == 0o700,
            "private reviewed public recovery authority required",
        )?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let mut inputs = BTreeMap::new();
        for name in ["pubring.gpg", "trustdb.gpg", "gpg.conf", "approved.trust"] {
            inputs.insert(
                name.into(),
                Input::open(&directory, name, 16 * 1024 * 1024)?,
            );
        }
        let this = Self {
            directory,
            shape,
            mount,
            inputs,
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        let named = files::directory(Path::new(KEYS), Some(0))?;
        require(
            shape(&self.directory)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original reviewed recovery authority replaced/covered",
        )?;
        let names = files::directory_names(&self.directory, 5)?
            .into_iter()
            .map(|s| {
                s.into_string()
                    .map_err(|_| Error("recovery authority filename encoding".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            names == self.inputs.keys().cloned().collect(),
            "reviewed authority member set changed",
        )?;
        for (name, input) in &self.inputs {
            input.recheck(&self.directory, name)?;
        }
        Ok(())
    }
}
/// An explicitly created mount in the RAM runtime. Drop only closes that exact
/// original mount normally; uncertainty never permits force or lazy detach.
struct Authority {
    path: PathBuf,
    file: Option<File>,
    mount: u64,
    row: mountinfo::Row,
    object: Value,
    filesystem: Value,
    device: Block,
}
impl Authority {
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn mount(path: PathBuf, ram: &backup_ram_source::Source) -> Result<Self> {
        ram.recheck()?;
        let device = Block::by_uuid(
            enzimos_platform::json::string(&ram.configuration()["filesystem_uuid"])?,
            false,
        )?;
        let directory = files::create_directory(&path, 0o700, 0)?;
        require(
            files::directory_names(&directory, 1)?.is_empty()
                && !storage_runtime::rows()?
                    .iter()
                    .any(|r| r.target == path.to_str().unwrap()),
            "fresh complete authority mount target required",
        )?;
        let source = CString::new(format!("/proc/self/fd/{}", device.file.as_raw_fd())).unwrap();
        let target = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            // SAFETY: All non-null pointers are NUL-terminated CStrings that outlive the call.
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    c"btrfs".as_ptr(),
                    libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                    c"subvol=enzimos-authority".as_ptr().cast(),
                )
            } == 0,
            "fresh authority mount failed; boot preparation receipt retained",
        )?;
        // Capture immediately before another operation can fail.
        let file = files::directory(&path, Some(0))?;
        let mount = mount_identity::id(file.as_fd(), true)?;
        let normal = mount_identity::id(file.as_fd(), false)?;
        let row = storage_runtime::mount_row(
            &storage_runtime::rows()?,
            path.to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            Some("/enzimos-authority"),
            normal,
        )?
        .clone();
        let filesystem = filesystem::observe(file.as_fd())?;
        let (object, readonly) = subvolume::observe(file.as_fd(), "enzimos-authority")?;
        let this = Self {
            path,
            file: Some(file),
            mount,
            row,
            object,
            filesystem,
            device,
        };
        require(
            this.filesystem["filesystem_uuid"] == ram.configuration()["filesystem_uuid"]
                && !readonly
                && this.object["parent_uuid"].is_null()
                && this
                    .file
                    .as_ref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                    .metadata()?
                    .ino()
                    == 256
                && files::directory_names(
                    this.file
                        .as_ref()
                        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                    1,
                )?
                .is_empty(),
            "explicit empty fresh authority subvolume required",
        )?;
        this.recheck()?;
        Ok(this)
    }
    fn file(&self) -> Result<&File> {
        self.recheck()?;
        self.file
            .as_ref()
            .ok_or_else(|| Error("complete authority mount closed".into()))
    }
    fn recheck(&self) -> Result<()> {
        self.device.recheck()?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| Error("complete authority mount closed".into()))?;
        let named = files::directory(&self.path, Some(0))?;
        for actual in [file, &named] {
            require(
                actual.metadata()?.ino() == 256
                    && actual.metadata()?.uid() == 0
                    && actual.metadata()?.gid() == 0
                    && actual.metadata()?.mode() & 0o7777 == 0o700
                    && mount_identity::id(actual.as_fd(), true)? == self.mount
                    && filesystem::observe(actual.as_fd())? == self.filesystem
                    && subvolume::observe(actual.as_fd(), "enzimos-authority")?
                        == (self.object.clone(), false),
                "original complete authority object replaced/changed",
            )?;
        }
        let rows = storage_runtime::rows()?;
        require(
            rows.iter()
                .filter(|r| r.target == self.path.to_str().unwrap())
                .collect::<Vec<_>>()
                == [&self.row],
            "original complete authority mount replaced",
        )?;
        crate::backup_destination::writable(&self.row)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    fn close(&mut self) -> Result<()> {
        self.recheck()?;
        let target = CString::new(self.path.as_os_str().as_encoded_bytes())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        drop(self.file.take());
        // SAFETY: `target` is a NUL-terminated CString.
        let code = unsafe { libc::umount2(target.as_ptr(), 0) };
        if code != 0 {
            self.file = Some(files::directory(&self.path, Some(0))?);
            return Err(Error(
                "owned complete authority normal unmount failed".into(),
            ));
        }
        Ok(())
    }
}
impl Drop for Authority {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = self.close();
        }
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn set_root_readonly(
    target: &Target,
    guard: &Source<'_>,
    readonly: bool,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    authorize()?;
    target.recheck(guard)?;
    let mut flags = 0u64;
    require(
        // SAFETY: BTRFS_IOC_SUBVOL_GETFLAGS writes one u64 into the passed buffer, and the
        // directory stays open.
        unsafe {
            libc::ioctl(
                target.directory.as_raw_fd(),
                0x80089419 as libc::c_ulong,
                &mut flags,
            )
        } == 0
            && flags == if target.readonly.get() { 2 } else { 0 },
        "original replacement subvolume flags differ",
    )?;
    let next = if readonly { 2u64 } else { 0u64 };
    require(
        // SAFETY: BTRFS_IOC_SUBVOL_SETFLAGS reads one u64 from the passed buffer, and the directory
        // stays open.
        unsafe {
            libc::ioctl(
                target.directory.as_raw_fd(),
                0x4008941a as libc::c_ulong,
                &next,
            )
        } == 0,
        "owned replacement readonly transition failed; preparing receipt retained",
    )?;
    target.readonly.set(readonly);
    target.recheck(guard)?;
    authorize()
}
fn output(parent: &File, name: &str, bytes: &[u8]) -> Result<File> {
    super::complete_fat::write(parent, name, bytes, None)
}
fn copy_file(
    source: &File,
    name: &str,
    target: &File,
    destination: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<File> {
    authorize()?;
    let input = Input::open(source, name, 32 * 1024 * 1024)?;
    let result = output(target, destination, &input.bytes)?;
    input.recheck(source, name)?;
    authorize()?;
    Ok(result)
}

#[path = "backup_complete_boot/publication.rs"]
mod publication;
pub use publication::publish_locked;
