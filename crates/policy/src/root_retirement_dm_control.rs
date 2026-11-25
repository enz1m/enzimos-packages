// SPDX-License-Identifier: MIT
//! Retained actual DM control/status, never table/key queries or arbitrary names.
//! ABI: linux/dm-ioctl.h. Kernel semantics:
//! https://raw.githubusercontent.com/torvalds/linux/master/drivers/md/dm-ioctl.c
use crate::{
    recovery_unlock::{CreatedMapping, MAPPER},
    root_retirement_offline_mount::ReleasedMount,
    root_retirement_offline_scope::Scope,
    root_retirement_unlock_source::Verified,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
};
pub(crate) const STATUS: u32 = 0xc138fd07;
pub(crate) const REMOVE: u32 = 0xc138fd04;
const VERSION: libc::c_ulong = 0xc138fd00;
#[repr(C)]
struct Header {
    version: [u32; 3],
    size: u32,
    start: u32,
    targets: u32,
    opens: i32,
    flags: u32,
    event: u32,
    padding: u32,
    device: u64,
    name: [u8; 128],
    uuid: [u8; 129],
    data: [u8; 7],
}
impl Header {
    fn empty() -> Self {
        Self {
            version: [4, 0, 0],
            size: 312,
            start: 312,
            targets: 0,
            opens: 0,
            flags: 0,
            event: 0,
            padding: 0,
            device: 0,
            name: [0; 128],
            uuid: [0; 129],
            data: [0; 7],
        }
    }
    fn by_device(device: u64) -> Self {
        let mut value = Self::empty();
        value.device = device;
        value
    }
}
fn string(bytes: &[u8]) -> Result<&str> {
    let length = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error("unterminated actual DM status string".into()))?;
    require(
        length > 0 && bytes[length..].iter().all(|b| *b == 0),
        "empty or ambiguous actual DM status string",
    )?;
    let value = std::str::from_utf8(&bytes[..length])
        .map_err(|_| Error("actual DM status string encoding".into()))?;
    require(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "actual DM status string grammar",
    )?;
    Ok(value)
}
fn encoded(major: u32, minor: u32) -> Result<u64> {
    require(
        major > 0 && major < 4096 && minor < (1 << 20),
        "bounded actual Linux DM device number",
    )?;
    Ok(u64::from(
        (minor & 255) | (major << 8) | ((minor & !255) << 12),
    ))
}
fn status_valid(header: &Header, device: u64, uuid: &str) -> Result<()> {
    require(
        header.version[0] == 4
            && header.size == 312
            && header.start == 312
            && header.device == device
            && header.targets == 1
            && header.opens >= 0
            && header.flags == 32
            && string(&header.name)? == MAPPER
            && string(&header.uuid)? == uuid,
        "actual DM status differs from original active writable owned mapper",
    )
}
fn flags(file: &File) -> Result<i32> {
    let f = enzimos_platform::files::status_flags(&file);
    require(
        f >= 0 && f & libc::O_ACCMODE == libc::O_RDONLY,
        "original DM observation read-only descriptor",
    )?;
    Ok(f)
}
fn sys_device(file: &File) -> Result<u64> {
    let mut bytes = [0; 65];
    let count = file.read_at(&mut bytes, 0)?;
    require(
        count > 0 && count <= 64,
        "bounded actual DM control sysfs device",
    )?;
    let raw = std::str::from_utf8(&bytes[..count])
        .map_err(|_| Error("DM control sysfs device encoding".into()))?;
    let raw = raw.strip_suffix('\n').unwrap_or(raw);
    let (major, minor) = raw
        .split_once(':')
        .ok_or_else(|| Error("DM control sysfs device shape".into()))?;
    let number = |part: &str| -> Result<u32> {
        require(
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
            "DM control sysfs integer",
        )?;
        part.parse()
            .map_err(|_| Error("DM control sysfs integer bound".into()))
    };
    Ok(libc::makedev(number(major)?, number(minor)?))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn link_description(parent: &File) -> Result<File> {
    let name = std::ffi::CString::new(MAPPER)
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "original fixed mapper symlink unavailable")?;
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(raw) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn link_absent(parent: &File) -> Result<()> {
    let name = std::ffi::CString::new(MAPPER)
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let error = std::io::Error::last_os_error();
    if raw >= 0 {
        // SAFETY: `raw` was just returned by openat and is owned by nothing else.
        drop(unsafe { File::from_raw_fd(raw) });
    }
    require(
        raw == -1 && error.raw_os_error() == Some(libc::ENOENT),
        "actual original mapper name still present or absence uncertain",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (readlinkat).")]
fn link_value(file: &File) -> Result<Vec<u8>> {
    let mut bytes = [0u8; 129];
    // SAFETY: The empty path is NUL-terminated, the buffer pointer and length describe `bytes`, and
    // `file` stays open.
    let count = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    require(
        count > 0 && count < bytes.len() as isize,
        "bounded original mapper symlink target required",
    )?;
    Ok(bytes[..count as usize].to_vec())
}
struct OriginalName {
    parent: File,
    parent_epoch: files::FileIdentity,
    parent_flags: i32,
    link: File,
    link_epoch: files::FileIdentity,
    link_flags: i32,
    mount: u64,
    target: Vec<u8>,
    retired: bool,
}
impl OriginalName {
    fn observe(mapper: &Path) -> Result<Self> {
        let parent = files::directory(Path::new("/dev/mapper"), Some(0))?;
        let link = link_description(&parent)?;
        let metadata = link.metadata()?;
        require(
            metadata.mode() & libc::S_IFMT == libc::S_IFLNK
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.nlink() == 1,
            "actual fixed mapper name must be an original Root symlink",
        )?;
        let target = link_value(&link)?;
        let name = mapper
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error("actual mapper device name encoding".into()))?;
        require(
            mapper.parent() == Some(Path::new("/dev"))
                && name
                    .strip_prefix("dm-")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                && target == format!("../{name}").as_bytes(),
            "original fixed mapper symlink must identify the actual kernel dm node",
        )?;
        let link_flags = enzimos_platform::files::status_flags(&link);
        require(
            link_flags >= 0 && link_flags & libc::O_PATH != 0,
            "retained actual mapper symlink description required",
        )?;
        let result = Self {
            parent_epoch: files::identity(&parent.metadata()?),
            parent_flags: flags(&parent)?,
            mount: mount_identity::id(link.as_fd(), true)?,
            link_epoch: files::identity(&metadata),
            link_flags,
            target,
            parent,
            link,
            retired: false,
        };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&self) -> Result<()> {
        let parent = files::directory(Path::new("/dev/mapper"), Some(0))?;
        if self.retired {
            link_absent(&self.parent)?;
            return require(
                files::identity(&self.parent.metadata()?) == self.parent_epoch
                    && files::identity(&parent.metadata()?) == self.parent_epoch
                    && flags(&self.parent)? == self.parent_flags
                    && mount_identity::id(parent.as_fd(), true)? == self.mount
                    && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                    && files::identity(&self.link.metadata()?) == self.link_epoch
                    && mount_identity::id(self.link.as_fd(), true)? == self.mount
                    && enzimos_platform::files::status_flags(&self.link) == self.link_flags
                    && link_value(&self.link)? == self.target,
                "actual retired original mapper symlink or parent changed",
            );
        }
        let named = link_description(&self.parent)?;
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch
                && files::identity(&parent.metadata()?) == self.parent_epoch
                && flags(&self.parent)? == self.parent_flags
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && files::identity(&self.link.metadata()?) == self.link_epoch
                && files::identity(&named.metadata()?) == self.link_epoch
                && mount_identity::id(self.link.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && enzimos_platform::files::status_flags(&self.link) == self.link_flags
                && link_value(&self.link)? == self.target
                && link_value(&named)? == self.target,
            "original fixed mapper symlink or parent replaced, covered or modified",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn retire(mut self) -> Result<Self> {
        self.recheck()?;
        require(
            !self.retired,
            "original mapper name already retired; no replay",
        )?;
        let name = std::ffi::CString::new(MAPPER)
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            // SAFETY: `name` is a NUL-terminated C string and `self.parent` keeps the descriptor
            // open.
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "actual original mapper symlink retirement uncertain; no retry",
        )?;
        let link = files::identity(&self.link.metadata()?);
        let old = self.link_epoch;
        require(
            (old.0, old.1, old.2, old.3, old.4, old.7, old.8, old.9)
                == (
                    link.0, link.1, link.2, link.3, link.4, link.7, link.8, link.9,
                )
                && old.10 == 1
                && link.10 == 0,
            "actual owned symlink unlink changed original identity",
        )?;
        let parent = files::identity(&self.parent.metadata()?);
        let old = self.parent_epoch;
        require(
            (old.0, old.1, old.7, old.8, old.9)
                == (parent.0, parent.1, parent.7, parent.8, parent.9),
            "actual owned symlink unlink changed original parent identity",
        )?;
        self.link_epoch = link;
        self.parent_epoch = parent;
        self.retired = true;
        self.recheck()?;
        Ok(self)
    }
}
pub(crate) struct Original<'s> {
    scope: &'s Scope,
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    sys: File,
    sys_path: PathBuf,
    sys_epoch: files::FileIdentity,
    sys_flags: i32,
    sys_mount: u64,
    control_device: u64,
    generation: String,
    mapper_epoch: files::FileIdentity,
    device: u64,
    uuid: String,
    name: OriginalName,
}
/// The mapping unmounted and ready to close.
pub struct CloseReady<'s> {
    control: Original<'s>,
    unmounted: ReleasedMount<'s>,
}
/// The mapper description closed.
pub struct DescriptionClosed<'s, 'm> {
    original: CloseReady<'s>,
    closed: crate::recovery_unlock::ClosedDescription<'m>,
}
pub(crate) struct RemovalSucceeded<'s> {
    scope: &'s Scope,
    mapper_epoch: files::FileIdentity,
}
impl RemovalSucceeded<'_> {
    pub(crate) fn require_original(&self, scope: &Scope, epoch: files::FileIdentity) -> Result<()> {
        self.scope.recheck()?;
        require(
            std::ptr::eq(self.scope, scope) && self.mapper_epoch == epoch,
            "actual removal witness belongs to another original mapper",
        )
    }
}
/// The mapping removed.
pub struct Removed<'s, 'm> {
    control: Original<'s>,
    unmounted: ReleasedMount<'s>,
    source: crate::recovery_unlock::RemovedSource<'m>,
}
impl<'s> Original<'s> {
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (fstatfs, ioctl, major, minor)."
    )]
    pub(crate) fn observe(verified: &Verified<'_, '_, 's>) -> Result<Self> {
        verified.recheck()?;
        require(
            std::mem::size_of::<Header>() == 312
                && std::mem::offset_of!(Header, name) == 48
                && std::mem::offset_of!(Header, uuid) == 176,
            "exact native DM header ABI required",
        )?;
        let scope = verified.original_scope()?;
        let sys_parent = std::fs::canonicalize("/sys/class/misc/device-mapper")?;
        require(
            sys_parent.starts_with("/sys/devices")
                && sys_parent.file_name() == Some(std::ffi::OsStr::new("device-mapper")),
            "actual DM control sysfs origin",
        )?;
        let directory = files::directory(&sys_parent, Some(0))?;
        let sys = files::open_relative(&directory, Path::new("dev"))?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        require(
            // SAFETY: `stat` is writable for one `libc::statfs` and `sys` keeps the descriptor
            // open.
            unsafe { libc::fstatfs(sys.as_raw_fd(), stat.as_mut_ptr()) } == 0
                // SAFETY: fstatfs returned 0, so it initialized `stat`.
                && unsafe { stat.assume_init() }.f_type == 0x62656572,
            "actual DM control kernel sysfs required",
        )?;
        let control_device = sys_device(&sys)?;
        let parent = files::directory(Path::new("/dev/mapper"), Some(0))?;
        let file = files::open_relative(&parent, Path::new("control"))?;
        let metadata = file.metadata()?;
        require(
            metadata.mode() & libc::S_IFMT == libc::S_IFCHR
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.rdev() == control_device,
            "protected actual kernel DM control node required",
        )?;
        let mut version = Header::empty();
        require(
            // SAFETY: The request is a complete 312-byte repr(C) dm_ioctl header that the kernel
            // updates in place, and the control file stays open.
            unsafe { libc::ioctl(file.as_raw_fd(), VERSION, &mut version) } == 0
                && version.version[0] == 4,
            "native DM control version unavailable",
        )?;
        let mapping = verified.mapping()?;
        let (mapper, _) = mapping.original_mapper_node()?;
        let mapper_metadata = mapper.metadata()?;
        let name = OriginalName::observe(mapping.original_mapper_node()?.1)?;
        let device = encoded(
            libc::major(mapper_metadata.rdev()),
            libc::minor(mapper_metadata.rdev()),
        )?;
        let mut status = Header::by_device(device);
        require(
            // SAFETY: The request is a complete 312-byte repr(C) dm_ioctl header that the kernel
            // updates in place, and the control file stays open.
            unsafe { libc::ioctl(file.as_raw_fd(), libc::c_ulong::from(STATUS), &mut status) } == 0,
            "actual created mapper DM status unavailable",
        )?;
        let uuid = string(&status.uuid)?.to_owned();
        let compact = verified.original_luks_uuid()?.replace('-', "");
        require(
            [
                format!("CRYPT-LUKS1-{compact}-{MAPPER}"),
                format!("CRYPT-LUKS2-{compact}-{MAPPER}"),
            ]
            .contains(&uuid),
            "actual DM UUID does not identify original LUKS source/fixed mapper",
        )?;
        status_valid(&status, device, &uuid)?;
        let result = Self {
            scope,
            epoch: files::identity(&metadata),
            flags: flags(&file)?,
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            sys_path: sys_parent.join("dev"),
            sys_epoch: files::identity(&sys.metadata()?),
            sys_flags: flags(&sys)?,
            sys_mount: mount_identity::id(sys.as_fd(), true)?,
            sys,
            control_device,
            generation: mapping.original_generation()?.to_owned(),
            mapper_epoch: files::identity(&mapper_metadata),
            device,
            uuid,
            name,
        };
        result.require_original_mapping(mapping)?;
        Ok(result)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub(crate) fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        self.name.recheck()?;
        self.recheck_descriptions()?;
        require(
            !self.name.retired,
            "original mapper already removed; no active-status replay",
        )?;
        let mut status = Header::by_device(self.device);
        require(
            // SAFETY: The request is a complete 312-byte repr(C) dm_ioctl header that the kernel
            // updates in place, and the control file stays open.
            unsafe {
                libc::ioctl(
                    self.file.as_raw_fd(),
                    libc::c_ulong::from(STATUS),
                    &mut status,
                )
            } == 0,
            "original mapper DM status unavailable",
        )?;
        status_valid(&status, self.device, &self.uuid)?;
        self.scope.recheck()
    }
    fn recheck_descriptions(&self) -> Result<()> {
        self.scope.recheck()?;
        let parent = files::directory(Path::new("/dev/mapper"), Some(0))?;
        let named = files::open_relative(&parent, Path::new("control"))?;
        let sys_parent = files::directory(
            self.sys_path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let sys = files::open_relative(&sys_parent, Path::new("dev"))?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&self.file)? == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && self.file.metadata()?.rdev() == self.control_device
                && files::identity(&self.sys.metadata()?) == self.sys_epoch
                && files::identity(&sys.metadata()?) == self.sys_epoch
                && flags(&self.sys)? == self.sys_flags
                && mount_identity::id(self.sys.as_fd(), true)? == self.sys_mount
                && mount_identity::id(sys.as_fd(), true)? == self.sys_mount
                && sys_device(&self.sys)? == self.control_device
                && sys_device(&sys)? == self.control_device,
            "original DM control/sysfs descriptions replaced or covered",
        )?;
        self.scope.recheck()
    }
    pub(crate) fn require_original_mapping(&self, mapping: &CreatedMapping<'_>) -> Result<()> {
        mapping.recheck()?;
        require(
            std::ptr::eq(self.scope, mapping.original_scope()?)
                && self.generation == mapping.original_generation()?
                && files::identity(&mapping.original_mapper_node()?.0.metadata()?)
                    == self.mapper_epoch,
            "actual DM control/status belongs to another created mapping",
        )?;
        self.recheck()
    }
    pub(crate) fn descriptor(&self) -> Result<i32> {
        self.recheck()?;
        Ok(self.file.as_raw_fd())
    }
    pub(crate) fn prepare_close(
        self,
        unmounted: ReleasedMount<'s>,
        mapping: &CreatedMapping<'_>,
    ) -> Result<CloseReady<'s>> {
        self.require_original_mapping(mapping)?;
        unmounted.require_original_mapping(mapping)?;
        let result = CloseReady {
            control: self,
            unmounted,
        };
        result.recheck()?;
        Ok(result)
    }
}
impl<'s> CloseReady<'s> {
    /// Close only the actual original mapper FD after the actual normal unmount.
    /// Kernel mapping and fixed name remain for a separate consuming removal.
    pub(crate) fn close_description<'m>(
        self,
        mapping: CreatedMapping<'m>,
    ) -> Result<DescriptionClosed<'s, 'm>> {
        self.control.require_original_mapping(&mapping)?;
        self.unmounted.require_original_mapping(&mapping)?;
        let closed = mapping.close_description(&self.unmounted)?;
        let result = DescriptionClosed {
            original: self,
            closed,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.unmounted.recheck()?;
        self.control.recheck()
    }
    /// JSON evidence of this step; it grants no further mutation.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"original_dm_control_and_mapper_status_verified":true,"actual_owned_unmount_released":true,"mapping_closed":false,"execution_authorized":false}),
        )
    }
}
fn by_uuid(uuid: &str) -> Result<Header> {
    require(
        !uuid.is_empty()
            && uuid.len() < 129
            && uuid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "exact original DM UUID selector required",
    )?;
    let mut result = Header::empty();
    result.uuid[..uuid.len()].copy_from_slice(uuid.as_bytes());
    Ok(result)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn kernel_absent(control: &Original<'_>) -> Result<()> {
    control.recheck_descriptions()?;
    let mut name = Header::empty();
    name.name[..MAPPER.len()].copy_from_slice(MAPPER.as_bytes());
    for mut status in [
        Header::by_device(control.device),
        by_uuid(&control.uuid)?,
        name,
    ] {
        // SAFETY: The request is a complete 312-byte repr(C) dm_ioctl header that the kernel
        // updates in place, and the control file stays open.
        let result = unsafe {
            libc::ioctl(
                control.file.as_raw_fd(),
                libc::c_ulong::from(STATUS),
                &mut status,
            )
        };
        let error = std::io::Error::last_os_error();
        require(
            result == -1 && error.raw_os_error() == Some(libc::ENXIO),
            "actual removed mapper still resolves in kernel or status uncertain",
        )?;
    }
    control.recheck_descriptions()
}
impl<'s, 'm> DescriptionClosed<'s, 'm> {
    /// One nondeferred removal of the actual closed original mapper. Errors are
    /// terminal and leave artifacts for review; this method never retries.
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub(crate) fn remove(self) -> Result<Removed<'s, 'm>> {
        self.recheck()?;
        let DescriptionClosed { original, closed } = self;
        let CloseReady {
            mut control,
            unmounted,
        } = original;
        let mut request = by_uuid(&control.uuid)?;
        require(
            // SAFETY: The request is a complete 312-byte repr(C) dm_ioctl header that the kernel
            // updates in place, and the control file stays open.
            unsafe {
                libc::ioctl(
                    control.file.as_raw_fd(),
                    libc::c_ulong::from(REMOVE),
                    &mut request,
                )
            } == 0,
            "actual original DM removal uncertain; no deferred removal or retry",
        )?;
        kernel_absent(&control)?;
        control.name.recheck()?;
        let proof = RemovalSucceeded {
            scope: control.scope,
            mapper_epoch: control.mapper_epoch,
        };
        let source = closed.after_remove(&proof)?;
        control.name = control.name.retire()?;
        let result = Removed {
            control,
            unmounted,
            source,
        };
        result.recheck()?;
        Ok(result)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub(crate) fn recheck(&self) -> Result<()> {
        self.closed.recheck()?;
        self.original.recheck()?;
        let control = &self.original.control;
        let mut status = Header::by_device(control.device);
        require(
            // SAFETY: The request is a complete 312-byte repr(C) dm_ioctl header that the kernel
            // updates in place, and the control file stays open.
            unsafe {
                libc::ioctl(
                    control.file.as_raw_fd(),
                    libc::c_ulong::from(STATUS),
                    &mut status,
                )
            } == 0,
            "actual mapper status unavailable after original description close",
        )?;
        status_valid(&status, control.device, &control.uuid)?;
        require(
            status.opens == 0,
            "actual mapper still has open descriptions; no removal",
        )?;
        self.closed.recheck()?;
        self.original.recheck()
    }
    /// JSON evidence of this step; it grants no further mutation.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"original_mapper_description_closed":true,"actual_kernel_mapper_open_count_zero":true,
            "mapping_removed":false,"execution_authorized":false}),
        )
    }
}
impl Removed<'_, '_> {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.source.recheck()?;
        self.unmounted.recheck()?;
        require(
            self.control.name.retired,
            "actual original mapper name not retired",
        )?;
        self.control.name.recheck()?;
        kernel_absent(&self.control)?;
        self.source.recheck()
    }
    /// JSON evidence of this step; it grants no further mutation.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"original_mapper_description_closed":true,"actual_kernel_mapper_removed":true,
            "original_mapper_symlink_retired":true,"original_source_retained":true,"execution_authorized":false}),
        )
    }
}
