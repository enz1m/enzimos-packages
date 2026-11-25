// SPDX-License-Identifier: MIT
//! Actual independent PID1 kernel-helper settings, never a host operation.
//! Original proc descriptions are retained after the owned empty-string writes.
use crate::root_retirement_offline_scope::Scope;
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};
struct Setting {
    name: &'static str,
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
}
pub struct Disabled<'s> {
    scope: &'s Scope,
    parent: File,
    parent_epoch: files::FileIdentity,
    mount: u64,
    settings: Vec<Setting>,
    hotplug_present: bool,
}
fn contents(file: &File) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 4097];
    let used = file.read_at(&mut bytes, 0)?;
    require(used <= 4096, "actual kernel helper setting bound")?;
    bytes.truncate(used);
    Ok(bytes)
}
fn empty(bytes: &[u8]) -> Result<()> {
    require(
        bytes.is_empty() || bytes == b"\n",
        "actual kernel helper setting is not the empty string",
    )
}
fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "actual kernel helper original read descriptor",
    )?;
    Ok(value)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn protected(file: &File, mount: u64) -> Result<()> {
    let m = file.metadata()?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && mount_identity::id(file.as_fd(), true)? == mount
            && unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } == 0
            && unsafe { stat.assume_init() }.f_type == 0x9fa0,
        "actual initial proc kernel helper control required",
    )
}
impl<'s> Disabled<'s> {
    /// Coldplug is fully reaped before this actual sole PID1 operation. An
    /// uncertain write is not retried or restored by Drop.
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat, write).")]
    pub fn disable(scope: &'s Scope) -> Result<Self> {
        scope.recheck()?;
        let parent =
            files::directory_relative(scope.original_proc()?, Path::new("sys/kernel"), Some(0))?;
        let parent_epoch = files::identity(&parent.metadata()?);
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let mut settings = Vec::new();
        let mut hotplug_present = false;
        for name in ["modprobe", "hotplug"] {
            scope.recheck()?;
            let file = files::optional_relative(&parent, Path::new(name))?;
            let Some(file) = file else {
                require(
                    name == "hotplug",
                    "required original modprobe setting absent",
                )?;
                continue;
            };
            if name == "hotplug" {
                hotplug_present = true;
            }
            protected(&file, mount)?;
            let before = files::identity(&file.metadata()?);
            let _original = contents(&file)?;
            let literal = CString::new(name)
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    literal.as_ptr(),
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            require(raw >= 0, "original kernel helper writer unavailable")?;
            let writer = unsafe { File::from_raw_fd(raw) };
            protected(&writer, mount)?;
            require(
                files::identity(&writer.metadata()?) == before
                    && files::identity(&file.metadata()?) == before,
                "kernel helper control changed before owned write",
            )?;
            require(
                unsafe { libc::write(raw, b"\n".as_ptr().cast(), 1) } == 1,
                "kernel helper disable write uncertain; review required",
            )?;
            empty(&contents(&file)?)?;
            let epoch = files::identity(&file.metadata()?);
            require(
                (before.0, before.1, before.7, before.8, before.9, before.10)
                    == (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9, epoch.10)
                    && files::identity(&writer.metadata()?) == epoch,
                "owned kernel helper write changed its original identity",
            )?;
            drop(writer);
            settings.push(Setting {
                name,
                flags: flags(&file)?,
                file,
                epoch,
            });
            scope.recheck()?;
        }
        let result = Self {
            scope,
            parent,
            parent_epoch,
            mount,
            settings,
            hotplug_present,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_original_scope(&self, scope: &Scope) -> Result<()> {
        require(
            std::ptr::eq(self.scope, scope),
            "kernel helper actor belongs to another original scope",
        )?;
        self.recheck()
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        let named = files::directory_relative(
            self.scope.original_proc()?,
            Path::new("sys/kernel"),
            Some(0),
        )?;
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch
                && files::identity(&named.metadata()?) == self.parent_epoch
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "actual original kernel helper parent changed or was covered",
        )?;
        require(
            files::optional_relative(&self.parent, Path::new("hotplug"))?.is_some()
                == self.hotplug_present,
            "original optional hotplug control changed presence",
        )?;
        for setting in &self.settings {
            let named = files::open_relative(&self.parent, Path::new(setting.name))?;
            protected(&named, self.mount)?;
            protected(&setting.file, self.mount)?;
            require(
                files::identity(&named.metadata()?) == setting.epoch
                    && files::identity(&setting.file.metadata()?) == setting.epoch
                    && flags(&setting.file)? == setting.flags,
                "actual disabled kernel helper setting changed description",
            )?;
            empty(&contents(&named)?)?;
            empty(&contents(&setting.file)?)?;
        }
        self.scope.recheck()
    }
}
