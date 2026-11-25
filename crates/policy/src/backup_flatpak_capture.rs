// SPDX-License-Identifier: MIT
//! Original OFD locks coordinate qualified system Flatpak writers only.
use crate::{backup_attempt::Attempt, namespaces, operation, settings_command::Command};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && (owner != 0 || m.gid() == 0) && m.mode() & 0o022 == 0,
        "protected Flatpak capture directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
fn version(bytes: &[u8]) -> Result<String> {
    require(
        matches!(bytes, b"flatpak 1:1.18.2-1\n" | b"flatpak 1:1.18.3-1\n"),
        "unqualified Flatpak capture protocol version",
    )?;
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| Error("Flatpak version encoding".into()))?
        .trim_end_matches('\n')
        .trim_start_matches("flatpak ")
        .into())
}
struct HeldLock {
    file: File,
    epoch: files::FileIdentity,
    mount: u64,
    name: &'static std::ffi::CStr,
}
impl HeldLock {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, openat).")]
    fn acquire(parent: &File, name: &'static std::ffi::CStr, owner: u32) -> Result<Self> {
        require(
            std::mem::size_of::<libc::flock>() == 32,
            "qualified x86-64 OFD ABI required",
        )?;
        // SAFETY: The name is NUL-terminated and `parent` keeps the descriptor open.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: `raw` was just returned by openat and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(raw) };
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == owner
                && m.gid() == parent.metadata()?.gid()
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && m.len() <= 4096,
            "protected original Flatpak lock required",
        )?;
        // SAFETY: `libc::flock` is a plain C struct, for which all-zero bytes are a valid value.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        require(
            // SAFETY: `lock` is a complete flock struct that outlives the call, and `file` stays
            // open.
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) } == 0,
            "Flatpak capture lock busy or refused; no stale lock removal",
        )?;
        let this = Self {
            epoch: files::identity(&m),
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            name,
        };
        require(
            this.mount == mount_identity::id(parent.as_fd(), true)?,
            "Flatpak lock left original installation mount",
        )?;
        this.recheck(parent)?;
        Ok(this)
    }
    fn recheck(&self, parent: &File) -> Result<()> {
        let named = files::open_relative(
            parent,
            Path::new(
                self.name
                    .to_str()
                    .map_err(|_| enzimos_platform::Error("path encoding".into()))?,
            ),
        )?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original Flatpak capture lock changed or covered",
        )
    }
}
struct Present {
    system: File,
    system_shape: Shape,
    repository: File,
    repository_shape: Shape,
    locks: Vec<HeldLock>,
    vendor: Command,
    version: String,
}
/// Borrowed running attempt and operation lock outlive both original OFD locks.
/// Drop only closes descriptors; it never removes lock files or repairs contention.
pub(crate) struct Capture<'a, 'g> {
    attempt: &'a Attempt<'g>,
    operation: &'a files::Lock,
    parent: File,
    parent_shape: Shape,
    system: Option<(File, Shape)>,
    present: Option<Present>,
}
impl<'a, 'g> Capture<'a, 'g> {
    pub(crate) fn acquire(
        attempt: &'a Attempt<'g>,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        namespaces::initial()?;
        authorize()?;
        attempt.evidence()?;
        attempt.require_lock(lock)?;
        lock.recheck()?;
        let parent = files::directory(Path::new("/var/lib"), Some(0))?;
        let parent_shape = shape(&parent, 0)?;
        let system = files::optional_directory_relative(&parent, Path::new("flatpak"), Some(0))?
            .map(|f| shape(&f, 0).map(|s| (f, s)))
            .transpose()?;
        let repository = system
            .as_ref()
            .map(|(s, _)| files::optional_directory_relative(s, Path::new("repo"), Some(0)))
            .transpose()?
            .flatten();
        let present = if let Some(repository) = repository {
            let repository_shape = shape(&repository, 0)?;
            let system_file = system
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                .0
                .try_clone()?;
            let system_shape = shape(&system_file, 0)?;
            let vendor = Command::open("/usr/bin/pacman")?;
            // pacman -Q prints one short line; 4 KiB leaves room for a warning.
            let qualified = version(&vendor.run(&["-Q", "flatpak"], &[0], 4096)?)?;
            let mut locks = Vec::new();
            for name in [c"lock", c"repo-lock"] {
                authorize()?;
                attempt.evidence()?;
                lock.recheck()?;
                require(
                    shape(&system_file, 0)? == system_shape,
                    "Flatpak installation changed before lock entry",
                )?;
                let named = files::directory_relative(&parent, Path::new("flatpak"), Some(0))?;
                require(
                    shape(&named, 0)? == system_shape,
                    "Flatpak installation replaced before lock entry",
                )?;
                locks.push(HeldLock::acquire(&system_file, name, 0)?);
            }
            Some(Present {
                system: system_file,
                system_shape,
                repository,
                repository_shape,
                locks,
                vendor,
                version: qualified,
            })
        } else {
            None
        };
        let this = Self {
            attempt,
            operation: lock,
            parent,
            parent_shape,
            system,
            present,
        };
        this.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn require_original(&self, attempt: &Attempt<'_>, lock: &files::Lock) -> Result<()> {
        require(
            self.attempt.same_actor(attempt) && std::ptr::eq(self.operation, lock),
            "Flatpak barrier requires its original running attempt and operation lock",
        )?;
        self.recheck()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        namespaces::initial()?;
        self.attempt.evidence()?;
        self.operation.recheck()?;
        let named = files::directory(Path::new("/var/lib"), Some(0))?;
        require(
            shape(&self.parent, 0)? == self.parent_shape && shape(&named, 0)? == self.parent_shape,
            "original Flatpak parent changed or covered",
        )?;
        let current =
            files::optional_directory_relative(&self.parent, Path::new("flatpak"), Some(0))?;
        match (&self.system, current) {
            (None, None) => {}
            (Some((held, epoch)), Some(named)) => {
                require(
                    shape(held, 0)? == *epoch && shape(&named, 0)? == *epoch,
                    "original Flatpak installation replaced",
                )?;
            }
            _ => return Err(Error("Flatpak installation presence changed".into())),
        }
        if let Some(p) = &self.present {
            let named = files::directory_relative(&p.system, Path::new("repo"), Some(0))?;
            require(
                shape(&p.system, 0)? == p.system_shape
                    && shape(&p.repository, 0)? == p.repository_shape
                    && shape(&named, 0)? == p.repository_shape,
                "original Flatpak repository replaced or covered",
            )?;
            p.vendor.recheck()?;
            for lock in &p.locks {
                lock.recheck(&p.system)?;
            }
        } else if let Some((system, _)) = &self.system {
            require(
                files::optional_directory_relative(system, Path::new("repo"), Some(0))?.is_none(),
                "Flatpak repository appeared during absent capture",
            )?;
        }
        Ok(())
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(if let Some(p) = &self.present {
            json!({"system_installation_present":true,"version":p.version,"locks":["installation-OFD-exclusive","repository-OFD-exclusive"],"scope":"cooperating system Flatpak deployment/pull/prune only; not user installations, app state or raw OSTree writers","system":p.system_shape,"repository":p.repository_shape,"lock_epochs":p.locks.iter().map(|lock|json!({"file":lock.epoch,"mount":lock.mount})).collect::<Vec<_>>()})
        } else {
            json!({"system_installation_present":false,"scope":"no system repo observed; not user installation or app consistency"})
        })
    }
    pub(crate) fn close(self) -> Result<()> {
        self.recheck()
    }
}
