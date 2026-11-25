// SPDX-License-Identifier: MIT
//! Independent mounts are unwound normally, in reverse order, with no lazy detach.
use crate::{recovery_bootstrap, storage_runtime};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    path::{Path, PathBuf},
};
struct Mounted {
    path: PathBuf,
    file: Option<File>,
    unique: u64,
    normal: u64,
}
#[derive(Default)]
pub(crate) struct Mounts {
    mounts: Vec<Mounted>,
    uncertain: Option<PathBuf>,
}
impl Mounts {
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn attach(
        &mut self,
        source: BorrowedFd<'_>,
        target: &Path,
        kind: Option<&str>,
        data: Option<&str>,
    ) -> Result<()> {
        recovery_bootstrap::quiet()?;
        require(self.mounts.len() < 8, "independent mount count bound")?;
        let directory =
            files::ensure_directory(target, if kind == Some("vfat") { 0o755 } else { 0o700 }, 0)?;
        require(
            std::fs::read_dir(target)?.next().is_none()
                && !storage_runtime::rows()?
                    .iter()
                    .any(|r| r.target == target.to_str().unwrap()),
            "independent mount target must be empty and unmounted",
        )?;
        let source = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd())).unwrap();
        let named = CString::new(target.as_os_str().as_encoded_bytes())
            .map_err(|_| Error("mount target path".into()))?;
        let filesystem = kind.map(|s| CString::new(s).unwrap());
        let options = data.map(|s| CString::new(s).unwrap());
        let flags = if kind.is_some() {
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC
        } else {
            libc::MS_BIND
        };
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                named.as_ptr(),
                filesystem.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                flags,
                options
                    .as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
            )
        };
        require(result == 0, "independent mount failed")?;
        self.uncertain = Some(target.into());
        drop(directory);
        // Record the mount before further checks so failure cannot forget cleanup.
        let file = files::directory(target, Some(0))?;
        let unique = mount_identity::id(file.as_fd(), true)?;
        let normal = mount_identity::id(file.as_fd(), false)?;
        self.mounts.push(Mounted {
            path: target.into(),
            file: Some(file),
            unique,
            normal,
        });
        self.uncertain = None;
        self.recheck()
    }
    /// Match the installed ESP's synthesized permissions. FAT cannot chmod
    /// individual receipts; an inherited process umask would make files 0700.
    pub(crate) fn esp(&mut self, source: BorrowedFd<'_>) -> Result<()> {
        self.attach(
            source,
            Path::new("/boot"),
            Some("vfat"),
            Some("rw,uid=0,gid=0,fmask=0177,dmask=0077"),
        )
    }
    pub(crate) fn filesystem(
        &mut self,
        source: BorrowedFd<'_>,
        target: &Path,
        kind: &str,
        data: &str,
    ) -> Result<()> {
        require(kind == "btrfs", "fixed recovery filesystem required")?;
        self.attach(source, target, Some(kind), Some(data))
    }
    pub(crate) fn bind(&mut self, source: &File, target: &Path) -> Result<()> {
        self.attach(source.as_fd(), target, None, None)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        require(
            self.uncertain.is_none(),
            "independent mount tracking uncertain; retained for review",
        )?;
        recovery_bootstrap::direct_ram_pid1()?;
        crate::namespaces::initial()?;
        let rows = storage_runtime::rows()?;
        for mount in &self.mounts {
            let current = files::directory(&mount.path, Some(0))?;
            require(
                mount_identity::id(current.as_fd(), true)? == mount.unique
                    && mount_identity::id(mount.file.as_ref().unwrap().as_fd(), true)?
                        == mount.unique
                    && rows
                        .iter()
                        .filter(|r| r.target == mount.path.to_str().unwrap())
                        .count()
                        == 1
                    && rows
                        .iter()
                        .any(|r| r.target == mount.path.to_str().unwrap() && r.id == mount.normal),
                "independent owned mount replaced or shadowed",
            )?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    pub(crate) fn close(&mut self) -> Result<()> {
        require(
            self.uncertain.is_none(),
            "independent mount tracking uncertain; cleanup refused",
        )?;
        while !self.mounts.is_empty() {
            self.recheck()?;
            let mount = self.mounts.last_mut().unwrap();
            let named = CString::new(mount.path.as_os_str().as_encoded_bytes()).unwrap();
            drop(mount.file.take());
            let result = unsafe { libc::umount2(named.as_ptr(), 0) };
            if result != 0 {
                // Keep tracking a still-mounted target. No force, lazy detach, or
                // cryptsetup close can proceed past a failed normal unmount.
                mount.file = Some(files::directory(&mount.path, Some(0))?);
                return Err(Error(
                    "independent normal unmount failed; mount retained".into(),
                ));
            }
            require(
                !storage_runtime::rows()?
                    .iter()
                    .any(|r| r.target == mount.path.to_str().unwrap()),
                "independent mount cleanup uncertain",
            )?;
            self.mounts.pop();
        }
        Ok(())
    }
}
impl Drop for Mounts {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
