// SPDX-License-Identifier: MIT
//! Actual current update coordinator, limited to two installed native images.
use enzimos_platform::{Error, Result, files, json, mount_identity, process_identity, require};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
pub(crate) const POLICY: &str = "/usr/lib/enzimos-native/enzimos-policy";
pub(crate) const BACKEND: &str = "/usr/lib/enzimos-backend/enzimos-system-backend";
/// Syntax only. A recognized name is never process or execution authority.
pub(crate) fn image_path(path: &str) -> Result<&'static str> {
    match path {
        POLICY => Ok(POLICY),
        BACKEND => Ok(BACKEND),
        _ => Err(Error("closed native update coordinator image".into())),
    }
}
pub(crate) struct Actor {
    process: process_identity::Retained,
    image: File,
    epoch: files::FileIdentity,
    mount: u64,
    path: &'static str,
    sha: String,
}
impl Actor {
    pub(crate) fn current() -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        require(
            enzimos_platform::process_identity::real_uid() == 0
                && enzimos_platform::process_identity::real_gid() == 0
                && enzimos_platform::process_identity::effective_gid() == 0,
            "native update coordinator Root IDs",
        )?;
        let actual = std::fs::read_link("/proc/self/exe")?;
        let path = image_path(
            actual
                .to_str()
                .ok_or_else(|| Error("actual update executable encoding".into()))?,
        )?;
        let parent = files::directory(
            Path::new(path)
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let image = files::open_relative(
            &parent,
            Path::new(
                Path::new(path)
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let m = image.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o755,
            "protected installed native update coordinator",
        )?;
        let epoch = files::identity(&m);
        let mount = mount_identity::id(image.as_fd(), true)?;
        let bytes = files::read_file(&image, 32 * 1024 * 1024, Some(0), true)?;
        require(
            bytes.starts_with(b"\x7fELF"),
            "native update coordinator ELF",
        )?;
        let pid = std::process::id();
        let stat = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&stat)
                .map_err(|_| Error("update coordinator stat encoding".into()))?,
            pid,
        )?;
        let process = process_identity::Retained::open(pid, stat.start_ticks, 0, &[path.into()])?
            .pin_executable(&image)?;
        let this = Self {
            process,
            image,
            epoch,
            mount,
            path,
            sha: json::sha256(&bytes),
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.process.recheck()?;
        let parent = files::directory(
            Path::new(self.path)
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let named = files::open_relative(
            &parent,
            Path::new(
                Path::new(self.path)
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        require(
            self.process.stat.pid == std::process::id()
                && files::identity(&self.image.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.image.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original current update coordinator changed",
        )
    }
    pub(crate) fn path(&self) -> &'static str {
        self.path
    }
    pub(crate) fn image(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.image)
    }
    pub(crate) fn sha(&self) -> &str {
        &self.sha
    }
    pub(crate) fn process(&self) -> Result<&process_identity::Retained> {
        self.recheck()?;
        Ok(&self.process)
    }
}
