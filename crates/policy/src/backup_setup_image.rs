// SPDX-License-Identifier: MIT
//! A setup plan identifies the actual installed native backend currently running.
use enzimos_platform::{
    Error, Result, files, mount_identity, process_identity, require, stream_copy,
};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const IMAGE: &str = "/usr/lib/enzimos-backend/enzimos-system-backend";
pub(crate) struct Image {
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32),
    mount: u64,
    file: File,
    identity: files::FileIdentity,
    process: process_identity::Retained,
    sha: String,
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected installed setup image parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Image {
    pub(crate) fn descriptors(&self) -> Result<(&File, std::os::fd::BorrowedFd<'_>)> {
        self.recheck()?;
        Ok((&self.file, self.process.pidfd()))
    }
    pub(crate) fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        crate::operation::root_only()?;
        let parent = files::directory(Path::new(IMAGE).parent().unwrap(), Some(0))?;
        let file = files::open_relative(&parent, Path::new("enzimos-system-backend"))?;
        let m = file.metadata()?;
        require(
            m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o755 && m.nlink() == 1,
            "installed native setup image required",
        )?;
        let (_, sha) = stream_copy::hash_borrowed(&file, 128 * 1024 * 1024, Some(0))?;
        let pid = std::process::id();
        let body = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&body).map_err(|_| Error("setup process encoding".into()))?,
            pid,
        )?;
        let process =
            process_identity::Retained::open(pid, stat.start_ticks, 0, &[PathBuf::from(IMAGE)])?
                .pin_executable(&file)?;
        let this = Self {
            parent_shape: shape(&parent)?,
            mount: mount_identity::id(parent.as_fd(), true)?,
            parent,
            identity: files::identity(&m),
            file,
            process,
            sha,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.process.recheck()?;
        let parent = files::directory(Path::new(IMAGE).parent().unwrap(), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new("enzimos-system-backend"))?;
        require(
            shape(&parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity,
            "original installed setup image replaced",
        )
    }
    pub(crate) fn sha(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.sha)
    }
    pub(crate) fn actor(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"pid":self.process.stat.pid,"start_ticks":self.process.stat.start_ticks,
            "executable_sha256":self.sha}),
        )
    }
}
