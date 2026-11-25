// SPDX-License-Identifier: MIT
//! Original native backend caller retained for a future readonly data handoff.
//! This observes actual kernel process/image objects, never a decoded caller PID.
use enzimos_platform::{
    Error, Result, files, mount_identity, process_identity, require, stream_copy,
};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const IMAGE: &str = "/usr/lib/enzimos-backend/enzimos-system-backend";
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(parent: &File) -> Result<Shape> {
    let m = parent.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7022 == 0,
        "original protected backend image parent required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(parent.as_fd(), true)?,
    ))
}
pub struct Caller {
    process: process_identity::Retained,
    image: File,
    image_epoch: files::FileIdentity,
    parent: File,
    parent_shape: Shape,
    sha256: String,
}
impl Caller {
    /// Only the actual current backend image can originate this actor. There is
    /// no caller-selected executable or PID parameter and no metadata constructor.
    pub fn current() -> Result<Self> {
        Self::current_role(false)
    }
    /// Separate exact Root administrative entry; no arbitrary argv or image.
    pub fn metadata_migration_current() -> Result<Self> {
        Self::current_role(true)
    }
    fn current_role(metadata_migration: bool) -> Result<Self> {
        crate::operation::root_only()?;
        require(
            enzimos_platform::process_identity::real_uid() == 0
                && enzimos_platform::process_identity::real_gid() == 0
                && enzimos_platform::process_identity::effective_gid() == 0,
            "original native backend Root IDs required",
        )?;
        crate::namespaces::initial()?;
        let parent = files::directory(Path::new(IMAGE).parent().unwrap(), Some(0))?;
        let parent_shape = shape(&parent)?;
        let image = files::open_relative(&parent, Path::new("enzimos-system-backend"))?;
        let m = image.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o755,
            "original native backend ELF protection required",
        )?;
        let image_epoch = files::identity(&m);
        let bytes = files::read_file(&image, 32 * 1024 * 1024, Some(0), true)?;
        require(
            bytes.starts_with(b"\x7fELF"),
            "original native backend ELF required",
        )?;
        let sha256 = enzimos_platform::json::sha256(&bytes);
        let pid = std::process::id();
        let body = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&body).map_err(|_| Error("actual backend stat encoding".into()))?,
            pid,
        )?;
        let arguments = if metadata_migration {
            vec![IMAGE.into(), "--remote-rotation-migrate".into()]
        } else {
            vec![IMAGE.into()]
        };
        let process = process_identity::Retained::open(pid, stat.start_ticks, 0, &arguments)?
            .pin_executable(&image)?;
        let this = Self {
            process,
            image,
            image_epoch,
            parent,
            parent_shape,
            sha256,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.process.recheck()?;
        let named_parent = files::directory(Path::new(IMAGE).parent().unwrap(), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new("enzimos-system-backend"))?;
        require(
            self.process.stat.pid == std::process::id()
                && shape(&self.parent)? == self.parent_shape
                && shape(&named_parent)? == self.parent_shape
                && files::identity(&self.image.metadata()?) == self.image_epoch
                && files::identity(&named.metadata()?) == self.image_epoch
                && mount_identity::id(self.image.as_fd(), true)? == self.parent_shape.5
                && mount_identity::id(named.as_fd(), true)? == self.parent_shape.5,
            "original current backend caller or installed image changed",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"pid":self.process.stat.pid,"start_ticks":self.process.stat.start_ticks,
            "uid":0,"executable":IMAGE,"executable_sha256":self.sha256,"image_epoch":self.image_epoch}),
        )
    }
    pub fn image(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.image)
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.process.pidfd())
    }
    /// Every borrowed description must still be this actual producer's OFD.
    pub fn require_description(&self, file: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.recheck()?;
        self.process.require_description(file, number)
    }
    /// Full image readback is reserved for the handoff boundary; regular liveness
    /// checks retain exact metadata epochs and the kernel-pinned executable.
    pub fn verify_image_bytes(&self) -> Result<()> {
        self.recheck()?;
        require(
            stream_copy::hash_borrowed(&self.image, 32 * 1024 * 1024, Some(0))?.1 == self.sha256,
            "original backend image bytes changed",
        )?;
        self.recheck()
    }
}
