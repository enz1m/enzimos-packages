// SPDX-License-Identifier: MIT
//! A fresh delivery child group belongs only to the current initial-namespace backend unit.
use crate::{namespaces, operation};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const PARENT: &str = "/sys/fs/cgroup/system.slice/enzimos-system-backend.service";
const MEMBERSHIP: &str = "0::/system.slice/enzimos-system-backend.service";
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    let m = file.metadata()?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == 0x63677270,
        "original Root cgroup v2 directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
fn populated(body: &str) -> Result<bool> {
    require(
        body.len() <= 4096 && !body.contains('\0'),
        "delivery cgroup events bound",
    )?;
    let mut values = BTreeMap::new();
    for line in body.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 2
                && fields[0].len() <= 64
                && fields[0]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
                && values.len() < 16,
            "delivery cgroup events shape",
        )?;
        let number = fields[1]
            .parse::<u64>()
            .map_err(|_| Error("delivery cgroup event integer".into()))?;
        require(
            values.insert(fields[0], number).is_none(),
            "duplicate delivery cgroup event",
        )?;
    }
    match values.get("populated") {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(Error("delivery cgroup population unavailable".into())),
    }
}
pub fn membership_value(nonce: &str) -> Result<String> {
    require(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "delivery group nonce required",
    )?;
    Ok(format!("{MEMBERSHIP}/delivery-{nonce}"))
}
pub struct Group {
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32, u64),
    name: String,
    directory: File,
    shape: (u64, u64, u32, u32, u32, u64),
}
impl Group {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, mkdirat).")]
    pub fn create() -> Result<Self> {
        operation::root_only()?;
        namespaces::initial()?;
        let current = files::read_kernel(
            &Path::new("/proc")
                .join(std::process::id().to_string())
                .join("cgroup"),
            4096,
        )?;
        require(
            std::str::from_utf8(&current)
                .map_err(|_| Error("delivery backend cgroup encoding".into()))?
                .trim_end_matches('\n')
                == MEMBERSHIP,
            "delivery supervisor must run in its fixed backend unit",
        )?;
        let parent = files::directory(Path::new(PARENT), Some(0))?;
        let parent_shape = shape(&parent)?;
        let name = format!("delivery-{}", files::random_hex(16)?);
        let c = CString::new(name.as_bytes())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } == 0,
            "fresh delivery cgroup required",
        )?;
        let directory = files::directory_relative(&parent, Path::new(&name), Some(0))?;
        require(
            unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } == 0,
            "private delivery cgroup protection refused",
        )?;
        let this = Self {
            parent,
            parent_shape,
            name,
            shape: shape(&directory)?,
            directory,
        };
        this.recheck()?;
        require(this.empty()?, "new delivery cgroup already populated")?;
        Ok(this)
    }
    pub(crate) fn clone_target(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.directory.as_fd())
    }
    pub fn nonce(&self) -> Result<&str> {
        self.recheck()?;
        let nonce = self
            .name
            .strip_prefix("delivery-")
            .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?;
        membership_value(nonce)?;
        Ok(nonce)
    }
    fn recheck(&self) -> Result<()> {
        namespaces::initial()?;
        require(
            shape(&self.parent)? == self.parent_shape
                && shape(&files::directory(Path::new(PARENT), Some(0))?)? == self.parent_shape
                && shape(&self.directory)? == self.shape
                && shape(&files::directory_relative(
                    &self.parent,
                    Path::new(&self.name),
                    Some(0),
                )?)? == self.shape,
            "original delivery cgroup replaced or covered",
        )
    }
    fn read(&self, name: &str, maximum: usize) -> Result<String> {
        self.recheck()?;
        let file = files::open_relative(&self.directory, Path::new(name))?;
        let m = file.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o022 == 0
                && mount_identity::id(file.as_fd(), true)? == self.shape.5,
            "original delivery cgroup interface changed",
        )?;
        let mut bytes = Vec::new();
        (&file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        require(bytes.len() <= maximum, "delivery cgroup interface bound")?;
        let result = String::from_utf8(bytes)
            .map_err(|_| Error("delivery cgroup interface encoding".into()))?;
        let after = file.metadata()?;
        require(
            (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
                == (
                    after.dev(),
                    after.ino(),
                    after.uid(),
                    after.gid(),
                    after.mode(),
                ),
            "original delivery cgroup interface replaced",
        )?;
        self.recheck()?;
        Ok(result)
    }
    /// Only the owned pre-exec child writes the constant "0\n" to this actual FD.
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub fn membership(&self) -> Result<File> {
        self.recheck()?;
        let c = CString::new("cgroup.procs")
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o022 == 0
                && mount_identity::id(file.as_fd(), true)? == self.shape.5,
            "delivery child membership interface differs",
        )?;
        self.recheck()?;
        Ok(file)
    }
    pub fn contains_only(&self, pid: u32) -> Result<()> {
        require(
            pid > 1 && pid < i32::MAX as u32,
            "actual delivery child PID bound",
        )?;
        let body = self.read("cgroup.procs", 4096)?;
        let rows = body.lines().collect::<Vec<_>>();
        require(
            rows == [pid.to_string().as_str()] && populated(&self.read("cgroup.events", 4096)?)?,
            "delivery cgroup does not contain only the original worker",
        )
    }
    pub fn empty(&self) -> Result<bool> {
        let empty = !populated(&self.read("cgroup.events", 4096)?)?;
        if empty {
            require(
                self.read("cgroup.procs", 4096)?.is_empty(),
                "delivery cgroup member state differs",
            )?;
        }
        self.recheck()?;
        Ok(empty)
    }
    /// No Drop cleanup. Unknown outcomes keep their original directory for review.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub fn retire(self) -> Result<()> {
        self.recheck()?;
        require(self.empty()?, "populated delivery cgroup cannot retire")?;
        let name = CString::new(self.name.as_bytes())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                == 0,
            "empty original delivery cgroup retirement refused",
        )?;
        require(
            files::optional_directory_relative(&self.parent, Path::new(&self.name), Some(0))?
                .is_none(),
            "delivery cgroup name remains after retirement",
        )?;
        require(
            shape(&self.parent)? == self.parent_shape && shape(&self.directory)? == self.shape,
            "original retired delivery cgroup identity changed",
        )
    }
}
