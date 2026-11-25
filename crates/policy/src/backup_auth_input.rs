// SPDX-License-Identifier: MIT
//! Original private tmpfs input for the read-only Restic authentication consumer.
use crate::backup_secret_input::Validated;
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o7777 == 0o700,
        "original private input directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
#[expect(
    clippy::too_many_arguments,
    reason = "Each argument is a distinct retained input of this step."
)]
fn original(
    parent: &File,
    folder: &File,
    name: &str,
    expected: Shape,
    file: &File,
    identity: files::FileIdentity,
    mount: u64,
    owner: u32,
) -> Result<()> {
    let named = files::directory_relative(parent, Path::new(name), Some(owner))?;
    require(
        shape(&named, owner)? == expected
            && shape(folder, owner)? == expected
            && mount_identity::id(named.as_fd(), true)? == mount
            && mount_identity::id(folder.as_fd(), true)? == mount,
        "original authentication folder changed",
    )?;
    crate::backup_publication_identity::recheck(folder, "password", file, identity, mount, owner)
}
pub struct Temporary<'i> {
    input: &'i Validated,
    parent: File,
    parent_shape: Shape,
    folder: File,
    folder_shape: Shape,
    name: String,
    mount: u64,
    file: File,
    identity: files::FileIdentity,
}
impl<'i> Temporary<'i> {
    /// The consumer must have its own durable intent and original caller/mount
    /// proof before this boundary. Failures retain unknown input for inspection.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs, mkdirat, openat).")]
    pub fn create(
        id: &str,
        input: &'i Validated,
        preflight: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::namespaces::initial()?;
        require(
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "authentication input identifier",
        )?;
        input.recheck()?;
        preflight()?;
        let parent = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let parent_shape = shape(&parent, 0)?;
        // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `fs` is a writable `libc::statfs` and `parent` keeps the descriptor open.
            unsafe { libc::fstatfs(parent.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x01021994,
            "authentication input requires original tmpfs",
        )?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        for name in files::directory_names(&parent, 256)? {
            require(
                !name.as_encoded_bytes().starts_with(b"backup-auth-input-"),
                "existing authentication input is an unknown outcome; no adoption",
            )?;
        }
        let name = format!("backup-auth-input-{id}");
        let raw_name = CString::new(name.as_bytes())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        input.recheck()?;
        preflight()?;
        require(
            // SAFETY: `raw_name` is a NUL-terminated C string and `parent` keeps the descriptor
            // open.
            unsafe { libc::mkdirat(parent.as_raw_fd(), raw_name.as_ptr(), 0o700) } == 0,
            "new authentication folder refused",
        )?;
        let folder = files::directory_relative(&parent, Path::new(&name), Some(0))?;
        let folder_shape = shape(&folder, 0)?;
        require(
            mount_identity::id(folder.as_fd(), true)? == mount,
            "authentication folder left original tmpfs",
        )?;
        // SAFETY: The name is a NUL-terminated literal and `folder` keeps the descriptor open.
        let raw = unsafe {
            libc::openat(
                folder.as_raw_fd(),
                c"password".as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(raw >= 0, "new authentication password refused")?;
        // SAFETY: `raw` was just returned by openat and is owned by nothing else.
        let output = unsafe { File::from_raw_fd(raw) };
        let created = files::identity(&output.metadata()?);
        let named_folder = files::directory_relative(&parent, Path::new(&name), Some(0))?;
        require(
            shape(&named_folder, 0)? == folder_shape
                && shape(&folder, 0)? == folder_shape
                && mount_identity::id(output.as_fd(), true)? == mount,
            "original empty authentication output changed",
        )?;
        input.recheck()?;
        preflight()?;
        input.copy_into_new(&output)?;
        let file = files::open_relative(&folder, Path::new("password"))?;
        let identity = files::identity(&output.metadata()?);
        require(
            identity.0 == created.0
                && identity.1 == created.1
                && identity.2 == input.length()? as u64
                && files::identity(&file.metadata()?) == identity,
            "original copied authentication input changed",
        )?;
        drop(output);
        let this = Self {
            input,
            parent,
            parent_shape,
            folder,
            folder_shape,
            name,
            mount,
            file,
            identity,
        };
        this.recheck()?;
        preflight()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.input.recheck()?;
        let parent = files::directory(Path::new("/run/enzimos"), Some(0))?;
        require(
            shape(&parent, 0)? == self.parent_shape
                && shape(&self.parent, 0)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount,
            "original input tmpfs parent changed",
        )?;
        original(
            &self.parent,
            &self.folder,
            &self.name,
            self.folder_shape,
            &self.file,
            self.identity,
            self.mount,
            0,
        )
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"name":self.name,"parent":self.parent_shape,
            "directory":self.folder_shape,"mount":self.mount,"identity":self.identity}),
        )
    }
    pub(crate) fn input_binding(&self) -> Result<(serde_json::Value, serde_json::Value)> {
        self.recheck()?;
        let file = File::from(self.input.descriptor()?.try_clone_to_owned()?);
        Ok((
            serde_json::to_value(files::identity(&file.metadata()?))?,
            self.input.reader_evidence()?,
        ))
    }
    /// Explicitly retire this known original input after the owned consumer and
    /// all its descendants have exited. Drop never guesses that execution ended.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fsync, unlinkat).")]
    pub fn retire(
        self,
        closed: &enzimos_platform::backup_worker_scope::Closed,
    ) -> Result<Retired<'i>> {
        require(
            self.name
                == format!(
                    "backup-auth-input-{}",
                    enzimos_platform::json::string(&closed.binding()?["id"])?
                ),
            "temporary retirement belongs to another original worker",
        )?;
        self.recheck()?;
        let evidence = self.evidence()?;
        closed.recheck()?;
        require(
            // SAFETY: The name is a NUL-terminated literal and `self.folder` keeps the descriptor
            // open.
            unsafe { libc::unlinkat(self.folder.as_raw_fd(), c"password".as_ptr(), 0) } == 0,
            "authentication input retirement unknown",
        )?;
        require(
            self.file.metadata()?.nlink() == 0
                && files::optional_relative(&self.folder, Path::new("password"))?.is_none(),
            "authentication input still named",
        )?;
        let named = files::directory_relative(&self.parent, Path::new(&self.name), Some(0))?;
        require(
            shape(&named, 0)? == self.folder_shape
                && shape(&self.folder, 0)? == self.folder_shape
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "authentication folder changed before retirement",
        )?;
        let name = CString::new(self.name.as_bytes())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        closed.recheck()?;
        require(
            // SAFETY: `name` is a NUL-terminated C string and `self.parent` keeps the descriptor
            // open.
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                == 0
                // SAFETY: fsync takes no pointers and `self.parent` keeps the descriptor open.
                && unsafe { libc::fsync(self.parent.as_raw_fd()) } == 0,
            "authentication folder retirement unknown",
        )?;
        closed.recheck()?;
        let identity = files::identity(&self.file.metadata()?);
        require(
            (
                self.identity.0,
                self.identity.1,
                self.identity.2,
                self.identity.3,
                self.identity.4,
                self.identity.7,
                self.identity.8,
                self.identity.9,
            ) == (
                identity.0, identity.1, identity.2, identity.3, identity.4, identity.7, identity.8,
                identity.9,
            ) && identity.10 == 0,
            "original temporary changed beyond known unlink transition",
        )?;
        let retired = Retired {
            input: self.input,
            parent: self.parent,
            parent_shape: self.parent_shape,
            folder: self.folder,
            folder_shape: self.folder_shape,
            name: self.name,
            mount: self.mount,
            file: self.file,
            identity,
            evidence,
        };
        retired.recheck()?;
        Ok(retired)
    }
}
/// Known original names retired after a kernel-backed whole-worker closure.
pub struct Retired<'i> {
    input: &'i Validated,
    parent: File,
    parent_shape: Shape,
    folder: File,
    folder_shape: Shape,
    name: String,
    mount: u64,
    file: File,
    identity: files::FileIdentity,
    evidence: serde_json::Value,
}
impl Retired<'_> {
    pub fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.input.recheck()?;
        let named = files::directory(Path::new("/run/enzimos"), Some(0))?;
        require(
            shape(&named, 0)? == self.parent_shape
                && shape(&self.parent, 0)? == self.parent_shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && shape(&self.folder, 0)? == self.folder_shape
                && self.folder.metadata()?.nlink() == 0
                && files::identity(&self.file.metadata()?) == self.identity
                && self.identity.10 == 0
                && files::optional_directory_relative(
                    &self.parent,
                    Path::new(&self.name),
                    Some(0),
                )?
                .is_none(),
            "retired original temporary changed or name reused",
        )
    }
    pub(crate) fn evidence(&self) -> Result<&serde_json::Value> {
        self.recheck()?;
        Ok(&self.evidence)
    }
}
// No Drop removal, plaintext reads or password hashing.
/// Read-only validation of the original caller-owned temporary received by SCM.
/// This does not acquire cleanup authority or recreate a typed Temporary.
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub(crate) fn borrowed(v: &serde_json::Value, id: &str, length: u64, file: &File) -> Result<()> {
    crate::namespaces::initial()?;
    crate::backup_worker_request::consumer(v, id, length)?;
    let parent = files::directory(Path::new("/run/enzimos"), Some(0))?;
    let name = enzimos_platform::json::string(&v["name"])?;
    let folder = files::directory_relative(&parent, Path::new(name), Some(0))?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        // SAFETY: `fs` is a writable `libc::statfs` and `parent` keeps the descriptor open.
        unsafe { libc::fstatfs(parent.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == 0x01021994
            && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_RDONLY
            && serde_json::to_value(shape(&parent, 0)?)? == v["parent"]
            && serde_json::to_value(shape(&folder, 0)?)? == v["directory"],
        "borrowed temporary parent/folder/read-only authority changed",
    )?;
    let mount = enzimos_platform::json::unsigned(&v["mount"])?;
    require(
        mount_identity::id(parent.as_fd(), true)? == mount
            && mount_identity::id(folder.as_fd(), true)? == mount
            && serde_json::to_value(files::identity(&file.metadata()?))? == v["identity"],
        "borrowed original temporary mount/inode changed",
    )?;
    original(
        &parent,
        &folder,
        name,
        shape(&folder, 0)?,
        file,
        files::identity(&file.metadata()?),
        mount,
        0,
    )?;
    let final_parent = files::directory(Path::new("/run/enzimos"), Some(0))?;
    require(
        serde_json::to_value(shape(&final_parent, 0)?)? == v["parent"]
            && mount_identity::id(final_parent.as_fd(), true)? == mount
            && serde_json::to_value(files::identity(&file.metadata()?))? == v["identity"],
        "borrowed temporary changed during observation",
    )
}
