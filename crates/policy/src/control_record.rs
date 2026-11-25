// SPDX-License-Identifier: MIT
//! Private journal reads remain on the held control mount and retain file identity.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};
pub(crate) struct Retained {
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32),
    name: PathBuf,
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    limit: usize,
    owner: u32,
    bytes: Vec<u8>,
    value: Value,
}
/// The actual original inode retired by one successful owned publication.
/// Its new unlink epoch is never reconstructed from a named or serialized row.
pub(crate) struct Predecessor {
    file: File,
    before_identity: files::FileIdentity,
    identity: files::FileIdentity,
    flags: i32,
    mount: u64,
    owner: u32,
    limit: usize,
    bytes: Vec<u8>,
}
impl Predecessor {
    pub(crate) fn require_original_observation(&self, original: &Observation) -> Result<()> {
        self.require_original_retained(&original.original)
    }
    pub(crate) fn require_original_retained(&self, old: &Retained) -> Result<()> {
        self.recheck()?;
        require(
            old.identity == self.before_identity
                && old.mount == self.mount
                && old.owner == self.owner
                && old.bytes == self.bytes
                && files::identity(&old.file.metadata()?) == self.identity
                && enzimos_platform::files::status_flags(&old.file) == self.flags
                && mount_identity::id(old.file.as_fd(), true)? == self.mount
                && files::read_file(&old.file, old.limit, Some(old.owner), false)? == self.bytes
                && files::identity(&old.file.metadata()?) == self.identity,
            "owned predecessor does not belong to original observed receipt",
        )?;
        self.recheck()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        require(
            files::identity(&self.file.metadata()?) == self.identity
                && enzimos_platform::files::status_flags(&self.file) == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && files::read_file(&self.file, self.limit, Some(self.owner), false)? == self.bytes
                && files::identity(&self.file.metadata()?) == self.identity,
            "actual owned publication predecessor changed",
        )
    }
}
/// Retained read-only record for other native crates. Publication and archival
/// remain private to their owning policy transaction.
pub struct Observation {
    original: Retained,
}
impl Observation {
    pub fn open(parent: &File, name: &Path, limit: usize, mount: u64) -> Result<Self> {
        Ok(Self {
            original: Retained::open(parent, name, limit, mount)?,
        })
    }
    pub(crate) fn optional(
        parent: &File,
        name: &Path,
        limit: usize,
        mount: u64,
    ) -> Result<Option<Self>> {
        Ok(Retained::optional_open(parent, name, limit, mount)?.map(|original| Self { original }))
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    /// Observation data for comparison only; it cannot reopen a retained actor.
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.original.recheck()?;
        Ok(
            serde_json::json!({"epoch":self.original.identity,"mount":self.original.mount,
            "bytes_sha256":json::sha256(&self.original.bytes)}),
        )
    }
    pub(crate) fn replace_with_predecessor(&mut self, next: &Value) -> Result<Predecessor> {
        self.original.replace_with_predecessor(next)
    }
    pub(crate) fn replace_original(&mut self, next: &Value) -> Result<()> {
        self.original.recheck()?;
        self.original.replace(next)
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.original.recheck()?;
        Ok(&self.original.file)
    }
    pub fn value(&self) -> Result<&Value> {
        self.original.value()
    }
}
fn shape(parent: &File, owner: u32) -> Result<(u64, u64, u32, u32, u32)> {
    let m = parent.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "private original record directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Retained {
    /// The owning transaction first proves this actual SCM description against
    /// its still-live original Root producer. Metadata/JSON cannot supply it.
    pub(crate) fn admit_original(
        parent: &File,
        name: &Path,
        file: File,
        limit: usize,
        mount: u64,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let original = Self::from_file(parent, name, limit, mount, 0, file)?;
        original.recheck()?;
        Ok(original)
    }
    pub(crate) fn open(parent: &File, name: &Path, limit: usize, mount: u64) -> Result<Self> {
        Self::open_owned(parent, name, limit, mount, 0)
    }
    pub(crate) fn optional_open(
        parent: &File,
        name: &Path,
        limit: usize,
        mount: u64,
    ) -> Result<Option<Self>> {
        Self::optional_owned(parent, name, limit, mount, 0)
    }
    fn optional_owned(
        parent: &File,
        name: &Path,
        limit: usize,
        mount: u64,
        owner: u32,
    ) -> Result<Option<Self>> {
        require(
            name.components().count() == 1
                && matches!(name.components().next(), Some(Component::Normal(_))),
            "single optional retained record name required",
        )?;
        shape(parent, owner)?;
        require(
            mount_identity::id(parent.as_fd(), true)? == mount,
            "optional record parent mount differs",
        )?;
        files::optional_relative(parent, name)?
            .map(|file| Self::from_file(parent, name, limit, mount, owner, file))
            .transpose()
    }
    fn open_owned(
        parent: &File,
        name: &Path,
        limit: usize,
        mount: u64,
        owner: u32,
    ) -> Result<Self> {
        let file = files::open_relative(parent, name)?;
        Self::from_file(parent, name, limit, mount, owner, file)
    }
    fn from_file(
        parent: &File,
        name: &Path,
        limit: usize,
        mount: u64,
        owner: u32,
        file: File,
    ) -> Result<Self> {
        require(
            name.components().count() == 1
                && matches!(name.components().next(), Some(Component::Normal(_))),
            "single retained record name required",
        )?;
        let parent_shape = shape(parent, owner)?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == owner
                && m.gid() == parent_shape.3
                && m.nlink() == 1
                && matches!(m.mode() & 0o7777, 0o400 | 0o600)
                && mount_identity::id(parent.as_fd(), true)? == mount
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original private record protection or mount differs",
        )?;
        let identity = files::identity(&m);
        let bytes = files::read_file(&file, limit, Some(owner), true)?;
        let value = json::decode(&bytes, limit)?;
        let this = Self {
            parent: parent.try_clone()?,
            parent_shape,
            name: name.into(),
            file,
            identity,
            mount,
            limit,
            owner,
            bytes,
            value,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let named = files::open_relative(&self.parent, &self.name)?;
        require(
            shape(&self.parent, self.owner)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::read_file(&self.file, self.limit, Some(self.owner), true)? == self.bytes
                && files::identity(&self.file.metadata()?) == self.identity,
            "original control record changed, replaced or remounted",
        )
    }
    /// Cached decoded data remains bound to both original descriptions and the
    /// full immutable kernel epoch. No fresh read adopts a changed baseline.
    pub(crate) fn checkpoint_value(&self) -> Result<&Value> {
        let named = files::open_relative(&self.parent, &self.name)?;
        require(
            shape(&self.parent, self.owner)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original control record checkpoint changed/replaced/covered",
        )?;
        Ok(&self.value)
    }
    /// The original descriptor remains bound to its immutable private epoch.
    /// Caller must separately retain its original shared descriptor flags.
    pub(crate) fn checkpoint_descriptor(&self) -> Result<&File> {
        self.checkpoint_value()?;
        Ok(&self.file)
    }
    pub(crate) fn value(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.value)
    }
    /// Review data only: callers still retain and recheck the actual file.
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"file":self.identity,"mount":self.mount,"parent":[self.parent_shape.0,self.parent_shape.1,self.parent_shape.4,self.parent_shape.2,self.parent_shape.3],"bytes_sha256":json::sha256(&self.bytes)}),
        )
    }
    pub(crate) fn require_original_publication(
        &self,
        pending: &enzimos_platform::publication::Prepared,
    ) -> Result<()> {
        pending.require_original_epoch(&self.file, self.identity)
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub(crate) fn matches_entry(
        &self,
        entry: &enzimos_platform::directory_entry::Entry,
    ) -> Result<()> {
        self.recheck()?;
        entry.matches(&self.file)?;
        self.recheck()
    }
    pub(crate) fn replace(&mut self, next: &Value) -> Result<()> {
        self.recheck()?;
        let mut bytes = json::canonical(next)?;
        bytes.push(b'\n');
        require(
            bytes.len() <= self.limit,
            "retained record publication bound",
        )?;
        let file = files::atomic_replace_original(
            &self.parent,
            &self.name,
            &bytes,
            0o600,
            Some(self.owner),
            self.limit,
            &self.file,
        )?;
        self.identity = files::identity(&file.metadata()?);
        self.file = file;
        self.bytes = bytes;
        self.value = next.clone();
        self.recheck()
    }
    pub(crate) fn replace_with_predecessor(&mut self, next: &Value) -> Result<Predecessor> {
        self.recheck()?;
        let file = self.file.try_clone()?;
        let before = self.identity;
        let flags = enzimos_platform::files::status_flags(&file);
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original predecessor read-only description required",
        )?;
        let bytes = self.bytes.clone();
        self.replace(next)?;
        let after = files::identity(&file.metadata()?);
        require(
            (
                before.0, before.1, before.2, before.3, before.4, before.7, before.8, before.9,
            ) == (
                after.0, after.1, after.2, after.3, after.4, after.7, after.8, after.9,
            ) && before.10 == 1
                && after.10 == 0
                && (after.5, after.6) >= (before.5, before.6),
            "owned publication changed predecessor beyond actual unlink epoch",
        )?;
        let result = Predecessor {
            file,
            before_identity: before,
            identity: after,
            flags,
            mount: self.mount,
            owner: self.owner,
            limit: self.limit,
            bytes,
        };
        result.recheck()?;
        self.recheck()?;
        Ok(result)
    }
    /// Retain the original file across one no-replace archival rename.
    /// Failure leaves evidence in place; there is no unlink, retry or rollback.
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub(crate) fn archive(mut self, target: &File, name: &Path) -> Result<Self> {
        self.recheck()?;
        require(
            name.components().count() == 1
                && matches!(name.components().next(), Some(Component::Normal(_))),
            "single archive name required",
        )?;
        let target_shape = shape(target, self.owner)?;
        require(
            mount_identity::id(target.as_fd(), true)? == self.mount,
            "archive left original control mount",
        )?;
        let old_parent = self.parent.try_clone()?;
        let old_name = self.name.clone();
        let source = CString::new(self.name.as_os_str().as_bytes())
            .map_err(|_| enzimos_platform::Error("archive source encoding".into()))?;
        let destination = CString::new(name.as_os_str().as_bytes())
            .map_err(|_| enzimos_platform::Error("archive destination encoding".into()))?;
        self.recheck()?;
        require(
            // SAFETY: Both names are NUL-terminated and the parent descriptor stays open.
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    source.as_ptr(),
                    target.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "original receipt archive rename refused",
        )?;
        let after = files::identity(&self.file.metadata()?);
        let mut known = self.identity;
        require(
            (after.5, after.6) >= (known.5, known.6),
            "archive timestamp regressed",
        )?;
        known.5 = after.5;
        known.6 = after.6;
        require(known == after, "original receipt changed during archive")?;
        self.parent = target.try_clone()?;
        self.parent_shape = target_shape;
        self.name = name.into();
        self.identity = after;
        self.recheck()?;
        require(
            files::optional_relative(&old_parent, &old_name)?.is_none(),
            "original receipt name remains after archive",
        )?;
        old_parent.sync_all()?;
        self.parent.sync_all()?;
        self.recheck()?;
        Ok(self)
    }
    pub(crate) fn create(
        parent: &File,
        name: &Path,
        value: &Value,
        limit: usize,
        mount: u64,
    ) -> Result<Self> {
        shape(parent, 0)?;
        require(
            mount_identity::id(parent.as_fd(), true)? == mount,
            "new record parent left original control mount",
        )?;
        let mut bytes = json::canonical(value)?;
        bytes.push(b'\n');
        let file =
            files::atomic_relative_retained(parent, name, &bytes, 0o600, Some(0), false, limit)?;
        Self::from_file(parent, name, limit, mount, 0, file)
    }
}
pub fn read(parent: &File, name: &Path, limit: usize, mount: u64) -> Result<Value> {
    require(
        name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_))),
        "invalid control record filename",
    )?;
    let metadata = parent.metadata()?;
    require(
        metadata.uid() == 0
            && metadata.mode() & 0o7777 == 0o700
            && mount_identity::id(parent.as_fd(), true)? == mount,
        "unsafe control record directory",
    )?;
    let file = files::open_relative(parent, name)?;
    require(
        file.metadata()?.mode() & 0o077 == 0 && mount_identity::id(file.as_fd(), true)? == mount,
        "unsafe or independently mounted control record",
    )?;
    let identity = files::identity(&file.metadata()?);
    let bytes = files::read_file(&file, limit, Some(0), true)?;
    let current = files::open_relative(parent, name)?;
    require(
        files::identity(&current.metadata()?) == identity
            && files::identity(&file.metadata()?) == identity
            && mount_identity::id(current.as_fd(), true)? == mount,
        "control record changed during read",
    )?;
    json::decode(&bytes, limit)
}
