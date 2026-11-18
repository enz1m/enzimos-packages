// SPDX-License-Identifier: MIT
//! Actual fixed-name rotation objects; classification data never constructs them.
use crate::{
    backup_repository_header::Header, backup_rotation_mount::Mount, storage_runtime::Guard,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
#[derive(Clone, Copy)]
pub(crate) enum RepositoryName {
    Current,
    Stage,
    Retired,
}
impl RepositoryName {
    fn name(self) -> &'static str {
        match self {
            Self::Current => "restic",
            Self::Stage => "restic-rotation",
            Self::Retired => "restic-retired",
        }
    }
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original rotation repository directory",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub(crate) struct Repository {
    name: RepositoryName,
    file: File,
    shape: Shape,
    mount: u64,
    header: Option<Header>,
}
impl Repository {
    pub(crate) fn observe(mount: &Mount<'_>, name: RepositoryName) -> Result<Option<Self>> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        mount.recheck()?;
        let parent = mount.descriptor()?;
        let Some(file) =
            files::optional_directory_relative(parent, Path::new(name.name()), Some(0))?
        else {
            return Ok(None);
        };
        require(
            mount_identity::id(file.as_fd(), true)? == mount.mount_id(),
            "rotation repository crossed destination mount",
        )?;
        let header = if files::optional_relative(&file, Path::new("config"))?.is_some() {
            Some(Header::observe(&file)?)
        } else {
            None
        };
        let original = Self {
            name,
            shape: shape(&file)?,
            file,
            mount: mount.mount_id(),
            header,
        };
        original.recheck(mount)?;
        Ok(Some(original))
    }
    pub(crate) fn recheck(&self, mount: &Mount<'_>) -> Result<()> {
        mount.recheck()?;
        let named =
            files::directory_relative(mount.descriptor()?, Path::new(self.name.name()), Some(0))?;
        require(
            shape(&self.file)? == self.shape
                && shape(&named)? == self.shape
                && self.mount == mount.mount_id()
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original rotation repository replaced/remounted",
        )?;
        if let Some(header) = &self.header {
            header.recheck(&self.file)?;
        } else {
            require(
                files::optional_relative(&self.file, Path::new("config"))?.is_none(),
                "partial rotation repository header appeared",
            )?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub(crate) fn remove_original(
        self,
        mount: &Mount<'_>,
        layout: crate::backup_rotation_layout::Layout,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<RemovedRepository> {
        use std::{ffi::CString, os::fd::AsRawFd};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck(mount)?;
        layout.require_root(&self.file)?;
        let layout = layout.empty_original(authorize)?;
        layout.require_root(&self.file)?;
        let parent = mount.descriptor()?;
        let before = files::identity(&parent.metadata()?);
        let entry =
            enzimos_platform::directory_entry::Entry::observe(parent, Path::new(self.name.name()))?;
        entry.matches(&self.file)?;
        let mut names = files::directory_names(parent, 131072)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            names.remove(std::ffi::OsStr::new(self.name.name())),
            "original repository removal name missing",
        )?;
        let name = CString::new(self.name.name()).unwrap();
        authorize()?;
        entry.recheck()?;
        layout.require_root(&self.file)?;
        require(
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0,
            "original repository rmdir refused; no replay",
        )?;
        require(
            self.file.metadata()?.nlink() == 0,
            "actual original repository remains linked",
        )?;
        crate::backup_rotation_epoch::parent_changed(
            before,
            files::identity(&parent.metadata()?),
            true,
        )?;
        require(
            files::directory_names(parent, 131072)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == names,
            "repository removal parent changed beyond original directory",
        )?;
        parent.sync_all()?;
        authorize()?;
        let removed = RemovedRepository { original: self };
        removed.recheck(mount)?;
        Ok(removed)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub(crate) fn rename(
        mut self,
        mount: &Mount<'_>,
        target: RepositoryName,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        use std::{ffi::CString, os::fd::AsRawFd};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck(mount)?;
        let parent = mount.descriptor()?;
        require(
            files::optional_directory_relative(parent, Path::new(target.name()), Some(0))?
                .is_none(),
            "rotation rename target must be absent",
        )?;
        let before = files::identity(&self.file.metadata()?);
        let parent_before = files::identity(&parent.metadata()?);
        let mut names = files::directory_names(parent, 131072)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            names.remove(std::ffi::OsStr::new(self.name.name()))
                && names.insert(std::ffi::OsString::from(target.name())),
            "original rename membership differs",
        )?;
        let old = CString::new(self.name.name()).unwrap();
        let new = CString::new(target.name()).unwrap();
        authorize()?;
        self.recheck(mount)?;
        require(
            unsafe {
                libc::renameat2(
                    parent.as_raw_fd(),
                    old.as_ptr(),
                    parent.as_raw_fd(),
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "rotation repository rename collision/failure; no replay",
        )?;
        crate::backup_rotation_epoch::renamed(before, files::identity(&self.file.metadata()?))?;
        crate::backup_rotation_epoch::parent_changed(
            parent_before,
            files::identity(&parent.metadata()?),
            false,
        )?;
        require(
            files::directory_names(parent, 131072)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == names,
            "repository parent changed beyond original rename",
        )?;
        self.name = target;
        parent.sync_all()?;
        self.recheck(mount)?;
        authorize()?;
        Ok(self)
    }
    pub(crate) fn evidence(&self, mount: &Mount<'_>) -> Result<Value> {
        self.recheck(mount)?;
        Ok(
            json!({"shape":self.shape,"mount":self.mount,"header":self.header.as_ref().map(|h|h.evidence(&self.file)).transpose()?}),
        )
    }
    pub(crate) fn identity(&self, mount: &Mount<'_>) -> Result<Value> {
        self.recheck(mount)?;
        let sha = if let Some(header) = &self.header {
            header.evidence(&self.file)?["sha256"].clone()
        } else {
            json!("partial")
        };
        Ok(json!([sha, self.shape.1]))
    }
    pub(crate) fn descriptor(&self, mount: &Mount<'_>) -> Result<&File> {
        self.recheck(mount)?;
        Ok(&self.file)
    }
    pub(crate) fn classify(&self, mount: &Mount<'_>, record: &Value) -> Result<&'static str> {
        self.recheck(mount)?;
        let Some(header) = &self.header else {
            return Ok("partial");
        };
        let hash = header.evidence(&self.file)?["sha256"].clone();
        Ok(
            if hash == record["repository_binding"]["repository_sha256"]
                && record["repository_inode"] == self.shape.1
            {
                "old"
            } else if hash == record["new_repository_sha256"]
                && record["new_repository_inode"] == self.shape.1
            {
                "new"
            } else {
                "foreign"
            },
        )
    }
}
pub(crate) struct RemovedRepository {
    original: Repository,
}
impl RemovedRepository {
    pub(crate) fn recheck(&self, mount: &Mount<'_>) -> Result<()> {
        mount.recheck()?;
        let m = self.original.file.metadata()?;
        require(
            m.dev() == self.original.shape.0
                && m.ino() == self.original.shape.1
                && m.nlink() == 0
                && m.mode() == self.original.shape.2
                && m.uid() == self.original.shape.3
                && m.gid() == self.original.shape.4
                && mount_identity::id(self.original.file.as_fd(), true)? == self.original.mount
                && files::optional_directory_relative(
                    mount.descriptor()?,
                    Path::new(self.original.name.name()),
                    Some(0),
                )?
                .is_none(),
            "original removed repository changed or name reused",
        )
    }
}
#[derive(Clone, Copy)]
pub(crate) enum CredentialName {
    Current,
    Input,
    Retired,
}
impl CredentialName {
    fn name(self) -> &'static str {
        match self {
            Self::Current => "backup.password",
            Self::Input => "backup.rotation-password",
            Self::Retired => "backup.retired-password",
        }
    }
}
pub(crate) struct Credential {
    name: CredentialName,
    parent: File,
    parent_shape: Shape,
    file: File,
    epoch: files::FileIdentity,
    mount: u64,
    identity: Value,
}
impl Credential {
    pub(crate) fn observe(guard: &Guard, name: CredentialName) -> Result<Option<Self>> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let source = guard.backup_root_binding()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            mount_identity::id(parent.as_fd(), true)? == guard.root_mount_id(),
            "rotation credential parent outside live root",
        )?;
        let Some(file) = files::optional_relative(&parent, Path::new(name.name()))? else {
            return Ok(None);
        };
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o077 == 0
                && m.nlink() == 1
                && (1..=4096).contains(&m.len())
                && m.dev() == guard.root_device()
                && mount_identity::id(file.as_fd(), true)? == guard.root_mount_id(),
            "protected original live-root rotation credential",
        )?;
        let mtime = m
            .mtime()
            .checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(m.mtime_nsec()))
            .ok_or_else(|| enzimos_platform::Error("rotation credential time overflow".into()))?;
        let identity = json!({"inode":m.ino(),"size":m.len(),"mtime_ns":mtime,"filesystem_uuid":source["configuration"]["filesystem_uuid"],
            "root_uuid":source["root"]["uuid"],"root_id":source["root"]["id"],"root_path":source["root"]["path"]});
        crate::backup_rotation_record::credential_identity(&identity)?;
        let original = Self {
            name,
            parent_shape: shape(&parent)?,
            parent,
            file,
            epoch: files::identity(&m),
            mount: guard.root_mount_id(),
            identity,
        };
        original.recheck(guard)?;
        Ok(Some(original))
    }
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new(self.name.name()))?;
        require(
            shape(&parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && self.mount == guard.root_mount_id()
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original rotation credential replaced/changed/remounted",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub(crate) fn unlink_original(
        mut self,
        guard: &Guard,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<RemovedCredential> {
        use std::{ffi::CString, os::fd::AsRawFd};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck(guard)?;
        let before = files::identity(&self.parent.metadata()?);
        let entry = enzimos_platform::directory_entry::Entry::observe(
            &self.parent,
            Path::new(self.name.name()),
        )?;
        entry.matches(&self.file)?;
        let mut names = files::directory_names(&self.parent, 131072)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            names.remove(std::ffi::OsStr::new(self.name.name())),
            "original credential removal name missing",
        )?;
        let name = CString::new(self.name.name()).unwrap();
        authorize()?;
        entry.recheck()?;
        self.recheck(guard)?;
        require(
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "original credential unlink failed; no replay",
        )?;
        let after = files::identity(&self.file.metadata()?);
        crate::backup_rotation_epoch::unlinked(self.epoch, after)?;
        crate::backup_rotation_epoch::parent_changed(
            before,
            files::identity(&self.parent.metadata()?),
            false,
        )?;
        require(
            files::directory_names(&self.parent, 131072)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == names,
            "credential removal parent changed beyond original file",
        )?;
        self.epoch = after;
        self.parent.sync_all()?;
        authorize()?;
        let removed = RemovedCredential { original: self };
        removed.recheck(guard)?;
        Ok(removed)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub(crate) fn rename(
        mut self,
        guard: &Guard,
        target: CredentialName,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        use std::{ffi::CString, os::fd::AsRawFd};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck(guard)?;
        require(
            files::optional_relative(&self.parent, Path::new(target.name()))?.is_none(),
            "rotation credential rename target must be absent",
        )?;
        let parent_before = files::identity(&self.parent.metadata()?);
        let mut names = files::directory_names(&self.parent, 131072)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            names.remove(std::ffi::OsStr::new(self.name.name()))
                && names.insert(std::ffi::OsString::from(target.name())),
            "original credential rename membership differs",
        )?;
        let old = CString::new(self.name.name()).unwrap();
        let new = CString::new(target.name()).unwrap();
        authorize()?;
        self.recheck(guard)?;
        require(
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    old.as_ptr(),
                    self.parent.as_raw_fd(),
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "rotation credential rename collision/failure; no replay",
        )?;
        let after = files::identity(&self.file.metadata()?);
        crate::backup_rotation_epoch::renamed(self.epoch, after)?;
        crate::backup_rotation_epoch::parent_changed(
            parent_before,
            files::identity(&self.parent.metadata()?),
            false,
        )?;
        require(
            files::directory_names(&self.parent, 131072)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == names,
            "credential parent changed beyond original rename",
        )?;
        self.epoch = after;
        self.name = target;
        self.parent.sync_all()?;
        self.recheck(guard)?;
        authorize()?;
        Ok(self)
    }
    pub(crate) fn evidence(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        Ok(
            json!({"epoch":self.epoch,"parent":self.parent_shape,"mount":self.mount,"identity":self.identity}),
        )
    }
    pub(crate) fn descriptor(&self, guard: &Guard) -> Result<&File> {
        self.recheck(guard)?;
        Ok(&self.file)
    }
    pub(crate) fn classify(&self, guard: &Guard, record: &Value) -> Result<&'static str> {
        self.recheck(guard)?;
        Ok(if self.identity == record["password_identity"] {
            "old"
        } else if self.identity == record["input_identity"] {
            "new"
        } else {
            "foreign"
        })
    }
}

pub(crate) struct RemovedCredential {
    original: Credential,
}
impl RemovedCredential {
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            shape(&parent)? == self.original.parent_shape
                && shape(&self.original.parent)? == self.original.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.original.mount
                && mount_identity::id(self.original.parent.as_fd(), true)? == self.original.mount
                && mount_identity::id(self.original.file.as_fd(), true)? == self.original.mount
                && files::identity(&self.original.file.metadata()?) == self.original.epoch
                && self.original.epoch.10 == 0
                && files::optional_relative(
                    &self.original.parent,
                    Path::new(self.original.name.name()),
                )?
                .is_none(),
            "original removed credential changed or name reused",
        )
    }
}
