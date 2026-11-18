// SPDX-License-Identifier: MIT
//! Explicit retained-member quarantine and unlink. Drop never mutates a name.
use crate::{Result, files, mount_identity, require, stream_copy};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0,
        "protected retirement parent required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn single(name: &Path) -> Result<CString> {
    require(
        name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_))),
        "single retirement member name required",
    )?;
    CString::new(name.as_os_str().as_bytes())
        .map_err(|_| crate::Error("retirement name encoding".into()))
}
fn renamed(before: files::FileIdentity, after: files::FileIdentity) -> bool {
    before.0 == after.0
        && before.1 == after.1
        && before.2 == after.2
        && before.3 == after.3
        && before.4 == after.4
        && before.7 == after.7
        && before.8 == after.8
        && before.9 == after.9
        && before.10 == after.10
}
pub struct Quarantined {
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    file: File,
    epoch: files::FileIdentity,
    before_epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    original: PathBuf,
    name: PathBuf,
    directory: bool,
    digest: Option<String>,
    owner: u32,
    maximum: u64,
}
impl Quarantined {
    /// Caller must durably enter retirement and retain its original transaction
    /// lock/authority before invoking. A mismatched rename is retained untouched.
    pub fn enter(
        parent: &File,
        original: &File,
        name: &Path,
        owner: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::enter_bounded(parent, original, name, owner, 65536, authorize)
    }
    /// Fixed-role callers provide an independently reviewed upper byte bound.
    pub fn enter_bounded(
        parent: &File,
        original: &File,
        name: &Path,
        owner: u32,
        maximum: u64,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::enter_checked(parent, original, name, owner, maximum, None, authorize)
    }
    /// The caller's independently retained original epoch is a precondition,
    /// checked before any rename and after all fresh bounded hash callbacks.
    pub fn enter_original(
        parent: &File,
        original: &File,
        name: &Path,
        owner: u32,
        maximum: u64,
        expected: files::FileIdentity,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::enter_checked(
            parent,
            original,
            name,
            owner,
            maximum,
            Some(expected),
            authorize,
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, geteuid, syscall).")]
    fn enter_checked(
        parent: &File,
        original: &File,
        name: &Path,
        owner: u32,
        maximum: u64,
        expected: Option<files::FileIdentity>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        require(
            maximum > 0 && maximum <= 16 * 1024 * 1024 * 1024,
            "retirement member byte bound",
        )?;
        authorize()?;
        require(
            unsafe { libc::geteuid() } == owner,
            "retirement writer authority",
        )?;
        let old = single(name)?;
        let parent_shape = shape(parent, owner)?;
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        let metadata = original.metadata()?;
        let directory = metadata.is_dir();
        require(
            (directory || metadata.is_file())
                && metadata.uid() == owner
                && metadata.mode() & 0o022 == 0
                && (directory || metadata.nlink() == 1),
            "protected regular member/empty directory required",
        )?;
        let epoch = files::identity(&metadata);
        require(
            expected.is_none_or(|before| before == epoch),
            "caller original retirement epoch changed before quarantine",
        )?;
        let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original retirement description must remain read-only",
        )?;
        let mount = mount_identity::id(original.as_fd(), true)?;
        require(
            mount == parent_mount,
            "retirement member covered or crossed mount",
        )?;
        let digest = if directory {
            require(
                files::directory_is_empty(original)?,
                "directory retirement refuses unknown members",
            )?;
            None
        } else {
            Some(
                stream_copy::hash_borrowed_with_checkpoint(
                    original,
                    maximum,
                    Some(owner),
                    authorize,
                )?
                .1,
            )
        };
        let named = if directory {
            files::directory_relative(parent, name, Some(owner))?
        } else {
            files::open_relative(parent, name)?
        };
        require(
            files::identity(&named.metadata()?) == epoch
                && mount_identity::id(named.as_fd(), true)? == mount,
            "retirement name differs from held original member",
        )?;
        let fresh = PathBuf::from(format!(".retiring-{}", files::random_hex(16)?));
        let new = single(&fresh)?;
        authorize()?;
        require(
            shape(parent, owner)? == parent_shape
                && mount_identity::id(parent.as_fd(), true)? == parent_mount
                && files::identity(&original.metadata()?) == epoch,
            "retirement actor changed before quarantine",
        )?;
        let named = if directory {
            files::directory_relative(parent, name, Some(owner))?
        } else {
            files::open_relative(parent, name)?
        };
        require(
            files::identity(&named.metadata()?) == epoch,
            "retirement original name changed before quarantine",
        )?;
        require(
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    parent.as_raw_fd(),
                    old.as_ptr(),
                    parent.as_raw_fd(),
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "retirement quarantine uncertain; never replace/retry",
        )?;
        parent.sync_all()?;
        let after = files::identity(&original.metadata()?);
        require(
            renamed(epoch, after),
            "quarantine changed original member beyond owned rename; retain",
        )?;
        let this = Self {
            parent: parent.try_clone()?,
            parent_shape,
            parent_mount,
            file: original.try_clone()?,
            epoch: after,
            before_epoch: epoch,
            flags,
            mount,
            original: name.into(),
            name: fresh,
            directory,
            digest,
            owner,
            maximum,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.recheck_authorized(&mut || Ok(()))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn recheck_authorized(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        require(
            shape(&self.parent, self.owner)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount,
            "original quarantine parent changed",
        )?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) } == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "original quarantined member changed",
        )?;
        let named = if self.directory {
            files::directory_relative(&self.parent, &self.name, Some(self.owner))?
        } else {
            files::open_relative(&self.parent, &self.name)?
        };
        require(
            files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "quarantine name replaced or covered",
        )?;
        if self.directory {
            require(
                files::directory_is_empty(&self.file)?,
                "quarantined directory has unknown members",
            )?;
        } else {
            require(
                self.digest.as_ref()
                    == Some(
                        &stream_copy::hash_borrowed_with_checkpoint(
                            &self.file,
                            self.maximum,
                            Some(self.owner),
                            authorize,
                        )?
                        .1,
                    ),
                "quarantined document content changed",
            )?;
        }
        // Hash checkpoints can run caller code. Reopen the quarantined name
        // afterward so replacement during a bounded read cannot authorize unlink.
        let final_named = if self.directory {
            files::directory_relative(&self.parent, &self.name, Some(self.owner))?
        } else {
            files::open_relative(&self.parent, &self.name)?
        };
        require(
            shape(&self.parent, self.owner)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&final_named.metadata()?) == self.epoch
                && mount_identity::id(final_named.as_fd(), true)? == self.mount,
            "quarantine binding changed during fresh checkpoints",
        )?;
        require(
            files::optional_relative(&self.parent, &self.original)?.is_none(),
            "original retirement name reappeared; retain",
        )
    }
    /// Explicit owned unlink only; no recursive deletion or destructor cleanup.
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, unlinkat).")]
    pub fn unlink(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Removed> {
        authorize()?;
        self.recheck_authorized(authorize)?;
        require(
            unsafe { libc::geteuid() } == self.owner,
            "retirement unlink writer authority",
        )?;
        let name = single(&self.name)?;
        require(
            unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    name.as_ptr(),
                    if self.directory {
                        libc::AT_REMOVEDIR
                    } else {
                        0
                    },
                )
            } == 0,
            "quarantined member unlink uncertain; retain intent",
        )?;
        self.parent.sync_all()?;
        let epoch = files::identity(&self.file.metadata()?);
        let before = self.epoch;
        require(
            epoch.10 == 0
                && (
                    before.0, before.1, before.2, before.3, before.4, before.7, before.8, before.9,
                ) == (
                    epoch.0, epoch.1, epoch.2, epoch.3, epoch.4, epoch.7, epoch.8, epoch.9,
                ),
            "retired original changed beyond owned unlink",
        )?;
        let removed = Removed {
            original: self,
            epoch,
        };
        removed.recheck()?;
        Ok(removed)
    }
}
pub struct Removed {
    original: Quarantined,
    epoch: files::FileIdentity,
}
impl Removed {
    /// Original caller file before either owned rename or unlink, for comparison
    /// with its already-held inventory. No decoded identity creates this actor.
    pub fn before_epoch(&self) -> Result<files::FileIdentity> {
        self.recheck()?;
        Ok(self.original.before_epoch)
    }
    pub fn original_name(&self) -> Result<&Path> {
        self.recheck()?;
        Ok(&self.original.original)
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.original.file)
    }
    pub fn parent(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.original.parent)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub fn recheck(&self) -> Result<()> {
        let q = &self.original;
        require(
            shape(&q.parent, q.owner)? == q.parent_shape
                && mount_identity::id(q.parent.as_fd(), true)? == q.parent_mount
                && files::identity(&q.file.metadata()?) == self.epoch
                && self.epoch.10 == 0
                && unsafe { libc::fcntl(q.file.as_raw_fd(), libc::F_GETFL) } == q.flags
                && mount_identity::id(q.file.as_fd(), true)? == q.mount
                && files::optional_relative(&q.parent, &q.name)?.is_none()
                && files::optional_relative(&q.parent, &q.original)?.is_none(),
            "original retired member/parent changed or name reappeared",
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("retire-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(
                std::env::var_os("ENZIMOS_TEST_TMPDIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::env::current_dir().unwrap()),
            )
            .unwrap()
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn revocation_replacement_and_unknown_directory_members_preserve_data() {
        let d = fixture();
        let uid = unsafe { libc::geteuid() };
        let parent = files::directory(d.path(), Some(uid)).unwrap();
        std::fs::write(d.path().join("info"), b"captured").unwrap();
        let file = files::open_relative(&parent, Path::new("info")).unwrap();
        assert!(
            Quarantined::enter(&parent, &file, Path::new("info"), uid, &mut || Err(
                crate::Error("revoked".into())
            ))
            .is_err()
        );
        std::fs::rename(d.path().join("info"), d.path().join("old")).unwrap();
        std::fs::write(d.path().join("info"), b"replacement").unwrap();
        assert!(
            Quarantined::enter(&parent, &file, Path::new("info"), uid, &mut || Ok(())).is_err()
        );
        assert_eq!(
            std::fs::read(d.path().join("info")).unwrap(),
            b"replacement"
        );
        std::fs::create_dir(d.path().join("other")).unwrap();
        std::fs::write(d.path().join("other/member"), b"keep").unwrap();
        let other = files::directory_relative(&parent, Path::new("other"), Some(uid)).unwrap();
        assert!(
            Quarantined::enter(&parent, &other, Path::new("other"), uid, &mut || Ok(())).is_err()
        );
        assert_eq!(
            std::fs::read(d.path().join("other/member")).unwrap(),
            b"keep"
        );
        let replacement = files::open_relative(&parent, Path::new("info")).unwrap();
        let q = Quarantined::enter(
            &parent,
            &replacement,
            Path::new("info"),
            uid,
            &mut || Ok(()),
        )
        .unwrap();
        assert!(
            q.unlink(&mut || Err(crate::Error("revoked".into())))
                .is_err()
        );
        assert!(
            files::directory_names(&parent, 16)
                .unwrap()
                .iter()
                .any(|n| n.to_string_lossy().starts_with(".retiring-"))
        );
    }
}
