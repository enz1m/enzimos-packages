// SPDX-License-Identifier: MIT
//! Metadata-only original private credential quarantine. Never reads/hashes bytes.
//! Caller owns the durable intent and live authority. Drop never changes a name.
use crate::{Result, files, mount_identity, require};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(parent: &File, owner: u32) -> Result<Shape> {
    let m = parent.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0,
        "protected original credential parent",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn name(path: &Path) -> Result<CString> {
    require(
        path.components().count() == 1
            && matches!(path.components().next(), Some(Component::Normal(_))),
        "single credential retirement name required",
    )?;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| crate::Error("credential name encoding".into()))
}
fn names(parent: &File) -> Result<BTreeSet<std::ffi::OsString>> {
    Ok(files::directory_names(parent, 131072)?
        .into_iter()
        .collect())
}
fn renamed(before: files::FileIdentity, after: files::FileIdentity) -> Result<()> {
    let mut known = before;
    require(
        (after.5, after.6) >= (before.5, before.6),
        "credential rename time regressed",
    )?;
    known.5 = after.5;
    known.6 = after.6;
    require(known == after, "credential changed beyond original rename")
}
/// A private credential renamed to a random quarantine name in its parent, retained until
/// [`Quarantined::unlink`].
pub struct Quarantined {
    parent: File,
    shape: Shape,
    parent_mount: u64,
    file: File,
    epoch: files::FileIdentity,
    before: files::FileIdentity,
    mount: u64,
    flags: i32,
    original: PathBuf,
    quarantine: PathBuf,
    owner: u32,
    members: BTreeSet<std::ffi::OsString>,
}
impl Quarantined {
    /// Rename `file`, found at `original`, to a random quarantine name after checking it still has
    /// epoch `expected`.
    ///
    /// # Errors
    ///
    /// Fails unless the caller's effective UID is `owner`, when the credential is not private,
    /// read-only and single-link, when it changed, or when the rename collides or fails.
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub fn enter_original(
        parent: &File,
        file: &File,
        original: &Path,
        expected: files::FileIdentity,
        owner: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        require(
            crate::process_identity::effective_uid() == owner,
            "credential retirement writer authority",
        )?;
        let old = name(original)?;
        let shape = shape(parent, owner)?;
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        let m = file.metadata()?;
        let epoch = files::identity(&m);
        let mount = mount_identity::id(file.as_fd(), true)?;
        let flags = crate::files::status_flags(&file);
        require(
            epoch == expected
                && m.is_file()
                && m.uid() == owner
                && m.gid() == shape.4
                && m.mode() & 0o077 == 0
                && m.nlink() == 1
                && (1..=4096).contains(&m.len())
                && mount == parent_mount
                && flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && flags & libc::O_PATH == 0,
            "original private readonly credential epoch/protection/mount",
        )?;
        let entry = crate::directory_entry::Entry::observe(parent, original)?;
        entry.matches(file)?;
        let quarantine = PathBuf::from(format!(".retiring-credential-{}", files::random_hex(16)?));
        let new = name(&quarantine)?;
        let mut members = names(parent)?;
        require(
            members.remove(original.as_os_str()) && members.insert(quarantine.as_os_str().into()),
            "credential original parent membership",
        )?;
        authorize()?;
        entry.recheck()?;
        entry.matches(file)?;
        require(
            files::identity(&file.metadata()?) == expected
                && mount_identity::id(file.as_fd(), true)? == mount
                && crate::files::status_flags(&file) == flags,
            "original credential changed before quarantine",
        )?;
        require(
            // SAFETY: Both names are NUL-terminated CStrings and `parent` keeps the descriptor
            // open.
            unsafe {
                libc::renameat2(
                    parent.as_raw_fd(),
                    old.as_ptr(),
                    parent.as_raw_fd(),
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "credential quarantine collision/failure; retain intent, no replay",
        )?;
        let after = files::identity(&file.metadata()?);
        renamed(epoch, after)?;
        parent.sync_all()?;
        let this = Self {
            parent: parent.try_clone()?,
            shape,
            parent_mount,
            file: file.try_clone()?,
            epoch: after,
            before: epoch,
            mount,
            flags,
            original: original.into(),
            quarantine,
            owner,
            members,
        };
        this.recheck()?;
        authorize()?;
        Ok(this)
    }
    /// Verify the quarantined credential, its parent and membership are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when any of them changed or the original name reappeared.
    pub fn recheck(&self) -> Result<()> {
        let named = files::open_relative(&self.parent, &self.quarantine)?;
        require(
            shape(&self.parent, self.owner)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && crate::files::status_flags(&self.file) == self.flags
                && names(&self.parent)? == self.members
                && files::optional_relative(&self.parent, &self.original)?.is_none(),
            "original quarantined credential changed/replaced/covered or membership differs",
        )
    }
    /// Unlink the quarantined credential.
    ///
    /// # Errors
    ///
    /// Fails unless the caller's effective UID is the owner, when `authorize` or a recheck fails,
    /// or when the unlink is refused or uncertain. It is never retried.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub fn unlink(mut self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Removed> {
        authorize()?;
        self.recheck()?;
        require(
            crate::process_identity::effective_uid() == self.owner,
            "credential unlink writer authority",
        )?;
        let entry = crate::directory_entry::Entry::observe(&self.parent, &self.quarantine)?;
        entry.matches(&self.file)?;
        let leaf = name(&self.quarantine)?;
        authorize()?;
        self.recheck()?;
        entry.recheck()?;
        require(
            // SAFETY: `leaf` is a NUL-terminated CString and `self.parent` keeps the descriptor
            // open.
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), leaf.as_ptr(), 0) } == 0,
            "credential unlink refused/uncertain; no retry",
        )?;
        let mut expected = self.epoch;
        let after = files::identity(&self.file.metadata()?);
        require(
            expected.10 == 1 && after.10 == 0 && (after.5, after.6) >= (expected.5, expected.6),
            "credential unlink epoch/link count",
        )?;
        expected.5 = after.5;
        expected.6 = after.6;
        expected.10 = 0;
        require(
            expected == after,
            "credential changed beyond original unlink",
        )?;
        require(
            self.members.remove(self.quarantine.as_os_str()),
            "original credential quarantine membership missing",
        )?;
        require(
            names(&self.parent)? == self.members,
            "credential unlink parent changed outside original removal",
        )?;
        self.parent.sync_all()?;
        let removed = Removed {
            original: self,
            epoch: after,
        };
        removed.recheck()?;
        authorize()?;
        Ok(removed)
    }
}
/// Proof of an owned credential unlink.
pub struct Removed {
    original: Quarantined,
    epoch: files::FileIdentity,
}
impl Removed {
    /// Verify the removed credential and its parent are unchanged and no name reappeared.
    ///
    /// # Errors
    ///
    /// Fails when any of them changed.
    pub fn recheck(&self) -> Result<()> {
        let q = &self.original;
        require(
            shape(&q.parent, q.owner)? == q.shape
                && mount_identity::id(q.parent.as_fd(), true)? == q.parent_mount
                && files::identity(&q.file.metadata()?) == self.epoch
                && self.epoch.10 == 0
                && mount_identity::id(q.file.as_fd(), true)? == q.mount
                && crate::files::status_flags(&q.file) == q.flags
                && files::optional_relative(&q.parent, &q.original)?.is_none()
                && files::optional_relative(&q.parent, &q.quarantine)?.is_none(),
            "original retired credential changed or names/membership reappeared",
        )
    }
    /// Credential epoch before quarantine.
    ///
    /// # Errors
    ///
    /// Fails on [`Removed::recheck`].
    pub fn before_epoch(&self) -> Result<files::FileIdentity> {
        self.recheck()?;
        Ok(self.original.before)
    }
    /// The removed credential's description.
    ///
    /// # Errors
    ///
    /// Fails on [`Removed::recheck`].
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.original.file)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(std::env::var_os("ENZIMOS_TEST_TMPDIR").map_or_else(
                || std::env::current_dir().unwrap(),
                std::path::PathBuf::from,
            ))
            .unwrap()
    }
    #[test]
    fn actual_private_credential_retains_original_unlinked_description_and_refuses_reappearance() {
        let d = fixture();
        let uid = crate::process_identity::effective_uid();
        let path = d.path().join("secret");
        std::fs::write(&path, b"fixture-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let parent = files::directory(d.path(), Some(uid)).unwrap();
        let file = files::open_relative(&parent, Path::new("secret")).unwrap();
        let before = files::identity(&file.metadata().unwrap());
        let q = Quarantined::enter_original(
            &parent,
            &file,
            Path::new("secret"),
            before,
            uid,
            &mut || Ok(()),
        )
        .unwrap();
        assert!(!path.exists());
        let removed = q.unlink(&mut || Ok(())).unwrap();
        assert_eq!(removed.before_epoch().unwrap(), before);
        assert_eq!(removed.descriptor().unwrap().metadata().unwrap().nlink(), 0);
        removed.recheck().unwrap();
        std::fs::write(&path, b"fixture-only").unwrap();
        assert!(removed.recheck().is_err());
    }
}
