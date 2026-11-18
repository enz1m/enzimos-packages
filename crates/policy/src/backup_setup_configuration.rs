// SPDX-License-Identifier: MIT
//! One private configuration publication from the original coordinator/credential.
use crate::{
    backup_published_credential::Published,
    backup_setup_context::{Prepared, Step},
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const LIMIT: usize = 32768;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected setup configuration parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn absent(parent: &File, name: &str) -> Result<()> {
    require(
        files::optional_relative(parent, Path::new(name))?.is_none(),
        "configuration/partial setup already exists; no replay",
    )
}
fn initial(
    context: &Prepared<'_, '_, '_, '_>,
    credential: &Published,
    parent: &File,
) -> Result<()> {
    context.check_source(credential.source(), Some(credential.owner()))?;
    credential.recheck()?;
    for name in ["backup.json", ".backup-setup-config"] {
        absent(parent, name)?;
    }
    for name in [
        "backup-destination.json",
        "backup.enabled",
        "backup-setup.json",
    ] {
        absent(credential.source().control(), name)?;
    }
    Ok(())
}
/// Holds original native-published bytes and their inode; never adopts an equal
/// replacement. Its fields contain no credential contents or password digest.
pub struct Configuration<'a> {
    credential: &'a Published,
    parent: File,
    parent_shape: Shape,
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
}
impl<'a> Configuration<'a> {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fsync, linkat, unlinkat).")]
    pub fn publish(
        context: &Prepared<'_, '_, '_, '_>,
        credential: &'a Published,
        lock: &files::Lock,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        crate::namespaces::initial()?;
        crate::operation::root_only()?;
        lock.recheck()?;
        authorize()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let parent_shape = shape(&parent)?;
        require(
            parent_shape.0 == credential.source().root_device()
                && mount_identity::id(parent.as_fd(), true)? == credential.source().root_mount_id(),
            "setup configuration outside original Root",
        )?;
        initial(context, credential, &parent)?;
        let v = value!({"repository":crate::backup_configuration::REPOSITORY,
            "password_file":crate::backup_configuration::PASSWORD,"destination_uuid":context.filesystem()});
        crate::backup_configuration::validate(&v)?;
        let bytes = json::canonical(&v)?;
        context.claim(Step::Configuration)?;
        lock.recheck()?;
        authorize()?;
        initial(context, credential, &parent)?;
        // This fixed private draft persists on failure and blocks repetition.
        let draft = files::atomic_relative_retained(
            &parent,
            Path::new(".backup-setup-config"),
            &bytes,
            0o600,
            Some(0),
            false,
            LIMIT,
        )?;
        let original = files::identity(&draft.metadata()?);
        let check = || {
            context.check_source(credential.source(), Some(credential.owner()))?;
            credential.recheck()?;
            lock.recheck()?;
            let named_parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
            let named = files::open_relative(&parent, Path::new(".backup-setup-config"))?;
            require(
                shape(&named_parent)? == parent_shape
                    && shape(&parent)? == parent_shape
                    && mount_identity::id(named_parent.as_fd(), true)?
                        == credential.source().root_mount_id()
                    && files::identity(&named.metadata()?) == original
                    && files::identity(&draft.metadata()?) == original
                    && mount_identity::id(named.as_fd(), true)?
                        == credential.source().root_mount_id()
                    && draft.metadata()?.uid() == 0
                    && draft.metadata()?.gid() == 0
                    && draft.metadata()?.mode() & 0o7777 == 0o600
                    && draft.metadata()?.nlink() == 1
                    && files::read_file(&draft, LIMIT, Some(0), true)? == bytes,
                "original private setup draft changed",
            )?;
            absent(&parent, "backup.json")?;
            for name in [
                "backup-destination.json",
                "backup.enabled",
                "backup-setup.json",
            ] {
                absent(credential.source().control(), name)?;
            }
            authorize()
        };
        check()?;
        require(
            unsafe {
                libc::linkat(
                    parent.as_raw_fd(),
                    c".backup-setup-config".as_ptr(),
                    parent.as_raw_fd(),
                    c"backup.json".as_ptr(),
                    0,
                )
            } == 0,
            "configuration publication refused; draft retained",
        )?;
        let file = files::open_relative(&parent, Path::new("backup.json"))?;
        let named_draft = files::open_relative(&parent, Path::new(".backup-setup-config"))?;
        let held = draft.metadata()?;
        require(
            held.nlink() == 2
                && [file.metadata()?, named_draft.metadata()?]
                    .iter()
                    .all(|m| files::identity(m) == files::identity(&held))
                && held.dev() == original.0
                && held.ino() == original.1
                && held.len() == original.2
                && held.mtime() == original.3
                && held.mtime_nsec() == original.4
                && held.uid() == 0
                && held.gid() == 0
                && held.mode() & 0o7777 == 0o600,
            "configuration publication original inode changed",
        )?;
        require(
            unsafe { libc::unlinkat(parent.as_raw_fd(), c".backup-setup-config".as_ptr(), 0) } == 0
                && unsafe { libc::fsync(parent.as_raw_fd()) } == 0,
            "configuration publication durability unknown",
        )?;
        let this = Self {
            credential,
            parent_shape,
            parent,
            identity: crate::backup_publication_identity::after_unlink(original, &file)?,
            file,
            bytes,
        };
        this.recheck()?;
        context.check_source(credential.source(), Some(credential.owner()))?;
        lock.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.credential.recheck()?;
        crate::backup_publication_identity::recheck(
            &self.parent,
            "backup.json",
            &self.file,
            self.identity,
            self.credential.source().root_mount_id(),
            0,
        )?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new("backup.json"))?;
        require(
            shape(&parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)?
                    == self.credential.source().root_mount_id()
                && mount_identity::id(self.parent.as_fd(), true)?
                    == self.credential.source().root_mount_id()
                && files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)?
                    == self.credential.source().root_mount_id()
                && mount_identity::id(self.file.as_fd(), true)?
                    == self.credential.source().root_mount_id()
                && self.file.metadata()?.uid() == 0
                && self.file.metadata()?.gid() == 0
                && self.file.metadata()?.mode() & 0o7777 == 0o600
                && self.file.metadata()?.nlink() == 1
                && files::read_file(&self.file, LIMIT, Some(0), true)? == self.bytes,
            "original published setup configuration changed",
        )?;
        absent(&self.parent, ".backup-setup-config")
    }
    /// Failure rollback of an incomplete setup: remove exactly this run's
    /// configuration (its credential is retracted separately, afterwards).
    pub fn retract(&self, lock: &files::Lock) -> Result<()> {
        lock.recheck()?;
        self.recheck()?;
        crate::backup_publication_identity::retract(&self.parent, c"backup.json")?;
        lock.recheck()
    }
    pub fn public_bytes(&self) -> Result<&[u8]> {
        self.recheck()?;
        Ok(&self.bytes)
    }
    pub fn value(&self) -> Result<Value> {
        self.recheck()?;
        json::decode(&self.bytes, LIMIT)
    }
    pub fn credential_binding(&self) -> Result<Value> {
        self.recheck()?;
        self.credential.binding()
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub fn credential_descriptor(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        self.recheck()?;
        self.credential.descriptor()
    }
    pub(crate) fn credential_owner(&self) -> u32 {
        self.credential.owner()
    }
}
