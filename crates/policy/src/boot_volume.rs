// SPDX-License-Identifier: MIT
//! Retained ESP and artifact identities for loader publication and observations.
use crate::{recovery_devices, recovery_records, storage_runtime, topology};
use enzimos_platform::{Error, Result, files, mount_identity, process, require, stream_copy};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};
fn probe_uuid(device: &File) -> Result<String> {
    let output = process::run_with_fds(
        "/usr/bin/blkid",
        &["-p", "-s", "UUID", "-o", "value", "@fd:0"],
        &[],
        Duration::from_secs(30),
        4096,
        &[device.as_fd()],
    )?;
    require(output.status.success(), "mounted ESP UUID probe refused")?;
    let uuid = std::str::from_utf8(&output.stdout)
        .map_err(|_| Error("boot UUID encoding".into()))?
        .trim()
        .to_owned();
    recovery_records::fat_uuid(&uuid)?;
    Ok(uuid)
}
pub struct Volume {
    pub directory: File,
    pub uuid: String,
    pub unique: u64,
    normal: u64,
    device: topology::Device,
    topology: topology::Graph,
}
impl Volume {
    pub fn writable(&self) -> Result<()> {
        self.recheck()?;
        let rows = storage_runtime::rows()?;
        let row = rows
            .iter()
            .find(|r| r.target == "/boot")
            .ok_or_else(|| Error("boot mount missing".into()))?;
        require(
            row.options.split(',').any(|s| s == "rw") && !row.options.split(',').any(|s| s == "ro"),
            "boot mount is read-only",
        )
    }
    pub fn observe() -> Result<Self> {
        storage_runtime::initial_namespace()?;
        let directory = files::directory(Path::new("/boot"), Some(0))?;
        let unique = mount_identity::id(directory.as_fd(), true)?;
        let normal = mount_identity::id(directory.as_fd(), false)?;
        let rows = storage_runtime::rows()?;
        let rows = rows
            .iter()
            .filter(|row| row.target == "/boot")
            .collect::<Vec<_>>();
        require(
            rows.len() == 1 && rows[0].id == normal && rows[0].filesystem == "vfat",
            "boot volume mount identity changed",
        )?;
        let device = (rows[0].major, rows[0].minor);
        // Probe the mounted block itself. RAM recovery has no udev tag cache,
        // so findmnt's UUID column can be empty despite a valid mounted ESP.
        let block = recovery_devices::Block::by_device(device)?;
        let uuid = probe_uuid(&block.file)?;
        block.recheck()?;

        let graph = topology::observe(&[device])?;
        let volume = Self {
            directory,
            uuid,
            unique,
            normal,
            device,
            topology: graph,
        };
        volume.recheck()?;
        Ok(volume)
    }
    pub fn recheck(&self) -> Result<()> {
        storage_runtime::initial_namespace()?;
        let current = files::directory(Path::new("/boot"), Some(0))?;
        let a = self.directory.metadata()?;
        let b = current.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
                && mount_identity::id(current.as_fd(), true)? == self.unique
                && mount_identity::id(self.directory.as_fd(), true)? == self.unique,
            "boot mount replaced",
        )?;
        let rows = storage_runtime::rows()?;
        let found = rows
            .iter()
            .filter(|r| r.target == "/boot")
            .collect::<Vec<_>>();
        require(
            found.len() == 1
                && found[0].id == self.normal
                && found[0].filesystem == "vfat"
                && (found[0].major, found[0].minor) == self.device,
            "boot mount missing, shadowed or wrong filesystem",
        )?;
        require(
            topology::observe(&[self.device])? == self.topology,
            "boot disk topology or disk sequence changed",
        )
    }
    pub fn directory(&self, relative: &Path) -> Result<File> {
        let path = self.path(relative)?;
        let file = files::directory(&path, Some(0))?;
        require(
            mount_identity::id(file.as_fd(), true)? == self.unique,
            "boot folder crosses another mount",
        )?;
        self.recheck()?;
        Ok(file)
    }
    pub fn path(&self, relative: &Path) -> Result<PathBuf> {
        require(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
                && relative.as_os_str().len() <= 4096,
            "invalid relative boot path",
        )?;
        Ok(Path::new("/boot").join(relative))
    }
    pub fn artifact(&self, relative: &Path, limit: u64) -> Result<Artifact> {
        self.recheck()?;
        let path = self.path(relative)?;
        let parent = self.directory(relative.parent().unwrap_or_else(|| Path::new("")))?;
        let mut file = files::open_relative(
            &parent,
            Path::new(
                relative
                    .file_name()
                    .ok_or_else(|| Error("boot artifact filename".into()))?,
            ),
        )?;
        require(
            mount_identity::id(file.as_fd(), true)? == self.unique,
            "boot artifact crosses another mount",
        )?;
        let metadata = files::identity(&file.metadata()?);
        let (bytes, sha) = stream_copy::hash(&mut file, limit, Some(0))?;
        let artifact = Artifact {
            path,
            file,
            metadata,
            bytes,
            sha,
            unique: self.unique,
        };
        artifact.recheck()?;
        self.recheck()?;
        Ok(artifact)
    }
}
pub struct Artifact {
    pub path: PathBuf,
    pub file: File,
    metadata: files::FileIdentity,
    pub bytes: u64,
    pub sha: String,
    unique: u64,
}
impl Artifact {
    /// Recognize only the actual retirement of this original inventory member.
    /// Used before retiring its parent directory; a decoded before/after tuple
    /// cannot supply the retained Removed actor or the old file description.
    pub fn require_owned_removal(
        &self,
        removed: &enzimos_platform::named_retirement::Removed,
    ) -> Result<()> {
        removed.recheck()?;
        let parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let a = parent.metadata()?;
        let b = removed.parent()?.metadata()?;
        require(
            removed.before_epoch()? == self.metadata
                && removed.original_name()?
                    == Path::new(
                        self.path
                            .file_name()
                            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
                    )
                && files::identity(&self.file.metadata()?)
                    == files::identity(&removed.descriptor()?.metadata()?)
                && mount_identity::id(self.file.as_fd(), true)? == self.unique
                && mount_identity::id(removed.parent()?.as_fd(), true)? == self.unique
                && (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                    == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid()),
            "retirement differs from original boot artifact/parent",
        )?;
        removed.recheck()
    }
    /// Bind destructive preparation to this original private epoch before
    /// mutation. A post-removal comparison alone cannot protect changed bytes.
    pub fn quarantine_original(
        &self,
        parent: &File,
        maximum: u64,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<enzimos_platform::named_retirement::Quarantined> {
        self.recheck()?;
        let named_parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let a = named_parent.metadata()?;
        let b = parent.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid())
                && mount_identity::id(parent.as_fd(), true)? == self.unique,
            "original boot artifact quarantine parent differs",
        )?;
        enzimos_platform::named_retirement::Quarantined::enter_original(
            parent,
            &self.file,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
            0,
            maximum,
            self.metadata,
            authorize,
        )
    }
    pub fn require_original_publication(
        &self,
        pending: &enzimos_platform::publication::Prepared,
    ) -> Result<()> {
        pending.require_original_epoch(&self.file, self.metadata)
    }
    /// Join this independently retained artifact to an actual replacement.
    /// Decoded epochs and freshly reopened paths cannot supply its predecessor.
    pub fn require_owned_replacement(
        &self,
        committed: &enzimos_platform::publication::Committed,
    ) -> Result<()> {
        let parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        committed.require_destination(
            &parent,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let (old, before) = committed.replaced_original()?;
        require(
            before == self.metadata
                && files::identity(&old.metadata()?) == files::identity(&self.file.metadata()?)
                && mount_identity::id(old.as_fd(), true)? == self.unique
                && mount_identity::id(self.file.as_fd(), true)? == self.unique,
            "replacement differs from independently original boot artifact",
        )?;
        committed.recheck()
    }
    /// Consume only the actual replacement of this independently held original
    /// artifact. Existing output data or a newly reopened old filename cannot
    /// supply the publication's retained predecessor description.
    pub fn into_replaced(
        self,
        committed: enzimos_platform::publication::Committed,
    ) -> Result<ReplacedArtifact> {
        let parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        committed.require_destination(
            &parent,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let (old, before) = committed.replaced_original()?;
        require(
            before == self.metadata
                && files::identity(&old.metadata()?) == files::identity(&self.file.metadata()?)
                && mount_identity::id(old.as_fd(), true)? == self.unique
                && mount_identity::id(self.file.as_fd(), true)? == self.unique,
            "publication differs from independently held original boot artifact",
        )?;
        let replaced = ReplacedArtifact {
            original: self,
            committed,
        };
        replaced.recheck()?;
        Ok(replaced)
    }
    /// Consume this original inventory artifact into its actual owned removal.
    /// Admission occurs while the original parent still exists. Later checks
    /// retain descriptors and do not reopen a deliberately retired directory.
    pub fn into_retired(
        self,
        removed: enzimos_platform::named_retirement::Removed,
    ) -> Result<RetiredArtifact> {
        self.require_owned_removal(&removed)?;
        let retired = RetiredArtifact {
            original: self,
            removed,
        };
        retired.recheck()?;
        Ok(retired)
    }
    pub fn recheck(&self) -> Result<()> {
        let parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let current = files::open_relative(
            &parent,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        require(
            files::identity(&self.file.metadata()?) == self.metadata
                && files::identity(&current.metadata()?) == self.metadata
                && mount_identity::id(current.as_fd(), true)? == self.unique
                && mount_identity::id(self.file.as_fd(), true)? == self.unique,
            "boot artifact replaced or changed",
        )
    }
}

/// Original artifact plus its actual removal proof. No value constructor or
/// destructor mutation exists, and its original parent descriptor stays held.
pub struct RetiredArtifact {
    original: Artifact,
    removed: enzimos_platform::named_retirement::Removed,
}
impl RetiredArtifact {
    pub(crate) fn removal(&self) -> Result<&enzimos_platform::named_retirement::Removed> {
        self.recheck()?;
        Ok(&self.removed)
    }

    pub fn recheck(&self) -> Result<()> {
        self.removed.recheck()?;
        require(
            self.removed.before_epoch()? == self.original.metadata
                && self.removed.original_name()?
                    == Path::new(
                        self.original
                            .path
                            .file_name()
                            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
                    )
                && files::identity(&self.original.file.metadata()?)
                    == files::identity(&self.removed.descriptor()?.metadata()?)
                && mount_identity::id(self.original.file.as_fd(), true)? == self.original.unique
                && mount_identity::id(self.removed.parent()?.as_fd(), true)?
                    == self.original.unique,
            "retired original artifact changed outside actual owned removal",
        )?;
        self.removed.recheck()
    }
    /// Join another independently retained observation of this same original
    /// artifact to the actual removal. JSON/inode claims cannot supply either.
    pub fn require_original(&self, original: &Artifact) -> Result<()> {
        self.recheck()?;
        require(
            original.path == self.original.path
                && original.metadata == self.original.metadata
                && original.unique == self.original.unique
                && original.bytes == self.original.bytes
                && original.sha == self.original.sha
                && files::identity(&original.file.metadata()?)
                    == files::identity(&self.removed.descriptor()?.metadata()?)
                && mount_identity::id(original.file.as_fd(), true)? == self.original.unique,
            "retirement requires independently retained original artifact",
        )?;
        self.recheck()
    }
    pub fn path(&self) -> Result<&Path> {
        self.recheck()?;
        Ok(&self.original.path)
    }
}

/// Original metadata artifact and its actual replacement witness, retained
/// through receipt completion. The original unlinked descriptor stays live.
pub struct ReplacedArtifact {
    original: Artifact,
    committed: enzimos_platform::publication::Committed,
}
impl ReplacedArtifact {
    pub(crate) fn require_original(&self, other: &Artifact) -> Result<()> {
        self.recheck()?;
        require(
            other.metadata == self.original.metadata
                && other.unique == self.original.unique
                && other.path == self.original.path
                && files::identity(&other.file.metadata()?)
                    == files::identity(&self.original.file.metadata()?),
            "owned replacement does not belong to independently retained original artifact",
        )?;
        self.recheck()
    }

    pub(crate) fn require_parent_member(&self, parent: &File, name: &Path) -> Result<()> {
        self.recheck()?;
        require(
            self.original.path.file_name() == name.file_name() && name.components().count() == 1,
            "owned replacement leaf differs from original",
        )?;
        self.committed.require_destination(parent, name)?;
        let named = files::open_relative(parent, name)?;
        require(
            files::identity(&named.metadata()?) == files::identity(&self.file()?.metadata()?)
                && mount_identity::id(parent.as_fd(), true)? == self.original.unique,
            "owned replacement parent differs from original volume",
        )?;
        self.recheck()
    }

    pub fn recheck(&self) -> Result<()> {
        self.committed.recheck()?;
        let parent = files::directory(
            self.original
                .path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        self.committed.require_destination(
            &parent,
            Path::new(
                self.original
                    .path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let (old, before) = self.committed.replaced_original()?;
        require(
            before == self.original.metadata
                && files::identity(&old.metadata()?)
                    == files::identity(&self.original.file.metadata()?)
                && mount_identity::id(self.original.file.as_fd(), true)? == self.original.unique
                && mount_identity::id(self.committed.file()?.as_fd(), true)?
                    == self.original.unique,
            "replaced original boot artifact changed outside owned publication",
        )?;
        self.committed.recheck()
    }
    pub fn file(&self) -> Result<&File> {
        self.recheck()?;
        self.committed.file()
    }
}
