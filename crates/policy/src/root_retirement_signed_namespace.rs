// SPDX-License-Identifier: MIT
//! Original fixed ESP signing namespace and one owned directory preparation.
//! Existing paths, directory metadata and decoded evidence are not constructors.
use crate::{
    boot_volume::{Artifact, Volume},
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const PARENT: &str = "enzimos";
const CHILD: &str = "secure-boot";
struct Directory {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
}
impl Directory {
    fn retain(file: File, mount: u64) -> Result<Self> {
        let m = file.metadata()?;
        let flags = enzimos_platform::files::status_flags(&file);
        require(
            m.is_dir()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o022 == 0
                && flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original signing namespace protected read-only directory required",
        )?;
        Ok(Self {
            file,
            epoch: files::identity(&m),
            flags,
        })
    }
    fn recheck(&self, named: &File, mount: u64) -> Result<()> {
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && enzimos_platform::files::status_flags(&self.file) == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == mount
                && mount_identity::id(named.as_fd(), true)? == mount,
            "original signing namespace directory changed/replaced/covered",
        )
    }
}
fn names(file: &File, limit: usize) -> Result<BTreeSet<String>> {
    files::directory_names(file, limit)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| enzimos_platform::Error("signing namespace member encoding".into()))?;
            crate::identity::safe_id(&name)?;
            Ok(name)
        })
        .collect()
}
fn same_object(before: files::FileIdentity, after: files::FileIdentity) -> bool {
    (before.0, before.1, before.7, before.8, before.9)
        == (after.0, after.1, after.7, after.8, after.9)
}
pub(crate) struct Original<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    volume: Volume,
    parent: Directory,
    parent_names: BTreeSet<String>,
    siblings: BTreeMap<String, Directory>,
    folder: Option<Directory>,
    members: BTreeMap<String, Artifact>,
    member_flags: BTreeMap<String, i32>,
}
/// The fixed ESP parent exists only once something was published there (a
/// boot generation or a signed UKI). A fresh install has none; an observation
/// that is not a signing actor then only proves and rechecks its absence.
#[expect(
    clippy::large_enum_variant,
    reason = "Built once per operation and rarely moved; boxing would only add an allocation."
)]
pub(crate) enum Namespace<'a> {
    Present(Original<'a>),
    Absent {
        guard: &'a Guard,
        lock: &'a files::Lock,
        volume: Volume,
    },
}
/// Whether a fixed ESP path is absent (exact ENOENT); any other error refuses.
pub(crate) fn absent(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(false),
    }
}
impl<'a> Namespace<'a> {
    pub(crate) fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        authorize()?;
        let volume = Volume::observe()?;
        if !absent(&volume.path(Path::new(PARENT))?)? {
            drop(volume);
            return Ok(Self::Present(Original::observe(guard, lock, authorize)?));
        }
        let this = Self::Absent {
            guard,
            lock,
            volume,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        match self {
            Self::Present(original) => original.recheck(authorize),
            Self::Absent {
                guard,
                lock,
                volume,
            } => {
                crate::operation::root_only()?;
                crate::namespaces::initial()?;
                authorize()?;
                guard.recheck()?;
                lock.recheck()?;
                volume.writable()?;
                require(
                    absent(&volume.path(Path::new(PARENT))?)?,
                    "originally absent signing namespace parent appeared",
                )?;
                authorize()
            }
        }
    }
    /// The signing actor that staging requires; absent before any publication.
    pub(crate) fn original(&self) -> Result<&Original<'a>> {
        match self {
            Self::Present(original) => Ok(original),
            Self::Absent { .. } => Err(enzimos_platform::Error(
                "ESP signing namespace parent /boot/enzimos is absent".into(),
            )),
        }
    }
    pub(crate) fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        match self {
            Self::Present(original) => original.evidence(authorize),
            Self::Absent { volume, .. } => {
                self.recheck(authorize)?;
                Ok(json!({"parent_absent":true,"boot_uuid":volume.uuid,
                    "mount":volume.unique,"execution_authorized":false}))
            }
        }
    }
}
pub struct Prepared<'a> {
    original: Original<'a>,
    folder: Directory,
    parent_epoch: files::FileIdentity,
    parent_names: BTreeSet<String>,
    created: bool,
}
impl<'a> Original<'a> {
    pub(crate) fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        authorize()?;
        let volume = Volume::observe()?;
        volume.writable()?;
        let parent = Directory::retain(volume.directory(Path::new(PARENT))?, volume.unique)?;
        let parent_names = names(&parent.file, 128)?;
        let mut siblings = BTreeMap::new();
        for name in parent_names.iter().filter(|name| name.as_str() != CHILD) {
            siblings.insert(
                name.clone(),
                Directory::retain(
                    files::directory_relative(&parent.file, Path::new(name), Some(0))?,
                    volume.unique,
                )?,
            );
        }
        let folder = files::optional_directory_relative(&parent.file, Path::new(CHILD), Some(0))?
            .map(|folder| Directory::retain(folder, volume.unique))
            .transpose()?;
        let mut members = BTreeMap::new();
        let mut member_flags = BTreeMap::new();
        let mut total = 0u64;
        if let Some(folder) = &folder {
            for name in names(&folder.file, 128)? {
                crate::identity::sha(name.strip_suffix(".efi").ok_or_else(|| {
                    enzimos_platform::Error(
                        "unknown or interrupted signing namespace member".into(),
                    )
                })?)?;
                let artifact = volume.artifact(
                    Path::new(&format!("{PARENT}/{CHILD}/{name}")),
                    256 * 1024 * 1024,
                )?;
                total = total.checked_add(artifact.bytes).ok_or_else(|| {
                    enzimos_platform::Error("signing namespace byte overflow".into())
                })?;
                require(
                    total <= 4 * 1024 * 1024 * 1024,
                    "original signing namespace byte bound",
                )?;
                let flags = enzimos_platform::files::status_flags(&artifact.file);
                require(
                    flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
                    "original signing member read-only description required",
                )?;
                member_flags.insert(name.clone(), flags);
                members.insert(name, artifact);
            }
        }
        let this = Self {
            guard,
            lock,
            volume,
            parent,
            parent_names,
            siblings,
            folder,
            members,
            member_flags,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.source_barrier(authorize)?;
        self.parent.recheck(
            &self.volume.directory(Path::new(PARENT))?,
            self.volume.unique,
        )?;
        require(
            names(&self.parent.file, 128)? == self.parent_names,
            "original signing parent membership changed",
        )?;
        let named =
            files::optional_directory_relative(&self.parent.file, Path::new(CHILD), Some(0))?;
        match (&self.folder, named) {
            (None, None) => (),
            (Some(original), Some(named)) => {
                original.recheck(&named, self.volume.unique)?;
                require(
                    names(&original.file, 128)? == self.members.keys().cloned().collect(),
                    "original signing namespace membership changed",
                )?;
            }
            _ => {
                return Err(enzimos_platform::Error(
                    "original signing namespace appeared/disappeared".into(),
                ));
            }
        }
        self.original_members(authorize)?;
        self.source_barrier(authorize)
    }
    fn source_barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.volume.writable()?;
        authorize()
    }
    fn original_members(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        for (name, sibling) in &self.siblings {
            sibling.recheck(
                &files::directory_relative(&self.parent.file, Path::new(name), Some(0))?,
                self.volume.unique,
            )?;
            authorize()?;
        }
        for (name, member) in &self.members {
            require(
                enzimos_platform::files::status_flags(&member.file) == self.member_flags[name],
                "original signing member description flags changed",
            )?;
            member.recheck()?;
            authorize()?;
        }
        Ok(())
    }
    pub(crate) fn require_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "signing namespace belongs to another original guard/lock",
        )?;
        self.source_barrier(authorize)
    }
    fn same_original(
        &self,
        other: &Original<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.source_barrier(authorize)?;
        other.source_barrier(authorize)?;
        require(
            std::ptr::eq(self.guard, other.guard)
                && std::ptr::eq(self.lock, other.lock)
                && self.volume.unique == other.volume.unique
                && self.volume.uuid == other.volume.uuid
                && self.parent.epoch == other.parent.epoch
                && self.parent.flags == other.parent.flags
                && self.parent_names == other.parent_names
                && self.folder.as_ref().map(|d| (d.epoch, d.flags))
                    == other.folder.as_ref().map(|d| (d.epoch, d.flags))
                && self.siblings.keys().eq(other.siblings.keys())
                && self.members.keys().eq(other.members.keys())
                && self.member_flags == other.member_flags,
            "owned signing namespace differs from independently original source",
        )?;
        for (name, directory) in &self.siblings {
            let original = &other.siblings[name];
            require(
                directory.epoch == original.epoch && directory.flags == original.flags,
                "original signing sibling description differs",
            )?;
        }
        self.original_members(authorize)?;
        other.original_members(authorize)?;
        for (name, member) in &self.members {
            let original = &other.members[name];
            require(
                files::identity(&member.file.metadata()?)
                    == files::identity(&original.file.metadata()?)
                    && member.sha == original.sha
                    && member.bytes == original.bytes,
                "original signing namespace member differs",
            )?;
        }
        self.source_barrier(authorize)?;
        other.source_barrier(authorize)
    }
    pub(crate) fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"parent_epoch":self.parent.epoch,"parent_flags":self.parent.flags,
            "folder_epoch":self.folder.as_ref().map(|d| d.epoch),
            "folder_flags":self.folder.as_ref().map(|d| d.flags),"boot_uuid":self.volume.uuid,
            "mount":self.volume.unique,"parent_members":self.parent_names,
            "siblings":self.siblings.iter().map(|(n,d)| (n.clone(),json!({"epoch":d.epoch,"flags":d.flags}))).collect::<BTreeMap<_,_>>(),
            "members":self.members.iter().map(|(n,a)| Ok((n.clone(),json!({"epoch":files::identity(&a.file.metadata()?),"sha256":a.sha,"bytes":a.bytes,"flags":self.member_flags[n]}))))
                .collect::<Result<BTreeMap<_,_>>>()?,"execution_authorized":false}),
        )
    }
    /// Consume one original absence into exactly one mkdir; failures preserve
    /// evidence and have no deletion, retry, rollback or Drop cleanup.
    pub(crate) fn prepare(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Prepared<'a>> {
        self.recheck(authorize)?;
        let created = self.folder.is_none();
        require(
            !created || self.parent_names.len() < 128,
            "new signing namespace requires parent membership headroom",
        )?;
        authorize()?;
        self.recheck(authorize)?;
        let file = match &self.folder {
            Some(folder) => folder.file.try_clone()?,
            None => files::create_directory_relative(
                &self.parent.file,
                Path::new(CHILD),
                files::public_directory_mode(&self.parent.file)?,
                0,
            )?,
        };
        file.sync_all()?;
        self.parent.file.sync_all()?;
        let folder = Directory::retain(file, self.volume.unique)?;
        let parent_epoch = files::identity(&self.parent.file.metadata()?);
        require(
            same_object(self.parent.epoch, parent_epoch)
                && (parent_epoch.10 == self.parent.epoch.10
                    || (created && self.parent.epoch.10.checked_add(1) == Some(parent_epoch.10))),
            "owned signing directory creation changed original parent identity/protection",
        )?;
        if !created {
            require(
                parent_epoch == self.parent.epoch,
                "existing signing parent epoch changed",
            )?;
        }
        let mut parent_names = self.parent_names.clone();
        parent_names.insert(CHILD.into());
        let prepared = Prepared {
            original: self,
            folder,
            parent_epoch,
            parent_names,
            created,
        };
        prepared.recheck(authorize)?;
        Ok(prepared)
    }
}
impl<'a> Prepared<'a> {
    fn parent_barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.original.source_barrier(authorize)?;
        let named = self.original.volume.directory(Path::new(PARENT))?;
        require(
            files::identity(&self.original.parent.file.metadata()?) == self.parent_epoch
                && files::identity(&named.metadata()?) == self.parent_epoch
                && enzimos_platform::files::status_flags(&self.original.parent.file)
                    == self.original.parent.flags
                && mount_identity::id(named.as_fd(), true)? == self.original.volume.unique
                && mount_identity::id(self.original.parent.file.as_fd(), true)?
                    == self.original.volume.unique
                && names(&self.original.parent.file, 128)? == self.parent_names,
            "actual prepared signing parent changed/replaced/covered",
        )?;
        require(
            enzimos_platform::files::status_flags(&self.folder.file) == self.folder.flags
                && mount_identity::id(self.folder.file.as_fd(), true)?
                    == self.original.volume.unique
                && same_object(
                    self.folder.epoch,
                    files::identity(&self.folder.file.metadata()?),
                ),
            "actual prepared signing directory description changed",
        )?;
        self.original.original_members(authorize)?;
        self.original.source_barrier(authorize)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.parent_barrier(authorize)?;
        self.folder.recheck(
            &files::directory_relative(&self.original.parent.file, Path::new(CHILD), Some(0))?,
            self.original.volume.unique,
        )?;
        require(
            names(&self.folder.file, 128)? == self.original.members.keys().cloned().collect(),
            "actual prepared signing namespace membership changed",
        )?;
        self.original.original_members(authorize)?;
        self.original.source_barrier(authorize)
    }
    /// Derive signing input only from the actual staged receipt, then consume
    /// this namespace through the actual retained signer. Partial errors remain
    /// durable; no retry, named-output adoption or rollback is available.
    pub(crate) fn sign(
        self,
        receipt: &crate::root_retirement_online_journal::Published<'_>,
        protected: &crate::root_retirement_online_stage_targets::Protected<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>> {
        receipt.require_source(self.original.guard, self.original.lock)?;
        self.recheck(authorize)?;
        protected.recheck_signing(receipt, &State::Prepared(&self), authorize)?;
        let record = receipt.record()?;
        let coordinator = &record["coordinator"];
        let text = crate::root_retirement_boot_contract::entries(
            crate::recovery_records::text(coordinator, "options")?,
            crate::recovery_records::text(coordinator, "image")?,
        )?
        .uefi;
        let wrapped =
            crate::signed_entry::wrap_retained_authorized(&text, self.original.lock, &mut || {
                receipt.require_source(self.original.guard, self.original.lock)?;
                self.parent_barrier(authorize)
            })?;
        let result = self.finish(wrapped, authorize)?;
        result.require_original_entry(&text, authorize)?;
        protected.recheck_signing(receipt, &State::Published(&result), authorize)?;
        receipt.require_source(
            result.prepared.original.guard,
            result.prepared.original.lock,
        )?;
        result.recheck(authorize)?;
        Ok(result)
    }
    /// Consume only the actual retained signer output, preserving original
    /// unrelated members. Cold files and reopened paths cannot supply creation.
    pub(crate) fn finish(
        self,
        wrapped: crate::signed_entry::Wrapped,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Published<'a>>
    where
        Self: Sized,
    {
        self.parent_barrier(authorize)?;
        let output = wrapped.namespace_output(&self.folder.file, self.folder.epoch, authorize)?;
        let mut expected = self
            .original
            .members
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let current = files::identity(&self.folder.file.metadata()?);
        require(
            same_object(self.folder.epoch, current) && self.folder.epoch.10 == current.10,
            "owned signer changed namespace directory identity/protection/links",
        )?;
        if let Some((leaf, epoch, created)) = &output {
            if *created {
                require(
                    !expected.contains(leaf),
                    "signer creation cannot adopt original namespace member",
                )?;
                expected.insert(leaf.clone());
                require(
                    self.original
                        .members
                        .values()
                        .map(|a| a.bytes)
                        .sum::<u64>()
                        .checked_add(epoch.2)
                        .is_some_and(|total| total <= 4 * 1024 * 1024 * 1024),
                    "owned signer namespace total byte bound",
                )?;
            } else {
                let original = self.original.members.get(leaf).ok_or_else(|| {
                    enzimos_platform::Error(
                        "existing signed output was not an original namespace member".into(),
                    )
                })?;
                original.recheck()?;
                require(
                    files::identity(&original.file.metadata()?) == *epoch
                        && current == self.folder.epoch,
                    "existing signed output differs from original retained namespace",
                )?;
            }
        } else {
            require(
                current == self.folder.epoch,
                "unsigned entry cannot change signing namespace",
            )?;
        }
        let folder = Directory::retain(self.folder.file.try_clone()?, self.original.volume.unique)?;
        let result = Published {
            prepared: self,
            wrapped,
            folder,
            expected,
            output,
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    pub(crate) fn require_original(
        &self,
        original: &Original<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        self.original.same_original(original, authorize)?;
        require(
            files::identity(&original.parent.file.metadata()?) == self.parent_epoch
                && enzimos_platform::files::status_flags(&original.parent.file)
                    == original.parent.flags
                && mount_identity::id(original.parent.file.as_fd(), true)?
                    == self.original.volume.unique,
            "known preparation differs from independently held original parent",
        )?;
        if let Some(folder) = &original.folder {
            require(
                files::identity(&folder.file.metadata()?) == self.folder.epoch
                    && enzimos_platform::files::status_flags(&folder.file) == folder.flags,
                "known preparation differs from independently held original directory",
            )?;
        }
        self.recheck(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"created":self.created,"original_parent_epoch":self.original.parent.epoch,
            "parent_epoch":self.parent_epoch,"folder_epoch":self.folder.epoch,"boot_uuid":self.original.volume.uuid,
            "members":self.original.members.keys().collect::<Vec<_>>(),"execution_authorized":false}),
        )
    }
}

/// Actual owned signer/namespace join. No serialized constructor or delete actor.
pub struct Published<'a> {
    prepared: Prepared<'a>,
    wrapped: crate::signed_entry::Wrapped,
    folder: Directory,
    expected: BTreeSet<String>,
    output: Option<(String, files::FileIdentity, bool)>,
}
impl Published<'_> {
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.prepared.parent_barrier(authorize)?;
        let named = files::directory_relative(
            &self.prepared.original.parent.file,
            Path::new(CHILD),
            Some(0),
        )?;
        self.folder
            .recheck(&named, self.prepared.original.volume.unique)?;
        require(
            names(&self.folder.file, 128)? == self.expected,
            "owned signing namespace membership changed",
        )?;
        require(
            self.wrapped.namespace_output(
                &self.folder.file,
                self.prepared.folder.epoch,
                authorize,
            )? == self.output,
            "actual retained signer output changed after namespace publication",
        )?;
        self.prepared.original.original_members(authorize)?;
        self.folder
            .recheck(&named, self.prepared.original.volume.unique)?;
        self.prepared.parent_barrier(authorize)
    }
    pub(crate) fn require_original(
        &self,
        original: &Original<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        self.prepared.original.same_original(original, authorize)?;
        require(
            files::identity(&original.parent.file.metadata()?) == self.prepared.parent_epoch
                && enzimos_platform::files::status_flags(&original.parent.file)
                    == original.parent.flags
                && mount_identity::id(original.parent.file.as_fd(), true)?
                    == self.prepared.original.volume.unique,
            "known signer publication differs from independently original parent",
        )?;
        if let Some(folder) = &original.folder {
            require(
                files::identity(&folder.file.metadata()?) == self.folder.epoch
                    && enzimos_platform::files::status_flags(&folder.file) == folder.flags,
                "known signer publication differs from independently original directory",
            )?;
        }
        self.recheck(authorize)
    }
    pub(crate) fn require_original_entry(
        &self,
        expected: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        self.wrapped.require_original_entry(expected, authorize)?;
        self.recheck(authorize)
    }
    pub(crate) fn entry(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&str> {
        self.recheck(authorize)?;
        self.wrapped.text(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(json!({"directory_created":self.prepared.created,
            "original_folder_epoch":self.prepared.folder.epoch,"folder_epoch":self.folder.epoch,
            "members":self.expected,"output":self.output,"signer":self.wrapped.evidence(authorize)?,
            "execution_authorized":false}))
    }
}

/// Closed actual owned namespace states; decoded values cannot supply variants.
pub(crate) enum State<'b, 'a> {
    Prepared(&'b Prepared<'a>),
    Published(&'b Published<'a>),
}
impl State<'_, '_> {
    pub(crate) fn require_original(
        &self,
        original: &Original<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Prepared(actor) => actor.require_original(original, authorize),
            Self::Published(actor) => actor.require_original(original, authorize),
        }
    }
}
