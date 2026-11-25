// SPDX-License-Identifier: MIT
//! Exact owned one-shot deletion through one efivarfs attributes-only write.
//! Retained O_PATH descriptions do not keep kernel read-open counts alive.
use super::*;
use crate::{
    control_record::Observation, root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::Journal,
};
use std::ffi::CString;

struct Metadata {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
}
impl Metadata {
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn observe(parent: &File, name: &str) -> Result<Self> {
        let leaf =
            CString::new(name).map_err(|_| enzimos_platform::Error("EFI basename".into()))?;
        // SAFETY: `leaf` is a NUL-terminated C string and `parent` keeps the descriptor open.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "original EFI metadata descriptor unavailable")?;
        // SAFETY: `fd` was just returned by openat and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(fd) };
        let epoch = files::identity(&file.metadata()?);
        let flags = enzimos_platform::files::status_flags(&file);
        require(
            file.metadata()?.is_file()
                && file.metadata()?.uid() == 0
                && file.metadata()?.gid() == 0
                && file.metadata()?.mode() & 0o022 == 0
                && file.metadata()?.nlink() == 1
                && flags & libc::O_PATH != 0,
            "original protected EFI metadata required",
        )?;
        Ok(Self { file, epoch, flags })
    }
    fn recheck(&self, parent: &File, name: &str, mount: u64) -> Result<()> {
        let named = Self::observe(parent, name)?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && named.epoch == self.epoch
                && enzimos_platform::files::status_flags(&self.file) == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == mount
                && mount_identity::id(named.file.as_fd(), true)? == mount,
            "original EFI metadata changed/replaced/covered",
        )
    }
}
pub struct Original<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    receipt: Observation,
    record: Value,
    directory: File,
    epoch: files::FileIdentity,
    directory_flags: i32,
    mount: u64,
    members: BTreeSet<String>,
    metadata: BTreeMap<String, Metadata>,
    one_shot: Option<Variable>,
    owned: bool,
}
impl<'a> Original<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        journal: &Journal<'_>,
        inventory: &Inventory<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        journal.require_original_source(guard, lock)?;
        inventory.require_deleted(journal, authorize)?;
        let receipt = journal.duplicate_observation()?;
        let record = receipt.value()?.clone();
        let directory = files::directory(Path::new(EFI), Some(0))?;
        filesystem(&directory)?;
        let epoch = files::identity(&directory.metadata()?);
        let directory_flags = flags(&directory)?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let members = names(&directory)?;
        let leaf = format!("LoaderEntryOneShot-{GUID}");
        let mut metadata = BTreeMap::new();
        for name in &members {
            metadata.insert(name.clone(), Metadata::observe(&directory, name)?);
        }
        let one_shot = if members.contains(&leaf) {
            Some(Variable::observe(&directory, &leaf, mount)?)
        } else {
            None
        };
        let owned = match &one_shot {
            Some(row) => {
                crate::boot_entries::efi_string(&row.bytes)?
                    == crate::recovery_records::text(&record["coordinator"], "uefi_entry")?
            }
            None => false,
        };
        let result = Self {
            guard,
            lock,
            receipt,
            record,
            directory,
            epoch,
            directory_flags,
            mount,
            members,
            metadata,
            one_shot,
            owned,
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    fn barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.barrier_inner(None, authorize)
    }
    fn barrier_inner(
        &self,
        completed: Option<&crate::root_retirement_online_journal::Completed<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        match completed {
            Some(receipt) => {
                receipt.require_source(self.guard, self.lock)?;
                receipt.require_original_observation(&self.receipt)?;
                require(
                    receipt.before()? == &self.record,
                    "completed EFI predecessor differs",
                )?;
            }
            None => {
                self.receipt.recheck()?;
                require(
                    self.receipt.value()? == &self.record && self.record["phase"] == "deleted",
                    "finish EFI deleted receipt changed",
                )?;
            }
        }
        let named = files::directory(Path::new(EFI), Some(0))?;
        let a = files::identity(&self.directory.metadata()?);
        let b = files::identity(&named.metadata()?);
        require(
            (a.0, a.1, a.7, a.8, a.9, a.10)
                == (
                    self.epoch.0,
                    self.epoch.1,
                    self.epoch.7,
                    self.epoch.8,
                    self.epoch.9,
                    self.epoch.10,
                )
                && (b.0, b.1, b.7, b.8, b.9, b.10) == (a.0, a.1, a.7, a.8, a.9, a.10)
                && flags(&self.directory)? == self.directory_flags
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "finish EFI directory replaced/covered",
        )?;
        filesystem(&self.directory)?;
        authorize()
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.barrier(authorize)?;
        require(
            files::identity(&self.directory.metadata()?) == self.epoch
                && names(&self.directory)? == self.members,
            "finish original EFI namespace changed",
        )?;
        for (name, row) in &self.metadata {
            row.recheck(&self.directory, name, self.mount)?;
        }
        if let Some(row) = &self.one_shot {
            row.recheck(
                &self.directory,
                &format!("LoaderEntryOneShot-{GUID}"),
                self.mount,
            )?;
        }
        self.barrier(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let metadata = self
            .metadata
            .iter()
            .map(|(name, row)| {
                (
                    name.clone(),
                    serde_json::json!({"epoch":row.epoch,"flags":row.flags}),
                )
            })
            .collect::<BTreeMap<_, _>>();
        Ok(
            serde_json::json!({"directory_epoch":self.epoch,"directory_flags":self.directory_flags,"mount":self.mount,"members":metadata,"one_shot_sha256":self.one_shot.as_ref().map(|row|enzimos_platform::json::sha256(&row.bytes)),"clear_owned_one_shot":self.owned,"deletion_authorized":false}),
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat, write).")]
    pub fn clear(
        mut self,
        inventory: &Inventory<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Completed<'a>> {
        self.recheck(authorize)?;
        inventory.require_deleted_record(&self.receipt, authorize)?;
        if !self.owned {
            return Ok(Completed {
                original: self,
                retired_epoch: None,
                directory_epoch: None,
            });
        }
        let leaf = format!("LoaderEntryOneShot-{GUID}");
        let variable = self
            .one_shot
            .take()
            .ok_or_else(|| enzimos_platform::Error("owned EFI reader missing".into()))?;
        require(
            variable.bytes
                == one_shot_bytes(crate::recovery_records::text(
                    &self.record["coordinator"],
                    "uefi_entry",
                )?)?,
            "owned one-shot attributes/bytes differ",
        )?;
        let leaf_c = CString::new(leaf.as_str())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        // SAFETY: `leaf_c` is a NUL-terminated C string and `self.directory` keeps the descriptor
        // open.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "actual owned EFI writer unavailable")?;
        // SAFETY: `fd` was just returned by openat and is owned by nothing else.
        let writer = unsafe { File::from_raw_fd(fd) };
        let writer_flags = enzimos_platform::files::status_flags(&writer);
        require(
            writer_flags >= 0 && writer_flags & libc::O_ACCMODE == libc::O_WRONLY,
            "actual EFI writer status required",
        )?;
        require(
            files::identity(&writer.metadata()?) == variable.epoch
                && mount_identity::id(writer.as_fd(), true)? == self.mount,
            "owned EFI writer differs from original reader",
        )?;
        // Close our read-open before deletion. O_PATH retains the original inode
        // without delaying efivarfs's zero-size last-close removal.
        drop(variable.file);
        self.barrier(authorize)?;
        for (name, row) in &self.metadata {
            row.recheck(&self.directory, name, self.mount)?;
        }
        inventory.require_deleted_record(&self.receipt, authorize)?;
        let attributes = 7u32.to_le_bytes();
        // SAFETY: The buffer pointer and length describe `attributes`, and `writer` keeps the
        // descriptor open.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                attributes.as_ptr().cast(),
                attributes.len(),
            )
        };
        require(
            written == 4,
            "one attributes-only EFI deletion write failed/partial; no retry",
        )?;
        require(
            enzimos_platform::files::status_flags(&writer) == writer_flags,
            "EFI writer status changed during single write",
        )?;
        require(
            writer.metadata()?.len() == 0,
            "EFI deletion writer did not become empty",
        )?;
        drop(writer);
        let original = self
            .metadata
            .get(&leaf)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        let retired_epoch = files::identity(&original.file.metadata()?);
        require(
            retired_epoch.0 == original.epoch.0
                && retired_epoch.1 == original.epoch.1
                && retired_epoch.2 == 0
                && (retired_epoch.7, retired_epoch.8, retired_epoch.9)
                    == (original.epoch.7, original.epoch.8, original.epoch.9)
                && retired_epoch.10 == 0
                && files::optional_relative(&self.directory, Path::new(&leaf))?.is_none(),
            "kernel owned EFI deletion remains uncertain; no replay/unlink",
        )?;
        let directory_epoch = files::identity(&self.directory.metadata()?);
        let result = Completed {
            original: self,
            retired_epoch: Some(retired_epoch),
            directory_epoch: Some(directory_epoch),
        };
        result.recheck(authorize)?;
        inventory.require_deleted_record(&result.original.receipt, authorize)?;
        Ok(result)
    }
}
pub struct Completed<'a> {
    original: Original<'a>,
    retired_epoch: Option<files::FileIdentity>,
    directory_epoch: Option<files::FileIdentity>,
}
impl Completed<'_> {
    pub(crate) fn require_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.original.guard, guard)
                && std::ptr::eq(self.original.lock, lock)
                && &self.original.record == record,
            "finish firmware belongs to another original receipt/guard/lock",
        )?;
        self.recheck(authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_inner(None, authorize)
    }
    pub(crate) fn recheck_completed(
        &self,
        receipt: &crate::root_retirement_online_journal::Completed<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck_inner(Some(receipt), authorize)
    }
    fn recheck_inner(
        &self,
        completed: Option<&crate::root_retirement_online_journal::Completed<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let Some(epoch) = self.retired_epoch else {
            self.original.barrier_inner(completed, authorize)?;
            require(
                files::identity(&self.original.directory.metadata()?) == self.original.epoch
                    && names(&self.original.directory)? == self.original.members,
                "unchanged EFI namespace changed",
            )?;
            for (name, row) in &self.original.metadata {
                row.recheck(&self.original.directory, name, self.original.mount)?;
            }
            if let Some(row) = &self.original.one_shot {
                row.recheck(
                    &self.original.directory,
                    &format!("LoaderEntryOneShot-{GUID}"),
                    self.original.mount,
                )?;
            }
            return self.original.barrier_inner(completed, authorize);
        };
        self.original.barrier_inner(completed, authorize)?;
        let leaf = format!("LoaderEntryOneShot-{GUID}");
        let mut expected = self.original.members.clone();
        expected.remove(&leaf);
        require(
            names(&self.original.directory)? == expected
                && Some(files::identity(&self.original.directory.metadata()?))
                    == self.directory_epoch,
            "owned EFI deletion namespace changed",
        )?;
        for (name, row) in &self.original.metadata {
            if name == &leaf {
                require(
                    files::identity(&row.file.metadata()?) == epoch
                        && enzimos_platform::files::status_flags(&row.file) == row.flags,
                    "retired original EFI metadata changed",
                )?;
            } else {
                row.recheck(&self.original.directory, name, self.original.mount)?;
            }
        }
        self.original.barrier_inner(completed, authorize)
    }
}
