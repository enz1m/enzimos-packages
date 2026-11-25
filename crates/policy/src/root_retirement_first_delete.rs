// SPDX-License-Identifier: MIT
//! First exact-ID selector over the actual original durable in-flight actor.
//! No decoded constructor, syscall-success claim, progress grant or cold replay.
use crate::{birth_runtime::Records, root_retirement_offline_journal::StepEntered};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::Value;
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
pub(crate) struct Descriptions<'a> {
    pub top: &'a File,
    pub target: &'a File,
    pub parent: &'a File,
    pub identity: &'a Value,
    pub before: &'a Records,
    pub objects: &'a [crate::root_retirement_objects::Original],
}
pub(crate) fn selector(id: u64) -> Result<[u64; 512]> {
    require(
        (256..=u64::MAX - 255).contains(&id),
        "actual first root ID selector bound",
    )?;
    let mut args = [0u64; 512];
    args[2] = 1 << 4; // BTRFS_SUBVOL_SPEC_BY_ID, flags offset16.
    args[7] = id; // subvolid union, offset56. No name or other flag.
    Ok(args)
}
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original first deletion read-only descriptors required",
    )?;
    Ok(flags)
}
pub struct First<'j, 'a, 's> {
    entered: StepEntered<'j, 'a, 's>,
    identity: Value,
    before: Records,
    target_epoch: files::FileIdentity,
    parent_epoch: files::FileIdentity,
    target_flags: i32,
    parent_flags: i32,
    top_flags: i32,
    top_descriptor: i32,
    parent_root: Value,
    filesystem: Value,
    mount: u64,
    name: String,
    args: [u64; 512],
    remaining: Vec<crate::root_retirement_objects::Original>,
}
pub struct After<'j, 'a, 's> {
    original: First<'j, 'a, 's>,
    top: File,
    target: File,
    parent: File,
    top_epoch: files::FileIdentity,
    target_epoch: files::FileIdentity,
    parent_epoch: files::FileIdentity,
    after: Records,
}
/// Only an actual successful, synced deletion and its owned durable publication
/// construct this actor. Decoded progress cannot restore it.
pub struct Advanced<'j, 'a, 's> {
    original: After<'j, 'a, 's>,
}
/// Prepared from live consumed progress only. The second durable in-flight row
/// alone cannot construct this actor or grant a retry.
pub struct Next<'j, 'a, 's> {
    original: Advanced<'j, 'a, 's>,
    remaining: Vec<crate::root_retirement_objects::Original>,
    args: [u64; 512],
}
#[allow(unsafe_code, reason = "Linux syscall ABI (close, openat).")]
pub(crate) fn absent(parent: &File, name: &str) -> Result<()> {
    let name = CString::new(name).map_err(|_| Error("original removed target name".into()))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw >= 0 {
        unsafe {
            libc::close(raw);
        }
        return Err(Error("original removed target name still resolves".into()));
    }
    require(
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        "original target absence is not exact ENOENT; review required",
    )
}
impl<'j, 'a, 's> First<'j, 'a, 's> {
    /// Consume the original preparation. An uncertain call is never retried,
    /// and no progress is adopted from a cold absent-name or in-flight row.
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub fn delete(self) -> Result<After<'j, 'a, 's>> {
        self.recheck()?;
        let originals = self.entered.first_descriptions()?;
        let top = originals.top.try_clone()?;
        let target = originals.target.try_clone()?;
        let parent = originals.parent.try_clone()?;
        let top_before = files::identity(&top.metadata()?);
        require(
            flags(&top)? == self.top_flags
                && flags(&target)? == self.target_flags
                && flags(&parent)? == self.parent_flags,
            "original first duplicate description flags changed",
        )?;
        self.entered.mark_first_attempt()?;
        let mut args = self.args;
        require(
            unsafe {
                libc::ioctl(
                    self.top_descriptor,
                    0x5000943fu64 as libc::c_ulong,
                    args.as_mut_ptr(),
                )
            } == 0,
            "original exact-ID deletion uncertain; preserve in-flight receipt, no retry",
        )?;
        let target_epoch = files::identity(&target.metadata()?);
        let parent_epoch = files::identity(&parent.metadata()?);
        crate::root_retirement_delete_observation::held_dead_root(self.target_epoch, target_epoch)?;
        crate::root_retirement_delete_observation::parent_delta(
            self.parent_epoch,
            parent_epoch,
            &self.name,
        )?;
        absent(&parent, &self.name)?;
        self.entered.require_actual_first_attempt()?;
        // The removed root's in-memory refs reach zero in the delete call,
        // while commit_fs_roots serializes that root item during commit.
        // Commit the actual successful unlink before interpreting the complete
        // Root Tree. An uncertain sync still leaves the original in-flight row.
        require(
            unsafe { libc::ioctl(self.top_descriptor, 0x9408 as libc::c_ulong) } == 0,
            "original first deletion filesystem durability uncertain; no progress",
        )?;
        self.entered.require_actual_first_attempt()?;
        let after = crate::root_retirement_kernel_inventory::query(&top)?;
        crate::root_retirement_delete_observation::inventory_delta(
            &self.before,
            &after,
            &self.identity,
        )?;
        let top_epoch = files::identity(&top.metadata()?);
        if Path::new(enzimos_platform::json::string(&self.identity["path"])?).parent()
            == Some(Path::new(""))
        {
            require(
                top_before == self.parent_epoch && top_epoch == parent_epoch,
                "owned top-parent removal differs from original parent descriptions",
            )?;
        } else {
            require(
                top_before == top_epoch,
                "original top directory changed during nested deletion",
            )?;
        }
        let result = After {
            original: self,
            top,
            target,
            parent,
            top_epoch,
            target_epoch,
            parent_epoch,
            after,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn prepare(entered: StepEntered<'j, 'a, 's>) -> Result<Self> {
        entered.recheck()?;
        let originals = entered.first_descriptions()?;
        let identity = originals.identity.clone();
        let path = identity["path"]
            .as_str()
            .ok_or_else(|| Error("original first target path".into()))?;
        let name = Path::new(path)
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| Error("original first target name".into()))?
            .to_owned();
        let before = originals.before.clone();
        let mut expected = before.clone();
        expected.remove(path);
        crate::root_retirement_delete_observation::inventory_delta(&before, &expected, &identity)?;
        let args = selector(
            identity["id"]
                .as_u64()
                .ok_or_else(|| Error("original first target ID".into()))?,
        )?;
        let target_epoch = files::identity(&originals.target.metadata()?);
        let parent_epoch = files::identity(&originals.parent.metadata()?);
        let target_flags = flags(originals.target)?;
        let parent_flags = flags(originals.parent)?;
        let top_flags = flags(originals.top)?;
        let top_descriptor = originals.top.as_raw_fd();
        let parent_root = crate::subvolume::containing_identity(originals.parent.as_fd())?;
        let filesystem =
            crate::filesystem::observe(originals.top.as_fd())?["filesystem_uuid"].clone();
        let mount = mount_identity::id(originals.top.as_fd(), true)?;
        let remaining = originals
            .objects
            .iter()
            .skip(1)
            .map(|object| object.duplicate_original(originals.top, &filesystem))
            .collect::<Result<Vec<_>>>()?;
        let result = Self {
            entered,
            identity,
            before,
            target_epoch,
            parent_epoch,
            target_flags,
            parent_flags,
            top_flags,
            top_descriptor,
            parent_root,
            filesystem,
            mount,
            name,
            args,
            remaining,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.entered.recheck()?;
        let originals = self.entered.first_descriptions()?;
        require(
            originals.top.as_raw_fd() == self.top_descriptor
                && flags(originals.top)? == self.top_flags
                && files::identity(&originals.target.metadata()?) == self.target_epoch
                && files::identity(&originals.parent.metadata()?) == self.parent_epoch
                && flags(originals.target)? == self.target_flags
                && flags(originals.parent)? == self.parent_flags
                && originals.identity == &self.identity
                && originals.before == &self.before,
            "original first target, parent or sealed top description changed",
        )?;
        for file in [originals.top, originals.target, originals.parent] {
            require(
                mount_identity::id(file.as_fd(), true)? == self.mount
                    && crate::filesystem::observe(file.as_fd())?["filesystem_uuid"]
                        == self.filesystem,
                "original first deletion descriptions cross filesystem or mount",
            )?;
        }
        require(
            crate::subvolume::containing_identity(originals.parent.as_fd())? == self.parent_root
                && self.args == selector(enzimos_platform::json::unsigned(&self.identity["id"])?)?,
            "original first parent root or exact ID selector changed",
        )?;
        let path = enzimos_platform::json::string(&self.identity["path"])?;
        require(
            Path::new(path).file_name().and_then(|v| v.to_str()) == Some(self.name.as_str()),
            "original first literal target name changed",
        )?;
        self.entered.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"actual_original_durable_inflight_step":0,"exact_original_kernel_target_id":self.identity["id"],
            "complete_before_inventory_roots":self.before.len(),"selector":"SPEC_BY_ID","delete_performed":false,"cold_replay_available":false,"execution_authorized":false}),
        )
    }
}
impl<'j, 'a, 's> After<'j, 'a, 's> {
    pub(crate) fn parent_transition(
        &self,
        path: &str,
        root: &Value,
        before: files::FileIdentity,
    ) -> Result<files::FileIdentity> {
        parent_epoch_transition(
            Path::new(enzimos_platform::json::string(
                &self.original.identity["path"],
            )?)
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            &self.original.parent_root,
            self.original.parent_epoch,
            self.parent_epoch,
            path,
            root,
            before,
        )
    }
    pub fn advance(self) -> Result<Advanced<'j, 'a, 's>> {
        self.recheck()?;
        self.original.entered.advance_first(&self)?;
        let result = Advanced { original: self };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_original_step(&self, step: &StepEntered<'j, 'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(&self.original.entered, step),
            "successful deletion is not the original consumed step",
        )
    }
    pub(crate) fn require_original_seal(
        &self,
        seal: &crate::root_retirement_seal::Installed<'a, 's>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.original.entered.original_seal(), seal),
            "actual successful deletion belongs to another original sealed actor",
        )?;
        self.original.entered.require_actual_first_attempt()
    }
    pub(crate) fn recheck_kernel(&self) -> Result<()> {
        self.original.entered.require_actual_first_attempt()?;
        self.recheck_physical()?;
        self.original.entered.require_actual_first_attempt()
    }
    fn recheck_physical(&self) -> Result<()> {
        require(
            files::identity(&self.top.metadata()?) == self.top_epoch
                && files::identity(&self.target.metadata()?) == self.target_epoch
                && files::identity(&self.parent.metadata()?) == self.parent_epoch
                && flags(&self.top)? == self.original.top_flags
                && flags(&self.target)? == self.original.target_flags
                && flags(&self.parent)? == self.original.parent_flags,
            "original post-delete descriptions changed",
        )?;
        for file in [&self.top, &self.target, &self.parent] {
            require(
                mount_identity::id(file.as_fd(), true)? == self.original.mount,
                "actual removed descriptions crossed original mount",
            )?;
        }
        for file in [&self.top, &self.parent] {
            require(
                crate::filesystem::observe(file.as_fd())?["filesystem_uuid"]
                    == self.original.filesystem,
                "actual removed source filesystem changed",
            )?;
        }
        require(
            crate::subvolume::containing_identity(self.parent.as_fd())?
                == self.original.parent_root,
            "actual unlink parent root identity changed",
        )?;
        absent(&self.parent, &self.original.name)?;
        let current = crate::root_retirement_kernel_inventory::query(&self.top)?;
        require(
            current == self.after,
            "complete post-delete kernel inventory changed",
        )?;
        crate::root_retirement_delete_observation::inventory_delta(
            &self.original.before,
            &current,
            &self.original.identity,
        )?;
        for remaining in &self.original.remaining {
            remaining.recheck_after_first(&self.top, &self.original.filesystem, self)?;
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        self.original
            .entered
            .original_seal()
            .recheck_after_first(self)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"actual_original_exact_id_syscall_succeeded":true,"original_leaf_name_absent":true,
            "complete_kernel_inventory_exactly_one_target_removed":true,"filesystem_synced":true,
            "durable_inflight_retained":true,"receipt_progress_advanced":false,"cold_replay_available":false}),
        )
    }
}
pub(crate) fn parent_epoch_transition(
    changed_path: &str,
    changed_root: &Value,
    old: files::FileIdentity,
    new: files::FileIdentity,
    path: &str,
    root: &Value,
    before: files::FileIdentity,
) -> Result<files::FileIdentity> {
    if path != changed_path {
        return Ok(before);
    }
    require(
        root["id"] == changed_root["id"] && root["uuid"] == changed_root["uuid"] && before == old,
        "known parent delta does not match original path, kernel root identity and epoch",
    )?;
    Ok(new)
}
impl<'j, 'a, 's> Advanced<'j, 'a, 's> {
    pub(crate) fn require_original_step(&self, step: &StepEntered<'j, 'a, 's>) -> Result<()> {
        self.original.require_original_step(step)
    }
    pub fn begin_next(self) -> Result<Next<'j, 'a, 's>> {
        self.recheck()?;
        require(
            !self.original.original.remaining.is_empty(),
            "no remaining original target",
        )?;
        let remaining = self
            .original
            .original
            .remaining
            .iter()
            .map(|object| {
                object.duplicate_after_first(
                    &self.original.top,
                    &self.original.original.filesystem,
                    &self.original,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let args = selector(
            remaining[0].identity()["id"]
                .as_u64()
                .ok_or_else(|| Error("original remaining target ID".into()))?,
        )?;
        let mut expected = self.original.after.clone();
        expected.remove(enzimos_platform::json::string(
            &remaining[0].identity()["path"],
        )?);
        crate::root_retirement_delete_observation::inventory_delta(
            &self.original.after,
            &expected,
            remaining[0].identity(),
        )?;
        self.recheck()?;
        self.original.original.entered.begin_second(&self)?;
        let result = Next {
            original: self,
            remaining,
            args,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_original_seal(
        &self,
        seal: &crate::root_retirement_seal::Installed<'a, 's>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.original.original.entered.original_seal(), seal),
            "durable successful progress belongs to another sealed actor",
        )?;
        self.original.original.entered.require_first_advanced()
    }
    pub(crate) fn recheck_kernel(&self) -> Result<()> {
        self.original.original.entered.require_first_advanced()?;
        self.original.recheck_physical()?;
        self.original.original.entered.require_first_advanced()
    }
    pub fn recheck(&self) -> Result<()> {
        self.original
            .original
            .entered
            .original_seal()
            .recheck_advanced_first(self)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"actual_original_exact_id_syscall_succeeded":true,
            "filesystem_synced":true,"receipt_progress_advanced":true,"next_step":1,
            "owned_predecessors_retained":3,"cold_replay_available":false}),
        )
    }
}
impl<'j, 'a, 's> Next<'j, 'a, 's> {
    pub fn into_cursor(self) -> Result<crate::root_retirement_cursor::Executing<'j, 'a, 's>> {
        self.recheck()?;
        let After {
            original,
            top,
            target,
            target_epoch,
            after,
            top_epoch,
            ..
        } = self.original.original;
        crate::root_retirement_cursor::Executing::from_original_next(
            original.entered,
            original.top_descriptor,
            top,
            top_epoch,
            target,
            target_epoch,
            original.target_flags,
            after,
            self.remaining,
            original.filesystem,
            original.mount,
        )
    }
    pub(crate) fn require_original_seal(
        &self,
        seal: &crate::root_retirement_seal::Installed<'a, 's>,
    ) -> Result<()> {
        require(
            std::ptr::eq(
                self.original.original.original.entered.original_seal(),
                seal,
            ),
            "next prepared target belongs to another actual sealed actor",
        )?;
        self.original
            .original
            .original
            .entered
            .require_second_inflight()
    }
    pub(crate) fn recheck_kernel(&self) -> Result<()> {
        self.original
            .original
            .original
            .entered
            .require_second_inflight()?;
        self.original.original.recheck_physical()?;
        for remaining in &self.remaining {
            remaining.recheck(
                &self.original.original.top,
                &self.original.original.original.filesystem,
            )?;
        }
        require(
            self.args
                == selector(enzimos_platform::json::unsigned(
                    &self.remaining[0].identity()["id"],
                )?)?,
            "next exact original ID selector changed",
        )?;
        self.original
            .original
            .original
            .entered
            .require_second_inflight()
    }
    pub fn recheck(&self) -> Result<()> {
        self.original
            .original
            .original
            .entered
            .original_seal()
            .recheck_next(self)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"actual_original_durable_inflight_step":1,
            "exact_original_kernel_target_id":self.remaining[0].identity()["id"],
            "owned_predecessors_retained":4,"selector":"SPEC_BY_ID",
            "delete_performed":false,"cold_replay_available":false}),
        )
    }
}
