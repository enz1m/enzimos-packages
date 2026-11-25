// SPDX-License-Identifier: MIT
//! Consuming remaining-target execution. Only the original live first success
//! and its owned second in-flight transition construct this cursor.
use crate::{
    birth_runtime::Records, root_retirement_objects::Original,
    root_retirement_offline_journal::StepEntered,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::Value;
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
#[derive(Clone, Copy)]
enum Phase {
    Inflight,
    Succeeded,
    Progress,
}
struct Dead {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
}
pub(crate) struct State<'j, 'a, 's> {
    step: StepEntered<'j, 'a, 's>,
    descriptor: i32,
    top: File,
    top_epoch: files::FileIdentity,
    top_flags: i32,
    dead: Vec<Dead>,
    remaining: Vec<Original>,
    expected: Records,
    filesystem: Value,
    mount: u64,
    index: usize,
    phase: Phase,
}
pub struct Executing<'j, 'a, 's> {
    original: State<'j, 'a, 's>,
}
pub struct Succeeded<'j, 'a, 's> {
    original: State<'j, 'a, 's>,
}
pub struct Progress<'j, 'a, 's> {
    original: State<'j, 'a, 's>,
}
/// Private fields are populated only after the actual successful kernel call,
/// exact name absence, dead target and complete inventory delta checks.
pub(crate) struct Change {
    parent_path: String,
    parent_root: Value,
    before: files::FileIdentity,
    after: files::FileIdentity,
}
impl Change {
    pub(crate) fn parent_transition(
        &self,
        path: &str,
        root: &Value,
        before: files::FileIdentity,
    ) -> Result<files::FileIdentity> {
        crate::root_retirement_first_delete::parent_epoch_transition(
            &self.parent_path,
            &self.parent_root,
            self.before,
            self.after,
            path,
            root,
            before,
        )
    }
}
fn flags(file: &File) -> Result<i32> {
    let result = enzimos_platform::files::status_flags(&file);
    require(
        result >= 0 && result & libc::O_ACCMODE == libc::O_RDONLY,
        "original remaining descriptor flags",
    )?;
    Ok(result)
}
fn selector(id: u64) -> Result<[u64; 512]> {
    require(
        (256..=u64::MAX - 255).contains(&id),
        "remaining exact ID bound",
    )?;
    let mut result = [0u64; 512];
    result[2] = 16;
    result[7] = id;
    Ok(result)
}
impl<'j, 'a, 's> State<'j, 'a, 's> {
    fn lineage(&self) -> Result<()> {
        let (index, inflight, attempt) = match self.phase {
            Phase::Inflight => (
                self.index,
                true,
                self.index.checked_sub(1).filter(|v| *v > 0),
            ),
            Phase::Succeeded => (self.index, true, Some(self.index)),
            Phase::Progress => (self.index + 1, false, Some(self.index)),
        };
        self.step.cursor_lineage(index, inflight, attempt)
    }
    pub(crate) fn require_original_seal(
        &self,
        seal: &crate::root_retirement_seal::Installed<'a, 's>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.step.original_seal(), seal),
            "remaining cursor belongs to another original sealed actor",
        )?;
        self.lineage()
    }
    pub(crate) fn recheck_physical(&self) -> Result<()> {
        self.lineage()?;
        require(
            files::identity(&self.top.metadata()?) == self.top_epoch
                && flags(&self.top)? == self.top_flags
                && mount_identity::id(self.top.as_fd(), true)? == self.mount
                && crate::filesystem::observe(self.top.as_fd())?["filesystem_uuid"]
                    == self.filesystem,
            "original remaining top descriptor changed",
        )?;
        require(
            crate::root_retirement_kernel_inventory::query(&self.top)? == self.expected,
            "complete remaining kernel inventory differs from owned removals",
        )?;
        for dead in &self.dead {
            require(
                files::identity(&dead.file.metadata()?) == dead.epoch
                    && flags(&dead.file)? == dead.flags
                    && dead.epoch.0 == 0
                    && mount_identity::id(dead.file.as_fd(), true)? == self.mount,
                "actual retained removed target changed",
            )?;
        }
        for remaining in &self.remaining {
            remaining.recheck(&self.top, &self.filesystem)?;
        }
        self.lineage()
    }
    fn recheck(&self) -> Result<()> {
        self.step.original_seal().recheck_cursor(self)
    }
    fn require_step(&self, step: &StepEntered<'j, 'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(&self.step, step),
            "remaining operation differs from actual consumed original step",
        )
    }
}
impl<'j, 'a, 's> Executing<'j, 'a, 's> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_original_next(
        step: StepEntered<'j, 'a, 's>,
        descriptor: i32,
        top: File,
        top_epoch: files::FileIdentity,
        dead: File,
        dead_epoch: files::FileIdentity,
        dead_flags: i32,
        expected: Records,
        remaining: Vec<Original>,
        filesystem: Value,
        mount: u64,
    ) -> Result<Self> {
        step.require_second_inflight()?;
        require(!remaining.is_empty(), "original remaining targets missing")?;
        let top_flags = flags(&top)?;
        let result = Self {
            original: State {
                step,
                descriptor,
                top,
                top_epoch,
                top_flags,
                dead: vec![Dead {
                    file: dead,
                    epoch: dead_epoch,
                    flags: dead_flags,
                }],
                remaining,
                expected,
                filesystem,
                mount,
                index: 1,
                phase: Phase::Inflight,
            },
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_original_step(&self, step: &StepEntered<'j, 'a, 's>) -> Result<()> {
        self.original.require_step(step)
    }
    pub(crate) fn index(&self) -> usize {
        self.original.index
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    /// One exact original ID call. Any failure consumes the live actor and
    /// leaves its durable in-flight row; there is no decoded retry constructor.
    #[allow(unsafe_code, reason = "Linux syscall ABI (close, ioctl, openat).")]
    pub fn delete(mut self) -> Result<Succeeded<'j, 'a, 's>> {
        self.recheck()?;
        let first = self
            .original
            .remaining
            .first()
            .ok_or_else(|| Error("original remaining target absent".into()))?;
        let identity = first.identity().clone();
        let (target, parent) = first.descriptions();
        let target = target.try_clone()?;
        let parent = parent.try_clone()?;
        let target_before = files::identity(&target.metadata()?);
        let parent_before = files::identity(&parent.metadata()?);
        let target_flags = flags(&target)?;
        let parent_flags = flags(&parent)?;
        let parent_root = crate::subvolume::containing_identity(parent.as_fd())?;
        let path = Path::new(enzimos_platform::json::string(&identity["path"])?);
        let parent_path = path
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?
            .to_owned();
        let name = path
            .file_name()
            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?;
        let literal = CString::new(name).map_err(|_| Error("remaining literal name".into()))?;
        let mut args = selector(enzimos_platform::json::unsigned(&identity["id"])?)?;
        let mut expected = self.original.expected.clone();
        expected.remove(enzimos_platform::json::string(&identity["path"])?);
        crate::root_retirement_delete_observation::inventory_delta(
            &self.original.expected,
            &expected,
            &identity,
        )?;
        self.original.step.mark_cursor_attempt(&self)?;
        require(
            // SAFETY: BTRFS_IOC_SNAP_DESTROY_V2 reads the vol_args_v2 buffer the request expects,
            // and the descriptor stays open.
            unsafe {
                libc::ioctl(
                    self.original.descriptor,
                    0x5000943fu64 as libc::c_ulong,
                    args.as_mut_ptr(),
                )
            } == 0,
            "remaining exact-ID syscall uncertain; preserve in-flight, no retry",
        )?;
        let target_after = files::identity(&target.metadata()?);
        let parent_after = files::identity(&parent.metadata()?);
        crate::root_retirement_delete_observation::held_dead_root(target_before, target_after)?;
        crate::root_retirement_delete_observation::parent_delta(parent_before, parent_after, name)?;
        require(
            flags(&target)? == target_flags
                && flags(&parent)? == parent_flags
                && crate::subvolume::containing_identity(parent.as_fd())? == parent_root,
            "remaining actual target/parent flags or root identity changed",
        )?;
        // SAFETY: `literal` is a NUL-terminated CString and `parent` keeps the descriptor open.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                literal.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw >= 0 {
            // SAFETY: `raw` was just returned by openat and is closed exactly once.
            unsafe {
                libc::close(raw);
            }
            return Err(Error("remaining removed name still resolves".into()));
        }
        require(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
            "remaining removed name does not have exact ENOENT",
        )?;
        self.original
            .step
            .cursor_lineage(self.original.index, true, Some(self.original.index))?;
        // Root-item refs are written during transaction commit. The raw in-memory
        // deletion and exact ENOENT checks precede this one owned sync; only the
        // resulting complete serialized Root Tree can prove the final delta.
        require(
            // SAFETY: BTRFS_IOC_SYNC takes no argument.
            unsafe { libc::ioctl(self.original.descriptor, 0x9408 as libc::c_ulong) } == 0,
            "remaining filesystem sync uncertain; no progress",
        )?;
        self.original
            .step
            .cursor_lineage(self.original.index, true, Some(self.original.index))?;
        let actual = crate::root_retirement_kernel_inventory::query(&self.original.top)?;
        crate::root_retirement_delete_observation::inventory_delta(
            &self.original.expected,
            &actual,
            &identity,
        )?;
        let top_after = files::identity(&self.original.top.metadata()?);
        if parent_path.is_empty() {
            require(
                self.original.top_epoch == parent_before && top_after == parent_after,
                "remaining top-parent delta differs from actual original parent",
            )?;
        } else {
            require(
                top_after == self.original.top_epoch,
                "remaining unrelated top epoch changed",
            )?;
        }
        let change = Change {
            parent_path,
            parent_root,
            before: parent_before,
            after: parent_after,
        };
        let old = std::mem::take(&mut self.original.remaining);
        self.original.remaining = old
            .into_iter()
            .skip(1)
            .map(|object| {
                object.apply_owned_change(&self.original.top, &self.original.filesystem, &change)
            })
            .collect::<Result<Vec<_>>>()?;
        self.original.dead.push(Dead {
            file: target,
            epoch: target_after,
            flags: target_flags,
        });
        self.original.expected = actual;
        self.original.top_epoch = top_after;
        self.original.phase = Phase::Succeeded;
        let result = Succeeded {
            original: self.original,
        };
        result.recheck()?;
        Ok(result)
    }
}
impl<'j, 'a, 's> Succeeded<'j, 'a, 's> {
    pub(crate) fn require_original_step(&self, step: &StepEntered<'j, 'a, 's>) -> Result<()> {
        self.original.require_step(step)
    }
    pub(crate) fn index(&self) -> usize {
        self.original.index
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    pub fn advance(mut self) -> Result<Progress<'j, 'a, 's>> {
        self.recheck()?;
        self.original.step.advance_cursor(&self)?;
        self.original.phase = Phase::Progress;
        let result = Progress {
            original: self.original,
        };
        result.recheck()?;
        Ok(result)
    }
}
impl<'j, 'a, 's> Progress<'j, 'a, 's> {
    pub(crate) fn require_original_step(&self, step: &StepEntered<'j, 'a, 's>) -> Result<()> {
        self.original.require_step(step)
    }
    pub(crate) fn next_index(&self) -> usize {
        self.original.index + 1
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    pub fn finished(&self) -> Result<bool> {
        self.recheck()?;
        Ok(self.original.remaining.is_empty())
    }
    pub fn begin_next(mut self) -> Result<Executing<'j, 'a, 's>> {
        self.recheck()?;
        require(
            !self.original.remaining.is_empty(),
            "all original remaining targets deleted",
        )?;
        self.original.step.begin_cursor(&self)?;
        self.original.index += 1;
        self.original.phase = Phase::Inflight;
        let result = Executing {
            original: self.original,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(serde_json::json!({"next_step":self.next_index(),
            "actual_owned_deletions":self.original.dead.len(),
            "remaining_targets":self.original.remaining.len(),
            "filesystem_synced":true,"receipt_progress_advanced":true,
            "cold_replay_available":false}))
    }
}
