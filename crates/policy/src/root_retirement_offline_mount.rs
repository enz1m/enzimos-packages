// SPDX-License-Identifier: MIT
//! Actual owned offline mount, with the original underlying RAM point retained.
//! Drop neither unmounts nor repairs. Failed setup/unmount stays for review.
use crate::root_retirement_exclusive_claim::{Held, Released};
use crate::{recovery_unlock::CreatedMapping, root_retirement_offline_scope::Mounts};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const PARENT: &str = "/run/enzimos";
const NAME: &str = "root-retirement-top";
const TOP: &str = "/run/enzimos/root-retirement-top";
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn flags(file: &File) -> Result<i32> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "owned offline directory flags",
    )?;
    Ok(flags)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn ram(file: &File) -> Result<()> {
    let mut data = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), data.as_mut_ptr()) } == 0
            && matches!(
                unsafe { data.assume_init() }.f_type as u64,
                0x858458f6 | 0x01021994
            ),
        "actual original RAM mountpoint directory required",
    )
}
pub struct OwnedTop<'a, 's> {
    mapping: &'a CreatedMapping<'s>,
    parent: File,
    point: File,
    parent_epoch: files::FileIdentity,
    point_epoch: files::FileIdentity,
    parent_flags: i32,
    point_flags: i32,
    ram_mount: u64,
    top: Option<File>,
    top_shape: (u64, u64, u32, u32, u32),
    top_mount: u64,
    top_flags: i32,
    filesystem: Value,
    before_mount: Released<'a, 's>,
}
/// Produced only by actual normal unmount and a fresh kernel-exclusive probe.
/// Diagnostic output cannot replace this owner or authorize mapper teardown.
pub struct Unmounted<'a, 's> {
    original: OwnedTop<'a, 's>,
    after_unmount: Released<'a, 's>,
}
pub struct ReleasedMount<'s> {
    scope: &'s crate::root_retirement_offline_scope::Scope,
    generation: String,
    mapper_epoch: files::FileIdentity,
    parent: File,
    point: File,
    parent_epoch: files::FileIdentity,
    point_epoch: files::FileIdentity,
    parent_flags: i32,
    point_flags: i32,
    ram_mount: u64,
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original offline mounted directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
impl<'a, 's> OwnedTop<'a, 's> {
    pub(crate) fn require_original_unlock(
        &self,
        verified: &crate::root_retirement_unlock_source::Verified<'_, '_, '_>,
    ) -> Result<()> {
        verified.require_original_mapping(self.mapping)?;
        self.recheck()
    }
    pub(crate) fn require_original_mounts(&self, mounts: &Mounts<'_>) -> Result<()> {
        self.recheck()?;
        self.mapping.require_original_mount(mounts)?;
        require(
            shape(mounts.original_top()?)? == self.top_shape
                && mount_identity::id(mounts.original_top()?.as_fd(), true)? == self.top_mount,
            "original owned mount and observation differ",
        )?;
        self.recheck()
    }
    pub(crate) fn original_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        self.top
            .as_ref()
            .ok_or_else(|| Error("owned top already released".into()))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    pub fn mount(mapping: &'a CreatedMapping<'s>) -> Result<Self> {
        mapping.recheck()?;
        let exclusive = Held::acquire(mapping)?;
        let parent = files::ensure_directory(Path::new(PARENT), 0o700, 0)?;
        ram(&parent)?;
        let point = files::create_directory_relative(&parent, Path::new(NAME), 0o700, 0)?;
        ram(&point)?;
        require(
            files::directory_is_empty(&point)?,
            "new owned offline mountpoint not empty",
        )?;
        let parent_epoch = files::identity(&parent.metadata()?);
        let point_epoch = files::identity(&point.metadata()?);
        let parent_flags = flags(&parent)?;
        let point_flags = flags(&point)?;
        let ram_mount = mount_identity::id(point.as_fd(), true)?;
        require(
            mount_identity::id(parent.as_fd(), true)? == ram_mount,
            "new offline mountpoint crossed RAM filesystem",
        )?;
        mapping.recheck()?;
        let named_parent = files::directory(Path::new(PARENT), Some(0))?;
        let named_point = files::directory_relative(&parent, Path::new(NAME), Some(0))?;
        require(
            files::identity(&named_parent.metadata()?) == parent_epoch
                && files::identity(&named_point.metadata()?) == point_epoch
                && mount_identity::id(named_point.as_fd(), true)? == ram_mount,
            "actual newly created RAM mountpoint replaced before mount",
        )?;
        let source = CString::new(format!(
            "/proc/self/fd/{}",
            mapping.descriptor()?.as_raw_fd()
        ))
        .unwrap();
        let before_mount = exclusive.release()?;
        before_mount.require_original_mapping(mapping)?;
        require(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    c"/run/enzimos/root-retirement-top".as_ptr(),
                    c"btrfs".as_ptr(),
                    libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                    c"subvolid=5,nodiscard".as_ptr().cast(),
                )
            } == 0,
            "owned offline mount refused; no adoption or retry",
        )?;
        // If any following check fails, preserve the mounted state for review.
        let top = files::directory(Path::new(TOP), Some(0))?;
        let filesystem = crate::filesystem::observe(top.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == mapping.filesystem_uuid()?,
            "actual owned offline filesystem differs from created mapping",
        )?;
        let this = Self {
            mapping,
            parent,
            point,
            parent_epoch,
            point_epoch,
            parent_flags,
            point_flags,
            ram_mount,
            top_shape: shape(&top)?,
            top_mount: mount_identity::id(top.as_fd(), true)?,
            top_flags: flags(&top)?,
            filesystem,
            before_mount,
            top: Some(top),
        };
        this.recheck()?;
        Ok(this)
    }
    fn point_recheck(&self, uncovered: bool) -> Result<()> {
        ram(&self.parent)?;
        ram(&self.point)?;
        let parent = files::directory(Path::new(PARENT), Some(0))?;
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch
                && files::identity(&parent.metadata()?) == self.parent_epoch
                && files::identity(&self.point.metadata()?) == self.point_epoch
                && flags(&self.parent)? == self.parent_flags
                && flags(&self.point)? == self.point_flags
                && mount_identity::id(self.parent.as_fd(), true)? == self.ram_mount
                && mount_identity::id(parent.as_fd(), true)? == self.ram_mount
                && mount_identity::id(self.point.as_fd(), true)? == self.ram_mount
                && files::directory_is_empty(&self.point)?,
            "original owned RAM mountpoint/parent changed",
        )?;
        if uncovered {
            let named = files::directory_relative(&self.parent, Path::new(NAME), Some(0))?;
            ram(&named)?;
            require(
                files::identity(&named.metadata()?) == self.point_epoch
                    && mount_identity::id(named.as_fd(), true)? == self.ram_mount,
                "normal unmount did not uncover original RAM mountpoint",
            )?;
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        self.mapping.recheck()?;
        self.before_mount.require_original_mapping(self.mapping)?;
        self.point_recheck(false)?;
        let top = self
            .top
            .as_ref()
            .ok_or_else(|| Error("owned offline mount already released".into()))?;
        let named = files::directory(Path::new(TOP), Some(0))?;
        for file in [top, &named] {
            require(
                shape(file)? == self.top_shape
                    && mount_identity::id(file.as_fd(), true)? == self.top_mount
                    && crate::filesystem::observe(file.as_fd())? == self.filesystem,
                "original owned offline mount/root replaced or covered",
            )?;
        }
        require(
            flags(top)? == self.top_flags,
            "original owned offline mounted descriptor flags changed",
        )?;
        let observed = Mounts::observe(
            self.mapping.original_scope()?,
            top,
            self.mapping.filesystem_uuid()?,
        )?;
        self.mapping.require_original_mount(&observed)?;
        self.mapping.recheck()
    }
    /// Returned observation borrows this owner; it must retire before unmount.
    pub fn observation(&self) -> Result<Mounts<'_>> {
        self.recheck()?;
        Mounts::observe(
            self.mapping.original_scope()?,
            self.top.as_ref().unwrap(),
            self.mapping.filesystem_uuid()?,
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    pub fn unmount(mut self) -> Result<Unmounted<'a, 's>> {
        self.recheck()?;
        crate::subvolume::sync(self.top.as_ref().unwrap().as_fd())?;
        self.recheck()?;
        drop(self.top.take());
        require(
            unsafe { libc::umount2(c"/run/enzimos/root-retirement-top".as_ptr(), 0) } == 0,
            "normal owned offline unmount refused; retain mapping/mount for manual review",
        )?;
        self.point_recheck(true)?;
        self.mapping.recheck()?;
        let after_unmount = Held::acquire(self.mapping)?.release()?;
        after_unmount.require_original_mapping(self.mapping)?;
        let result = Unmounted {
            original: self,
            after_unmount,
        };
        result.recheck()?;
        Ok(result)
    }
}
impl<'a, 's> Unmounted<'a, 's> {
    /// Consume the actual unmount while its exact created mapping still exists.
    /// The returned private owner releases the mapping borrow, not its lineage.
    pub fn release(self) -> Result<ReleasedMount<'s>> {
        self.recheck()?;
        let mapping = self.original.mapping;
        let scope = mapping.original_scope()?;
        let generation = mapping.original_generation()?.to_owned();
        let mapper_epoch = files::identity(&mapping.original_mapper_node()?.0.metadata()?);
        let OwnedTop {
            parent,
            point,
            parent_epoch,
            point_epoch,
            parent_flags,
            point_flags,
            ram_mount,
            ..
        } = self.original;
        let result = ReleasedMount {
            scope,
            generation,
            mapper_epoch,
            parent,
            point,
            parent_epoch,
            point_epoch,
            parent_flags,
            point_flags,
            ram_mount,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        require(
            self.original.top.is_none(),
            "actual owned top descriptor still held after unmount",
        )?;
        self.original.point_recheck(true)?;
        self.original
            .before_mount
            .require_original_mapping(self.original.mapping)?;
        self.after_unmount
            .require_original_mapping(self.original.mapping)?;
        self.original.mapping.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"status":"offline-original-mount-unmounted","original_ram_point_uncovered":true,
            "actual_exclusive_before_mount":true,"actual_exclusive_after_unmount":true,"persistent_exclusive_claim_held":false,
            "ram_point_removed":false,"mapping_closed":false,"execution_authorized":false}),
        )
    }
}
impl ReleasedMount<'_> {
    pub(crate) fn require_original_mapping(&self, mapping: &CreatedMapping<'_>) -> Result<()> {
        self.recheck()?;
        require(
            std::ptr::eq(self.scope, mapping.original_scope()?)
                && self.generation == mapping.original_generation()?
                && self.mapper_epoch
                    == files::identity(&mapping.original_mapper_node()?.0.metadata()?),
            "actual released mount belongs to another original mapping",
        )?;
        mapping.recheck()
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        let parent = files::directory(Path::new(PARENT), Some(0))?;
        let point = files::directory_relative(&self.parent, Path::new(NAME), Some(0))?;
        for (held, named, epoch, expected_flags) in [
            (&self.parent, &parent, self.parent_epoch, self.parent_flags),
            (&self.point, &point, self.point_epoch, self.point_flags),
        ] {
            ram(held)?;
            ram(named)?;
            require(
                files::identity(&held.metadata()?) == epoch
                    && files::identity(&named.metadata()?) == epoch
                    && flags(held)? == expected_flags
                    && mount_identity::id(held.as_fd(), true)? == self.ram_mount
                    && mount_identity::id(named.as_fd(), true)? == self.ram_mount,
                "actual released RAM mountpoint replaced or covered",
            )?;
        }
        require(
            files::directory_is_empty(&self.point)?,
            "actual released RAM mountpoint not empty",
        )?;
        self.scope.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"actual_owned_unmount_released":true,"actual_exclusive_before_after_unmount":true,"execution_authorized":false,"mapping_closed":false}),
        )
    }
}
