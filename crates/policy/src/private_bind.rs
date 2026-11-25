// SPDX-License-Identifier: MIT
//! One detached clone, protected before attachment to its original directory.
//! This internal kernel object has no JSON or pathname ownership constructor.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, FromRawFd},
    os::unix::fs::MetadataExt,
};
#[repr(C)]
struct Attributes {
    set: u64,
    clear: u64,
    propagation: u64,
    user_namespace: u64,
}
const _: () = assert!(std::mem::size_of::<Attributes>() == 32);
pub(crate) struct Detached {
    file: File,
    original: files::FileIdentity,
    parent_mount: u64,
    unique: u64,
}
impl Detached {
    /// Caller must durably reserve its fixed role before entry. Every checkpoint
    /// retains the caller's original source, intent and lock authorization.
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    pub(crate) fn prepare(original: &File, checkpoint: &dyn Fn() -> Result<()>) -> Result<Self> {
        crate::storage_runtime::initial_namespace()?;
        checkpoint()?;
        let metadata = original.metadata()?;
        require(
            metadata.is_dir()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o700
                && files::directory_is_empty(original)?,
            "original private empty bind directory required",
        )?;
        let identity = files::identity(&metadata);
        let parent_mount = mount_identity::id(original.as_fd(), true)?;
        // SAFETY: The empty path is a NUL-terminated literal and `original` keeps the descriptor
        // open.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                original.as_raw_fd(),
                c"".as_ptr(),
                1u32 | libc::O_CLOEXEC as u32 | libc::AT_EMPTY_PATH as u32,
            )
        };
        require(
            raw >= 0,
            "detached private-area clone failed; intent retained",
        )?;
        // SAFETY: `raw` was just returned by open_tree and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(raw as i32) };
        let unique = mount_identity::id(file.as_fd(), true)?;
        let this = Self {
            file,
            original: identity,
            parent_mount,
            unique,
        };
        this.recheck(original)?;
        checkpoint()?;
        let attributes = Attributes {
            set: 2 | 4 | 8,
            clear: 0,
            propagation: libc::MS_PRIVATE,
            user_namespace: 0,
        };
        require(
            // SAFETY: The empty path is a NUL-terminated literal, `attributes` is a complete
            // mount_attr passed with its size, and the descriptor stays open.
            unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    this.file.as_raw_fd(),
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH as u32,
                    &attributes as *const Attributes,
                    std::mem::size_of::<Attributes>(),
                )
            } == 0,
            "detached private-area protection failed; intent retained",
        )?;
        this.recheck(original)?;
        checkpoint()?;
        Ok(this)
    }
    fn recheck(&self, original: &File) -> Result<()> {
        crate::storage_runtime::initial_namespace()?;
        require(
            files::identity(&original.metadata()?) == self.original
                && files::identity(&self.file.metadata()?) == self.original
                && mount_identity::id(original.as_fd(), true)? == self.parent_mount
                && mount_identity::id(self.file.as_fd(), true)? == self.unique
                && self.unique != self.parent_mount
                && files::directory_is_empty(original)?,
            "original private-area directory or detached clone changed",
        )
    }
    pub(crate) fn unique(&self) -> u64 {
        self.unique
    }
    /// Consume once. Attachment cannot select another directory or supply flags.
    /// The returned actual mount description must remain owned until normal close.
    /// `checkpoint` runs before attachment and again after it; callers whose
    /// checkpoint requires the directory to be uncovered use `attach_only`.
    pub(crate) fn attach(
        self,
        original: &File,
        checkpoint: &dyn Fn() -> Result<()>,
    ) -> Result<File> {
        self.attach_only(original, checkpoint)?.protect(checkpoint)
    }
    /// Attach the protected clone and return immediately, so the caller can arm
    /// an identity-checked rollback before any later check may fail. The
    /// attachment is not admitted until `protect` succeeds.
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    pub(crate) fn attach_only(
        self,
        original: &File,
        checkpoint: &dyn Fn() -> Result<()>,
    ) -> Result<Attachment> {
        self.recheck(original)?;
        checkpoint()?;
        self.recheck(original)?;
        require(
            // SAFETY: The empty paths are NUL-terminated literals and both descriptors stay open.
            unsafe {
                libc::syscall(
                    libc::SYS_move_mount,
                    self.file.as_raw_fd(),
                    c"".as_ptr(),
                    original.as_raw_fd(),
                    c"".as_ptr(),
                    4u32 | 0x40,
                )
            } == 0,
            "detached private-area attachment failed; intent retained",
        )?;
        Ok(Attachment {
            file: self.file,
            original: self.original,
            unique: self.unique,
        })
    }
}
/// An attached, not yet admitted clone. Its mount stays attached on error; the
/// caller's rollback (armed before `protect`) owns detaching it.
pub(crate) struct Attachment {
    file: File,
    original: files::FileIdentity,
    unique: u64,
}
impl Attachment {
    /// Kernel short mount ID of the attached clone (the mountinfo row ID).
    pub(crate) fn normal(&self) -> Result<u64> {
        mount_identity::id(self.file.as_fd(), false)
    }
    /// `checkpoint` here must accept the directory as covered by this mount.
    pub(crate) fn protect(self, checkpoint: &dyn Fn() -> Result<()>) -> Result<File> {
        self.protect_with(false, checkpoint)
    }
    /// A new peer group only for this owned empty bind. Later systemd slave
    /// namespaces must receive normal destination unmounts instead of retaining
    /// a hidden filesystem reference. No parent propagation is changed.
    pub(crate) fn protect_shared(self, checkpoint: &dyn Fn() -> Result<()>) -> Result<File> {
        self.protect_with(true, checkpoint)
    }
    #[allow(
        unsafe_code,
        reason = "Linux mount_setattr on the retained owned mount."
    )]
    fn protect_with(self, shared: bool, checkpoint: &dyn Fn() -> Result<()>) -> Result<File> {
        require(
            files::identity(&self.file.metadata()?) == self.original
                && mount_identity::id(self.file.as_fd(), true)? == self.unique,
            "attached private-area original mount identity changed",
        )?;
        // Attachment below a shared parent can give this empty clone a new
        // shared group. Normalize only the actual owned mount, before any
        // payload or owned volume is admitted; never change the parent.
        checkpoint()?;
        let attributes = Attributes {
            set: 2 | 4 | 8,
            clear: 0,
            propagation: libc::MS_PRIVATE,
            user_namespace: 0,
        };
        require(
            // SAFETY: The empty path is a NUL-terminated literal, `attributes` is a complete
            // mount_attr passed with its size, and the descriptor stays open.
            unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    self.file.as_raw_fd(),
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH as u32,
                    &attributes as *const Attributes,
                    std::mem::size_of::<Attributes>(),
                )
            } == 0,
            "attached private-area protection failed; intent retained",
        )?;
        if shared {
            // The preceding MS_PRIVATE detached any inherited peer group.
            // MS_SHARED now creates a fresh group for this protected bind only.
            let attributes = Attributes {
                propagation: libc::MS_SHARED,
                ..attributes
            };
            // SAFETY: the descriptor and attribute buffer are live; empty-path
            // scope addresses only the mount retained by this Attachment.
            require(
                // SAFETY: The empty path is a NUL-terminated literal, `attributes` is a complete
                // mount_attr passed with its size, and the descriptor stays open.
                unsafe {
                    libc::syscall(
                        libc::SYS_mount_setattr,
                        self.file.as_raw_fd(),
                        c"".as_ptr(),
                        libc::AT_EMPTY_PATH as u32,
                        &attributes as *const Attributes,
                        std::mem::size_of::<Attributes>(),
                    )
                } == 0,
                "owned backup-area propagation failed; intent retained",
            )?;
        }
        checkpoint()?;
        require(
            files::identity(&self.file.metadata()?) == self.original
                && mount_identity::id(self.file.as_fd(), true)? == self.unique,
            "original attached mount changed during protection",
        )?;
        let normal = mount_identity::id(self.file.as_fd(), false)?;
        let rows = crate::storage_runtime::rows()?;
        let owned = rows
            .iter()
            .filter(|row| row.id == normal)
            .collect::<Vec<_>>();
        require(
            owned.len() == 1
                && if shared {
                    shared_group(&owned[0].optional)
                } else {
                    owned[0].optional.is_empty()
                }
                && ["rw", "nodev", "nosuid", "noexec"]
                    .iter()
                    .all(|flag| owned[0].options.split(',').any(|actual| actual == *flag))
                && !owned[0].options.split(',').any(|flag| flag == "ro"),
            "actual attached private-area kernel flags or propagation refused",
        )?;
        Ok(self.file)
    }
}

/// A sole shared peer group, without a master or other propagation roles.
pub(crate) fn shared_group(optional: &[String]) -> bool {
    matches!(optional, [tag] if tag.strip_prefix("shared:").is_some_and(|id|
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
        && id.parse::<u64>().is_ok_and(|n| n > 0)))
}

/// Keep the destination itself private even when attached above the backup
/// area's shared bind. Unmount delivery follows the shared parent; the worker
/// continues to require an unpropagated original destination description.
#[allow(
    unsafe_code,
    reason = "Linux mount_setattr on the retained destination mount."
)]
pub(crate) fn private_destination(file: &File) -> Result<()> {
    crate::storage_runtime::initial_namespace()?;
    let original = mount_identity::id(file.as_fd(), true)?;
    let attributes = Attributes {
        set: 0,
        clear: 0,
        propagation: libc::MS_PRIVATE,
        user_namespace: 0,
    };
    // The live descriptor addresses this original mount, not a freshly resolved path.
    require(
        // SAFETY: The empty path is a NUL-terminated literal, `attributes` is a complete mount_attr
        // passed with its size, and the descriptor stays open.
        unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as u32,
                &attributes as *const Attributes,
                std::mem::size_of::<Attributes>(),
            )
        } == 0,
        "owned destination propagation normalization failed",
    )?;
    require(
        mount_identity::id(file.as_fd(), true)? == original,
        "owned destination mount replaced",
    )
}
