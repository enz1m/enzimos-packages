// SPDX-License-Identifier: MIT
//! Identity-checked rollback of a mount this process attached but did not close.
//!
//! Normal closure stays with the owner (recheck, then a plain unmount). This is
//! the failure path: an error, an early return or a panic after attachment must
//! never leave the mount behind. Only the mount whose unique ID is on top of
//! the fixed target is touched; anything else is refused and logged.
use enzimos_platform::{Error, Result, mount_identity, require};
use std::{
    ffi::CStr,
    fs::File,
    os::fd::{AsFd, FromRawFd},
};

/// Kernel seam so the rollback decisions are testable without privileges.
pub(crate) trait Kernel {
    /// Unique mount ID of the mount on top of `target`; None if it cannot be opened.
    fn top(&self, target: &CStr) -> Result<Option<u64>>;
    /// Whether the mountinfo row with this short mount ID is in this namespace.
    fn present(&self, normal: u64) -> Result<bool>;
    fn umount(&self, target: &CStr, lazy: bool) -> std::io::Result<()>;
}
pub(crate) struct Live;
impl Kernel for Live {
    #[allow(unsafe_code, reason = "Linux syscall ABI (open).")]
    fn top(&self, target: &CStr) -> Result<Option<u64>> {
        // SAFETY: `target` is NUL-terminated.
        let raw = unsafe {
            libc::open(
                target.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Ok(None);
        }
        // SAFETY: `raw` was just returned by open and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(raw) };
        Ok(Some(mount_identity::id(file.as_fd(), true)?))
    }
    fn present(&self, normal: u64) -> Result<bool> {
        Ok(crate::storage_runtime::rows()?
            .iter()
            .any(|row| row.id == normal))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    fn umount(&self, target: &CStr, lazy: bool) -> std::io::Result<()> {
        let flags = if lazy { libc::MNT_DETACH } else { 0 };
        // SAFETY: `target` is NUL-terminated.
        if unsafe { libc::umount2(target.as_ptr(), flags) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    AlreadyGone,
    Unmounted,
    Detached,
}
/// Remove exactly the owned mount (`unique`, mountinfo row `normal`) from the
/// top of `target`. A busy mount is lazily detached: it is already unreachable
/// to new users and is released when its last reference closes. `normal == 0`
/// means the row ID was not observable; the unique ID on top then decides.
pub(crate) fn rollback(
    kernel: &dyn Kernel,
    target: &CStr,
    unique: u64,
    normal: u64,
) -> Result<Outcome> {
    let top = kernel.top(target)?;
    if normal != 0 && !kernel.present(normal)? {
        return Ok(Outcome::AlreadyGone);
    }
    require(
        top == Some(unique),
        "owned mount is no longer on top of its fixed target; rollback refused",
    )?;
    let outcome = match kernel.umount(target, false) {
        Ok(()) => Outcome::Unmounted,
        Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
            require(
                kernel.top(target)? == Some(unique),
                "owned mount changed while busy; rollback refused",
            )?;
            kernel
                .umount(target, true)
                .map_err(|e| Error(format!("owned mount detach failed: {e}")))?;
            Outcome::Detached
        }
        Err(error) => return Err(Error(format!("owned mount unmount failed: {error}"))),
    };
    let gone = if normal != 0 {
        !kernel.present(normal)?
    } else {
        kernel.top(target)? != Some(unique)
    };
    require(gone, "owned mount still present after rollback")?;
    Ok(outcome)
}
/// Armed from the moment of attachment until the owner's normal unmount
/// succeeds. Dropping it armed (error, early return, panic) rolls back.
pub(crate) struct Armed {
    target: &'static CStr,
    unique: u64,
    normal: u64,
    label: &'static str,
    armed: bool,
}
impl Armed {
    pub(crate) fn new(
        target: &'static CStr,
        unique: u64,
        normal: u64,
        label: &'static str,
    ) -> Self {
        Self {
            target,
            unique,
            normal,
            label,
            armed: true,
        }
    }
    /// Normal closure succeeded; nothing remains to roll back.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
    /// Roll back now (once). The outcome is always written to the journal.
    pub(crate) fn release(&mut self) -> Result<()> {
        self.release_with(&Live)
    }
    pub(crate) fn release_with(&mut self, kernel: &dyn Kernel) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        let target = self.target.to_string_lossy();
        match rollback(kernel, self.target, self.unique, self.normal) {
            Ok(outcome) => {
                eprintln!(
                    "enzimos-backup-setup: rollback of {} at {target}: {outcome:?}",
                    self.label
                );
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "enzimos-backup-setup: rollback of {} at {target} FAILED: {}",
                    self.label,
                    crate::diagnostic::bounded(&error.0)
                );
                Err(error)
            }
        }
    }
}
impl Drop for Armed {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    /// A fixed target holding a stack of (unique, normal) mounts.
    pub(crate) struct Fake {
        pub stack: RefCell<Vec<(u64, u64)>>,
        pub busy: RefCell<bool>,
        pub calls: RefCell<Vec<&'static str>>,
    }
    impl Fake {
        pub(crate) fn new(stack: Vec<(u64, u64)>) -> Self {
            Self {
                stack: RefCell::new(stack),
                busy: RefCell::new(false),
                calls: RefCell::new(Vec::new()),
            }
        }
    }
    impl Kernel for Fake {
        fn top(&self, _: &CStr) -> Result<Option<u64>> {
            Ok(self.stack.borrow().last().map(|m| m.0))
        }
        fn present(&self, normal: u64) -> Result<bool> {
            Ok(self.stack.borrow().iter().any(|m| m.1 == normal))
        }
        fn umount(&self, _: &CStr, lazy: bool) -> std::io::Result<()> {
            self.calls
                .borrow_mut()
                .push(if lazy { "detach" } else { "umount" });
            if !lazy && *self.busy.borrow() {
                return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
            }
            self.stack.borrow_mut().pop();
            Ok(())
        }
    }
    const TARGET: &CStr = c"/backup-repository";
    #[test]
    fn rollback_refuses_a_covered_or_foreign_mount_and_skips_absent_ones() {
        let fake = Fake::new(vec![(100, 10), (200, 20)]);
        // Owned area is covered by another mount: never unmount the cover.
        assert!(rollback(&fake, TARGET, 100, 10).is_err());
        assert!(fake.calls.borrow().is_empty());
        assert_eq!(fake.stack.borrow().len(), 2);
        // Not present at all: nothing to do.
        assert_eq!(
            rollback(&fake, TARGET, 300, 30).unwrap(),
            Outcome::AlreadyGone
        );
        assert!(fake.calls.borrow().is_empty());
    }
}
