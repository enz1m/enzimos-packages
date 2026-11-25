// SPDX-License-Identifier: MIT
//! Observe the exclusive flock attached to this exact open description.
//! Linux show_fd_locks filters by filp/flc_file; another opener's lock is absent.
use crate::{Error, Result, files, require};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::PathBuf,
};
fn parse(bytes: &[u8], inode: u64) -> Result<()> {
    let body =
        std::str::from_utf8(bytes).map_err(|_| Error("kernel lock observation encoding".into()))?;
    let locks = body
        .lines()
        .filter(|line| line.starts_with("lock:"))
        .collect::<Vec<_>>();
    require(
        locks.len() == 1,
        "original description no longer owns one exclusive flock",
    )?;
    let row = locks[0].split_whitespace().collect::<Vec<_>>();
    require(
        row.len() == 9
            && row[0] == "lock:"
            && row[1]
                .strip_suffix(':')
                .is_some_and(|s| s.parse::<u32>().is_ok_and(|n| n > 0))
            && row[2..5] == ["FLOCK", "ADVISORY", "WRITE"]
            && row[5].parse::<u32>().is_ok()
            && row[7..9] == ["0", "EOF"],
        "exclusive whole-file original flock required",
    )?;
    // fdinfo already filters the exact struct file, not merely this inode.
    // Btrfs fstat reports root->anon_dev while locks.c reports i_sb->s_dev;
    // those device numbers need not agree. Named/held stat identities remain
    // checked independently by each owner; this observation cannot repair them.
    let fields = row[6].split(':').collect::<Vec<_>>();
    require(
        fields.len() == 3
            && u32::from_str_radix(fields[0], 16).is_ok_and(|n| n < 1 << 12)
            && u32::from_str_radix(fields[1], 16).is_ok_and(|n| n < 1 << 20)
            && fields[2].parse::<u64>().ok() == Some(inode),
        "original flock inode differs",
    )
}
/// Require that `file`'s open description holds an exclusive flock on its inode.
/// No LOCK_EX, conversion or repair occurs here. Callers also retain their
/// original inode/parent/mount checks and independent rival-open exclusion.
///
/// # Errors
///
/// Fails when the lock is absent or shared, the file changed, or its fdinfo cannot be read.
pub fn exclusive(file: &File) -> Result<()> {
    let before = file.metadata()?;
    let identity = files::identity(&before);
    let path = PathBuf::from(format!(
        "/proc/{}/fdinfo/{}",
        std::process::id(),
        file.as_raw_fd()
    ));
    let bytes = files::read_kernel_owned(&path, 8192, crate::process_identity::effective_uid())?;
    parse(&bytes, before.ino())?;
    require(
        files::identity(&file.metadata()?) == identity,
        "original lock metadata changed while observed",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::unix::fs::PermissionsExt, path::Path};
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    fn actual_duplicate_description_owns_lock_but_another_opener_cannot_substitute_or_repair_it() {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        let dir = tempfile::tempdir_in(work).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("lock");
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let duplicate = held.try_clone().unwrap();
        let rival = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(exclusive(&held).is_err());
        assert_eq!(
            // SAFETY: flock takes no pointers and `held` keeps the descriptor open.
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        exclusive(&held).unwrap();
        exclusive(&duplicate).unwrap();
        assert!(exclusive(&rival).is_err());
        // SAFETY: flock takes no pointers and `held` keeps the descriptor open.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_UN) }, 0);
        assert_eq!(
            // SAFETY: flock takes no pointers and `rival` keeps the descriptor open.
            unsafe { libc::flock(rival.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(exclusive(&held).is_err());
        assert!(exclusive(&duplicate).is_err());
        exclusive(&rival).unwrap();
        // SAFETY: flock takes no pointers and `rival` keeps the descriptor open.
        assert_eq!(unsafe { libc::flock(rival.as_raw_fd(), libc::LOCK_UN) }, 0);
        assert!(exclusive(&held).is_err());
        assert_eq!(
            // SAFETY: flock takes no pointers and `rival` keeps the descriptor open.
            unsafe { libc::flock(rival.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }
}
