// SPDX-License-Identifier: MIT
//! Stable descriptor copies, digest verification and durable exclusive publication.
use crate::{Error, Result, files, require};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

/// The largest single file a verified stream copy accepts: the recovery
/// environment and base AI models packages are over 512 MiB.
pub const STREAM_BOUND: u64 = 2 * 1024 * 1024 * 1024;

/// Hash an immutable descriptor without moving its shared open-file offset.
/// Empty files are legitimate manifest members; positive-byte callers retain
/// their separate size requirements.
///
/// # Errors
///
/// Fails when the file is not a regular file within `max` bytes owned by `owner`, or changes while
/// hashed.
pub fn hash_borrowed(file: &File, max: u64, owner: Option<u32>) -> Result<(u64, String)> {
    hash_borrowed_with_checkpoint(file, max, owner, &mut || Ok(()))
}
/// Bounded descriptor hash with fresh authorization between each read. Shared
/// open-file offsets remain unchanged and the original full epoch must persist.
pub(crate) fn hash_borrowed_with_checkpoint(
    file: &File,
    max: u64,
    owner: Option<u32>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<(u64, String)> {
    authorize()?;
    use std::os::unix::fs::FileExt;
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.len() <= max
            && owner.is_none_or(|u| before.uid() == u && before.mode() & 0o022 == 0),
        "unsafe borrowed manifest file",
    )?;
    let mut sum = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = vec![0; 256 * 1024];
    loop {
        authorize()?;
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| Error("manifest hash byte overflow".into()))?;
        require(offset <= before.len(), "manifest file grew")?;
        sum.update(&buffer[..count]);
    }
    authorize()?;
    require(
        offset == before.len() && files::identity(&before) == files::identity(&file.metadata()?),
        "manifest file changed while hashing",
    )?;
    Ok((offset, format!("{:x}", sum.finalize())))
}
/// Hash a file from its start, returning its size and lowercase hex SHA-256.
///
/// # Errors
///
/// Fails when the file is not a regular file within `max` bytes owned by `owner`, or grows or
/// changes while hashed.
pub fn hash(file: &mut File, max: u64, owner: Option<u32>) -> Result<(u64, String)> {
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= max
            && owner.is_none_or(|u| before.uid() == u && before.mode() & 0o022 == 0),
        "unsafe streamed file",
    )?;
    file.seek(SeekFrom::Start(0))?;
    let mut sum = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0; 256 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| Error("stream byte overflow".into()))?;
        require(total <= before.len(), "streamed file growth")?;
        sum.update(&buffer[..n]);
    }
    require(
        total == before.len() && files::identity(&before) == files::identity(&file.metadata()?),
        "streamed file changed",
    )?;
    Ok((total, format!("{:x}", sum.finalize())))
}
/// The output remains at its exclusive temporary name on every incomplete path.
///
/// # Errors
///
/// As [`verified_with_checkpoint`].
pub fn verified(
    input: &mut File,
    parent: &File,
    name: &str,
    bytes: u64,
    digest: &str,
    owner: u32,
) -> Result<()> {
    verified_with_checkpoint(input, parent, name, bytes, digest, owner, &mut || Ok(()))
}
/// Copy exactly `bytes` bytes of `input` into a new file `name` in `parent` and publish it only
/// when its SHA-256 equals `digest`.
///
/// # Errors
///
/// Fails unless the caller's effective UID is `owner`, when the bounds are invalid, the source
/// changes or grows, the digest differs, `checkpoint` fails, or the name already exists.
/// Fresh caller/resource checks surround each bounded copy write and publication.
/// Refusal retains the exclusive partial file; this helper grants no replay.
#[allow(unsafe_code, reason = "Linux syscall ABI (openat, renameat2).")]
pub fn verified_with_checkpoint(
    input: &mut File,
    parent: &File,
    name: &str,
    bytes: u64,
    digest: &str,
    owner: u32,
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    checkpoint()?;
    require(
        !name.is_empty()
            && name.len() <= 255
            && !name.contains('/')
            && !matches!(name, "." | "..")
            && bytes > 0
            && bytes <= STREAM_BOUND
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "copy target bounds",
    )?;
    require(
        crate::process_identity::effective_uid() == owner && parent.metadata()?.uid() == owner,
        "copy writer authority",
    )?;
    let before = input.metadata()?;
    require(
        before.is_file() && before.nlink() == 1 && before.len() == bytes,
        "copy source identity",
    )?;
    input.seek(SeekFrom::Start(0))?;
    let temporary = CString::new(format!(".copy-{}", files::random_hex(16)?))
        .map_err(|_| Error("invalid generated native name".into()))?;
    let destination = CString::new(name).map_err(|_| Error("copy filename".into()))?;
    checkpoint()?;
    // SAFETY: `temporary` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0, "exclusive copy creation failed")?;
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    let mut out = unsafe { File::from_raw_fd(fd) };
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0; 256 * 1024];
    loop {
        checkpoint()?;
        require(
            files::identity(&before) == files::identity(&input.metadata()?),
            "original copy source changed before bounded write",
        )?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| Error("copy byte overflow".into()))?;
        require(total <= bytes, "copy source grew")?;
        out.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
    }
    require(
        total == bytes
            && format!("{:x}", hash.finalize()) == digest
            && files::identity(&before) == files::identity(&input.metadata()?),
        "copy source changed or digest mismatch",
    )?;
    checkpoint()?;
    out.sync_all()?;
    let actual = hash_file(&mut out, bytes, owner)?;
    require(actual == (bytes, digest.to_owned()), "copy readback failed")?;
    checkpoint()?;
    require(
        files::identity(&before) == files::identity(&input.metadata()?),
        "original copy source changed before publication",
    )?;
    require(
        // SAFETY: Both names are NUL-terminated CStrings and `parent` keeps the descriptor open.
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "copy publication collision",
    )?;
    parent.sync_all()?;
    checkpoint()
}
fn hash_file(file: &mut File, bytes: u64, owner: u32) -> Result<(u64, String)> {
    hash(file, bytes, Some(owner))
}
/// Stream exactly `bytes` bytes from `input` into `name` in `parent` with `mode`, publishing only
/// when the SHA-256 equals `digest`, and return the published read-only file.
///
/// # Errors
///
/// Fails when the size, mode or name is out of bounds, the caller is not `owner`, the stream is
/// short, long or has another digest, or the destination exists while `replace` is unset.
/// Publish a measured archive member without loading its executable into RAM.
/// A preexisting regular destination remains pinned until the replacement rename.
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, openat, renameat2).")]
#[expect(
    clippy::too_many_arguments,
    reason = "Measured size, digest and publication mode are independent inputs."
)]
pub fn verified_reader(
    input: &mut impl Read,
    parent: &File,
    name: &str,
    bytes: u64,
    digest: &str,
    mode: u32,
    owner: u32,
    replace: bool,
) -> Result<File> {
    require(
        bytes <= STREAM_BOUND
            && matches!(mode, 0o400 | 0o440 | 0o444 | 0o600 | 0o644 | 0o755)
            && name.len() <= 255
            && Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(std::path::Component::Normal(_))
            )
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "stream publication member bounds",
    )?;
    let m = parent.metadata()?;
    require(
        m.is_dir()
            && m.uid() == owner
            && m.mode() & 0o022 == 0
            && crate::process_identity::effective_uid() == owner,
        "stream publication parent authority",
    )?;
    let shape = (m.dev(), m.ino(), m.mode(), m.uid(), m.gid());
    let mount = crate::mount_identity::id(parent.as_fd(), true)?;
    let previous = files::optional_relative(parent, Path::new(name))?;
    require(
        replace || previous.is_none(),
        "stream publication refuses an existing destination",
    )?;
    let identity = previous
        .as_ref()
        .map(|file| file.metadata().map(|m| files::identity(&m)))
        .transpose()?;
    if let Some(file) = &previous {
        let m = file.metadata()?;
        require(
            m.uid() == owner
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && crate::mount_identity::id(file.as_fd(), true)? == mount,
            "unsafe previous stream destination",
        )?;
    }
    let temp = CString::new(format!(".copy-{}", files::random_hex(16)?))
        .map_err(|_| Error("invalid generated native name".into()))?;
    let name_c = CString::new(name).map_err(|_| Error("stream filename encoding".into()))?;
    // SAFETY: `temp` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temp.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(raw >= 0, "exclusive stream destination creation failed")?;
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    let mut output = unsafe { File::from_raw_fd(raw) };
    let mut total = 0u64;
    let mut sum = Sha256::new();
    let mut buffer = vec![0; 256 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| Error("stream copy overflow".into()))?;
        require(total <= bytes, "archive member exceeds its reviewed size")?;
        output.write_all(&buffer[..n])?;
        sum.update(&buffer[..n]);
    }
    require(
        total == bytes && format!("{:x}", sum.finalize()) == digest,
        "streamed archive member digest differs",
    )?;
    output.sync_all()?;
    require(
        hash_borrowed(&output, bytes, Some(owner))? == (bytes, digest.into()),
        "stream member readback differs",
    )?;
    require(
        // SAFETY: fchmod takes no pointers and `output` keeps the descriptor open.
        unsafe { libc::fchmod(output.as_raw_fd(), mode) } == 0,
        "stream member mode publication failed",
    )?;
    output.sync_all()?;
    let now = parent.metadata()?;
    require(
        (now.dev(), now.ino(), now.mode(), now.uid(), now.gid()) == shape
            && crate::mount_identity::id(parent.as_fd(), true)? == mount,
        "original stream parent changed",
    )?;
    let named = files::optional_relative(parent, Path::new(name))?;
    match (&previous, named, identity) {
        (None, None, None) => {}
        (Some(held), Some(named), Some(identity)) => require(
            files::identity(&held.metadata()?) == identity
                && files::identity(&named.metadata()?) == identity
                && crate::mount_identity::id(named.as_fd(), true)? == mount,
            "original stream destination replaced",
        )?,
        _ => return Err(Error("stream destination appeared or disappeared".into())),
    }
    require(
        // SAFETY: Both names are NUL-terminated CStrings and `parent` keeps the descriptor open.
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                temp.as_ptr(),
                parent.as_raw_fd(),
                name_c.as_ptr(),
                if replace { 0 } else { libc::RENAME_NOREPLACE },
            )
        } == 0,
        "stream publication rename refused",
    )?;
    parent.sync_all()?;
    let named = files::open_relative(parent, Path::new(name))?;
    require(
        files::identity(&output.metadata()?) == files::identity(&named.metadata()?),
        "published stream inode changed",
    )?;
    Ok(output)
}
/// Open a regular file below `parent` by relative path.
///
/// # Errors
///
/// As [`files::open_relative`].
pub fn open(parent: &File, name: &str) -> Result<File> {
    files::open_relative(parent, Path::new(name))
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    fn fixture() -> tempfile::TempDir {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        tempfile::tempdir_in(work).unwrap()
    }
    #[test]
    fn source_mutation_after_first_write_prevents_publication() {
        let temp = fixture();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let bytes = vec![7; 512 * 1024];
        std::fs::write(&source, &bytes).unwrap();
        let owner = crate::process_identity::effective_uid();
        let parent = files::directory(&output, Some(owner)).unwrap();
        let digest = crate::json::sha256(&bytes);
        let mut input = File::open(&source).unwrap();
        let mut changed = false;
        let mut boundary = || {
            if !changed
                && std::fs::read_dir(&output)?
                    .any(|entry| entry.unwrap().metadata().unwrap().len() > 0)
            {
                std::fs::write(&source, vec![8; bytes.len()])?;
                changed = true;
            }
            Ok(())
        };
        assert!(
            verified_with_checkpoint(
                &mut input,
                &parent,
                "complete",
                bytes.len() as u64,
                &digest,
                owner,
                &mut boundary
            )
            .is_err()
        );
        assert!(changed);
        assert!(!output.join("complete").exists());
    }
}
