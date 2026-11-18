// SPDX-License-Identifier: MIT
//! Exclusive measured copy keeps actual created/old/new descriptions through rename.
use crate::stream_copy::STREAM_BOUND;
use crate::{Error, Result, files, mount_identity, require, stream_copy};
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
type Shape = (u64, u64, u32, u32, u32);
fn shape(f: &File, owner: u32) -> Result<Shape> {
    let m = f.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o7022 == 0,
        "original protected copy parent required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn name(n: &str) -> Result<CString> {
    require(
        !n.is_empty() && n.len() <= 255 && !n.contains('/') && !matches!(n, "." | ".."),
        "single copy publication name",
    )?;
    CString::new(n).map_err(|_| Error("copy name encoding".into()))
}
fn file(f: &File, owner: u32, mount: u64, maximum: u64) -> Result<files::FileIdentity> {
    let m = f.metadata()?;
    require(
        m.is_file()
            && m.uid() == owner
            && m.gid() == owner
            && m.mode() & 0o7022 == 0
            && m.nlink() == 1
            && m.len() <= maximum
            && mount_identity::id(f.as_fd(), true)? == mount,
        "original copied file protection/mount/size",
    )?;
    Ok(files::identity(&m))
}
fn renamed(a: files::FileIdentity, b: files::FileIdentity) -> bool {
    a.0 == b.0
        && a.1 == b.1
        && a.2 == b.2
        && a.3 == b.3
        && a.4 == b.4
        && a.7 == b.7
        && a.8 == b.8
        && a.9 == b.9
        && a.10 == b.10
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn description_flags(file: &File) -> Result<i32> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(flags >= 0, "original copy description flags unavailable")?;
    Ok(flags)
}
pub struct Copy {
    source: File,
    source_epoch: files::FileIdentity,
    source_flags: i32,
    source_mount: u64,
    parent: File,
    shape: Shape,
    parent_flags: i32,
    mount: u64,
    owner: u32,
    written: File,
    readonly: File,
    written_flags: i32,
    readonly_flags: i32,
    epoch: files::FileIdentity,
    name: String,
    bytes: u64,
    sha: String,
    removed: Option<(File, files::FileIdentity, files::FileIdentity)>,
    removed_flags: Option<i32>,
    prior_names: Vec<String>,
    moves: u8,
}
impl Copy {
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, openat).")]
    pub fn create(
        input: &mut File,
        parent: &File,
        destination: &str,
        bytes: u64,
        digest: &str,
        owner: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        name(destination)?;
        require(
            bytes > 0
                && bytes <= STREAM_BOUND
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "copy measured size/digest bounds",
        )?;
        require(unsafe { libc::geteuid() } == owner, "original copy writer")?;
        let parent_shape = shape(parent, owner)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let m = input.metadata()?;
        require(
            m.is_file() && m.nlink() == 1 && m.len() == bytes,
            "original copy source shape/size",
        )?;
        let source_epoch = files::identity(&m);
        let source_mount = mount_identity::id(input.as_fd(), true)?;
        let source = input.try_clone()?;
        let source_flags = description_flags(&source)?;
        let parent_flags = description_flags(parent)?;
        require(
            files::optional_relative(parent, Path::new(destination))?.is_none(),
            "copy destination already exists; no adoption",
        )?;
        input.seek(SeekFrom::Start(0))?;
        let temporary = format!(".copy-{}", files::random_hex(16)?);
        let temp = name(&temporary)?;
        authorize()?;
        require(
            shape(parent, owner)? == parent_shape
                && mount_identity::id(parent.as_fd(), true)? == mount
                && files::identity(&input.metadata()?) == source_epoch
                && description_flags(&source)? == source_flags
                && description_flags(parent)? == parent_flags,
            "original copy inputs changed before create",
        )?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temp.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(raw >= 0, "exclusive copy pending; retain uncertainty")?;
        let mut written = unsafe { File::from_raw_fd(raw) };
        let written_flags = description_flags(&written)?;
        let created = file(&written, owner, mount, bytes)?;
        let mut total = 0u64;
        let mut sum = Sha256::new();
        let mut buffer = vec![0; 256 * 1024];
        loop {
            authorize()?;
            let named = files::open_relative(parent, Path::new(&temporary))?;
            let now = file(&written, owner, mount, bytes)?;
            require(
                now.0 == created.0
                    && now.1 == created.1
                    && now.7 == created.7
                    && now.8 == created.8
                    && now.9 == created.9
                    && file(&named, owner, mount, bytes)? == now
                    && shape(parent, owner)? == parent_shape
                    && mount_identity::id(parent.as_fd(), true)? == mount
                    && description_flags(&source)? == source_flags
                    && description_flags(parent)? == parent_flags
                    && description_flags(&written)? == written_flags
                    && files::identity(&input.metadata()?) == source_epoch
                    && mount_identity::id(input.as_fd(), true)? == source_mount,
                "original copy source/created description/parent changed",
            )?;
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as u64)
                .ok_or_else(|| Error("copy byte overflow".into()))?;
            require(total <= bytes, "copy source grew")?;
            written.write_all(&buffer[..n])?;
            sum.update(&buffer[..n]);
        }
        require(
            total == bytes
                && format!("{:x}", sum.finalize()) == digest
                && files::identity(&input.metadata()?) == source_epoch,
            "copy source bytes or epoch changed",
        )?;
        written.sync_all()?;
        let epoch = file(&written, owner, mount, bytes)?;
        let readonly = files::open_relative(parent, Path::new(&temporary))?;
        require(
            file(&readonly, owner, mount, bytes)? == epoch,
            "created copy readonly description differs",
        )?;
        let readonly_flags = description_flags(&readonly)?;
        let copy = Self {
            source,
            source_epoch,
            source_flags,
            source_mount,
            parent: parent.try_clone()?,
            shape: parent_shape,
            parent_flags,
            mount,
            owner,
            written,
            readonly,
            written_flags,
            readonly_flags,
            epoch,
            name: temporary,
            bytes,
            sha: digest.into(),
            removed: None,
            removed_flags: None,
            prior_names: Vec::new(),
            moves: 0,
        };
        copy.recheck(authorize)?;
        let copy = copy.rename(destination, None, authorize)?;
        copy.recheck(authorize)?;
        Ok(copy)
    }
    fn light(&self) -> Result<()> {
        self.light_at(self.source_epoch)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn light_at(&self, source_epoch: files::FileIdentity) -> Result<()> {
        require(
            description_flags(&self.source)? == self.source_flags
                && description_flags(&self.parent)? == self.parent_flags
                && description_flags(&self.written)? == self.written_flags
                && description_flags(&self.readonly)? == self.readonly_flags,
            "original copy description flags changed",
        )?;
        require(
            unsafe { libc::geteuid() } == self.owner
                && shape(&self.parent, self.owner)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && files::identity(&self.source.metadata()?) == source_epoch
                && mount_identity::id(self.source.as_fd(), true)? == self.source_mount,
            "original copy source/owner/parent changed",
        )?;
        let named = files::open_relative(&self.parent, Path::new(&self.name))?;
        require(
            file(&self.written, self.owner, self.mount, self.bytes)? == self.epoch
                && file(&self.readonly, self.owner, self.mount, self.bytes)? == self.epoch
                && file(&named, self.owner, self.mount, self.bytes)? == self.epoch,
            "original copied file replaced/changed",
        )?;
        for prior in &self.prior_names {
            require(
                files::optional_relative(&self.parent, Path::new(prior))?.is_none(),
                "prior copy name reappeared",
            )?;
        }
        if let Some((original, before, closed)) = &self.removed {
            let after = files::identity(&original.metadata()?);
            require(
                after == *closed
                    && Some(description_flags(original)?) == self.removed_flags
                    && after.10 == 0
                    && before.0 == after.0
                    && before.1 == after.1
                    && before.2 == after.2
                    && before.3 == after.3
                    && before.4 == after.4
                    && before.7 == after.7
                    && before.8 == after.8
                    && before.9 == after.9
                    && mount_identity::id(original.as_fd(), true)? == self.mount,
                "replaced original copy destination changed beyond owned unlink",
            )?;
        }
        Ok(())
    }
    /// Cheap fresh checkpoint of the original measured descriptions. A content
    /// mutation changes the full kernel epoch; no new file or epoch is adopted.
    pub fn checkpoint(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        self.light()?;
        authorize()
    }
    pub fn descriptor(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&File> {
        self.checkpoint(authorize)?;
        Ok(&self.readonly)
    }
    pub fn checkpoint_after_source_replacement(
        &self,
        replacement: &Copy,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if replacement.original_epoch(&self.source)?.is_none() {
            return self.checkpoint(authorize);
        }
        authorize()?;
        require(
            replacement.original_epoch(&self.source)? == Some(self.source_epoch),
            "source replacement differs from original copy input",
        )?;
        self.light_at(files::identity(&self.source.metadata()?))?;
        replacement.light()?;
        authorize()
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let mut check = || {
            authorize()?;
            self.light()?;
            authorize()
        };
        check()?;
        require(
            stream_copy::hash_borrowed_with_checkpoint(
                &self.readonly,
                self.bytes,
                Some(self.owner),
                &mut check,
            )? == (self.bytes, self.sha.clone()),
            "original copy readback differs",
        )?;
        check()
    }
    /// A live actual replacement can attest only its own source unlink transition.
    /// No epoch is adopted or stored, and the replacement is rechecked each chunk.
    pub fn recheck_after_source_replacement(
        &self,
        replacement: &Copy,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if replacement.original_epoch(&self.source)?.is_none() {
            return self.recheck(authorize);
        }
        let mut check = || self.checkpoint_after_source_replacement(replacement, authorize);
        check()?;
        require(
            stream_copy::hash_borrowed_with_checkpoint(
                &self.readonly,
                self.bytes,
                Some(self.owner),
                &mut check,
            )? == (self.bytes, self.sha.clone()),
            "original copy readback after source replacement differs",
        )?;
        check()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    fn rename(
        mut self,
        destination: &str,
        original: Option<&File>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        self.recheck(authorize)?;
        name(destination)?;
        require(
            destination != self.name && self.removed.is_none() && self.moves < 2,
            "copy publication already consumed",
        )?;
        let previous = original.map(std::fs::File::try_clone).transpose()?;
        let previous_flags = previous.as_ref().map(description_flags).transpose()?;
        let previous_epoch = previous
            .as_ref()
            .map(|f| file(f, self.owner, self.mount, STREAM_BOUND))
            .transpose()?;
        let current = files::optional_relative(&self.parent, Path::new(destination))?;
        match (current, previous_epoch) {
            (None, None) => (),
            (Some(named), Some(epoch)) => require(
                file(&named, self.owner, self.mount, STREAM_BOUND)? == epoch,
                "copy destination differs from caller original",
            )?,
            _ => {
                return Err(Error(
                    "copy destination appeared/disappeared; retain original copy".into(),
                ));
            }
        }
        authorize()?;
        self.light()?;
        let current = files::optional_relative(&self.parent, Path::new(destination))?;
        match (current, previous.as_ref(), previous_epoch) {
            (None, None, None) => (),
            (Some(named), Some(original), Some(epoch)) => require(
                file(&named, self.owner, self.mount, STREAM_BOUND)? == epoch
                    && file(original, self.owner, self.mount, STREAM_BOUND)? == epoch
                    && Some(description_flags(original)?) == previous_flags,
                "original copy replacement changed before rename",
            )?,
            _ => return Err(Error("copy replacement uncertainty before rename".into())),
        }
        let from = name(&self.name)?;
        let to = name(destination)?;
        require(
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    from.as_ptr(),
                    self.parent.as_raw_fd(),
                    to.as_ptr(),
                    if previous.is_some() {
                        0
                    } else {
                        libc::RENAME_NOREPLACE
                    },
                )
            } == 0,
            "copy publication uncertain; no retry",
        )?;
        self.parent.sync_all()?;
        let after = file(&self.written, self.owner, self.mount, self.bytes)?;
        require(
            renamed(self.epoch, after),
            "owned copy rename changed original beyond ctime",
        )?;
        self.epoch = after;
        self.prior_names.push(self.name);
        self.moves += 1;
        self.name = destination.into();
        self.removed_flags = previous_flags;
        self.removed = if let Some((previous, before)) = previous.zip(previous_epoch) {
            let closed = files::identity(&previous.metadata()?);
            require(
                closed.10 == 0
                    && before.0 == closed.0
                    && before.1 == closed.1
                    && before.2 == closed.2
                    && before.3 == closed.3
                    && before.4 == closed.4
                    && before.7 == closed.7
                    && before.8 == closed.8
                    && before.9 == closed.9,
                "original replacement changed beyond known unlink",
            )?;
            Some((previous, before, closed))
        } else {
            None
        };
        self.recheck(&mut || Ok(()))?;
        Ok(self)
    }
    /// Only the original exclusive copied description may cross this one-use
    /// replacement boundary. A caller must retain its original target beforehand
    /// and perform fresh post-mutation checks with this actual actor before
    /// completing any receipt. The old target may no longer have its old name.
    pub fn replace(
        self,
        destination: &str,
        original: Option<&File>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        require(
            self.moves == 1,
            "original copy replacement already consumed",
        )?;
        self.rename(destination, original, authorize)
    }
    pub fn file(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&File> {
        self.recheck(authorize)?;
        Ok(&self.readonly)
    }
    pub fn sha256(&self) -> &str {
        &self.sha
    }
    pub fn replaced(&self, original: &File) -> Result<bool> {
        self.light()?;
        if let Some((file, _, _)) = &self.removed {
            Ok(files::identity(&file.metadata()?) == files::identity(&original.metadata()?))
        } else {
            Ok(false)
        }
    }
    /// The original input name may have been replaced only through this actual
    /// retained actor; its pre-rename epoch remains bound rather than decoded.
    pub fn original_epoch(&self, original: &File) -> Result<Option<files::FileIdentity>> {
        self.light()?;
        if self.replaced(original)? {
            Ok(self.removed.as_ref().map(|(_, epoch, _)| *epoch))
        } else {
            Ok(None)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("owned-copy-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(
                std::env::var_os("ENZIMOS_TEST_TMPDIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::env::current_dir().unwrap()),
            )
            .unwrap()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn source(d: &tempfile::TempDir) -> File {
        std::fs::write(d.path().join("source"), b"original").unwrap();
        files::open_relative(
            &files::directory(d.path(), Some(unsafe { libc::geteuid() })).unwrap(),
            Path::new("source"),
        )
        .unwrap()
    }

    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, geteuid).")]
    fn actual_created_copy_replaces_only_caller_original_and_never_replays() {
        let d = fixture();
        let uid = unsafe { libc::geteuid() };
        let parent = files::directory(d.path(), Some(uid)).unwrap();
        let mut input = source(&d);
        std::fs::write(d.path().join("target"), b"old").unwrap();
        let original = files::open_relative(&parent, Path::new("target")).unwrap();
        let before = files::identity(&original.metadata().unwrap());
        let copy = Copy::create(
            &mut input,
            &parent,
            "staged",
            8,
            &json::sha256(b"original"),
            uid,
            &mut || Ok(()),
        )
        .unwrap();
        let copy = copy
            .replace("target", Some(&original), &mut || Ok(()))
            .unwrap();
        copy.recheck(&mut || Ok(())).unwrap();
        assert_eq!(copy.original_epoch(&original).unwrap(), Some(before));
        assert_eq!(
            files::read_file(copy.file(&mut || Ok(())).unwrap(), 1024, Some(uid), true).unwrap(),
            b"original"
        );
        assert_eq!(
            unsafe {
                libc::fcntl(
                    copy.file(&mut || Ok(())).unwrap().as_raw_fd(),
                    libc::F_GETFL,
                )
            } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        assert!(copy.replace("another", None, &mut || Ok(())).is_err());
        assert_eq!(std::fs::read(d.path().join("target")).unwrap(), b"original");
    }
}
