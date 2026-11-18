// SPDX-License-Identifier: MIT
//! Fixed pending publication retains original descriptions through owned rename.
use crate::{Error, Result, files, json, mount_identity, require, stream_copy};
use std::os::unix::ffi::OsStrExt as _;
use std::{
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const LIMIT: u64 = 2 * 1024 * 1024;
type Shape = (u64, u64, u32, u32, u32);
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn status(file: &File) -> Result<i32> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(
        flags >= 0,
        "original publication description status unavailable",
    )?;
    Ok(flags)
}
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o7022 == 0,
        "original protected publication parent required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn member(file: &File, owner: u32, mount: u64) -> Result<files::FileIdentity> {
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.uid() == owner
            && m.gid() == owner
            && m.mode() & 0o7022 == 0
            && m.nlink() == 1
            && m.len() <= LIMIT
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original publication file owner/mode/link/mount/bound",
    )?;
    Ok(files::identity(&m))
}
fn renamed(before: files::FileIdentity, after: files::FileIdentity) -> bool {
    before.0 == after.0
        && before.1 == after.1
        && before.2 == after.2
        && before.3 == after.3
        && before.4 == after.4
        && before.7 == after.7
        && before.8 == after.8
        && before.9 == after.9
        && before.10 == after.10
}
pub struct Prepared {
    parent: File,
    parent_flags: i32,
    parent_path: PathBuf,
    shape: Shape,
    mount: u64,
    owner: u32,
    temporary: CString,
    destination: CString,
    original: Option<File>,
    original_flags: Option<i32>,
    original_epoch: Option<files::FileIdentity>,
    written: File,
    written_flags: i32,
    written_epoch: files::FileIdentity,
    sha256: String,
}
impl Prepared {
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, openat).")]
    pub fn write(path: &Path, body: &[u8], owner: u32) -> Result<Self> {
        require(
            unsafe { libc::geteuid() } == owner && body.len() as u64 <= LIMIT,
            "publication writer or size",
        )?;
        let parent_path = path
            .parent()
            .ok_or_else(|| Error("missing publication parent".into()))?
            .to_owned();
        let parent = files::directory(&parent_path, Some(owner))?;
        let parent_flags = status(&parent)?;
        let shape = shape(&parent, owner)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error("invalid publication name".into()))?;
        require(
            !name.is_empty() && name != "." && name != ".." && name.len() <= 240,
            "single bounded publication filename",
        )?;
        let destination =
            CString::new(name).map_err(|_| Error("publication name encoding".into()))?;
        let temporary = CString::new(format!("{name}.new"))
            .map_err(|_| Error("invalid generated native name".into()))?;
        let original = files::optional_relative(&parent, Path::new(name))?;
        let original_flags = original.as_ref().map(status).transpose()?;
        let original_epoch = original
            .as_ref()
            .map(|f| member(f, owner, mount))
            .transpose()?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0, "publication pending; inspection required")?;
        let mut written = unsafe { File::from_raw_fd(fd) };
        let written_flags = status(&written)?;
        written.write_all(body)?;
        written.sync_all()?;
        parent.sync_all()?;
        // Admit the actual filesystem mode. FAT may expose a fixed mount mode;
        // no fabricated chmod result can substitute for its observed protection.
        let written_epoch = member(&written, owner, mount)?;
        let this = Self {
            parent,
            parent_flags,
            parent_path,
            shape,
            mount,
            owner,
            temporary,
            destination,
            original,
            original_flags,
            original_epoch,
            written,
            written_flags,
            written_epoch,
            sha256: json::sha256(body),
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn write_authorized(
        path: &Path,
        body: &[u8],
        owner: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        let prepared = Self::write(path, body, owner)?;
        authorize()?;
        prepared.recheck()?;
        Ok(prepared)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn parent(&self) -> Result<()> {
        require(
            unsafe { libc::geteuid() } == self.owner,
            "original publication writer changed",
        )?;
        require(
            status(&self.parent)? == self.parent_flags
                && status(&self.written)? == self.written_flags
                && self.original.as_ref().map(status).transpose()? == self.original_flags,
            "original publication description flags changed",
        )?;
        let named = files::directory(&self.parent_path, Some(self.owner))?;
        require(
            shape(&self.parent, self.owner)? == self.shape
                && shape(&named, self.owner)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original publication parent replaced/covered",
        )
    }
    pub fn recheck(&self) -> Result<()> {
        self.parent()?;
        let temporary = Path::new(std::ffi::OsStr::from_bytes(self.temporary.to_bytes()));
        let named = files::open_relative(&self.parent, temporary)?;
        require(
            member(&self.written, self.owner, self.mount)? == self.written_epoch
                && member(&named, self.owner, self.mount)? == self.written_epoch,
            "original pending publication file replaced/changed",
        )?;
        require(
            stream_copy::hash_borrowed(&self.written, LIMIT, Some(self.owner))?.1 == self.sha256,
            "original pending publication bytes changed",
        )?;
        let current = files::optional_relative(
            &self.parent,
            Path::new(std::ffi::OsStr::from_bytes(self.destination.to_bytes())),
        )?;
        match (&self.original, current, self.original_epoch) {
            (None, None, None) => (),
            (Some(original), Some(named), Some(epoch)) => require(
                member(original, self.owner, self.mount)? == epoch
                    && member(&named, self.owner, self.mount)? == epoch,
                "original publication destination replaced/changed",
            )?,
            _ => return Err(Error("publication destination appeared/disappeared".into())),
        }
        // Reads must not leave a stale temporary description check behind.
        let named = files::open_relative(&self.parent, temporary)?;
        require(
            member(&named, self.owner, self.mount)? == self.written_epoch
                && member(&self.written, self.owner, self.mount)? == self.written_epoch,
            "pending publication changed during readback",
        )?;
        self.parent()
    }
    /// Bind replacement to the caller's already held original description,
    /// rather than merely a file discovered while preparing this publication.
    /// Bind an actual pending exclusive creation to the independently held
    /// parent and exact leaf. Existing destinations cannot supply this proof.
    /// Return only the temporary name of this live writer beneath its original
    /// parent, after joining an independently held parent and destination.
    pub fn pending_name(&self, parent: &File, destination: &Path) -> Result<&str> {
        self.recheck()?;
        require(
            shape(parent, self.owner)? == self.shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && destination.as_os_str().as_encoded_bytes() == self.destination.as_bytes(),
            "pending publication parent/destination differs",
        )?;
        self.temporary
            .to_str()
            .map_err(|_| Error("pending publication name encoding".into()))
    }
    pub fn require_new_destination(&self, parent: &File, name: &Path) -> Result<()> {
        self.recheck()?;
        require(
            self.original.is_none()
                && self.original_epoch.is_none()
                && shape(parent, self.owner)? == self.shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && name == Path::new(std::ffi::OsStr::from_bytes(self.destination.to_bytes())),
            "pending creation differs from original parent/leaf or adopts existing output",
        )?;
        self.recheck()
    }
    pub fn require_original(&self, original: &File) -> Result<()> {
        self.recheck()?;
        require(
            self.original_epoch == Some(member(original, self.owner, self.mount)?),
            "publication requires caller original destination description",
        )
    }
    /// Check an independently retained caller epoch before the destructive
    /// replacement, rather than adopting metadata observed during preparation.
    pub fn require_original_epoch(
        &self,
        original: &File,
        expected: files::FileIdentity,
    ) -> Result<()> {
        self.recheck()?;
        require(
            self.original_epoch == Some(expected)
                && member(original, self.owner, self.mount)? == expected,
            "publication requires caller original retained epoch",
        )?;
        self.require_original(original)
    }
    pub fn commit(self, replace: bool) -> Result<()> {
        self.commit_retained(replace)?.recheck()
    }
    pub fn commit_authorized(
        self,
        replace: bool,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.commit_retained_authorized(replace, authorize)?
            .recheck()
    }
    pub fn commit_retained_authorized(
        self,
        replace: bool,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Committed> {
        authorize()?;
        self.recheck()?;
        authorize()?;
        let committed = self.commit_retained(replace)?;
        authorize()?;
        committed.recheck()?;
        authorize()?;
        Ok(committed)
    }
    /// Check the actual retained replacement after the sole rename attempt.
    /// The postcondition receives only the producer returned by that attempt.
    pub fn commit_checked(
        self,
        replace: bool,
        before: &mut dyn FnMut() -> Result<()>,
        after: &mut dyn FnMut(&Committed) -> Result<()>,
    ) -> Result<Committed> {
        before()?;
        self.recheck()?;
        before()?;
        let committed = self.commit_retained(replace)?;
        after(&committed)?;
        committed.recheck()?;
        after(&committed)?;
        Ok(committed)
    }
    /// Original-file witness returned only by this actual owned publication.
    /// Drop never removes a pending file or repairs an uncertain rename.
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub fn commit_retained(self, replace: bool) -> Result<Committed> {
        self.recheck()?;
        require(
            replace || self.original.is_none(),
            "exclusive publication destination already exists",
        )?;
        require(
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    self.temporary.as_ptr(),
                    self.parent.as_raw_fd(),
                    self.destination.as_ptr(),
                    if replace && self.original.is_some() {
                        0
                    } else {
                        libc::RENAME_NOREPLACE
                    },
                )
            } == 0,
            "publication changed or incomplete; no replay",
        )?;
        self.parent.sync_all()?;
        let epoch = member(&self.written, self.owner, self.mount)?;
        require(
            renamed(self.written_epoch, epoch),
            "owned publication rename changed original beyond ctime",
        )?;
        let published = files::open_relative(
            &self.parent,
            Path::new(std::ffi::OsStr::from_bytes(self.destination.to_bytes())),
        )?;
        require(
            member(&published, self.owner, self.mount)? == epoch,
            "published readonly original differs from owned file",
        )?;
        let published_flags = status(&published)?;
        let mut committed = Committed {
            original: self,
            epoch,
            published,
            published_flags,
            replaced_epoch: None,
        };
        if let Some(original) = &committed.original.original {
            committed.replaced_epoch = Some(files::identity(&original.metadata()?));
        }
        committed.recheck()?;
        Ok(committed)
    }
}
pub struct Committed {
    original: Prepared,
    epoch: files::FileIdentity,
    published: File,
    published_flags: i32,
    replaced_epoch: Option<files::FileIdentity>,
}
impl Committed {
    pub fn recheck(&self) -> Result<()> {
        let p = &self.original;
        p.parent()?;
        require(
            status(&self.published)? == self.published_flags,
            "committed publication readonly description flags changed",
        )?;
        let named = files::open_relative(
            &p.parent,
            Path::new(std::ffi::OsStr::from_bytes(p.destination.to_bytes())),
        )?;
        require(
            member(&p.written, p.owner, p.mount)? == self.epoch
                && member(&self.published, p.owner, p.mount)? == self.epoch
                && member(&named, p.owner, p.mount)? == self.epoch
                && files::optional_relative(
                    &p.parent,
                    Path::new(std::ffi::OsStr::from_bytes(p.temporary.to_bytes())),
                )?
                .is_none(),
            "original committed publication replaced or pending name reappeared",
        )?;
        self.recheck_replaced()?;
        require(
            stream_copy::hash_borrowed(&p.written, LIMIT, Some(p.owner))?.1 == p.sha256,
            "committed original publication bytes changed",
        )?;
        let named = files::open_relative(
            &p.parent,
            Path::new(std::ffi::OsStr::from_bytes(p.destination.to_bytes())),
        )?;
        require(
            member(&p.written, p.owner, p.mount)? == self.epoch
                && member(&self.published, p.owner, p.mount)? == self.epoch
                && member(&named, p.owner, p.mount)? == self.epoch,
            "committed original publication changed during readback",
        )?;
        p.parent()
    }
    fn recheck_replaced(&self) -> Result<()> {
        let p = &self.original;
        if let Some(old) = &p.original {
            let after = files::identity(&old.metadata()?);
            let before = p
                .original_epoch
                .ok_or_else(|| Error("original publication epoch missing".into()))?;
            require(
                Some(after) == self.replaced_epoch
                    && after.10 == 0
                    && before.0 == after.0
                    && before.1 == after.1
                    && before.2 == after.2
                    && before.3 == after.3
                    && before.4 == after.4
                    && before.7 == after.7
                    && before.8 == after.8
                    && before.9 == after.9
                    && mount_identity::id(old.as_fd(), true)? == p.mount,
                "replaced original publication member changed beyond owned unlink",
            )?;
        }
        Ok(())
    }
    /// Actual predecessor descriptions are retained by this owned replacement.
    /// The returned epoch is comparison data; it cannot construct a publication.
    pub fn replaced_original(&self) -> Result<(&File, files::FileIdentity)> {
        self.recheck()?;
        let original = self
            .original
            .original
            .as_ref()
            .ok_or_else(|| Error("publication did not replace an original member".into()))?;
        Ok((
            original,
            self.original
                .original_epoch
                .ok_or_else(|| Error("original publication epoch missing".into()))?,
        ))
    }
    /// Bind this actual publication to an already retained original parent and
    /// exact leaf. Metadata returned by evidence cannot supply this witness.
    pub fn require_destination(&self, parent: &File, name: &Path) -> Result<()> {
        self.recheck()?;
        require(
            shape(parent, self.original.owner)? == self.original.shape
                && mount_identity::id(parent.as_fd(), true)? == self.original.mount
                && name
                    == Path::new(std::ffi::OsStr::from_bytes(
                        self.original.destination.to_bytes(),
                    )),
            "owned publication requires original parent and exact leaf",
        )
    }
    pub fn file(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.published)
    }
    pub fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"inode":self.epoch,"mount":self.original.mount,"sha256":self.original.sha256}),
        )
    }
}
/// A bounded chain of actual owned replacements. Every superseded original
/// description stays retained; only its successor's actual unlink may change it.
/// Existing files or decoded receipts cannot construct or extend this chain.
pub struct Chain {
    publications: Vec<Committed>,
}
impl Chain {
    pub fn new(initial: Committed) -> Result<Self> {
        initial.recheck()?;
        Ok(Self {
            publications: vec![initial],
        })
    }
    pub fn recheck(&self) -> Result<()> {
        let latest = self
            .publications
            .last()
            .ok_or_else(|| Error("empty publication chain".into()))?;
        latest.recheck()?;
        for pair in self.publications.windows(2) {
            let (old, next) = (&pair[0], &pair[1]);
            old.original.parent()?;
            old.recheck_replaced()?;
            let old_epoch = files::identity(&old.published.metadata()?);
            require(
                next.original.original_epoch == Some(old.epoch)
                    && next.replaced_epoch == Some(old_epoch)
                    && files::identity(&old.original.written.metadata()?) == old_epoch
                    && old_epoch.10 == 0
                    && old.original.shape == next.original.shape
                    && old.original.mount == next.original.mount
                    && old.original.owner == next.original.owner
                    && old.original.parent_path == next.original.parent_path
                    && old.original.destination == next.original.destination
                    && mount_identity::id(old.published.as_fd(), true)? == old.original.mount
                    && mount_identity::id(old.original.written.as_fd(), true)?
                        == old.original.mount,
                "superseded original publication changed outside owned successor",
            )?;
        }
        latest.recheck()
    }
    pub fn replace(
        &mut self,
        body: &[u8],
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.recheck()?;
        require(
            self.publications.len() < 256
                && self.publications.iter().map(|p| p.epoch.2).sum::<u64>() + body.len() as u64
                    <= 16 * 1024 * 1024,
            "original publication chain count/byte budget",
        )?;
        let latest = self
            .publications
            .last()
            .ok_or_else(|| Error("publication chain is empty".into()))?;
        let original = latest.file()?.try_clone()?;
        let path = latest
            .original
            .parent_path
            .join(std::ffi::OsStr::from_bytes(
                latest.original.destination.to_bytes(),
            ));
        let prepared = Prepared::write_authorized(&path, body, latest.original.owner, authorize)?;
        prepared.require_original_epoch(&original, latest.epoch)?;
        let next = prepared.commit_retained_authorized(true, authorize)?;
        self.publications.push(next);
        self.recheck()?;
        authorize()
    }
    pub fn file(&self) -> Result<&File> {
        self.recheck()?;
        self.publications
            .last()
            .ok_or_else(|| Error("publication chain is empty".into()))?
            .file()
    }
    pub fn require_destination(&self, parent: &File, name: &Path) -> Result<()> {
        self.recheck()?;
        self.publications
            .last()
            .ok_or_else(|| Error("publication chain is empty".into()))?
            .require_destination(parent, name)
    }
    pub fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"current":self.publications.last().ok_or_else(|| Error("publication chain is empty".into()))?.evidence()?,"owned_publications":self.publications.len()}),
        )
    }
}
