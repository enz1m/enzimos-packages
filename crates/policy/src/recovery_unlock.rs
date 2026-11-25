// SPDX-License-Identifier: MIT
//! Passphrases stay in zeroed RAM and travel only over the bounded child's stdin.
use crate::{operation, recovery_bootstrap, recovery_devices::Block};
use enzimos_platform::{Error, Result, process, require};
use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, FromRawFd},
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
pub const MAPPER: &str = "enzimos-recover";
struct Echo {
    fd: i32,
    saved: libc::termios,
}
impl Drop for Echo {
    #[allow(unsafe_code, reason = "Linux syscall ABI (tcsetattr).")]
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (open, poll, read, tcgetattr and others)."
)]
fn console_password() -> Result<Zeroizing<Vec<u8>>> {
    let fd = unsafe {
        libc::open(
            c"/dev/console".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    require(fd >= 0, "recovery password console unavailable")?;
    let mut console = unsafe { File::from_raw_fd(fd) };
    // SAFETY: `libc::termios` is a plain C struct, for which all-zero bytes are a valid value.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::tcgetattr(fd, &mut saved) } == 0,
        "recovery console terminal required",
    )?;
    let mut private = saved;
    private.c_lflag &= !(libc::ECHO | libc::ECHONL);
    require(
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &private) } == 0,
        "recovery console echo suppression failed",
    )?;
    let _echo = Echo { fd, saved };
    console.write_all(b"ENZIMOS recovery passphrase: ")?;
    console.flush()?;
    let deadline = Instant::now() + Duration::from_secs(86400);
    let mut result = Zeroizing::new(Vec::with_capacity(1024));
    loop {
        require(Instant::now() < deadline, "recovery password deadline")?;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 1000) };
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(ready >= 0, "recovery console poll failed")?;
        if ready == 0 {
            continue;
        }
        require(
            poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
            "recovery console closed",
        )?;
        let mut byte = Zeroizing::new([0u8; 1]);
        let count = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(count == 1, "recovery console input unavailable")?;
        if byte[0] == b'\n' {
            break;
        }
        require(
            result.len() < 999 && byte[0] != 0,
            "recovery password input bound",
        )?;
        result.push(byte[0]);
    }
    console.write_all(b"\n")?;
    require(!result.is_empty(), "empty recovery password refused")?;
    Ok(result)
}
pub fn open(source: &Block, filesystem: &str) -> Result<(Block, Zeroizing<Vec<u8>>)> {
    recovery_bootstrap::quiet()?;
    source.recheck()?;
    require(
        matches!(std::fs::symlink_metadata("/dev/mapper/enzimos-recover"),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "existing recovery mapper cannot be adopted",
    )?;
    let secret = console_password()?;
    let result = process::recovery_cryptsetup(
        &["open", "--key-file", "-", "@fd:0", MAPPER],
        &secret,
        Duration::from_secs(120),
        &[source.file.as_fd()],
    )?;
    require(
        result.status.success(),
        "recovery passphrase unlock refused",
    )?;
    source.recheck()?;
    let path = std::fs::canonicalize("/dev/mapper/enzimos-recover")?;
    require(
        path.parent() == Some(Path::new("/dev")),
        "recovery mapper escaped device directory",
    )?;
    let mapper =
        Block::open(&path).map_err(|error| Error(format!("opened mapper identity: {error}")))?;
    let bytes = operation::query(
        "/usr/bin/blkid",
        &[
            "-s",
            "UUID",
            "-o",
            "value",
            path.to_str()
                .ok_or_else(|| Error("recovery mapper path encoding".into()))?,
        ],
        Duration::from_secs(30),
        4096,
        &[0],
    )?;
    require(
        std::str::from_utf8(&bytes)
            .ok()
            .is_some_and(|s| s.trim() == filesystem),
        "unlocked filesystem differs from plan",
    )?;
    mapper.recheck()?;
    source.recheck()?;
    Ok((mapper, secret))
}
pub fn close(source: &Block, mapper: Block) -> Result<()> {
    recovery_bootstrap::quiet()?;
    source.recheck()?;
    mapper.recheck()?;
    require(
        std::fs::canonicalize("/dev/mapper/enzimos-recover")? == mapper.path,
        "recovery mapper name replaced",
    )?;
    drop(mapper);
    let result =
        process::recovery_cryptsetup(&["close", MAPPER], &[], Duration::from_secs(60), &[])?;
    require(
        result.status.success(),
        "owned recovery mapper close failed",
    )?;
    require(
        matches!(std::fs::symlink_metadata("/dev/mapper/enzimos-recover"),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "recovery mapper cleanup uncertain",
    )?;
    source.recheck()
}

/// One actual successful fixed-name console unlock in the retained offline PID1
/// scope. It cannot be constructed from a mapper path, decoded row or inode.
/// Drop leaves the mapping for explicit review; it never closes or retries it.
pub struct CreatedMapping<'a> {
    scope: &'a crate::root_retirement_offline_scope::Scope,
    source: &'a Block,
    mapper: Block,
    source_identity: serde_json::Value,
    mapper_identity: serde_json::Value,
    source_flags: i32,
    mapper_flags: i32,
    filesystem: String,
    source_holders: Holders,
    mapper_holders: Holders,
    generation: String,
}
/// Actual successful close of the original mapper description, while the kernel
/// mapping still exists. No removal, pathname adoption or automatic retry.
pub(crate) struct ClosedDescription<'s> {
    scope: &'s crate::root_retirement_offline_scope::Scope,
    source: &'s Block,
    source_identity: serde_json::Value,
    source_flags: i32,
    source_holders: Holders,
    mapper_holders: Holders,
    mapper_path: std::path::PathBuf,
    mapper_epoch: enzimos_platform::files::FileIdentity,
}
pub(crate) struct RemovedSource<'s> {
    original: ClosedDescription<'s>,
}
impl<'s> ClosedDescription<'s> {
    pub(crate) fn after_remove(
        mut self,
        proof: &crate::root_retirement_dm_control::RemovalSucceeded<'_>,
    ) -> Result<RemovedSource<'s>> {
        proof.require_original(self.scope, self.mapper_epoch)?;
        require(
            matches!(std::fs::symlink_metadata(&self.mapper_path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                && matches!(std::fs::symlink_metadata(self.mapper_holders.path.parent().unwrap()), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "actual removed mapper node or kernel device still present",
        )?;
        let old = self.source_holders.epoch;
        let current = enzimos_platform::files::identity(&self.source_holders.directory.metadata()?);
        require(
            (old.0, old.1, old.7, old.8, old.9)
                == (current.0, current.1, current.7, current.8, current.9)
                && holder_names(&self.source_holders.directory)?.is_empty(),
            "actual removal did not release original source holder directory",
        )?;
        // Only the successful original removal witness may advance this owned
        // kernel directory epoch; cold observations cannot adopt a successor.
        self.source_holders.epoch = current;
        self.source_holders.link = None;
        let result = RemovedSource { original: self };
        result.recheck()?;
        Ok(result)
    }
}
impl RemovedSource<'_> {
    pub(crate) fn recheck(&self) -> Result<()> {
        let original = &self.original;
        original.scope.recheck()?;
        original.source.recheck()?;
        require(
            original_flags(&original.source.file)? == original.source_flags
                && crate::block::observe(original.source.file.as_fd())? == original.source_identity
                && matches!(std::fs::symlink_metadata(&original.mapper_path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                && matches!(std::fs::symlink_metadata(original.mapper_holders.path.parent().unwrap()), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "original source changed or removed mapper reappeared",
        )?;
        original.source_holders.recheck()?;
        original.scope.recheck()
    }
}
impl ClosedDescription<'_> {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        self.source.recheck()?;
        require(
            original_flags(&self.source.file)? == self.source_flags
                && crate::block::observe(self.source.file.as_fd())? == self.source_identity
                && enzimos_platform::files::identity(&std::fs::symlink_metadata(
                    &self.mapper_path,
                )?) == self.mapper_epoch
                && std::fs::canonicalize("/dev/mapper/enzimos-recover")? == self.mapper_path,
            "original source or still-live mapper changed after actual description close",
        )?;
        self.source_holders.recheck()?;
        self.mapper_holders.recheck()?;
        self.scope.recheck()
    }
}
fn original_flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline mapping observation flags",
    )?;
    Ok(flags)
}
/// The original scope is checked before prompting and after the actual vendor
/// child is reaped. The LUKS passphrase is zeroed immediately after unlocking;
/// it is not part of the mapping actor or a receipt.
pub fn open_offline<'a>(
    scope: &'a crate::root_retirement_offline_scope::Scope,
    source: &'a Block,
    filesystem: &str,
) -> Result<CreatedMapping<'a>> {
    scope.recheck()?;
    source.recheck()?;
    crate::identity::uuid(filesystem)?;
    let source_identity = crate::block::observe(source.file.as_fd())?;
    let source_flags = original_flags(&source.file)?;
    let (mapper, secret) = open(source, filesystem)?;
    drop(secret);
    scope.recheck()?;
    source.recheck()?;
    mapper.recheck()?;
    require(
        crate::block::observe(source.file.as_fd())? == source_identity
            && original_flags(&source.file)? == source_flags,
        "original offline encrypted source changed during owned unlock",
    )?;
    let mapper_identity = crate::block::observe(mapper.file.as_fd())?;
    require(
        mapper_identity["read_only"] == false && source_identity != mapper_identity,
        "new writable distinct offline mapper required",
    )?;
    let source_device = observed_device(&source_identity);
    let mapper_device = observed_device(&mapper_identity);
    let mapper_node = crate::topology::kernel_node(mapper_device)?;
    require(
        mapper_node.dependencies == vec![source_device],
        "actual created mapper must use only original encrypted source",
    )?;
    let source_holders = Holders::observe(source_device, Some(mapper_device))?;
    let mapper_holders = Holders::observe(mapper_device, None)?;
    let this = CreatedMapping {
        scope,
        source,
        mapper_flags: original_flags(&mapper.file)?,
        mapper,
        source_identity,
        mapper_identity,
        source_flags,
        filesystem: filesystem.into(),
        source_holders,
        mapper_holders,
        generation: enzimos_platform::files::random_hex(16)?,
    };
    this.recheck()?;
    Ok(this)
}
impl<'s> CreatedMapping<'s> {
    #[allow(unsafe_code, reason = "Linux syscall ABI (close, fcntl).")]
    pub(crate) fn close_description(
        self,
        unmounted: &crate::root_retirement_offline_mount::ReleasedMount<'_>,
    ) -> Result<ClosedDescription<'s>> {
        use std::os::fd::IntoRawFd;
        self.recheck()?;
        unmounted.require_original_mapping(&self)?;
        let mapper_epoch = enzimos_platform::files::identity(&self.mapper.file.metadata()?);
        let CreatedMapping {
            scope,
            source,
            mapper,
            source_identity,
            source_flags,
            source_holders,
            mapper_holders,
            ..
        } = self;
        let Block {
            file,
            path: mapper_path,
            ..
        } = mapper;
        let raw = file.into_raw_fd();
        // Do not retry close after an uncertain syscall result or touch a reused
        // descriptor. A failed result leaves the kernel mapping for review.
        require(
            unsafe { libc::close(raw) } == 0,
            "original mapper description close uncertain; no retry",
        )?;
        require(
            unsafe { libc::fcntl(raw, libc::F_GETFD) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
            "original mapper descriptor unexpectedly remains open",
        )?;
        let result = ClosedDescription {
            scope,
            source,
            source_identity,
            source_flags,
            source_holders,
            mapper_holders,
            mapper_path,
            mapper_epoch,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn original_generation(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.generation)
    }
    pub(crate) fn original_mapper_node(&self) -> Result<(&File, &Path)> {
        self.recheck()?;
        Ok((&self.mapper.file, &self.mapper.path))
    }
    pub(crate) fn original_scope(&self) -> Result<&'s crate::root_retirement_offline_scope::Scope> {
        self.recheck()?;
        Ok(self.scope)
    }
    pub(crate) fn filesystem_uuid(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.filesystem)
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        self.source.recheck()?;
        self.mapper.recheck()?;
        require(
            original_flags(&self.source.file)? == self.source_flags
                && original_flags(&self.mapper.file)? == self.mapper_flags
                && crate::block::observe(self.source.file.as_fd())? == self.source_identity
                && crate::block::observe(self.mapper.file.as_fd())? == self.mapper_identity
                && std::fs::canonicalize("/dev/mapper/enzimos-recover")? == self.mapper.path,
            "actual created offline mapping/source changed or fixed name replaced",
        )?;
        require(
            crate::topology::kernel_node(observed_device(&self.mapper_identity))?.dependencies
                == vec![observed_device(&self.source_identity)],
            "original mapping source dependency changed",
        )?;
        self.source_holders.recheck()?;
        self.mapper_holders.recheck()?;
        self.scope.recheck()
    }
    /// Join the actual created mapping to the actual original mounted filesystem;
    /// no UUID row or mapper pathname can supply either side of this join.
    pub fn require_original_mount(
        &self,
        mounts: &crate::root_retirement_offline_scope::Mounts<'_>,
    ) -> Result<()> {
        self.recheck()?;
        mounts.require_original_scope(self.scope)?;
        require(
            mounts.filesystem_binding()?["filesystem_uuid"] == self.filesystem
                && crate::topology::btrfs_roots(&self.filesystem)?
                    == vec![observed_device(&self.mapper_identity)],
            "original offline Btrfs mount is not solely the actual created mapper",
        )?;
        self.recheck()?;
        mounts.recheck()
    }
    /// Borrow the actual created read-only mapper description for mounting only;
    /// kernel filesystem checks and immutable retirement intent remain separate.
    pub fn descriptor(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.mapper.file.as_fd())
    }
    pub fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        let result = serde_json::json!({"source":self.source_identity,"mapper":self.mapper_identity,
            "filesystem_uuid":self.filesystem,"actual_owned_console_unlock":true,
            "passphrase_retained":false,"execution_authorized":false});
        self.recheck()?;
        Ok(result)
    }
    /// Only this actual produced mapping can enter explicit close. Caller must
    /// first normally unmount and release all its filesystem descriptions.
    pub fn close(self) -> Result<()> {
        self.recheck()?;
        close(self.source, self.mapper)?;
        self.source.recheck()?;
        self.scope.recheck()
    }
}

fn observed_device(value: &serde_json::Value) -> crate::topology::Device {
    (
        value["major"].as_u64().unwrap() as u32,
        value["minor"].as_u64().unwrap() as u32,
    )
}
struct Holders {
    directory: File,
    path: std::path::PathBuf,
    epoch: enzimos_platform::files::FileIdentity,
    mount: u64,
    flags: i32,
    link: Option<(
        String,
        enzimos_platform::files::FileIdentity,
        std::path::PathBuf,
    )>,
}
fn holder_names(directory: &File) -> Result<Vec<String>> {
    enzimos_platform::files::directory_names(directory, 2)?
        .into_iter()
        .map(|name| {
            name.into_string()
                .map_err(|_| Error("kernel holder name encoding".into()))
        })
        .collect()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn sysfs(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    let mut data = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(
        unsafe { libc::fstatfs(file.as_raw_fd(), data.as_mut_ptr()) } == 0
            && unsafe { data.assume_init() }.f_type as u64 == 0x62656572,
        "actual original kernel sysfs holder directory required",
    )
}
impl Holders {
    fn observe(
        device: crate::topology::Device,
        expected: Option<crate::topology::Device>,
    ) -> Result<Self> {
        use enzimos_platform::{files, mount_identity};
        let path = crate::topology::kernel_node(device)?.path.join("holders");
        require(
            path.starts_with("/sys/devices"),
            "fixed kernel holder directory required",
        )?;
        let directory = files::directory(&path, Some(0))?;
        sysfs(&directory)?;
        let names = holder_names(&directory)?;
        let link = if let Some(expected) = expected {
            require(
                names.len() == 1,
                "encrypted source has another or missing holder",
            )?;
            let name = &names[0];
            crate::identity::safe_id(name)?;
            let target = crate::topology::kernel_node(expected)?.path;
            let metadata = std::fs::symlink_metadata(path.join(name))?;
            require(
                metadata.file_type().is_symlink()
                    && std::fs::canonicalize(path.join(name))? == target,
                "source holder does not identify actual created mapping",
            )?;
            Some((name.clone(), files::identity(&metadata), target))
        } else {
            require(
                names.is_empty(),
                "created mapper has an unexpected kernel holder",
            )?;
            None
        };
        let this = Self {
            epoch: files::identity(&directory.metadata()?),
            mount: mount_identity::id(directory.as_fd(), true)?,
            flags: original_flags(&directory)?,
            directory,
            path,
            link,
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        use enzimos_platform::{files, mount_identity};
        let named = files::directory(&self.path, Some(0))?;
        for file in [&self.directory, &named] {
            sysfs(file)?;
            require(
                files::identity(&file.metadata()?) == self.epoch
                    && mount_identity::id(file.as_fd(), true)? == self.mount,
                "original kernel holder directory changed/replaced/covered",
            )?;
            let names = holder_names(file)?;
            require(
                names
                    == self
                        .link
                        .as_ref()
                        .map(|link| vec![link.0.clone()])
                        .unwrap_or_default(),
                "original kernel holder membership changed",
            )?;
        }
        require(
            original_flags(&self.directory)? == self.flags,
            "original kernel holder descriptor flags changed",
        )?;
        if let Some((name, epoch, target)) = &self.link {
            let link = self.path.join(name);
            require(
                files::identity(&std::fs::symlink_metadata(&link)?) == *epoch
                    && std::fs::canonicalize(&link)? == *target,
                "original kernel holder link changed",
            )?;
        }
        Ok(())
    }
}
