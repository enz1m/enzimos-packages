// SPDX-License-Identifier: MIT
//! Fresh apply intent remains durable at its last completed evidence boundary.
use crate::{operation, storage_runtime::Guard, update_apply_record as record};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
fn directory_shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private apply registry required",
    )?;
    Ok(
        value!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
pub struct Store<'a> {
    guard: Guard,
    lock: &'a files::Lock,
    lock_identity: files::FileIdentity,
    lock_mount: u64,
    path: PathBuf,
    directory: File,
    directory_shape: Value,
    file: File,
    file_identity: files::FileIdentity,
    current: Value,
    caller: crate::update_actor::Actor,
}
/// Finished apply records kept as history; older ones are retired so the
/// 128-entry registry never refuses a routine update.
const RETAINED_FINISHED: usize = 64;
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn retire_finished(directory: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    let mut finished = Vec::new();
    for name in files::directory_names(directory, record::MAXIMUM + 1)? {
        let Some(name) = name.to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        let file = files::open_relative(directory, Path::new(&name))?;
        let body = json::decode(
            &files::read_file(&file, crate::catalog::MAX_CATALOG, Some(0), true)?,
            crate::catalog::MAX_CATALOG,
        )?;
        if record::validate(&body, id).is_ok() && record::finished(&body) {
            finished.push((file.metadata()?.mtime(), name));
        }
    }
    if finished.len() <= RETAINED_FINISHED + 32 {
        return Ok(());
    }
    finished.sort();
    let excess = finished.len() - RETAINED_FINISHED;
    for (_, name) in finished.into_iter().take(excess) {
        let c_name = std::ffi::CString::new(name)
            .map_err(|_| enzimos_platform::Error("apply registry encoding".into()))?;
        require(
            // SAFETY: `c_name` is a NUL-terminated C string and `directory` keeps the descriptor
            // open.
            unsafe { libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), 0) } == 0,
            "finished apply record retirement failed",
        )?;
    }
    directory.sync_all()?;
    Ok(())
}
impl<'a> Store<'a> {
    pub fn create(document: &Value, image: &File, lock: &'a files::Lock) -> Result<Self> {
        Self::create_authorized(document, image, lock, None, &mut || lock.recheck())
    }
    pub(crate) fn create_authorized(
        document: &Value,
        image: &File,
        lock: &'a files::Lock,
        request_id: Option<&str>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        lock.recheck()?;
        operation::root_only()?;
        record::plan(document)?;
        crate::update_apply_pending::entry()?;
        let guard = Guard::observe()?;
        require(
            document["storage"] == guard.configuration
                && document["boot_id"] == operation::boot_id()?,
            "apply intent requires current storage and boot",
        )?;
        let caller = crate::update_actor::Actor::current()?;
        require(
            document["schema"] == 2
                && document["implementation_image"] == caller.path()
                && document["implementation_sha256"] == caller.sha()
                && files::identity(&image.metadata()?)
                    == files::identity(&caller.image()?.metadata()?)
                && mount_identity::id(image.as_fd(), true)?
                    == mount_identity::id(caller.image()?.as_fd(), true)?,
            "apply image differs from actual original current coordinator",
        )?;
        let pid = caller.process()?.stat.pid;
        let start_ticks = caller.process()?.stat.start_ticks;
        let id = if let Some(request_id) = request_id {
            require(
                caller.path() == crate::update_actor::BACKEND,
                "job-bound apply requires actual native backend",
            )?;
            crate::backup_worker_request::id(request_id)?;
            format!("api-{request_id}")
        } else {
            format!("api-{}", files::random_hex(16)?)
        };
        let current = record::initial(
            &id,
            document,
            &value!({"pid":pid,"start_ticks":start_ticks,"executable_sha256":document["implementation_sha256"]}),
        )?;
        let directory_path = Path::new(operation::CONTROL).join("update-applies");
        authorize()?;
        lock.recheck()?;
        let directory = files::ensure_directory(&directory_path, 0o700, 0)?;
        let directory_shape = directory_shape(&directory)?;
        require(
            directory_shape["mount"] == guard.control_mount_id(),
            "apply registry independently mounted",
        )?;
        retire_finished(&directory)?;
        let entries = std::fs::read_dir(&directory_path)?
            .take(record::MAXIMUM + 1)
            .collect::<std::io::Result<Vec<_>>>()?;
        require(
            entries.len() < record::MAXIMUM,
            "apply registry requires explicit retention review",
        )?;
        let path = directory_path.join(format!("{id}.json"));
        let lock_identity = files::identity(&lock.as_file().metadata()?);
        let lock_mount = mount_identity::id(lock.as_file().as_fd(), true)?;
        Self::verify_lock(lock, &lock_identity, lock_mount)?;
        guard.recheck()?;
        caller.recheck()?;
        authorize()?;
        lock.recheck()?;
        files::atomic(&path, &json::canonical(&current)?, 0o600, Some(0), false)?;
        let file = files::open_relative(
            &directory,
            Path::new(
                path.file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let file_identity = files::identity(&file.metadata()?);
        let store = Self {
            guard,
            lock,
            lock_identity,
            lock_mount,
            path,
            directory,
            directory_shape,
            file,
            file_identity,
            current,
            caller,
        };
        store.recheck()?;
        authorize()?;
        store.recheck()?;
        Ok(store)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    fn verify_lock(lock: &files::Lock, identity: &files::FileIdentity, mount: u64) -> Result<()> {
        let directory = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let named = files::open_relative(&directory, Path::new("operation.lock"))?;
        let m = lock.as_file().metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && m.len() == 0
                && files::identity(&m) == *identity
                && files::identity(&named.metadata()?) == *identity
                && mount_identity::id(lock.as_file().as_fd(), true)? == mount
                && mount_identity::id(named.as_fd(), true)? == mount,
            "original apply operation lock replaced",
        )?;
        enzimos_platform::flock_identity::exclusive(lock.as_file())?;
        // SAFETY: flock takes no pointers and `named` keeps the descriptor open.
        let result = unsafe { libc::flock(named.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        require(
            result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK),
            "apply operation lock was not already held",
        )?;
        enzimos_platform::flock_identity::exclusive(lock.as_file())
    }
    pub(crate) fn id(&self) -> &str {
        self.current["id"]
            .as_str()
            .expect("update records are validated with a string id")
    }
    pub fn current(&self) -> &Value {
        &self.current
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.caller.recheck()?;
        Self::verify_lock(self.lock, &self.lock_identity, self.lock_mount)?;
        let named = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        require(
            directory_shape(&named)? == self.directory_shape
                && directory_shape(&self.directory)? == self.directory_shape,
            "original apply registry replaced",
        )?;
        let file = files::open_relative(
            &self.directory,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        for file in [&file, &self.file] {
            require(
                files::identity(&file.metadata()?) == self.file_identity
                    && mount_identity::id(file.as_fd(), true)? == self.guard.control_mount_id(),
                "original apply receipt replaced or changed",
            )?;
        }
        require(
            json::decode(
                &files::read_file(&self.file, crate::catalog::MAX_CATALOG, Some(0), true)?,
                crate::catalog::MAX_CATALOG,
            )? == self.current,
            "durable apply receipt differs",
        )?;
        record::validate(&self.current, self.id())
    }
    pub(crate) fn checkpoint(
        &mut self,
        phase: &str,
        evidence: &Value,
        result: Option<&str>,
    ) -> Result<()> {
        self.recheck()?;
        let current = record::advance(&self.current, phase, evidence, result)?;
        files::atomic(
            &self.path,
            &json::canonical(&current)?,
            0o600,
            Some(0),
            true,
        )?;
        self.file = files::open_relative(
            &self.directory,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        self.file_identity = files::identity(&self.file.metadata()?);
        self.current = current;
        self.recheck()
    }
}
