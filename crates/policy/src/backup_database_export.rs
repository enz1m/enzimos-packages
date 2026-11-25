// SPDX-License-Identifier: MIT
//! One bounded SQLite backup enters durably before creating its private output.
use crate::{
    backup_attempt::Attempt, backup_database_sources::Source, backup_package_capture,
    control_record::Retained, operation,
};
use enzimos_platform::{Error, Result, files, mount_identity, require, stream_copy};
use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
    config::DbConfig,
    limits::Limit,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const MAX: u64 = 64 * 1024 * 1024;
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "original private SQLite output directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
fn sql<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|_| Error("native SQLite export failed; private output retained, no replay".into()))
}
#[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
fn configure(c: &Connection, deadline: Instant, readonly: bool) -> Result<()> {
    sql(c.busy_timeout(Duration::from_secs(1)))?;
    sql(c.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false))?;
    sql(c.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))?;
    require(
        // SAFETY: `c.handle()` is the live SQLite connection owned by `c`.
        unsafe { rusqlite::ffi::sqlite3_enable_load_extension(c.handle(), 0) } == 0,
        "SQLite extension loading could not be disabled",
    )?;
    sql(c.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX as i32))?;
    sql(c.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 4096))?;
    sql(c.progress_handler(10000, Some(move || Instant::now() >= deadline)))?;
    sql(c.execute_batch(if readonly{"PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048;"}else{"PRAGMA trusted_schema=OFF; PRAGMA journal_mode=MEMORY; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048;"}))?;
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn new_descriptor(
    before: &backup_package_capture::DescriptorSnapshot,
    proc: &File,
    original: &File,
    access: i32,
) -> Result<File> {
    let expected = files::identity(&original.metadata()?);
    let mount = mount_identity::id(original.as_fd(), true)?;
    let mut found = None;
    let descriptors = backup_package_capture::descriptors(proc)?;
    // Keep retained duplicates outside the inspected set, even when another thread closes a descriptor.
    let duplicate_from = descriptors
        .iter()
        .copied()
        .max()
        .unwrap_or(63)
        .checked_add(1)
        .ok_or_else(|| Error("SQLite descriptor bound".into()))?
        .max(64);
    for fd in descriptors {
        // SAFETY: F_GETFL takes no pointers; it only reads the flags of a retained descriptor
        // number.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != access {
            continue;
        }
        // SAFETY: F_DUPFD_CLOEXEC takes no pointers and only duplicates a descriptor of this
        // process.
        let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, duplicate_from) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error.into());
        }
        // SAFETY: `raw` is a fresh F_DUPFD_CLOEXEC duplicate owned by nothing else.
        let actual = unsafe { File::from_raw_fd(raw) };
        if !before.existed(fd, &actual, access)?
            && enzimos_platform::files::status_flags(&actual) & libc::O_ACCMODE == access
            && files::identity(&actual.metadata()?) == expected
            && mount_identity::id(actual.as_fd(), true)? == mount
        {
            require(
                found.is_none(),
                "ambiguous SQLite native input/output descriptors",
            )?;
            found = Some(actual);
        }
    }
    found.ok_or_else(|| {
        Error("SQLite did not retain the original admitted file; no pathname adoption".into())
    })
}
fn copy(
    path: &Path,
    input: &File,
    output: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    boundary()?;
    let proc = files::directory(
        &PathBuf::from(format!("/proc/{}/fd", std::process::id())),
        Some(enzimos_platform::process_identity::effective_uid()),
    )?;
    let before = backup_package_capture::DescriptorSnapshot::capture(&proc)?;
    let source = sql(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ))?;
    let original_input = new_descriptor(&before, &proc, input, libc::O_RDONLY)?;
    boundary()?;
    configure(&source, deadline, true)?;
    let page_size: i64 = sql(source.query_row("PRAGMA page_size", [], |row| row.get(0)))?;
    require(
        (512..=65536).contains(&page_size) && (page_size as u64).is_power_of_two(),
        "SQLite page size bound",
    )?;
    let before = backup_package_capture::DescriptorSnapshot::capture(&proc)?;
    let mut target = sql(Connection::open_with_flags(
        format!("/proc/self/fd/{}", output.as_raw_fd()),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ))?;
    let original_output = new_descriptor(&before, &proc, output, libc::O_RDWR)?;
    configure(&target, deadline, false)?;
    {
        let backup = sql(Backup::new(&source, &mut target))?;
        loop {
            boundary()?;
            require(
                Instant::now() < deadline,
                "SQLite export deadline; output retained",
            )?;
            let status = sql(backup.step(128))?;
            let progress = backup.progress();
            require(
                progress.pagecount >= 0
                    && progress.remaining >= 0
                    && (progress.pagecount as u64)
                        .checked_mul(page_size as u64)
                        .is_some_and(|size| size <= MAX)
                    && output.metadata()?.len() <= MAX,
                "SQLite export page or output size bound",
            )?;
            match status {
                StepResult::Done => break,
                StepResult::More => {}
                StepResult::Busy | StepResult::Locked => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => return Err(Error("unknown SQLite backup state".into())),
            }
        }
    }
    boundary()?;
    let rows = {
        let mut query = sql(target.prepare("PRAGMA quick_check"))?;
        let mapped = sql(query.query_map([], |row| row.get::<_, String>(0)))?;
        sql(mapped.take(2).collect::<rusqlite::Result<Vec<_>>>())?
    };
    require(rows == ["ok"], "SQLite export integrity check refused")?;
    sql(target.close().map_err(|(_, error)| error))?;
    sql(source.close().map_err(|(_, error)| error))?;
    require(Instant::now() < deadline, "SQLite export final deadline")?;
    boundary()?;
    require(
        files::identity(&original_input.metadata()?) == files::identity(&input.metadata()?)
            && files::identity(&original_output.metadata()?)
                == files::identity(&output.metadata()?),
        "SQLite native file binding changed",
    )?;
    output.sync_all()?;
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn create(parent: &File, name: &str, owner: u32) -> Result<File> {
    require(
        name.ends_with(".sqlite") && crate::delivery_cancel::filename(name),
        "fixed safe SQLite output leaf required",
    )?;
    shape(parent, owner)?;
    let name = std::ffi::CString::new(name)
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(raw) };
    let m = file.metadata()?;
    require(
        m.uid() == owner
            && m.gid() == parent.metadata()?.gid()
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() == 0,
        "new private SQLite output protection refused",
    )?;
    file.sync_all()?;
    parent.sync_all()?;
    Ok(file)
}
/// Successful export is an inventory artifact; it completes neither a backup nor
/// a recovery grant. Source epochs must remain stable throughout this primitive.
pub struct Completed<'a, 'g> {
    guard: &'g crate::storage_runtime::Guard,
    attempt: &'a Attempt<'g>,
    lock: &'a files::Lock,
    parent: File,
    parent_shape: Shape,
    name: String,
    file: File,
    readonly: File,
    epoch: files::FileIdentity,
    record: Retained,
    value: Value,
    registry: File,
    registry_shape: Shape,
}
impl<'a, 'g> Completed<'a, 'g> {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.attempt.evidence()?;
        self.lock.recheck()?;
        self.record.recheck()?;
        let registry = files::directory_relative(
            self.guard.control(),
            Path::new("backup-database-exports"),
            Some(0),
        )?;
        let named = files::open_relative(&self.parent, Path::new(&self.name))?;
        require(
            shape(&self.registry, 0)? == self.registry_shape
                && shape(&registry, 0)? == self.registry_shape
                && shape(&self.parent, 0)? == self.parent_shape
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && files::identity(&self.readonly.metadata()?) == self.epoch
                && enzimos_platform::files::status_flags(&self.readonly) & libc::O_ACCMODE
                    == libc::O_RDONLY
                && mount_identity::id(self.file.as_fd(), true)? == self.parent_shape.5
                && mount_identity::id(self.readonly.as_fd(), true)? == self.parent_shape.5
                && mount_identity::id(named.as_fd(), true)? == self.parent_shape.5
                && self.record.value()? == &self.value,
            "original completed SQLite export changed or covered",
        )
    }
    pub(crate) fn retire(
        mut self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Retired<'a, 'g>> {
        authorize()?;
        self.recheck()?;
        self.value["phase"] = value!("retirement-entered");
        self.record.replace(&self.value)?;
        let mut boundary = || {
            authorize()?;
            self.guard.recheck()?;
            self.lock.recheck()?;
            self.record.recheck()?;
            let registry = files::directory_relative(
                self.guard.control(),
                Path::new("backup-database-exports"),
                Some(0),
            )?;
            require(
                shape(&registry, 0)? == self.registry_shape
                    && shape(&self.registry, 0)? == self.registry_shape,
                "original SQLite retirement registry changed",
            )
        };
        let removed = enzimos_platform::named_retirement::Quarantined::enter_bounded(
            &self.parent,
            &self.readonly,
            Path::new(&self.name),
            0,
            MAX,
            &mut boundary,
        )?
        .unlink(&mut boundary)?;
        self.value["phase"] = value!("retired");
        self.record.replace(&self.value)?;
        let retired = Retired {
            guard: self.guard,
            lock: self.lock,
            record: self.record,
            value: self.value,
            registry: self.registry,
            registry_shape: self.registry_shape,
            removed,
        };
        retired.evidence()?;
        Ok(retired)
    }
    pub(crate) fn file_name(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.name)
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.readonly)
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?,"file":self.epoch}))
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
pub(crate) fn export<'a, 'g>(
    source: &Source<'_, 'g>,
    attempt: &'a Attempt<'g>,
    lock: &'a files::Lock,
    output_parent: &File,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Completed<'a, 'g>> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    authorize()?;
    lock.recheck()?;
    attempt.evidence()?;
    source.recheck()?;
    let parent = output_parent.try_clone()?;
    let parent_shape = shape(&parent, 0)?;
    let name = format!("{}.sqlite", source.name());
    let guard = source.guard();
    attempt.require_original(guard, lock)?;
    guard.recheck()?;
    let registry = files::ensure_directory_relative(
        guard.control(),
        Path::new("backup-database-exports"),
        0o700,
        0,
    )?;
    let registry_shape = shape(&registry, 0)?;
    require(
        registry_shape.5 == guard.control_mount_id(),
        "SQLite receipt left original control mount",
    )?;
    let mut value = value!({"schema":1,"id":id,"role":"sqlite-online-export","phase":"entered","boot_id":operation::boot_id()?,"source":source.evidence()?,"attempt":attempt.evidence()?,"output_parent":parent_shape,"output_name":name,"output":null,"global_atomicity":false,"backup_complete":false});
    let mut boundary = || {
        authorize()?;
        lock.recheck()?;
        attempt.evidence()?;
        source.recheck()?;
        require(
            shape(&parent, 0)? == parent_shape,
            "original SQLite output parent changed",
        )?;
        let named = files::directory_relative(
            guard.control(),
            Path::new("backup-database-exports"),
            Some(0),
        )?;
        require(
            shape(&registry, 0)? == registry_shape && shape(&named, 0)? == registry_shape,
            "original SQLite receipt directory changed",
        )
    };
    boundary()?;
    let mut record = Retained::create(
        &registry,
        Path::new(&format!("{id}.json")),
        &value,
        32768,
        guard.control_mount_id(),
    )?;
    boundary()?;
    let file = create(&parent, &name, 0)?;
    let input_raw =
        // SAFETY: F_DUPFD_CLOEXEC takes no pointers and `source` keeps the descriptor open.
        unsafe { libc::fcntl(source.descriptor()?.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    require(input_raw >= 0, "original SQLite input duplication refused")?;
    // SAFETY: `input_raw` is a fresh duplicate owned by nothing else.
    let input = unsafe { File::from_raw_fd(input_raw) };
    copy(source.path(), &input, &file, &mut boundary)?;
    boundary()?;
    record.recheck()?;
    let (bytes, sha) = stream_copy::hash_borrowed(&file, MAX, Some(0))?;
    let epoch = files::identity(&file.metadata()?);
    let named = files::open_relative(&parent, Path::new(&name))?;
    require(
        files::identity(&named.metadata()?) == epoch
            && mount_identity::id(file.as_fd(), true)? == parent_shape.5,
        "original SQLite output replaced or covered",
    )?;
    file.sync_all()?;
    parent.sync_all()?;
    boundary()?;
    value["phase"] = value!("complete");
    value["output"] =
        value!({"bytes":bytes,"sha256":sha,"file":epoch,"method":"sqlite-online-backup"});
    record.replace(&value)?;
    let readonly = files::open_relative(&parent, Path::new(&name))?;
    let completed = Completed {
        guard,
        attempt,
        lock,
        parent,
        parent_shape,
        name,
        file,
        readonly,
        epoch,
        record,
        value,
        registry,
        registry_shape,
    };
    completed.recheck()?;
    Ok(completed)
}

/// Actual original SQLite output retired; original durable receipt retained.
pub(crate) struct Retired<'a, 'g> {
    guard: &'g crate::storage_runtime::Guard,
    lock: &'a files::Lock,
    record: Retained,
    value: Value,
    registry: File,
    registry_shape: Shape,
    removed: enzimos_platform::named_retirement::Removed,
}
impl Retired<'_, '_> {
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.record.recheck()?;
        self.removed.recheck()?;
        let registry = files::directory_relative(
            self.guard.control(),
            Path::new("backup-database-exports"),
            Some(0),
        )?;
        require(
            shape(&registry, 0)? == self.registry_shape
                && shape(&self.registry, 0)? == self.registry_shape
                && self.record.value()? == &self.value
                && self.value["phase"] == "retired",
            "original SQLite retirement receipt changed",
        )?;
        Ok(value!({"receipt":self.value,"database_output_removed":true,"backup_complete":false}))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_sqlite_backup_uses_original_files_and_exclusive_private_output() {
        use std::os::unix::fs::PermissionsExt;
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        let temp = tempfile::tempdir_in(work).unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = enzimos_platform::process_identity::effective_uid();
        let parent = files::directory(temp.path(), Some(owner)).unwrap();
        let path = temp.path().join("source.db");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE fixture(v TEXT);INSERT INTO fixture VALUES('owned fixture');",
        )
        .unwrap();
        db.close().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let input = File::open(&path).unwrap();
        let output = create(&parent, "app.sqlite", owner).unwrap();
        let mut checks = 0;
        copy(&path, &input, &output, &mut || {
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert!(checks >= 4);
        assert!(create(&parent, "app.sqlite", owner).is_err());
        assert!(create(&parent, "../other.sqlite", owner).is_err());
        let checked = Connection::open_with_flags(
            temp.path().join("app.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            checked
                .query_row("SELECT v FROM fixture", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "owned fixture"
        );
        checked.close().unwrap();
        assert_eq!(
            output.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
        std::fs::rename(&path, temp.path().join("old.db")).unwrap();
        let replacement = Connection::open(&path).unwrap();
        replacement
            .execute_batch(
                "CREATE TABLE fixture(v TEXT);INSERT INTO fixture VALUES('different fixture');",
            )
            .unwrap();
        replacement.close().unwrap();
        let other = create(&parent, "other.sqlite", owner).unwrap();
        assert!(copy(&path, &input, &other, &mut || Ok(())).is_err());
        assert_eq!(other.metadata().unwrap().len(), 0);
    }
}
