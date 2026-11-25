// SPDX-License-Identifier: MIT
//! Retain the running kernel while a separate transaction writes the original tree.
use crate::{
    control_record, module_inventory as inventory, module_view_record as records, operation,
    storage_runtime, transition_idle,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
const LIVE: &str = "/usr/lib/modules";
const ALIAS: &str = "/run/enzimos/transaction-modules";
fn identity(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    Ok(value!({"device":m.dev(),"inode":m.ino(),"mount":mount_identity::id(file.as_fd(),true)?}))
}
fn mounted(path: &str) -> Result<bool> {
    Ok(storage_runtime::rows()?.iter().any(|r| r.target == path))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
fn bind(source: &File, path: &str) -> Result<()> {
    storage_runtime::initial_namespace()?;
    let source = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd()))
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    let target =
        CString::new(path).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    require(
        // SAFETY: All non-null pointers are NUL-terminated C strings that outlive the call.
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } == 0,
        "owned module bind mount failed",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
fn flags(path: &str, flags: libc::c_ulong) -> Result<()> {
    let target =
        CString::new(path).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    require(
        // SAFETY: All non-null pointers are NUL-terminated C strings that outlive the call.
        unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        } == 0,
        "owned module propagation or access flags failed",
    )
}
struct Mounted {
    path: &'static str,
    file: Option<File>,
    identity: Value,
    normal: u64,
}
impl Mounted {
    fn observe(path: &'static str, source: &File, readonly: bool) -> Result<Self> {
        let file = files::directory(Path::new(path), Some(0))?;
        let actual = identity(&file)?;
        let expected = identity(source)?;
        require(
            actual["device"] == expected["device"]
                && actual["inode"] == expected["inode"]
                && actual["mount"] != expected["mount"],
            "module bind mount identity differs from retained source",
        )?;
        let this = Self {
            normal: mount_identity::id(file.as_fd(), false)?,
            path,
            file: Some(file),
            identity: actual,
        };
        this.recheck(readonly)?;
        Ok(this)
    }
    fn recheck(&self, readonly: bool) -> Result<()> {
        let named = files::directory(Path::new(self.path), Some(0))?;
        require(
            identity(&named)? == self.identity
                && identity(
                    self.file
                        .as_ref()
                        .ok_or_else(|| Error("module mount already released".into()))?,
                )? == self.identity,
            "owned module mount changed",
        )?;
        let rows = storage_runtime::rows()?;
        let matches = rows
            .iter()
            .filter(|r| r.target == self.path)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1
                && matches[0].id == self.normal
                && (!readonly || matches[0].options.split(',').any(|s| s == "ro"))
                && !matches[0]
                    .optional
                    .iter()
                    .any(|s| s.starts_with("shared:") || s.starts_with("master:")),
            "module mount is missing, writable or propagating",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    fn close(&mut self, readonly: bool) -> Result<()> {
        self.recheck(readonly)?;
        self.file.take();
        let name = CString::new(self.path)
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        // SAFETY: `name` is a NUL-terminated CString.
        if unsafe { libc::umount2(name.as_ptr(), 0) } != 0 {
            self.file = Some(files::directory(Path::new(self.path), Some(0))?);
            return Err(Error(
                "normal module unmount failed; live view retained for review".into(),
            ));
        }
        require(!mounted(self.path)?, "module mount removal uncertain")
    }
}
/// A private view of the running kernel's modules kept while another transaction rewrites the tree.
pub struct ModuleView {
    snapshot: transition_idle::Snapshot,
    id: String,
    kernel: String,
    base: PathBuf,
    source: File,
    runtime: Option<File>,
    alias: Option<Mounted>,
    live: Option<Mounted>,
    baseline: Value,
    record: Value,
    journal: PathBuf,
}
impl ModuleView {
    fn checkpoint_authorized(
        &mut self,
        phase: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.snapshot.recheck()?;
        let parent = files::directory(
            self.journal
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        require(
            control_record::read(
                &parent,
                Path::new(
                    self.journal
                        .file_name()
                        .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
                ),
                65536,
                self.snapshot.guard.control_mount_id(),
            )? == self.record,
            "module view journal changed",
        )?;
        let mut next = self.record.clone();
        next["phase"] = value!(phase);
        if let Some(runtime) = &self.runtime {
            next["runtime"] = identity(runtime)?;
        }
        if let Some(alias) = &self.alias {
            next["alias"] = alias.identity.clone();
        }
        if let Some(live) = &self.live {
            next["live"] = live.identity.clone();
        }
        records::transition(Some(&self.record), &next, &self.id)?;
        authorize()?;
        files::atomic(
            &self.journal,
            &json::canonical(&next)?,
            0o600,
            Some(0),
            true,
        )?;
        self.snapshot.module_checkpoint(&self.id, &next)?;
        self.record = next;
        authorize()
    }
    /// Enter the module view for transaction `id` while `_lock` is held.
    ///
    /// # Errors
    ///
    /// Fails when a view is already active or cannot be created and verified.
    pub fn enter_locked(id: &str, _lock: &files::Lock) -> Result<Self> {
        Self::enter_authorized(id, _lock, &mut || _lock.recheck())
    }
    pub(crate) fn enter_authorized(
        id: &str,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        lock.recheck()?;
        let snapshot = transition_idle::Snapshot::module_view(id)?;
        require(
            !mounted(LIVE)? && !mounted(ALIAS)?,
            "pre-existing module view prevents update",
        )?;
        let version = operation::query(
            "/usr/bin/pacman",
            &["--query", "kernel-modules-hook"],
            Duration::from_secs(30),
            4096,
            &[0],
        )?;
        require(
            version == b"kernel-modules-hook 0.1.7-3\n",
            "unreviewed module-retention package version",
        )?;
        let kernel = String::from_utf8(files::read_kernel(
            Path::new("/proc/sys/kernel/osrelease"),
            4096,
        )?)
        .map_err(|_| Error("running kernel release encoding".into()))?
        .trim()
        .to_owned();
        crate::identity::safe_id(&kernel)?;
        let source = files::directory(Path::new(LIVE), Some(0))?;
        let baseline = inventory::observe(&source, 0)?;
        inventory::running(&baseline, &kernel)?;
        let parent = Path::new(operation::STATE).join("module-views");
        authorize()?;
        files::ensure_directory(&parent, 0o755, 0)
            .map_err(|error| Error(format!("module-view parent: {error}")))?;
        let base = parent.join(id);
        authorize()?;
        files::create_directory(&base, 0o700, 0)?;
        let journals = Path::new(operation::CONTROL).join("module-views");
        authorize()?;
        let directory = files::ensure_directory(&journals, 0o700, 0)?;
        require(
            mount_identity::id(directory.as_fd(), true)? == snapshot.guard.control_mount_id(),
            "module view journal left retained control storage",
        )?;
        let journal = journals.join(format!("{id}.json"));
        let record = value!({"schema":2,"id":id,"phase":"intent","boot_id":operation::boot_id()?,"kernel":kernel,"filesystem_uuid":snapshot.guard.configuration["filesystem_uuid"],"inventory_sha256":inventory::digest(&baseline)?,"source":identity(&source)?,"runtime":null,"alias":null,"live":null});
        records::validate(&record, id)?;
        snapshot.recheck()?;
        authorize()?;
        files::atomic(&journal, &json::canonical(&record)?, 0o600, Some(0), false)?;
        let mut this = Self {
            snapshot,
            id: id.into(),
            kernel,
            base,
            source,
            runtime: None,
            alias: None,
            live: None,
            baseline,
            record,
            journal,
        };
        this.snapshot.module_checkpoint(id, &this.record)?;
        authorize()?;
        lock.recheck()?;
        let entered = this.enter(authorize);
        if let Err(error) = entered {
            let _ = this.checkpoint_authorized("uncertain", authorize);
            return Err(error);
        }
        Ok(this)
    }
    fn enter(&mut self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        require(
            identity(&files::directory(Path::new(LIVE), Some(0))?)? == self.record["source"],
            "original module path changed before retention",
        )?;
        let runtime_path = self.base.join("modules");
        authorize()?;
        let runtime = files::create_directory(&runtime_path, 0o755, 0)?;
        self.snapshot.recheck()?;
        let copy = crate::settings_command::Command::open_boot(
            crate::settings_command::BootTool::CopyModules,
        )?;
        let copied = copy.run_fds_authorized(
            &[
                "--archive",
                "--reflink=always",
                "--",
                "@fd-dir:0",
                "@fd-dir:1",
            ],
            Duration::from_secs(600),
            65536,
            &[self.source.as_fd(), runtime.as_fd()],
            &mut || {
                authorize()?;
                self.snapshot.recheck()
            },
        )?;
        require(
            copied.status.success(),
            "running modules reflink copy failed",
        )?;
        require(
            inventory::observe(&self.source, 0)? == self.baseline
                && inventory::observe(&runtime, 0)? == self.baseline,
            "running modules changed during retention",
        )?;
        self.runtime = Some(runtime);
        self.checkpoint_authorized("cloned", authorize)?;
        authorize()?;
        files::atomic(
            &self.base.join("VIEW.json"),
            &json::canonical(
                &value!({"boot_id":self.record["boot_id"],"kernel":self.kernel,"generation":self.id}),
            )?,
            0o600,
            Some(0),
            false,
        )?;
        authorize()?;
        files::ensure_directory(Path::new(ALIAS), 0o700, 0)?;
        require(
            std::fs::read_dir(ALIAS)?.next().is_none() && !mounted(ALIAS)? && !mounted(LIVE)?,
            "module alias target is not empty or detached",
        )?;
        self.checkpoint_authorized("binding-alias", authorize)?;
        require(
            identity(&files::directory(Path::new(LIVE), Some(0))?)? == self.record["source"],
            "original module path changed before binding",
        )?;
        authorize()?;
        bind(&self.source, ALIAS)?;
        // Detach shared propagation before overmounting the live path.
        authorize()?;
        flags(ALIAS, libc::MS_PRIVATE | libc::MS_REC)?;
        self.alias = Some(Mounted::observe(ALIAS, &self.source, false)?);
        self.checkpoint_authorized("alias-mounted", authorize)?;
        self.checkpoint_authorized("binding-live", authorize)?;
        require(
            identity(&files::directory(Path::new(LIVE), Some(0))?)? == self.record["source"],
            "original module path changed before live overmount",
        )?;
        authorize()?;
        bind(
            self.runtime
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
            LIVE,
        )?;
        authorize()?;
        flags(LIVE, libc::MS_PRIVATE | libc::MS_REC)?;
        authorize()?;
        flags(LIVE, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY)?;
        self.live = Some(Mounted::observe(
            LIVE,
            self.runtime
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
            true,
        )?);
        self.checkpoint_authorized("active", authorize)?;
        self.recheck()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.snapshot.recheck()?;
        require(
            self.record["phase"] == "active",
            "module view is not active",
        )?;
        self.alias
            .as_ref()
            .ok_or_else(|| Error("transaction module alias missing".into()))?
            .recheck(false)?;
        self.live
            .as_ref()
            .ok_or_else(|| Error("retained live module view missing".into()))?
            .recheck(true)?;
        require(
            identity(&self.source)? == self.record["source"]
                && identity(
                    self.runtime
                        .as_ref()
                        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                )? == self.record["runtime"],
            "module source or runtime directory changed",
        )?;
        Ok(())
    }
    pub(crate) fn transaction_directory(&self) -> Result<&File> {
        self.recheck()?;
        self.alias
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .file
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))
    }
    /// Release of the retained kernel.
    pub fn kernel(&self) -> &str {
        &self.kernel
    }
    pub(crate) fn prepare_worker(&mut self, id: &str) -> Result<Value> {
        self.recheck()?;
        self.snapshot.prepare_worker(id)?;
        Ok(self.record.clone())
    }
    pub(crate) fn worker_checkpoint(&mut self, record: &Value) -> Result<()> {
        require(
            record["request"]["module_view"] == self.record
                && record["request"]["caller"]["pid"] == std::process::id(),
            "module view worker caller changed",
        )?;
        self.snapshot.worker_checkpoint(record)?;
        self.recheck()
    }
    pub(crate) fn worker_history(&mut self, id: &str, checkpoints: &[Value]) -> Result<()> {
        require(
            checkpoints
                .last()
                .is_some_and(|record| record["request"]["module_view"] == self.record),
            "module view worker history changed",
        )?;
        self.snapshot.worker_history(id, checkpoints)?;
        self.recheck()
    }
    /// Leave the module view while `_lock` is held.
    ///
    /// # Errors
    ///
    /// Fails when the view changed or cannot be removed.
    pub fn leave_locked(&mut self, _lock: &files::Lock) -> Result<()> {
        self.leave_authorized(_lock, &mut || _lock.recheck())
    }
    pub(crate) fn leave_authorized(
        &mut self,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        lock.recheck()?;
        self.recheck()?;
        self.checkpoint_authorized("restoring", authorize)?;
        let result = self.leave(authorize);
        if result.is_err() {
            let _ = self.checkpoint_authorized("uncertain", authorize);
        }
        result
    }
    fn leave(&mut self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        let old = files::directory(&self.base.join("modules").join(&self.kernel), Some(0))?;
        let destination = files::ensure_directory(&Path::new(ALIAS).join(&self.kernel), 0o755, 0)?;
        self.alias
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .recheck(false)?;
        self.live
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .recheck(true)?;
        self.snapshot.recheck()?;
        let restore = crate::settings_command::Command::open_boot(
            crate::settings_command::BootTool::RestoreModules,
        )?;
        let restored = restore.run_fds_authorized(
            &[
                "-AHXal",
                "--ignore-existing",
                "--",
                "@fd-dir:0",
                "@fd-dir:1",
            ],
            Duration::from_secs(600),
            65536,
            &[old.as_fd(), destination.as_fd()],
            &mut || {
                authorize()?;
                self.snapshot.recheck()
            },
        )?;
        require(
            restored.status.success(),
            "running generation restoration failed; live retained view stays mounted",
        )?;
        require(
            inventory::generation(
                &inventory::observe(
                    self.runtime
                        .as_ref()
                        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                    0,
                )?,
                &self.kernel,
            )? == inventory::generation(&self.baseline, &self.kernel)?
                && inventory::generation(&inventory::observe(&self.source, 0)?, &self.kernel)?
                    == inventory::generation(&self.baseline, &self.kernel)?,
            "running generation differs; live retained view stays mounted",
        )?;
        // Drop descriptors inside these bind mounts before their normal unmount.
        drop((old, destination));
        self.checkpoint_authorized("detaching-live", authorize)?;
        authorize()?;
        self.live
            .as_mut()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .close(true)?;
        require(
            identity(&files::directory(Path::new(LIVE), Some(0))?)? == self.record["source"],
            "original live module path did not return",
        )?;
        authorize()?;
        self.alias
            .as_mut()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .close(false)?;
        self.checkpoint_authorized("complete", authorize)
    }
}
