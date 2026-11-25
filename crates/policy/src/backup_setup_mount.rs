// SPDX-License-Identifier: MIT
//! One original reviewed device; fixed writable mount; durable ownership/no replay.
use crate::{
    backup_candidates::Selection, backup_mount_review::Review, backup_review_store::Store,
    filesystem, identity, storage_runtime, topology,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    ffi::{CStr, CString},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    sync::Arc,
};
const TARGET: &str = "/backup-repository";
const OPTIONS: &str = "rw,nodev,nosuid,noexec,subvolid=5";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected original setup directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn binding(v: &Value, uuid: &str) -> Result<()> {
    json::fields(v, "mount_id unique_mount_id target filesystem_uuid")?;
    require(
        v["target"] == TARGET
            && v["filesystem_uuid"] == uuid
            && ["mount_id", "unique_mount_id"]
                .iter()
                .all(|k| v[*k].as_u64().is_some_and(|n| n > 0)),
        "original setup mount binding required",
    )
}
pub(crate) fn validate_receipt(v: &Value, id: &str) -> Result<()> {
    identity::safe_id(id)?;
    require(
        v["id"] == id
            && matches!(
                v["phase"].as_str(),
                Some("prepared" | "mounted" | "complete" | "rolled-back")
            ),
        "setup mount ID/phase invalid",
    )?;
    let phase = enzimos_platform::json::string(&v["phase"])?;
    let closed = matches!(phase, "complete" | "rolled-back");
    match v["schema"].as_u64() {
        Some(2) => {
            json::fields(
                v,
                "schema phase id review_id selection_id boot_id filesystem_uuid device mount_scope mount_options mount_closed mount_binding",
            )?;
            require(
                v["mount_scope"] == "owned-fixed-path"
                    && v["mount_options"] == OPTIONS
                    && v["mount_closed"] == closed,
                "setup mount scope/protection/closure invalid",
            )?;
            if phase == "prepared" {
                require(
                    v["mount_binding"].is_null(),
                    "prepared setup cannot claim owned mount",
                )?;
            } else if phase == "rolled-back" && v["mount_binding"].is_null() {
                // Rolled back before the owned mount was recorded.
            } else {
                binding(
                    &v["mount_binding"],
                    v["filesystem_uuid"].as_str().unwrap_or(""),
                )?;
            }
        }
        Some(1) => {
            require(
                !matches!(phase, "mounted" | "rolled-back"),
                "legacy mount phase invalid",
            )?;
            json::fields(
                v,
                if phase == "complete" {
                    "schema phase id review_id selection_id boot_id filesystem_uuid device mount_closed"
                } else {
                    "schema phase id review_id selection_id boot_id filesystem_uuid device"
                },
            )?;
            if phase == "complete" {
                require(v["mount_closed"] == true, "legacy setup must be closed")?;
            }
        }
        _ => return Err(Error("setup mount schema unsupported".into())),
    }
    for k in ["boot_id", "filesystem_uuid"] {
        identity::uuid(
            v[k].as_str()
                .ok_or_else(|| Error("setup UUID required".into()))?,
        )?;
    }
    identity::safe_id(
        v["review_id"]
            .as_str()
            .ok_or_else(|| Error("setup review ID required".into()))?,
    )?;
    identity::sha(
        v["selection_id"]
            .as_str()
            .ok_or_else(|| Error("setup selection required".into()))?,
    )?;
    // Reuse the closed block codec rather than accepting arbitrary identity JSON.
    let review = value!({"schema":2,"phase":"prepared","id":id,"selection_id":v["selection_id"],
        "boot_id":v["boot_id"],"filesystem_uuid":v["filesystem_uuid"],"device":v["device"],
        "mount_scope":"detached-file-descriptor","mount_options":"ro,rescue=nologreplay,nodev,nosuid,noexec,subvolid=5",
        "descriptor_scope_closed":false,"result":null});
    crate::backup_mount_review::validate_receipt(&review, id)
}
#[allow(
    unsafe_code,
    reason = "Transfers an acquired native descriptor into Rust ownership."
)]
fn descriptor(raw: libc::c_long) -> Result<File> {
    if raw < 0 {
        return Err(Error(
            "exclusive writable filesystem operation refused".into(),
        ));
    }
    // SAFETY: Callers pass a descriptor-returning syscall result; nonnegative values are fresh and
    // owned by nothing else.
    Ok(unsafe { File::from_raw_fd(raw as i32) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
fn configure(file: &File, command: u32, key: Option<&CStr>, val: Option<&CStr>) -> Result<()> {
    let null = std::ptr::null::<libc::c_char>();
    require(
        // SAFETY: The key and value are NUL-terminated or null as fsconfig allows, and `file` stays
        // open.
        unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                file.as_raw_fd(),
                command,
                key.map_or(null, CStr::as_ptr),
                val.map_or(null, CStr::as_ptr),
                0i32,
            )
        } == 0,
        "exclusive writable filesystem configuration refused",
    )
}
fn mount_row(area: &crate::backup_private_area::Core, normal: u64) -> Result<mountinfo::Row> {
    let rows = area.destination_rows(normal)?;
    let row = storage_runtime::mount_row(&rows, TARGET, Some("/"), normal)?.clone();
    crate::backup_destination::writable(&row)?;
    Ok(row)
}
/// Only this module constructs ownership; callers cannot supply a mount identity.
pub(crate) struct Owned {
    area: Arc<crate::backup_private_area::Core>,
    root: Option<File>,
    mount: Option<File>,
    unique: u64,
    normal: u64,
    root_shape: Shape,
    filesystem: Value,
    row: mountinfo::Row,
    selected: Value,
    // Last: dropped after `root`/`mount` so a rollback normally unmounts.
    rollback: crate::mount_rollback::Armed,
}
impl Owned {
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl, openat, syscall).")]
    fn create(
        selection: &Selection<'_>,
        area: &crate::backup_private_area::Area<'_>,
        preflight: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        let core = area.core()?;
        selection.recheck_area(&core)?;
        area.recheck()?;
        let device = selection.descriptor_area(&core)?;
        let selected = selection.evidence_area(&core)?;
        let context =
            // SAFETY: The filesystem name is a NUL-terminated literal.
            descriptor(unsafe { libc::syscall(libc::SYS_fsopen, c"btrfs".as_ptr(), 1u32) })?;
        let source = CString::new(format!("/proc/self/fd/{}", device.as_raw_fd())).unwrap();
        configure(&context, 1, Some(c"source"), Some(&source))?;
        configure(&context, 0, Some(c"rw"), None)?;
        configure(&context, 1, Some(c"subvolid"), Some(c"5"))?;
        preflight()?;
        configure(&context, 8, None, None)?;
        preflight()?;
        // SAFETY: fsmount takes no pointers and `context` keeps the descriptor open.
        let mount = descriptor(unsafe {
            libc::syscall(libc::SYS_fsmount, context.as_raw_fd(), 1u32, 2u32 | 4 | 8)
        })?;
        drop(context);
        // SAFETY: The name is a NUL-terminated literal and `mount` keeps the descriptor open.
        let root = descriptor(libc::c_long::from(unsafe {
            libc::openat(
                mount.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }))?;
        let unique = mount_identity::id(root.as_fd(), true)?;
        let normal = mount_identity::id(root.as_fd(), false)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == selection.uuid_hint() && filesystem["members"] == 1,
            "writable filesystem does not match reviewed selected member",
        )?;
        let mut info = [0u64; 63];
        require(
            // SAFETY: `info` is 504 bytes, the size encoded in the Btrfs ioctl number, and `root`
            // stays open.
            unsafe {
                libc::ioctl(
                    root.as_raw_fd(),
                    0x81f8943cu64 as libc::c_ulong,
                    info.as_mut_ptr(),
                )
            } == 0
                && info[0] == 5
                && root.metadata()?.ino() == 256,
            "whole writable Btrfs top level required",
        )?;
        let root_shape = shape(&root)?;
        area.recheck()?;
        selection.recheck_area(&core)?;
        preflight()?;
        // Empty-path flags bind both sides to retained descriptors, never a new
        // lookup of a caller pathname. Attachment is tracked before body entry.
        require(
            // SAFETY: The empty paths are NUL-terminated literals and both descriptors stay open.
            unsafe {
                libc::syscall(
                    libc::SYS_move_mount,
                    mount.as_raw_fd(),
                    c"".as_ptr(),
                    area.descriptor()?.as_raw_fd(),
                    c"".as_ptr(),
                    4u32 | 0x40,
                )
            } == 0,
            "owned setup attachment refused",
        )?;
        // From attachment on, every failure path detaches exactly this mount
        // (identity-checked) before the caller closes the area beneath it.
        let rollback = crate::mount_rollback::Armed::new(
            c"/backup-repository",
            unique,
            normal,
            "backup destination",
        );
        let row = match crate::private_bind::private_destination(&mount)
            .and_then(|()| mount_row(&core, normal))
        {
            Ok(row) => row,
            Err(error) => {
                drop(root);
                drop(mount);
                drop(rollback);
                return Err(error);
            }
        };
        let this = Self {
            area: core,
            root: Some(root),
            mount: Some(mount),
            unique,
            normal,
            root_shape,
            filesystem,
            row,
            selected,
            rollback,
        };
        this.recheck_kernel()?;
        selection.recheck_attached(&this)?;
        Ok(this)
    }
    pub(crate) fn source_uuid(&self) -> &str {
        self.area.source_uuid()
    }
    pub(crate) fn source_members(&self) -> &[topology::Device] {
        self.area.source_members()
    }
    pub(crate) fn device(&self) -> &Value {
        &self.selected
    }
    fn binding(&self) -> Value {
        value!({"mount_id":self.normal,"unique_mount_id":self.unique,"target":TARGET,"filesystem_uuid":self.filesystem["filesystem_uuid"]})
    }
    pub(crate) fn recheck_kernel(&self) -> Result<()> {
        storage_runtime::initial_namespace()?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| Error("setup scope already closed".into()))?;
        let mount = self
            .mount
            .as_ref()
            .ok_or_else(|| Error("setup mount already closed".into()))?;
        let named = files::directory(Path::new(TARGET), Some(0))?;
        let uuid = enzimos_platform::json::string(&self.filesystem["filesystem_uuid"])?;
        let d = &self.selected["device"];
        let member = (
            enzimos_platform::json::unsigned(&d["major"])? as u32,
            enzimos_platform::json::unsigned(&d["minor"])? as u32,
        );
        require(
            shape(root)? == self.root_shape
                && shape(&named)? == self.root_shape
                && mount_identity::id(root.as_fd(), true)? == self.unique
                && mount_identity::id(mount.as_fd(), true)? == self.unique
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && mount_row(&self.area, self.normal)? == self.row
                && filesystem::observe(root.as_fd())? == self.filesystem
                && topology::btrfs_roots(uuid)? == vec![member]
                && topology::mounted_btrfs(uuid)?.json() == self.selected["topology"],
            "original owned writable mount changed; cleanup refused",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    fn close(
        mut self,
        selection: &Selection<'_>,
        lock: &files::Lock,
        area: &crate::backup_private_area::Area<'_>,
    ) -> Result<()> {
        lock.recheck()?;
        area.owns(&self.area)?;
        selection.recheck_attached(&self)?;
        self.recheck_kernel()?;
        drop(self.root.take());
        drop(self.mount.take());
        // Root-protected fixed target; original kernel identity checked immediately
        // before closing our references. Never force/lazy-detach/busy-retry.
        require(
            // SAFETY: The path is a NUL-terminated literal.
            unsafe { libc::umount2(c"/backup-repository".as_ptr(), 0) } == 0,
            "normal owned setup unmount failed; journal retained",
        )?;
        self.rollback.disarm();
        self.area.uncovered()?;
        crate::backup_review_mount::wait_closed(enzimos_platform::json::string(
            &self.filesystem["filesystem_uuid"],
        )?)?;
        selection.recheck_area(&self.area)?;
        drop(self.area);
        lock.recheck()
    }
}
pub struct Scope<'a, 'r, 'd> {
    owned: Owned,
    area: crate::backup_private_area::Area<'a>,
    review: &'a Review<'r, 'd>,
    lock: &'a files::Lock,
    authorize: &'a dyn Fn() -> Result<()>,
}
impl Scope<'_, '_, '_> {
    pub fn recheck(&self) -> Result<()> {
        self.lock.recheck()?;
        self.area.covered()?;
        self.review.selection().recheck_attached(&self.owned)?;
        self.review.document_recheck()?;
        (self.authorize)()
    }
    /// Borrow only during the body. Outstanding clones/children prevent normal
    /// unmount and durable completion; no descriptor number enters a receipt.
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self
            .owned
            .root
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .as_fd())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.owned.binding())
    }
}
/// Normal closure of this original owned mount. No cold-load or JSON constructor.
pub struct Closed<'a, 'r, 'd, T> {
    result: T,
    review: &'a Review<'r, 'd>,
    lock: &'a files::Lock,
    authorize: &'a dyn Fn() -> Result<()>,
    idle: Arc<crate::transition_idle::Snapshot>,
    stub: crate::backup_private_area::Restored<'a>,
    binding: Value,
    signature: Value,
}
impl<'a, 'r, 'd, T> Closed<'a, 'r, 'd, T> {
    /// Move the body result out while retaining the original normal-close proof.
    pub fn split(self) -> Result<(T, Closed<'a, 'r, 'd, ()>)> {
        self.recheck()?;
        let Self {
            result,
            review,
            lock,
            authorize,
            idle,
            stub,
            binding,
            signature,
        } = self;
        Ok((
            result,
            Closed {
                result: (),
                review,
                lock,
                authorize,
                idle,
                stub,
                binding,
                signature,
            },
        ))
    }
    pub fn recheck(&self) -> Result<()> {
        self.lock.recheck()?;
        (self.authorize)()?;
        self.review.recheck()?;
        self.idle.recheck()?;
        self.stub.recheck()?;
        crate::backup_review_mount::wait_closed(enzimos_platform::json::string(
            &self.binding["filesystem_uuid"],
        )?)?;
        require(
            crate::backup_signature::observe(self.review.selection())? == self.signature,
            "original closed destination signature changed",
        )?;
        self.lock.recheck()?;
        (self.authorize)()
    }
    pub fn binding(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.binding)
    }
    pub fn result(&self) -> Result<&T> {
        self.recheck()?;
        Ok(&self.result)
    }
    pub(crate) fn into_result(self) -> Result<T> {
        self.recheck()?;
        Ok(self.result)
    }
}
/// Actual owned destination lifetime that may close before terminal publication.
/// No constructor accepts a receipt or claimed mount identity.
pub struct Active<'a, 'r, 'd> {
    scope: Scope<'a, 'r, 'd>,
    store: Store<'a>,
    idle: Arc<crate::transition_idle::Snapshot>,
    signature: Value,
    id: String,
}
impl<'a, 'r, 'd> Active<'a, 'r, 'd> {
    pub fn open(
        review: &'a Review<'r, 'd>,
        id: &str,
        lock: &'a files::Lock,
        authorize: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        storage_runtime::initial_namespace()?;
        identity::safe_id(id)?;
        lock.recheck()?;
        authorize()?;
        review.recheck()?;
        let idle = Arc::new(crate::transition_idle::Snapshot::online()?);
        let selection = review.selection();
        require(
            idle.guard.configuration == selection.guard().configuration,
            "setup source authority mismatch",
        )?;
        let signature = crate::backup_signature::observe(selection)?;
        let guard = selection.guard();
        let directory = files::ensure_directory_relative(
            guard.control(),
            Path::new("backup-setup-mounts"),
            0o700,
            0,
        )?;
        require(
            mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
            "setup journal outside control mount",
        )?;
        let retained_idle = Arc::clone(&idle);
        let mut store = Store::retained_setup(
            &Path::new(crate::operation::CONTROL).join("backup-setup-mounts"),
            0,
            guard.control_mount_id(),
            Box::new(move || {
                guard.recheck()?;
                retained_idle.recheck()?;
                lock.recheck()?;
                authorize()
            }),
        )?;
        let original = review.original();
        let prepared = value!({"schema":2,"phase":"prepared","id":id,"review_id":review.id(),
        "selection_id":original["selection_id"],"boot_id":original["boot_id"],"filesystem_uuid":original["filesystem_uuid"],
        "device":original["device"],"mount_scope":"owned-fixed-path","mount_options":OPTIONS,"mount_closed":false,"mount_binding":null});
        // Refuse unfinished destination intents before creating any new bind. Both
        // journals are durable before their corresponding mount transitions.
        store.prepare(prepared)?;
        review.recheck()?;
        store.recheck()?;
        let area = match crate::backup_private_area::Area::create(
            selection.guard(),
            id,
            lock,
            authorize,
        ) {
            Ok(area) => area,
            Err(error) => {
                // Area::create already detached its own clone on failure.
                settle_rolled_back(&mut store, id);
                return Err(error);
            }
        };
        let created = review
            .document_recheck()
            .and_then(|()| area.recheck())
            .and_then(|()| store.recheck())
            .and_then(|()| {
                Owned::create(selection, &area, &|| {
                    review.document_recheck()?;
                    let core = area.core()?;
                    selection.recheck_area(&core)?;
                    store.recheck()
                })
            });
        let owned = match created {
            Ok(owned) => owned,
            Err(error) => {
                // Any destination mount was detached by Owned::create's rollback;
                // close the empty area normally, then settle the intent.
                match area.close() {
                    Ok(_) => settle_rolled_back(&mut store, id),
                    Err(close) => eprintln!(
                        "enzimos-backup-setup: private area close after failure: {}",
                        crate::diagnostic::bounded(&close.0)
                    ),
                }
                return Err(error);
            }
        };
        if let Err(recording) = store.mount_recorded(id, owned.binding()) {
            owned.close(selection, lock, &area)?;
            area.close()?;
            settle_rolled_back(&mut store, id);
            return Err(recording);
        }
        let scope = Scope {
            owned,
            area,
            review,
            lock,
            authorize,
        };
        let outcome = (|| {
            scope.recheck()?;
            require(
                crate::backup_review_mount::repository_metadata(
                    scope
                        .owned
                        .root
                        .as_ref()
                        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                    scope.owned.unique,
                    0,
                )? == review.original()["result"]["repository"],
                "repository changed after original readonly review; body refused",
            )?;
            scope.recheck()?;
            Ok(())
        })();
        let active = Self {
            scope,
            store,
            idle,
            signature,
            id: id.into(),
        };
        match outcome {
            Ok(()) => Ok(active),
            Err(error) => {
                active.close_result::<()>(Err(error))?;
                unreachable!()
            }
        }
    }
    pub fn scope(&self) -> Result<&Scope<'a, 'r, 'd>> {
        self.scope.recheck()?;
        self.store.recheck()?;
        Ok(&self.scope)
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope()?;
        Ok(())
    }
    /// Join the actual owned top-level mount and Source guard to the concrete
    /// destination used by the consumer; a matching JSON binding is insufficient.
    pub fn require_destination(
        &self,
        destination: &crate::backup_destination::Destination<'_>,
    ) -> Result<()> {
        self.recheck()?;
        destination.recheck()?;
        let root = destination.root_descriptor()?;
        let owned = self
            .scope
            .owned
            .root
            .as_ref()
            .ok_or_else(|| Error("actual owned destination root unavailable".into()))?;
        require(
            files::identity(&root.metadata()?) == files::identity(&owned.metadata()?)
                && mount_identity::id(root.as_fd(), true)? == self.scope.owned.unique
                && destination.storage().backup_root_binding()?
                    == self
                        .scope
                        .review
                        .selection()
                        .guard()
                        .backup_root_binding()?,
            "consumer destination is not the original owned mount/source",
        )?;
        self.recheck()
    }
    pub fn close(self) -> Result<Closed<'a, 'r, 'd, ()>> {
        self.close_result(Ok(()))
    }
    /// Close once even when the body failed or permission was revoked. A failed
    /// normal close is logged; the identity-checked rollback guards then detach
    /// whatever this scope still owns (never another mount), and the intent is
    /// settled once /backup-repository is proven empty.
    pub fn close_result<T>(self, outcome: Result<T>) -> Result<Closed<'a, 'r, 'd, T>> {
        let Self {
            scope,
            mut store,
            idle,
            signature,
            id,
        } = self;
        let review = scope.review;
        let lock = scope.lock;
        let authorize = scope.authorize;
        let selection = review.selection();
        let outcome = scope.recheck().and(outcome);
        // Cleanup of this original scope does not require renewed permission to begin
        // a new action. Journal completion and success still require fresh approval.
        let binding = scope.owned.binding();
        if let Err(error) = scope.owned.close(selection, lock, &scope.area) {
            // The destination's rollback guard ran when it was dropped inside
            // close(); close the area beneath it and settle the journal.
            log_failure("owned destination close", &error);
            if let Err(outcome) = &outcome {
                log_failure("setup body", outcome);
            }
            match scope.area.close() {
                Ok(_) => settle_rolled_back(&mut store, &id),
                Err(close) => log_failure("private area close", &close),
            }
            return Err(error);
        }
        let stub = match scope.area.close() {
            Ok(stub) => stub,
            Err(error) => {
                log_failure("private area close", &error);
                if let Err(outcome) = &outcome {
                    log_failure("setup body", outcome);
                }
                return Err(error);
            }
        };
        let result = match selection.recheck().and(outcome) {
            Ok(result) => result,
            Err(error) => {
                // The body failed but its mount closed normally and the stub is
                // restored: settle the intent now so the failure never blocks
                // the next attachment. A failed settlement is retried by
                // `settle_runtime` at the next runtime attachment.
                settle_rolled_back(&mut store, &id);
                return Err(error);
            }
        };
        review.recheck()?;
        store.recheck()?;
        require(
            crate::backup_signature::observe(selection)? == signature,
            "setup signature changed after closure",
        )?;
        store.recheck()?;
        store.mount_closed(&id)?;
        drop(store);
        let closed = Closed {
            result,
            review,
            lock,
            authorize,
            idle,
            stub,
            binding,
            signature,
        };
        closed.recheck()?;
        Ok(closed)
    }
}
fn log_failure(step: &str, error: &Error) {
    eprintln!(
        "enzimos-backup-setup: {step} failed: {}",
        crate::diagnostic::bounded(&error.0)
    );
}
/// Settle a setup-mount intent after its mounts are proven gone. A failure here
/// only leaves the intent for `enzimos-policy backup-setup reset-uncertain`.
fn settle_rolled_back(store: &mut Store<'_>, id: &str) {
    let gone = storage_runtime::rows().map(|rows| {
        !rows
            .iter()
            .any(|r| r.target == TARGET || r.target.starts_with("/backup-repository/"))
    });
    match gone {
        Ok(true) => {
            if let Err(error) = store.rolled_back(id) {
                log_failure("setup mount intent settlement", &error);
            }
        }
        Ok(false) => eprintln!(
            "enzimos-backup-setup: setup mount intent {id} retained: /backup-repository still mounted"
        ),
        Err(error) => log_failure("mount inventory after rollback", &error),
    }
}
/// Settle what an earlier runtime attachment (`runtime-*`: backup, cleanup,
/// restore, export) left unfinished, e.g. after its process was killed or its
/// approval was lost before the journal could close. The caller holds the
/// operation lock, so that process is gone, and nothing is mounted at or below
/// /backup-repository, so its mounts are gone: setup-mount and private-area
/// intents become rolled-back and interrupted read-only reviews are removed.
/// Setup attempts (non-runtime IDs) stay for `backup-setup reset-uncertain`.
pub(crate) fn settle_runtime(
    guard: &storage_runtime::Guard,
    lock: &files::Lock,
) -> Result<Vec<String>> {
    lock.recheck()?;
    guard.recheck()?;
    require(
        !storage_runtime::rows()?
            .iter()
            .any(|r| r.target == TARGET || r.target.starts_with("/backup-repository/")),
        "backup destination still mounted; runtime intents not settled",
    )?;
    let mut settled = Vec::new();
    for directory in [
        "backup-device-reviews",
        "backup-setup-mounts",
        "backup-setup-areas",
    ] {
        if files::optional_directory_relative(guard.control(), Path::new(directory), Some(0))?
            .is_none()
        {
            continue;
        }
        let path = Path::new(crate::operation::CONTROL).join(directory);
        let check = Box::new(move || {
            guard.recheck()?;
            lock.recheck()
        });
        let mut store = match directory {
            "backup-device-reviews" => Store::retained(&path, 0, guard.control_mount_id(), check)?,
            "backup-setup-mounts" => {
                Store::retained_setup(&path, 0, guard.control_mount_id(), check)?
            }
            _ => Store::retained_area(&path, 0, guard.control_mount_id(), check)?,
        };
        for id in store.unfinished()? {
            if !id.starts_with("runtime-") {
                continue;
            }
            if directory == "backup-device-reviews" {
                store.retire_interrupted_review(&id)?;
            } else {
                store.rolled_back(&id)?;
            }
            eprintln!("enzimos-backup: settled interrupted runtime intent {directory}/{id}");
            settled.push(format!("{directory}/{id}"));
        }
    }
    Ok(settled)
}
pub fn with_owned_mount<'a, 'r, 'd, T>(
    review: &'a Review<'r, 'd>,
    id: &str,
    lock: &'a files::Lock,
    authorize: &'a dyn Fn() -> Result<()>,
    body: impl FnOnce(&Scope<'_, '_, '_>) -> Result<T>,
) -> Result<Closed<'a, 'r, 'd, T>> {
    let active = Active::open(review, id, lock, authorize)?;
    let outcome = active.scope().and_then(body);
    active.close_result(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const UUID: &str = "11111111-2222-3333-4444-555555555555";
    fn prepared(id: &str) -> Value {
        value!({"schema":2,"phase":"prepared","id":id,"review_id":"review-1","selection_id":"a".repeat(64),
            "boot_id":UUID,"filesystem_uuid":UUID,"device":{"major":8,"minor":17,"device_inode":1,"device_filesystem":2,"disk_sequence":3,"bytes":4096,"read_only":false},
            "mount_scope":"owned-fixed-path","mount_options":OPTIONS,"mount_closed":false,"mount_binding":null})
    }
    fn actual_binding() -> Value {
        value!({"mount_id":10,"unique_mount_id":111,"target":TARGET,"filesystem_uuid":UUID})
    }
    fn fixture() -> tempfile::TempDir {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap()
    }
    fn store(dir: &tempfile::TempDir) -> Store<'static> {
        let f = files::directory(
            dir.path(),
            Some(enzimos_platform::process_identity::real_uid()),
        )
        .unwrap();
        Store::retained_setup(
            dir.path(),
            enzimos_platform::process_identity::real_uid(),
            mount_identity::id(f.as_fd(), true).unwrap(),
            Box::new(|| Ok(())),
        )
        .unwrap()
    }
    #[test]
    fn actual_setup_journal_requires_owned_stage_before_completion_and_never_replays() {
        let dir = fixture();
        let mut s = store(&dir);
        s.prepare(prepared("setup-1")).unwrap();
        assert!(s.mount_closed("setup-1").is_err());
        assert!(s.prepare(prepared("setup-2")).is_err());
        drop(s);
        let mut s = store(&dir);
        assert!(s.prepare(prepared("setup-2")).is_err());
        s.mount_recorded("setup-1", actual_binding()).unwrap();
        assert!(s.mount_recorded("setup-1", actual_binding()).is_err());
        drop(s);
        let mut s = store(&dir);
        assert!(s.prepare(prepared("setup-2")).is_err());
        let v = s.mount_closed("setup-1").unwrap();
        assert_eq!(v["mount_closed"], true);
        assert_eq!(v["mount_binding"], actual_binding());
        assert!(s.mount_closed("setup-1").is_err());
        assert!(s.prepare(prepared("setup-1")).is_err());
        s.prepare(prepared("setup-2")).unwrap();
    }
}
