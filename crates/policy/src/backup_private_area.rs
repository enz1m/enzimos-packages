// SPDX-License-Identifier: MIT
//! Original root-only backup area. Its fresh shared peer group delivers normal
//! destination unmounts to later systemd slave namespaces. Both mounts must close
//! normally; records never construct kernel ownership.
use crate::{
    backup_review_store::Store, filesystem, identity, mount_rollback, operation, private_bind,
    storage_runtime,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
    sync::Arc,
};
const TARGET: &str = "/backup-repository";
const STORE: &str = "backup-setup-areas";
const OPTIONS: &str = "rw,nodev,nosuid,noexec,owned-shared-bind";
const LEGACY_OPTIONS: &str = "rw,nodev,nosuid,noexec,private-bind";
type Shape = (u64, u64, u32, u32, u32);
fn shape(f: &File, private: bool) -> Result<Shape> {
    let m = f.metadata()?;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && (!private || m.mode() & 0o7777 == 0o700),
        "protected original backup area directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn namespace() -> Result<File> {
    // A fixed kernel namespace handle; no user pathname or cold record is followed.
    Ok(File::open("/proc/self/ns/mnt")?)
}
fn ns_identity(f: &File) -> Result<(u64, u64)> {
    let m = f.metadata()?;
    Ok((m.dev(), m.ino()))
}
struct Original {
    file: File,
    inode: files::FileIdentity,
    parent: File,
    parent_shape: Shape,
    mount: u64,
    parent_row: mountinfo::Row,
    namespace: File,
    namespace_inode: (u64, u64),
    filesystem: Value,
    members: Vec<crate::topology::Device>,
}
impl Original {
    fn open(guard: &storage_runtime::Guard) -> Result<Self> {
        guard.recheck()?;
        let parent = files::directory(Path::new("/"), Some(0))?;
        let rows = storage_runtime::rows()?;
        require(
            !rows
                .iter()
                .any(|r| r.target == TARGET || r.target.starts_with("/backup-repository/")),
            "existing backup area mount cannot be adopted",
        )?;
        let file =
            files::ensure_directory_relative(&parent, Path::new("backup-repository"), 0o700, 0)?;
        shape(&file, true)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.root_mount_id()
                && file.metadata()?.dev() == guard.root_device()
                && mount_identity::id(file.as_fd(), true)? == mount
                && files::directory_is_empty(&file)?,
            "backup area stub left original empty source Root",
        )?;
        let parent_row = storage_runtime::mount_row(
            &rows,
            "/",
            None,
            mount_identity::id(parent.as_fd(), false)?,
        )?
        .clone();
        let filesystem = filesystem::observe(parent.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "backup area source filesystem differs",
        )?;
        let members =
            crate::topology::btrfs_roots(filesystem["filesystem_uuid"].as_str().unwrap())?;
        require(
            filesystem["members"].as_u64() == Some(members.len() as u64),
            "private backup area source member count differs",
        )?;
        let namespace = namespace()?;
        let this = Self {
            inode: files::identity(&file.metadata()?),
            file,
            parent_shape: shape(&parent, false)?,
            parent,
            mount,
            parent_row,
            namespace_inode: ns_identity(&namespace)?,
            namespace,
            filesystem,
            members,
        };
        this.recheck()?;
        this.restored()?;
        guard.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        storage_runtime::initial_namespace()?;
        let parent = files::directory(Path::new("/"), Some(0))?;
        let rows = storage_runtime::rows()?;
        require(
            shape(&parent, false)? == self.parent_shape
                && shape(&self.parent, false)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && files::identity(&self.file.metadata()?) == self.inode
                && ns_identity(&self.namespace)? == self.namespace_inode
                && ns_identity(&namespace()?)? == self.namespace_inode
                && rows
                    .iter()
                    .filter(|r| r.id == self.parent_row.id)
                    .collect::<Vec<_>>()
                    == vec![&self.parent_row]
                && filesystem::observe(self.parent.as_fd())? == self.filesystem
                && crate::topology::btrfs_roots(
                    self.filesystem["filesystem_uuid"].as_str().unwrap(),
                )? == self.members
                && files::directory_is_empty(&self.file)?,
            "original backup area parent, namespace, filesystem or stub changed",
        )
    }
    fn restored(&self) -> Result<()> {
        self.recheck()?;
        let named =
            files::directory_relative(&self.parent, Path::new("backup-repository"), Some(0))?;
        require(
            files::identity(&named.metadata()?) == self.inode
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && !storage_runtime::rows()?
                    .iter()
                    .any(|r| r.target == TARGET || r.target.starts_with("/backup-repository/")),
            "original backup area stub was not normally restored",
        )
    }
}
pub(crate) struct Core {
    file: File,
    mount: u64,
    row: mountinfo::Row,
    original: Arc<Original>,
}
impl Core {
    pub(crate) fn source_members(&self) -> &[crate::topology::Device] {
        &self.original.members
    }
    pub(crate) fn source_uuid(&self) -> &str {
        self.original.filesystem["filesystem_uuid"]
            .as_str()
            .unwrap()
    }
    pub(crate) fn covered(&self) -> Result<()> {
        self.original.recheck()?;
        let rows = storage_runtime::rows()?;
        require(
            files::identity(&self.file.metadata()?) == self.original.inode
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && rows
                    .iter()
                    .filter(|r| r.id == self.row.id)
                    .collect::<Vec<_>>()
                    == vec![&self.row],
            "original private backup area changed",
        )
    }
    pub(crate) fn uncovered(&self) -> Result<()> {
        self.covered()?;
        let named = files::directory(Path::new(TARGET), Some(0))?;
        let rows = storage_runtime::rows()?;
        require(
            files::identity(&named.metadata()?) == self.original.inode
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && rows
                    .iter()
                    .filter(|r| r.target == TARGET)
                    .collect::<Vec<_>>()
                    == vec![&self.row]
                && !rows
                    .iter()
                    .any(|r| r.target.starts_with("/backup-repository/")),
            "original private backup area remains covered or changed",
        )
    }
    /// Remove only this actual retained area's row when checking its one owned
    /// destination. No ID from a request, JSON record or caller allowlist is used.
    pub(crate) fn destination_rows(&self, normal: u64) -> Result<Vec<mountinfo::Row>> {
        self.covered()?;
        let rows = storage_runtime::rows()?;
        owned_stack(&rows, &self.row, normal)?;
        Ok(rows.into_iter().filter(|r| r.id != self.row.id).collect())
    }
    fn binding(&self) -> Value {
        value!({"mount_id":self.row.id,"unique_mount_id":self.mount,"target":TARGET,
            "filesystem_uuid":self.original.filesystem["filesystem_uuid"]})
    }
}
/// The only accepted kernel stack on the fixed target: exactly this area's
/// protected bind (unchanged row), then exactly one Btrfs top level mounted on
/// it (`normal`), and nothing below the target.
pub(crate) fn owned_stack(
    rows: &[mountinfo::Row],
    area: &mountinfo::Row,
    normal: u64,
) -> Result<()> {
    let stack = rows
        .iter()
        .filter(|r| r.target == TARGET)
        .collect::<Vec<_>>();
    require(
        stack.len() == 2
            && stack[0] == area
            && stack[1].id == normal
            && stack[1].parent == area.id
            && stack[1].filesystem == "btrfs"
            && stack[1].root == "/"
            && !rows
                .iter()
                .any(|r| r.target.starts_with("/backup-repository/")),
        "backup destination is not the one original mount on its owned area",
    )
}
pub(crate) struct Area<'a> {
    core: Arc<Core>,
    store: Store<'a>,
    id: String,
    guard: &'a storage_runtime::Guard,
    lock: &'a files::Lock,
    // Last: dropped after `core` closes the bind's descriptor.
    rollback: mount_rollback::Armed,
}
impl<'a> Area<'a> {
    pub(crate) fn create(
        guard: &'a storage_runtime::Guard,
        id: &str,
        lock: &'a files::Lock,
        authorize: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        identity::safe_id(id)?;
        lock.recheck()?;
        authorize()?;
        guard.recheck()?;
        let original = Arc::new(Original::open(guard)?);
        let directory =
            files::ensure_directory_relative(guard.control(), Path::new(STORE), 0o700, 0)?;
        require(
            mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
            "backup area journal left original control mount",
        )?;
        let mut store = Store::retained_area(
            &Path::new(operation::CONTROL).join(STORE),
            0,
            guard.control_mount_id(),
            Box::new(move || {
                guard.recheck()?;
                lock.recheck()?;
                authorize()
            }),
        )?;
        store.prepare(value!({"schema":2,"id":id,"phase":"prepared","boot_id":operation::boot_id()?,
            "filesystem_uuid":guard.configuration["filesystem_uuid"],"source_configuration_sha256":json::fingerprint(&guard.configuration)?,
            "parent_mount":original.parent_row.id,"parent_unique":original.mount,
            "parent_inode":files::identity(&original.parent.metadata()?),"stub_inode":original.inode,
            "mount_scope":"owned-shared-bind","mount_options":OPTIONS,"mount_closed":false,"mount_binding":null}))?;
        // Before attachment the stub must be uncovered. After attachment it is
        // covered by exactly the clone being admitted, so the post-attach
        // checkpoint verifies the parent, namespace and empty stub instead.
        // (Reusing the "uncovered" checkpoint after attachment always failed,
        // leaving a shared, unadmitted bind on /backup-repository.)
        let checkpoint = || {
            store.recheck()?;
            original.restored()
        };
        let attached = || {
            store.recheck()?;
            original.recheck()
        };
        let detached = private_bind::Detached::prepare(&original.file, &checkpoint)?;
        let mount = detached.unique();
        let attachment = detached.attach_only(&original.file, &checkpoint)?;
        // From here every failure path detaches the clone again (identity-checked).
        let normal = attachment.normal().unwrap_or(0);
        let mut rollback =
            mount_rollback::Armed::new(c"/backup-repository", mount, normal, "private backup area");
        let admitted = (|| {
            let file = attachment.protect_shared(&attached)?;
            let rows = storage_runtime::rows()?;
            let normal = mount_identity::id(file.as_fd(), false)?;
            let row = storage_runtime::mount_row(&rows, TARGET, None, normal)?.clone();
            let expected_root = format!(
                "{}/backup-repository",
                original.parent_row.root.trim_end_matches('/')
            );
            let flags = row
                .options
                .split(',')
                .collect::<std::collections::BTreeSet<_>>();
            require(
                row.parent == original.parent_row.id
                    && row.root == expected_root
                    && (row.major, row.minor)
                        == (original.parent_row.major, original.parent_row.minor)
                    && private_bind::shared_group(&row.optional)
                    && ["rw", "nodev", "nosuid", "noexec"]
                        .iter()
                        .all(|k| flags.contains(k))
                    && !flags.contains("ro"),
                "private backup bind left original Root or required protections",
            )?;
            let core = Core {
                file,
                mount,
                row,
                original: Arc::clone(&original),
            };
            core.uncovered()?;
            Ok::<_, Error>(core)
        })();
        let core = match admitted {
            Ok(core) => Arc::new(core),
            Err(error) => {
                // The clone's descriptor is already closed; detach, then settle
                // the durable intent so it does not block every later setup.
                if rollback.release().is_ok()
                    && original.restored().is_ok()
                    && let Err(settle) = store.rolled_back(id)
                {
                    eprintln!(
                        "enzimos-backup-setup: private area intent {id} not settled: {}",
                        crate::diagnostic::bounded(&settle.0)
                    );
                }
                return Err(error);
            }
        };
        if let Err(error) = store.mount_recorded(id, core.binding()) {
            drop(core);
            if rollback.release().is_ok() && original.restored().is_ok() {
                let _ = store.rolled_back(id);
            }
            return Err(error);
        }
        Ok(Self {
            core,
            store,
            id: id.into(),
            guard,
            lock,
            rollback,
        })
    }
    pub(crate) fn owns(&self, core: &Arc<Core>) -> Result<()> {
        require(
            Arc::ptr_eq(&self.core, core),
            "cleanup area is not the original owned kernel object",
        )?;
        self.core.covered()
    }
    pub(crate) fn covered(&self) -> Result<()> {
        self.store.recheck()?;
        self.core.covered()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.store.recheck()?;
        self.core.uncovered()
    }
    pub(crate) fn core(&self) -> Result<Arc<Core>> {
        self.recheck()?;
        Ok(Arc::clone(&self.core))
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.core.file)
    }
    /// Original owned cleanup does not begin another action. Durable success still
    /// requires the store's fresh authorization after both normal unmounts.
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    pub(crate) fn close(mut self) -> Result<Restored<'a>> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.core.uncovered()?;
        let core = Arc::try_unwrap(self.core)
            .map_err(|_| Error("private backup area still has an owned reference".into()))?;
        let original = core.original;
        drop(core.file);
        require(
            unsafe { libc::umount2(c"/backup-repository".as_ptr(), 0) } == 0,
            "normal private backup area close failed; journal retained",
        )?;
        self.rollback.disarm();
        original.restored()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.store.mount_closed(&self.id)?;
        let restored = Restored {
            original,
            store: self.store,
            id: self.id,
        };
        restored.recheck()?;
        Ok(restored)
    }
}
pub(crate) struct Restored<'a> {
    original: Arc<Original>,
    store: Store<'a>,
    id: String,
}
impl Restored<'_> {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.original.restored()?;
        require(
            self.store.completed(&self.id)?["mount_closed"] == true,
            "original private backup area closure receipt missing",
        )
    }
}
fn inode(value: &Value, private: bool) -> Result<files::FileIdentity> {
    let inode: files::FileIdentity = serde_json::from_value(value.clone())
        .map_err(|_| Error("private backup area inode field bounds".into()))?;
    require(
        inode.1 > 0
            && inode.10 > 0
            && inode.8 == 0
            && inode.9 == 0
            && inode.7 & libc::S_IFMT == libc::S_IFDIR
            && inode.7 & 0o022 == 0
            && (!private || inode.7 & 0o7777 == 0o700)
            && (0..1_000_000_000).contains(&inode.4)
            && (0..1_000_000_000).contains(&inode.6),
        "private backup area requires protected Root directory evidence",
    )?;
    Ok(inode)
}
/// A closed journal codec. Validation never constructs an Area, Core or Restored.
pub(crate) fn validate_receipt(body: &Value, id: &str) -> Result<()> {
    json::fields(
        body,
        "schema id phase boot_id filesystem_uuid source_configuration_sha256 parent_mount parent_unique parent_inode stub_inode mount_scope mount_options mount_closed mount_binding",
    )?;
    identity::safe_id(id)?;
    require(
        body["schema"] == 2
            && body["id"] == id
            && ((body["mount_scope"] == "owned-shared-bind" && body["mount_options"] == OPTIONS)
                || (body["mount_scope"] == "owned-private-bind"
                    && body["mount_options"] == LEGACY_OPTIONS))
            && ["parent_mount", "parent_unique"]
                .iter()
                .all(|k| body[*k].as_u64().is_some_and(|v| v > 0)),
        "private backup area journal original scope differs",
    )?;
    for key in ["boot_id", "filesystem_uuid"] {
        identity::uuid(
            body[key]
                .as_str()
                .ok_or_else(|| Error("private area UUID missing".into()))?,
        )?;
    }
    identity::sha(
        body["source_configuration_sha256"]
            .as_str()
            .ok_or_else(|| Error("private area source configuration missing".into()))?,
    )?;
    let parent = inode(&body["parent_inode"], false)?;
    let stub = inode(&body["stub_inode"], true)?;
    require(
        parent.0 == stub.0 && parent.1 != stub.1,
        "private backup area stub left original parent filesystem",
    )?;
    let binding_valid = |binding: &Value| -> Result<()> {
        json::fields(binding, "mount_id unique_mount_id target filesystem_uuid")?;
        require(
            binding["target"] == TARGET
                && binding["filesystem_uuid"] == body["filesystem_uuid"]
                && ["mount_id", "unique_mount_id"]
                    .iter()
                    .all(|k| binding[*k].as_u64().is_some_and(|v| v > 0))
                && binding["mount_id"] != body["parent_mount"]
                && binding["unique_mount_id"] != body["parent_unique"],
            "private backup area original binding or closure evidence differs",
        )
    };
    match body["phase"].as_str() {
        Some("prepared") => require(
            body["mount_closed"] == false && body["mount_binding"].is_null(),
            "private area prepared intent cannot claim a mount or closure",
        ),
        Some("mounted" | "complete") => {
            binding_valid(&body["mount_binding"])?;
            require(
                body["mount_closed"] == (body["phase"] == "complete"),
                "private backup area original binding or closure evidence differs",
            )
        }
        Some("rolled-back") => {
            if !body["mount_binding"].is_null() {
                binding_valid(&body["mount_binding"])?;
            }
            require(
                body["mount_closed"] == true,
                "rolled-back private area must be closed",
            )
        }
        _ => Err(Error(
            "private backup area phase cannot authorize replay".into(),
        )),
    }
}
