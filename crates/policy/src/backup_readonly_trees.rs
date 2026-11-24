// SPDX-License-Identifier: MIT
//! Detached readonly archive trees, prepared under one original durable intent.
//! No global attachment, worker handoff, transfer or deletion is performed here.
use crate::{backup_archive_inputs::Inputs, control_record::Retained, identity, operation};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const FOLDER: &str = "backup-readonly-trees";
const MAX: usize = 128 * 1024;
#[repr(C)]
struct Attributes {
    set: u64,
    clear: u64,
    propagation: u64,
    user_namespace: u64,
}
const _: () = assert!(std::mem::size_of::<Attributes>() == 32);
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original protected readonly-tree registry required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
struct Tree<'a> {
    source: &'a File,
    epoch: files::FileIdentity,
    source_mount: u64,
    file: File,
    unique: u64,
}
impl<'a> Tree<'a> {
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    fn prepare(source: &'a File, checkpoint: &mut dyn FnMut() -> Result<()>) -> Result<Self> {
        checkpoint()?;
        let epoch = files::identity(&source.metadata()?);
        let source_mount = mount_identity::id(source.as_fd(), true)?;
        let raw = unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                source.as_raw_fd(),
                c"".as_ptr(),
                1u32 | libc::O_CLOEXEC as u32 | libc::AT_EMPTY_PATH as u32,
            )
        };
        require(
            raw >= 0,
            "detached readonly source clone failed; original intent retained",
        )?;
        let file = unsafe { File::from_raw_fd(raw as i32) };
        let unique = mount_identity::id(file.as_fd(), true)?;
        require(
            unique != source_mount && files::identity(&file.metadata()?) == epoch,
            "detached source clone differs from original",
        )?;
        checkpoint()?;
        let attributes = Attributes {
            set: 1 | 2 | 4 | 8,
            clear: 0,
            propagation: libc::MS_PRIVATE,
            user_namespace: 0,
        };
        require(
            unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH as u32,
                    &attributes as *const Attributes,
                    std::mem::size_of::<Attributes>(),
                )
            } == 0,
            "detached readonly source protection failed; original intent retained",
        )?;
        let this = Self {
            source,
            epoch,
            source_mount,
            file,
            unique,
        };
        this.recheck()?;
        checkpoint()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
    fn recheck(&self) -> Result<()> {
        let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
        let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
        require(
            files::identity(&self.source.metadata()?) == self.epoch
                && files::identity(&self.file.metadata()?) == self.epoch
                && mount_identity::id(self.source.as_fd(), true)? == self.source_mount
                && mount_identity::id(self.file.as_fd(), true)? == self.unique
                && self.unique != self.source_mount
                && unsafe { libc::fstatvfs(self.file.as_raw_fd(), &mut status) } == 0
                && status.f_flag & required == required,
            "original detached source or readonly protections changed",
        )
    }
    fn evidence(&self) -> Value {
        value!({"inode":self.epoch,"source_mount":self.source_mount,
        "detached_mount":self.unique,"readonly":true,"nodev":true,"nosuid":true,"noexec":true})
    }
}
pub struct Prepared<'a, 'b, 'c, 's, 'cfg, 'g> {
    inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
    lock: &'a files::Lock,
    registry: File,
    registry_shape: Shape,
    trees: BTreeMap<String, Tree<'a>>,
    record: Retained,
    value: Value,
}
impl<'a, 'b, 'c, 's, 'cfg, 'g> Prepared<'a, 'b, 'c, 's, 'cfg, 'g> {
    pub fn prepare(
        inputs: &'a Inputs<'b, 'c, 's, 'cfg, 'g>,
        lock: &'a files::Lock,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        identity::safe_id(id)?;
        require(id.len() <= 64, "readonly source intent ID bound")?;
        inputs.require_original_lock(lock)?;
        authorize()?;
        let guard = inputs.guard();
        let registry =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let registry_shape = shape(&registry)?;
        require(
            registry_shape.5 == guard.control_mount_id()
                && files::directory_names(&registry, 256)?.len() < 256,
            "original readonly-tree registry mount or capacity",
        )?;
        let input_sha256 = json::sha256(&json::canonical(&inputs.evidence()?)?);
        let mut body = value!({"schema":1,"id":id,"role":"backup-readonly-trees","phase":"entered",
            "boot_id":operation::boot_id()?,"input_sha256":input_sha256,"trees":null,
            "source_mounts_admitted":false,"worker_handoff":false,"transfer_complete":false,"backup_complete":false});
        let mut record = Retained::create(
            &registry,
            Path::new(&format!("{id}.json")),
            &body,
            MAX,
            registry_shape.5,
        )?;
        let mut checkpoint = || {
            authorize()?;
            inputs.require_original_lock(lock)?;
            record.recheck()?;
            let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
            require(
                shape(&registry)? == registry_shape && shape(&named)? == registry_shape,
                "original readonly-tree registry changed",
            )
        };
        let mut trees = BTreeMap::new();
        for (target, original) in inputs.directories()? {
            trees.insert(target.into(), Tree::prepare(original, &mut checkpoint)?);
        }
        checkpoint()?;
        for tree in trees.values() {
            tree.recheck()?;
        }
        body["trees"] = value!(
            trees
                .iter()
                .map(|(target, tree)| (target, tree.evidence()))
                .collect::<BTreeMap<_, _>>()
        );
        body["phase"] = value!("detached-readonly-ready");
        record.replace(&body)?;
        let this = Self {
            inputs,
            lock,
            registry,
            registry_shape,
            trees,
            record,
            value: body,
        };
        this.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    fn components(&self) -> Result<()> {
        enzimos_platform::recheck_scope::evaluation(|| {
            crate::namespaces::initial()?;
            self.inputs.require_original_lock(self.lock)?;
            let named = files::directory_relative(
                self.inputs.guard().control(),
                Path::new(FOLDER),
                Some(0),
            )?;
            require(
                shape(&self.registry)? == self.registry_shape
                    && shape(&named)? == self.registry_shape,
                "original readonly-tree registry changed or covered",
            )?;
            self.record.recheck()?;
            let originals = self.inputs.directories()?;
            require(
                originals.len() == self.trees.len(),
                "original detached source set incomplete",
            )?;
            for (target, tree) in &self.trees {
                require(
                    originals
                        .get(target.as_str())
                        .is_some_and(|original| std::ptr::eq(*original, tree.source)),
                    "detached source no longer pairs with original descriptor",
                )?;
                tree.recheck()?;
            }
            require(
                self.record.value()? == &self.value
                    && self.value["input_sha256"]
                        == json::sha256(&json::canonical(&self.inputs.evidence()?)?)
                    && self.value["trees"]
                        == value!(
                            self.trees
                                .iter()
                                .map(|(target, tree)| (target, tree.evidence()))
                                .collect::<BTreeMap<_, _>>()
                        ),
                "original detached source receipt changed",
            )
        })
    }
    pub fn recheck(&self) -> Result<()> {
        self.components()?;
        require(
            self.value["phase"] == "detached-readonly-ready",
            "original trees are not available for reservation",
        )
    }
    /// Consume these actual trees and one actual kernel-backed worker scope.
    /// The durable reservation is not a handoff or permission to attach globally.
    pub fn reserve_worker(
        mut self,
        scope: enzimos_platform::backup_worker_scope::Scope,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Reserved<'a, 'b, 'c, 's, 'cfg, 'g>> {
        authorize()?;
        self.recheck()?;
        let binding = scope.binding()?.clone();
        require(
            binding["id"] == self.value["id"]
                && binding["worker"]["pid"]
                    .as_u64()
                    .is_some_and(|pid| pid != u64::from(std::process::id())),
            "readonly trees require their original separate worker",
        )?;
        self.value["phase"] = value!("worker-reserved");
        self.value["worker"] = binding;
        self.record.replace(&self.value)?;
        let this = Reserved {
            prepared: self,
            scope,
        };
        this.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    /// Review evidence only. Detached descriptors stay private before reservation.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}

/// The exact original live worker and its readonly trees remain retained together.
/// This actor cannot be reconstructed from a receipt or caller-supplied PID.
pub struct Reserved<'a, 'b, 'c, 's, 'cfg, 'g> {
    prepared: Prepared<'a, 'b, 'c, 's, 'cfg, 'g>,
    scope: enzimos_platform::backup_worker_scope::Scope,
}
impl Reserved<'_, '_, '_, '_, '_, '_> {
    pub fn recheck(&self) -> Result<()> {
        self.prepared.components()?;
        require(
            matches!(
                self.prepared.value["phase"].as_str(),
                Some("worker-reserved" | "offer-entered" | "send-entered")
            ) && self.prepared.value["worker"] == *self.scope.binding()?,
            "original readonly-tree worker reservation changed",
        )
    }
    pub(crate) fn arguments(&self) -> Result<Vec<String>> {
        self.recheck()?;
        self.prepared.inputs.arguments()
    }
    pub(crate) fn worker_binding(&self) -> Result<&Value> {
        self.recheck()?;
        self.scope.binding()
    }
    pub(crate) fn enter_offer(&mut self, nonce: &str, request_sha256: &str) -> Result<()> {
        self.recheck()?;
        require(
            self.prepared.value["phase"] == "worker-reserved"
                && nonce.len() == 32
                && nonce.bytes().all(|b| b.is_ascii_hexdigit())
                && request_sha256.len() == 64
                && request_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "original source offer already entered or malformed; no replay",
        )?;
        self.prepared.value["offer"] = value!({"nonce":nonce,"request_sha256":request_sha256});
        self.prepared.value["phase"] = value!("offer-entered");
        self.prepared.record.replace(&self.prepared.value)?;
        self.recheck()
    }
    pub(crate) fn enter_send(&mut self, nonce: &str, request_sha256: &str) -> Result<()> {
        self.recheck()?;
        require(
            self.prepared.value["phase"] == "offer-entered"
                && self.prepared.value["offer"]
                    == value!({"nonce":nonce,"request_sha256":request_sha256}),
            "original source send already entered or changed; no replay",
        )?;
        self.prepared.value["phase"] = value!("send-entered");
        self.prepared.record.replace(&self.prepared.value)?;
        self.recheck()
    }
    /// Only the producer of this actual reserved worker may borrow these trees.
    /// Receiver-side original caller/OFD and private namespace checks are still
    /// required; this does not perform SCM transfer or attach a mount.
    pub fn descriptors(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BTreeMap<&str, std::os::fd::BorrowedFd<'_>>> {
        authorize()?;
        self.recheck()?;
        let files = self
            .prepared
            .trees
            .iter()
            .map(|(target, tree)| (target.as_str(), tree.file.as_fd()))
            .collect();
        authorize()?;
        self.recheck()?;
        Ok(files)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.prepared.value,"record_epoch":self.prepared.record.evidence()?}))
    }
    /// Release only our private descriptors after actual worker pidfd death and
    /// whole original cgroup emptiness. No guessed mount/snapshot deletion.
    pub fn close(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<ReleasedDescriptors> {
        authorize()?;
        self.prepared.components()?;
        let closed = self.scope.close()?;
        require(
            self.prepared.value["worker"] == *closed.binding()?,
            "closed original worker differs from readonly-tree reservation",
        )?;
        let mut prepared = self.prepared;
        let before = prepared.value.clone();
        let closed_binding = closed.binding()?.clone();
        // These are the exact private kernel descriptors made by our factory.
        // This makes no claim about unrelated Root-owned duplicate references.
        drop(std::mem::take(&mut prepared.trees));
        closed.recheck()?;
        prepared.inputs.require_original_lock(prepared.lock)?;
        authorize()?;
        prepared.record.recheck()?;
        let named = files::directory_relative(
            prepared.inputs.guard().control(),
            Path::new(FOLDER),
            Some(0),
        )?;
        require(
            shape(&prepared.registry)? == prepared.registry_shape
                && shape(&named)? == prepared.registry_shape,
            "original readonly-tree registry changed before closure publication",
        )?;
        let mut after = before;
        after["phase"] = value!("worker-closed-private-descriptors-released");
        after["worker_kernel_closed"] = value!(closed_binding);
        after["private_descriptors_released"] = value!(true);
        prepared.record.replace(&after)?;
        closed.recheck()?;
        Ok(ReleasedDescriptors {
            closed,
            record: prepared.record,
            value: after,
        })
    }
}
/// Kernel-backed worker closure and original descriptor retirement only.
/// This is not transfer, snapshot/stage cleanup or completed-backup evidence.
pub struct ReleasedDescriptors {
    closed: enzimos_platform::backup_worker_scope::Closed,
    record: Retained,
    value: Value,
}
impl ReleasedDescriptors {
    pub(crate) fn require_transfer(
        &self,
        worker: &Value,
        id: &Value,
        input_sha256: &Value,
    ) -> Result<()> {
        self.evidence()?;
        require(
            *self.closed.binding()? == *worker
                && self.value["id"] == *id
                && self.value["input_sha256"] == *input_sha256,
            "retired source descriptions differ from original captured transfer",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.closed.recheck()?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value
                && self.value["worker_kernel_closed"] == *self.closed.binding()?
                && self.value["private_descriptors_released"] == true,
            "original readonly descriptor closure receipt changed",
        )?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}
