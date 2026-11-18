// SPDX-License-Identifier: MIT
//! Fresh standalone remote initialization. Original inputs and exclusive entered
//! receipts precede one fixed consumer; an uncertain attempt is never replayed.
use crate::{
    backup_remote_inputs::Inputs,
    backup_remote_record,
    backup_restic_runtime::{Image, Runtime},
    operation,
    storage_runtime::Guard,
};
use enzimos_platform::{
    Result, files, json,
    publication::{Committed, Prepared},
    receipt_registry::Registry,
    require,
};
use serde_json::{Value, json as value};
use std::os::fd::AsFd;
use std::{
    cell::{Cell, RefCell},
    path::Path,
};
pub(crate) struct Entered<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    inputs: Inputs,
    image: Image,
    registry: RefCell<Registry>,
    init: Committed,
    pin: RefCell<Option<Committed>>,
    started: Cell<bool>,
    finished: Cell<bool>,
    record: Value,
}
fn absence(guard: &Guard, name: &str) -> Result<()> {
    require(
        files::optional_relative(guard.control(), Path::new(name))?.is_none(),
        "remote initialization already attempted/pinned; no adoption/replay",
    )
}
impl<'a> Entered<'a> {
    fn begin(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let inputs = Inputs::observe(guard)?;
        let image = Image::open()?;
        let mut source = || {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            inputs.recheck(guard)?;
            image.evidence()?;
            absence(guard, "backup-remote-init.json")?;
            absence(guard, "backup-remote-pin.json")
        };
        source()?;
        let directory = files::ensure_directory_relative(
            guard.control(),
            Path::new("backup-remote-initialization"),
            0o700,
            0,
        )?;
        require(
            enzimos_platform::mount_identity::id(directory.as_fd(), true)?
                == guard.control_mount_id(),
            "remote attempt receipt crossed control mount",
        )?;
        let path = Path::new(operation::CONTROL).join("backup-remote-initialization");
        let mut registry = Registry::observe(&path, &directory, "attempt.json", 0)?;
        let record = value!({"schema":1,"configuration_sha256":inputs.binding(guard)?["configuration_sha256"],"created_boot":operation::boot_id()?});
        backup_remote_record::initialization(&record)?;
        let mut bytes = json::canonical(&record)?;
        bytes.push(b'\n');
        registry.publish(&bytes, &mut source)?;
        source()?;
        registry.recheck()?;
        let legacy_path = Path::new(operation::CONTROL).join("backup-remote-init.json");
        let pending = Prepared::write_authorized(&legacy_path, &bytes, 0, &mut source)?;
        pending.require_new_destination(guard.control(), Path::new("backup-remote-init.json"))?;
        // After the sole rename, recognize only its actual returned producer.
        let init = pending.commit_checked(false, &mut source, &mut |producer| {
            producer.require_destination(guard.control(), Path::new("backup-remote-init.json"))?;
            guard.recheck()?;
            lock.recheck()?;
            inputs.recheck(guard)?;
            image.evidence()?;
            absence(guard, "backup-remote-pin.json")
        })?;
        let result = Self {
            guard,
            lock,
            inputs,
            image,
            registry: RefCell::new(registry),
            init,
            pin: RefCell::new(None),
            started: Cell::new(false),
            finished: Cell::new(false),
            record,
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.inputs.recheck(self.guard)?;
        self.image.evidence()?;
        self.init
            .require_destination(self.guard.control(), Path::new("backup-remote-init.json"))?;
        require(
            files::read_file(self.init.file()?, 32768, Some(0), true)? == {
                let mut body = json::canonical(&self.record)?;
                body.push(b'\n');
                body
            },
            "actual remote initialization intent changed",
        )?;
        self.registry.borrow().recheck()?;
        match self.pin.borrow().as_ref() {
            Some(pin) => {
                pin.require_destination(self.guard.control(), Path::new("backup-remote-pin.json"))?;
            }
            None => absence(self.guard, "backup-remote-pin.json")?,
        }
        self.guard.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    pub(crate) fn start(
        &self,
        runtime: &Runtime,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            runtime.image_evidence()? == self.image.evidence()?,
            "original remote initialization vendor image changed",
        )?;
        require(
            !self.started.replace(true),
            "remote initialization cannot replay actual entered consumer",
        )
    }
    pub(crate) fn configuration(&self) -> Result<&Value> {
        self.inputs.configuration(self.guard)
    }
    pub(crate) fn binding(&self) -> Result<&Value> {
        self.inputs.binding(self.guard)
    }
    pub(crate) fn descriptors(&self) -> Result<[std::os::fd::BorrowedFd<'_>; 3]> {
        self.inputs.descriptors(self.guard)
    }
    fn finish(
        &self,
        observed: crate::backup_restic_runtime::RemoteInitialized<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        observed.require_original(self, authorize)?;
        self.recheck(authorize)?;
        require(
            self.started.get() && !self.finished.replace(true),
            "remote pin requires one actual initialization outcome; no replay",
        )?;
        let pin = observed.pin(authorize)?.clone();
        backup_remote_record::pin(&pin)?;
        let mut bytes = json::canonical(&pin)?;
        bytes.push(b'\n');
        let path = Path::new(operation::CONTROL).join("backup-remote-pin.json");
        let pending =
            Prepared::write_authorized(&path, &bytes, 0, &mut || self.recheck(authorize))?;
        pending
            .require_new_destination(self.guard.control(), Path::new("backup-remote-pin.json"))?;
        let committed =
            pending.commit_checked(false, &mut || self.recheck(authorize), &mut |producer| {
                producer.require_destination(
                    self.guard.control(),
                    Path::new("backup-remote-pin.json"),
                )?;
                self.inputs.recheck(self.guard)?;
                self.init.recheck()?;
                self.registry.borrow().recheck()?;
                self.guard.recheck()?;
                self.lock.recheck()
            })?;
        *self.pin.borrow_mut() = Some(committed);
        self.recheck(authorize)?;
        require(
            files::read_file(
                self.pin.borrow().as_ref().unwrap().file()?,
                32768,
                Some(0),
                true,
            )? == bytes,
            "actual remote pin readback differs",
        )?;
        let mut complete = self.record.clone();
        complete["phase"] = value!("complete");
        complete["pin"] = pin.clone();
        let mut body = json::canonical(&complete)?;
        body.push(b'\n');
        // This registry checks its own actual chain. The callback checks every
        // independent original source, never its temporarily changing own row.
        self.registry.borrow_mut().publish(&body, &mut || {
            authorize()?;
            self.guard.recheck()?;
            self.lock.recheck()?;
            self.inputs.recheck(self.guard)?;
            self.init.recheck()?;
            self.pin.borrow().as_ref().unwrap().recheck()
        })?;
        self.recheck(authorize)?;
        Ok(
            value!({"status":"remote-repository-created-and-pinned","repository_id":pin["repository_id"],"scheduler_enabled":false}),
        )
    }
}
pub fn initialize_locked(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let entered = Entered::begin(guard, lock, authorize)?;
    let id = files::random_hex(16)?;
    let runtime = Runtime::create(&id, &mut || entered.recheck(authorize))?;
    let observed = runtime.initialize_remote(&entered, authorize)?;
    entered.finish(observed, authorize)
}
