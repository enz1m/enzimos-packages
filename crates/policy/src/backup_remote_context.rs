// SPDX-License-Identifier: MIT
//! Original Root remote inputs/pin. Remote network observations remain required.
use crate::{
    backup_remote_inputs::Inputs, backup_remote_record as record, backup_restic_runtime::Image,
    backup_transfer_caller::Caller, control_record::Observation, storage_runtime::Guard,
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json as value};
use std::path::Path;
pub(crate) struct Context<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    inputs: Inputs,
    caller: Caller,
    restic: Image,
    pin: Observation,
    rotation: Option<Observation>,
    original: Value,
}
impl<'a> Context<'a> {
    pub(crate) fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let inputs = Inputs::observe(guard)?;
        let pin = Observation::open(
            guard.control(),
            Path::new("backup-remote-pin.json"),
            32768,
            guard.control_mount_id(),
        )?;
        record::pin(pin.value()?)?;
        require(
            pin.value()?["configuration_sha256"] == inputs.binding(guard)?["configuration_sha256"],
            "remote pin public input binding differs",
        )?;
        let rotation = Observation::optional(
            guard.control(),
            Path::new("backup-remote-rotation.json"),
            record::ROTATION_LIMIT,
            guard.control_mount_id(),
        )?;
        if let Some(rotation) = &rotation {
            record::rotation(rotation.value()?)?;
            require(
                matches!(
                    rotation.value()?["phase"].as_str(),
                    Some("complete" | "abandoned")
                ),
                "unfinished remote compromise rotation; review first",
            )?;
        }
        let mut original = Self {
            guard,
            lock,
            inputs,
            pin,
            rotation,
            caller: Caller::current()?,
            restic: Image::open()?,
            original: Value::Null,
        };
        original.original = original.current(authorize)?;
        original.recheck(authorize)?;
        Ok(original)
    }
    fn current(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.inputs.recheck(self.guard)?;
        self.caller.recheck()?;
        self.pin.recheck()?;
        let rotation = if let Some(rotation) = &self.rotation {
            rotation.recheck()?;
            Some(rotation.evidence()?)
        } else {
            require(
                Observation::optional(
                    self.guard.control(),
                    Path::new("backup-remote-rotation.json"),
                    record::ROTATION_LIMIT,
                    self.guard.control_mount_id(),
                )?
                .is_none(),
                "remote rotation appeared at original absent name",
            )?;
            None
        };
        Ok(
            value!({"schema":1,"role":"remote-repository-context","boot_id":crate::operation::boot_id()?,
            "inputs":self.inputs.evidence(self.guard)?,"caller":self.caller.evidence()?,"restic":self.restic.evidence()?,
            "pin":self.pin.value()?,"pin_epoch":self.pin.evidence()?,"rotation_epoch":rotation,
            "remote_identity_authenticated":false,"copy_complete":false,"worker_closed":false,"scheduler_enabled":false}),
        )
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        require(
            self.current(authorize)? == self.original,
            "original remote context changed; no replacement adoption/replay",
        )
    }
    pub(crate) fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.original)
    }
    /// Original actual descriptions only; the future reservation must still
    /// prove sender OFDs, durably enter one send and close the actual worker scope.
    pub(crate) fn configuration(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&Value> {
        self.recheck(authorize)?;
        self.inputs.configuration(self.guard)
    }
    pub(crate) fn binding(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        self.inputs.binding(self.guard)
    }
    pub(crate) fn descriptors(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<std::collections::BTreeMap<&'static str, std::os::fd::BorrowedFd<'_>>> {
        use std::os::fd::AsFd;
        self.recheck(authorize)?;
        let inputs = self.inputs.descriptors(self.guard)?;
        let descriptors = std::collections::BTreeMap::from([
            ("remote-configuration", inputs[0]),
            ("remote-password", inputs[1]),
            ("remote-share-password", inputs[2]),
            ("caller-image", self.caller.image()?.as_fd()),
            ("caller-pidfd", self.caller.pidfd()?),
            ("restic", self.restic.descriptor()?.as_fd()),
            ("remote-pin", self.pin.descriptor()?.as_fd()),
            ("operation-lock", self.lock.as_file().as_fd()),
            ("root-control", self.guard.control().as_fd()),
        ]);
        let mut objects = std::collections::BTreeSet::new();
        for (role, fd) in &descriptors {
            if *role == "caller-pidfd" {
                continue;
            }
            let file = std::fs::File::from(fd.try_clone_to_owned()?);
            let epoch = files::identity(&file.metadata()?);
            require(
                objects.insert((epoch.0, epoch.1)),
                "remote descriptor roles alias one original inode",
            )?;
        }
        self.recheck(authorize)?;
        Ok(descriptors)
    }
    pub(crate) fn caller_actor(&self) -> &Caller {
        &self.caller
    }
    pub(crate) fn image_actor(&self) -> &Image {
        &self.restic
    }
    pub(crate) fn require_description(
        &self,
        fd: std::os::fd::BorrowedFd<'_>,
        number: u32,
    ) -> Result<()> {
        self.caller.require_description(fd, number)
    }
    pub(crate) fn compare_identity_data(
        &self,
        observed: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        record::pin(observed)?;
        require(
            observed == self.pin.value()?,
            "authenticated remote identity changed; explicit review required",
        )?;
        self.recheck(authorize)
    }
}
