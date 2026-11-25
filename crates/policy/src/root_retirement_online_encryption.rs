// SPDX-License-Identifier: MIT
//! Original online LUKS source for native Root coordinator options.
//! Public UUID/type metadata only; no unlock, key access or block mutation.
use crate::{recovery_devices::Block, settings_command::Command, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::{os::fd::AsFd, time::Duration};
fn one(bytes: &[u8]) -> Result<&str> {
    require(
        bytes.len() <= 4096 && !bytes.contains(&0),
        "online LUKS metadata bound",
    )?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error("online LUKS metadata encoding".into()))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    require(
        !text.is_empty() && !text.chars().any(|c| c.is_whitespace() || c.is_control()),
        "one exact online LUKS metadata value required",
    )?;
    Ok(text)
}
pub struct Source<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    block: Block,
    command: Command,
    epoch: files::FileIdentity,
    flags: i32,
    identity: Value,
    uuid: String,
}
impl<'a> Source<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        authorize()?;
        let uuid = crate::recovery_run_stage::luks_uuid(guard)?;
        let block = Block::by_uuid(&uuid, false)?;
        let epoch = files::identity(&block.file.metadata()?);
        let flags = enzimos_platform::files::status_flags(&block.file);
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "online original LUKS source read-only description required",
        )?;
        let identity = crate::block::observe(block.file.as_fd())?;
        let command = Command::open("/usr/bin/blkid")?;
        let this = Self {
            guard,
            lock,
            block,
            command,
            epoch,
            flags,
            identity,
            uuid,
        };
        this.verify(authorize)?;
        Ok(this)
    }
    pub(crate) fn require_original_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "online LUKS source belongs to another original guard/lock",
        )?;
        self.verify(authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.block.recheck()?;
        self.command.recheck()?;
        require(
            files::identity(&self.block.file.metadata()?) == self.epoch
                && enzimos_platform::files::status_flags(&self.block.file) == self.flags
                && crate::block::observe(self.block.file.as_fd())? == self.identity,
            "original online LUKS source identity/description changed",
        )?;
        self.lock.recheck()?;
        self.guard.recheck()?;
        authorize()
    }
    /// Re-probe the retained description without consulting the UUID cache,
    /// and rejoin the currently guarded live Root ancestry on both sides.
    pub fn verify(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck(authorize)?;
        require(
            crate::recovery_run_stage::luks_uuid(self.guard)? == self.uuid,
            "live Root encryption ancestry changed",
        )?;
        for (field, expected) in [("UUID", self.uuid.as_str()), ("TYPE", "crypto_LUKS")] {
            self.recheck(authorize)?;
            let bytes = self.command.run_fds(
                &["-p", "-s", field, "-o", "value", "@fd:0"],
                &[0],
                4096,
                Duration::from_secs(30),
                &[self.block.file.as_fd()],
            )?;
            self.recheck(authorize)?;
            require(
                one(&bytes)? == expected,
                "original online LUKS UUID/type differs from live Root ancestry",
            )?;
        }
        require(
            crate::recovery_run_stage::luks_uuid(self.guard)? == self.uuid,
            "live Root encryption ancestry changed after original source probe",
        )?;
        self.recheck(authorize)
    }
    pub fn uuid(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&str> {
        self.verify(authorize)?;
        Ok(&self.uuid)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.verify(authorize)?;
        Ok(
            json!({"luks_uuid":self.uuid,"original_epoch":self.epoch,"flags":self.flags,
            "block":self.identity,"execution_authorized":false}),
        )
    }
}
