// SPDX-License-Identifier: MIT
//! Actual original LUKS source descriptor, queried before and after owned unlock.
//! Source UUID/type are public metadata; no passphrase is retained or measured.
use crate::{
    recovery_devices::Block,
    recovery_unlock::{self, CreatedMapping},
    root_retirement_boot_artifacts::Restored,
    root_retirement_kernel_boot::Original as Kernel,
    root_retirement_offline_scope::Scope,
    settings_command::Command,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
fn one(bytes: &[u8]) -> Result<&str> {
    require(
        bytes.len() <= 4096 && !bytes.contains(&0),
        "original source UUID/type query bound",
    )?;
    let value = std::str::from_utf8(bytes)
        .map_err(|_| Error("original source UUID/type encoding".into()))?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    require(
        !value.is_empty() && !value.chars().any(char::is_whitespace),
        "one exact original source UUID/type value required",
    )?;
    Ok(value)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn flags(source: &Block) -> Result<i32> {
    let value = unsafe { libc::fcntl(source.file.as_raw_fd(), libc::F_GETFL) };
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original retirement source read-only descriptor",
    )?;
    Ok(value)
}
pub struct Source<'a, 's> {
    scope: &'s Scope,
    kernel: &'a Kernel<'s>,
    boot: &'a Restored<'a, 's>,
    source: &'a Block,
    command: Command,
    epoch: files::FileIdentity,
    flags: i32,
    identity: Value,
    uuid: String,
}
pub struct Verified<'b, 'a, 's> {
    original: &'b Source<'a, 's>,
    mapping: CreatedMapping<'b>,
}
impl<'a, 's> Source<'a, 's> {
    pub fn observe(
        scope: &'s Scope,
        kernel: &'a Kernel<'s>,
        boot: &'a Restored<'a, 's>,
        source: &'a Block,
    ) -> Result<Self> {
        kernel.require_original_scope(scope)?;
        boot.require_original_kernel_boot(kernel)?;
        source.recheck()?;
        let result = Self {
            scope,
            kernel,
            boot,
            source,
            command: Command::open("/usr/bin/blkid")?,
            epoch: files::identity(&source.file.metadata()?),
            flags: flags(source)?,
            identity: crate::block::observe(source.file.as_fd())?,
            uuid: kernel.parameters()?.luks.clone(),
        };
        result.query_original()?;
        result.recheck()?;
        Ok(result)
    }
    fn query_original(&self) -> Result<()> {
        self.recheck()?;
        for (field, expected) in [("UUID", self.uuid.as_str()), ("TYPE", "crypto_LUKS")] {
            // Probe the original inherited descriptor, bypassing any UUID cache.
            let bytes = self.command.run_fds(
                &["-p", "-s", field, "-o", "value", "@fd:0"],
                &[0],
                4096,
                Duration::from_secs(30),
                &[self.source.file.as_fd()],
            )?;
            // The bounded readonly child has been fully reaped before census.
            self.recheck()?;
            require(
                one(&bytes)? == expected,
                "original source is not the actual boot LUKS UUID/type",
            )?;
        }
        self.recheck()
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope.recheck()?;
        self.kernel.require_original_scope(self.scope)?;
        self.boot.require_original_kernel_boot(self.kernel)?;
        self.command.recheck()?;
        self.source.recheck()?;
        require(
            files::identity(&self.source.file.metadata()?) == self.epoch
                && flags(self.source)? == self.flags
                && crate::block::observe(self.source.file.as_fd())? == self.identity
                && self.kernel.parameters()?.luks == self.uuid,
            "original LUKS source descriptor/boot identity changed",
        )?;
        self.scope.recheck()
    }
    pub fn open_mapping(&self) -> Result<Verified<'_, 'a, 's>> {
        self.query_original()?;
        let mapping = recovery_unlock::open_offline(
            self.scope,
            self.source,
            &self.kernel.parameters()?.filesystem,
        )?;
        // Source UUID/type are measured again after this actual console unlock,
        // before any native seal. No later recheck executes an external child.
        self.query_original()?;
        let result = Verified {
            original: self,
            mapping,
        };
        result.recheck()?;
        Ok(result)
    }
}
impl<'b, 'a, 's> Verified<'b, 'a, 's> {
    pub fn into_mapping(self) -> Result<CreatedMapping<'b>> {
        self.recheck()?;
        Ok(self.mapping)
    }
    pub(crate) fn original_scope(&self) -> Result<&'s Scope> {
        self.recheck()?;
        Ok(self.original.scope)
    }
    pub(crate) fn original_luks_uuid(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.original.uuid)
    }
    pub(crate) fn require_original_mapping(&self, mapping: &CreatedMapping<'_>) -> Result<()> {
        require(
            std::ptr::eq(&self.mapping, mapping),
            "verified LUKS source belongs to another actual unlock",
        )?;
        self.recheck()
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()?;
        self.mapping.recheck()
    }
    pub fn mapping(&self) -> Result<&CreatedMapping<'b>> {
        self.recheck()?;
        Ok(&self.mapping)
    }
    pub(crate) fn require_original_kernel(&self, kernel: &Kernel<'_>) -> Result<()> {
        require(
            std::ptr::eq(self.original.kernel, kernel),
            "verified original unlock/kernel actor differs",
        )?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"luks_uuid":self.original.uuid,"original_source_uuid_type_verified_before_after_unlock":true,"passphrase_retained":false,"execution_authorized":false}),
        )
    }
}
