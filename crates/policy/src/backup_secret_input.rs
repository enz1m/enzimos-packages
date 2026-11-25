// SPDX-License-Identifier: MIT
//! A broker-owned sealed input is syntax-checked only by the pinned ordinary reader.
use crate::settings_command::Command;
use enzimos_platform::{Result, require, secret};
use std::{fs::File, os::fd::BorrowedFd, time::Duration};
pub struct Validated {
    uid: u32,
    original: secret::Retained,
    reader: Command,
}
impl Validated {
    pub fn retain(
        fd: BorrowedFd<'_>,
        uid: u32,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        crate::namespaces::initial()?;
        crate::operation::root_only()?;
        authorize()?;
        let original = secret::retain(fd, uid)?;
        let reader = Command::open("/usr/lib/enzimos-backend/enzimos-secret-validator")?;
        original.recheck()?;
        reader.recheck()?;
        authorize()?;
        let body = reader.run_fds(
            &["--fd", "@fd-number:0", "--uid", &uid.to_string()],
            &[0],
            32,
            Duration::from_secs(3),
            &[original.fd()?],
        )?;
        require(body.is_empty(), "credential reader must be silent")?;
        original.recheck()?;
        reader.recheck()?;
        authorize()?;
        Ok(Self {
            uid,
            original,
            reader,
        })
    }
    pub(crate) fn owner(&self) -> u32 {
        self.uid
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()?;
        self.reader.recheck()
    }
    pub(crate) fn length(&self) -> Result<usize> {
        self.recheck()?;
        self.original.length()
    }
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        self.original.fd()
    }
    pub(crate) fn reader_evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        self.reader.evidence()
    }
    /// The original Root caller must persist intent and recheck fresh approval
    /// before creating this output. Partial output must never be replayed.
    pub(crate) fn copy_into_new(&self, output: &File) -> Result<()> {
        self.recheck()?;
        self.original.copy_into_new(output)?;
        self.recheck()
    }
}
