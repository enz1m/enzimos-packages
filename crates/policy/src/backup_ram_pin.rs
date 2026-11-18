// SPDX-License-Identifier: MIT
//! Pin joins original control document to actual RAM restore repository.
use super::Document;
use enzimos_platform::{Result, require};
use std::path::Path;
pub(crate) struct Repository<'a, 'g> {
    destination: &'a crate::backup_destination::ram::Destination<'g>,
    document: Document,
}
impl<'a, 'g> Repository<'a, 'g> {
    pub(crate) fn open(
        destination: &'a crate::backup_destination::ram::Destination<'g>,
    ) -> Result<Self> {
        destination.recheck()?;
        let document = Document::optional(
            &Path::new(crate::operation::CONTROL).join("backup-destination.json"),
            0,
        )?
        .ok_or_else(|| {
            enzimos_platform::Error("existing backup repository must be explicitly bound".into())
        })?;
        require(
            document.mount == destination.source().control_mount_id()
                && crate::backup_binding::pin(&document.bytes)? == destination.expected_pin()?,
            "backup repository binding changed; explicit review required",
        )?;
        let this = Self {
            destination,
            document,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn original_for_retirement(&self) -> Result<Document> {
        self.recheck()?;
        self.document.duplicate()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.destination.recheck()?;
        self.document.recheck()
    }
}
