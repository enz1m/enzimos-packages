// SPDX-License-Identifier: MIT
//! Original encrypted ready-image receipt joined to actual restored boot actors.
use crate::{
    control_record::Retained, root_retirement_boot_artifacts::Restored,
    root_retirement_offline_control::Control,
};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "recovery-images";
const LIMIT: usize = 2 * 1024 * 1024;
fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original encrypted image receipt read-only description",
    )?;
    Ok(value)
}
fn private(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let metadata = file.metadata()?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o700
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original private encrypted image registry required",
    )?;
    Ok(files::identity(&metadata))
}
/// The ready-image receipt joined to the restored boot.
pub struct Receipt<'b, 'a, 's> {
    control: &'b Control<'a, 's>,
    boot: &'b Restored<'a, 's>,
    folder: File,
    epoch: files::FileIdentity,
    folder_flags: i32,
    record_flags: i32,
    mount: u64,
    original: Retained,
}
impl<'b, 'a, 's> Receipt<'b, 'a, 's> {
    pub(crate) fn identifier(&self) -> Result<&str> {
        self.recheck()?;
        self.boot.identifier()
    }
    pub(crate) fn require_original_control(&self, control: &Control<'_, '_>) -> Result<()> {
        require(
            std::ptr::eq(self.control, control),
            "original ready-image receipt/control actor differs",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_kernel_boot(
        &self,
        kernel: &crate::root_retirement_kernel_boot::Original<'_>,
    ) -> Result<()> {
        self.boot.require_original_kernel_boot(kernel)?;
        self.recheck()
    }
    pub(crate) fn observe(
        control: &'b Control<'a, 's>,
        boot: &'b Restored<'a, 's>,
    ) -> Result<Self> {
        boot.require_original_control(control)?;
        let mount = control.mount_id()?;
        let folder = files::directory_relative(control.descriptor()?, Path::new(FOLDER), Some(0))?;
        let epoch = private(&folder, mount)?;
        let original = Retained::open(
            &folder,
            Path::new(&format!("{}.json", boot.identifier()?)),
            LIMIT,
            mount,
        )?;
        boot.require_published_record(original.checkpoint_value()?)?;
        require(
            original.checkpoint_value()?["control"] == control.evidence()?["identity"],
            "actual encrypted published image belongs to another original control subvolume",
        )?;
        let result = Self {
            control,
            boot,
            epoch,
            folder_flags: flags(&folder)?,
            record_flags: flags(original.checkpoint_descriptor()?)?,
            folder,
            mount,
            original,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.boot.require_original_control(self.control)?;
        let named =
            files::directory_relative(self.control.descriptor()?, Path::new(FOLDER), Some(0))?;
        require(
            private(&self.folder, self.mount)? == self.epoch
                && private(&named, self.mount)? == self.epoch
                && flags(&self.folder)? == self.folder_flags
                && flags(self.original.checkpoint_descriptor()?)? == self.record_flags,
            "original encrypted ready-image registry/description changed",
        )?;
        self.boot
            .require_published_record(self.original.checkpoint_value()?)?;
        require(
            self.original.checkpoint_value()?["control"] == self.control.evidence()?["identity"],
            "original image receipt/control identity changed",
        )?;
        self.boot.recheck()
    }
    /// JSON evidence of this retained state; it grants no deletion.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"image":self.boot.identifier()?,"original_encrypted_ready_image_receipt_verified":true,"defaults_restored":true,"execution_authorized":false}),
        )
    }
}
