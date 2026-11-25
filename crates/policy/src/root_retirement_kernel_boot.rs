// SPDX-License-Identifier: MIT
//! Original kernel command-line descriptor joined to the actual offline scope.
use crate::{root_retirement_offline_scope::Scope, root_retirement_parameters::Parameters};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};

fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original kernel command line read-only descriptor",
    )?;
    Ok(value)
}
fn read(file: &File) -> Result<String> {
    let mut bytes = vec![0; 65537];
    let mut used = 0;
    while used < bytes.len() {
        let count = file.read_at(&mut bytes[used..], used as u64)?;
        if count == 0 {
            break;
        }
        used += count;
    }
    require(used <= 65536, "actual kernel command line bound")?;
    bytes.truncate(used);
    String::from_utf8(bytes).map_err(|_| Error("actual kernel command line encoding".into()))
}
pub struct Original<'a> {
    scope: &'a Scope,
    descriptor: File,
    epoch: files::FileIdentity,
    mount: u64,
    flags: i32,
    bytes: String,
    parameters: Parameters,
}
impl<'a> Original<'a> {
    pub(crate) fn require_original_mounts(
        &self,
        mounts: &crate::root_retirement_offline_scope::Mounts<'_>,
    ) -> Result<()> {
        mounts.require_original_scope(self.scope)?;
        self.recheck()
    }
    pub(crate) fn require_original_scope(&self, scope: &Scope) -> Result<()> {
        require(
            std::ptr::eq(self.scope, scope),
            "original kernel boot scope differs",
        )?;
        self.recheck()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    pub fn observe(scope: &'a Scope) -> Result<Self> {
        let proc = scope.original_proc()?;
        let descriptor = files::open_relative(proc, Path::new("cmdline"))?;
        let metadata = descriptor.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o222 == 0,
            "protected actual kernel command line",
        )?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        require(
            unsafe { libc::fstatfs(descriptor.as_raw_fd(), stat.as_mut_ptr()) } == 0,
            "actual kernel command line filesystem observation",
        )?;
        require(
            unsafe { stat.assume_init() }.f_type == 0x9fa0,
            "actual proc command line required",
        )?;
        let bytes = read(&descriptor)?;
        let parameters = Parameters::parse(&bytes)?;
        let result = Self {
            scope,
            epoch: files::identity(&descriptor.metadata()?),
            mount: mount_identity::id(descriptor.as_fd(), true)?,
            flags: flags(&descriptor)?,
            descriptor,
            bytes,
            parameters,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        let proc = self.scope.original_proc()?;
        let named = files::open_relative(proc, Path::new("cmdline"))?;
        require(
            files::identity(&self.descriptor.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.descriptor.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && flags(&self.descriptor)? == self.flags
                && read(&self.descriptor)? == self.bytes
                && read(&named)? == self.bytes,
            "original kernel boot command line replaced, covered or changed",
        )?;
        self.scope.recheck()
    }
    pub fn parameters(&self) -> Result<&Parameters> {
        self.recheck()?;
        Ok(&self.parameters)
    }
    pub fn matches_record(&self, record: &Value) -> Result<()> {
        self.recheck()?;
        self.parameters.matches_record(record)?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"retirement":self.parameters.id,"actual_kernel_parameters_verified":true,"execution_authorized":false,"coordinator_image_verified":false}),
        )
    }
}
