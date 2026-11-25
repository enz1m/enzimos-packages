// SPDX-License-Identifier: MIT
//! Original running native image closure on the actual independent RAM root.
//! This observes bytes and PID1 identity; it does not authorize a deletion.
use crate::{
    native_policy_files, recovery_image, recovery_records as records,
    root_retirement_boot_contract, root_retirement_offline_scope::Scope,
};
use enzimos_platform::{
    Error, Result, files, json, mount_identity, process_identity, require, stream_copy,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const DIRECTORY: &str = "/usr/lib/enzimos-native";
const DESCRIPTOR: &str = "recovery-image.json";
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
struct Member {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    sha: String,
}
fn flags(file: &File) -> Result<i32> {
    let f = enzimos_platform::files::status_flags(&file);
    require(
        f >= 0 && f & libc::O_ACCMODE == libc::O_RDONLY,
        "original native image read-only descriptor",
    )?;
    Ok(f)
}
fn names(directory: &File) -> Result<BTreeSet<String>> {
    files::directory_names(directory, 129)?
        .into_iter()
        .map(|name| {
            name.into_string()
                .map_err(|_| Error("native image member encoding".into()))
        })
        .collect()
}
pub struct Original<'a> {
    scope: &'a Scope,
    directory: File,
    epoch: files::FileIdentity,
    mount: u64,
    flags: i32,
    members: BTreeMap<String, Member>,
    descriptor: Value,
    image: String,
    kernel: File,
    kernel_epoch: files::FileIdentity,
    kernel_mount: u64,
    kernel_flags: i32,
    release: Vec<u8>,
    process: process_identity::Retained,
}
fn member(
    scope: &Scope,
    directory: &File,
    name: &str,
    executable: bool,
    limit: u64,
) -> Result<Member> {
    let file = files::open_relative(directory, Path::new(name))?;
    scope.require_ram_member(&file)?;
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= limit
            && (!executable || m.mode() & 0o111 == 0o111),
        "protected original native image member required",
    )?;
    if executable {
        use std::os::unix::fs::FileExt;
        let mut magic = [0; 4];
        require(
            file.read_at(&mut magic, 0)? == 4 && magic == *b"\x7fELF",
            "original native image executable must be ELF",
        )?;
    }
    let (_, sha) = stream_copy::hash_borrowed(&file, limit, Some(0))?;
    Ok(Member {
        epoch: files::identity(&m),
        flags: flags(&file)?,
        file,
        sha,
    })
}
impl<'a> Original<'a> {
    pub(crate) fn require_original_scope(&self, scope: &Scope) -> Result<()> {
        require(
            std::ptr::eq(self.scope, scope),
            "original running image scope differs",
        )?;
        self.recheck()
    }
    pub(crate) fn descriptor(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.descriptor)
    }
    pub(crate) fn identifier(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.image)
    }
    pub fn observe(scope: &'a Scope) -> Result<Self> {
        scope.recheck()?;
        let directory = files::directory(Path::new(DIRECTORY), Some(0))?;
        scope.require_ram_member(&directory)?;
        let descriptor_member = member(scope, &directory, DESCRIPTOR, false, 2 * 1024 * 1024)?;
        let descriptor = json::decode(
            &files::read_file(&descriptor_member.file, 2 * 1024 * 1024, Some(0), true)?,
            2 * 1024 * 1024,
        )?;
        recovery_image::descriptor(&descriptor)?;
        require(
            descriptor["schema"] == 2,
            "running retirement requires a native image descriptor",
        )?;
        let policy = descriptor["policy_files"].as_object().unwrap();
        let expected = policy
            .keys()
            .cloned()
            .chain(std::iter::once(DESCRIPTOR.into()))
            .collect::<BTreeSet<_>>();
        require(
            names(&directory)? == expected
                && native_policy_files::FILES
                    .iter()
                    .all(|name| policy.contains_key(*name)),
            "complete original native image membership differs",
        )?;
        let mut members = BTreeMap::new();
        let mut total = descriptor_member.file.metadata()?.len();
        members.insert(DESCRIPTOR.into(), descriptor_member);
        for (name, digest) in policy {
            let original = member(
                scope,
                &directory,
                name,
                name.starts_with("enzimos-"),
                MAX_FILE,
            )?;
            total = total
                .checked_add(original.file.metadata()?.len())
                .ok_or_else(|| Error("native image aggregate overflow".into()))?;
            require(
                total <= MAX_TOTAL && digest.as_str() == Some(&original.sha),
                "original native image byte closure differs",
            )?;
            members.insert(name.clone(), original);
        }
        let kernel =
            files::open_beneath(scope.original_proc()?, Path::new("sys/kernel/osrelease"))?;
        let release = files::read_file(&kernel, 4096, Some(0), false)?;
        require(
            std::str::from_utf8(&release).ok().map(str::trim)
                == descriptor["kernel_release"].as_str(),
            "actual running kernel release differs from native image",
        )?;
        let process = process_identity::Retained::open(
            1,
            scope.original_start()?,
            0,
            &[PathBuf::from(root_retirement_boot_contract::INIT)],
        )?
        .pin_executable(&members["enzimos-recovery-run-init"].file)?;
        let result = Self {
            scope,
            epoch: files::identity(&directory.metadata()?),
            mount: mount_identity::id(directory.as_fd(), true)?,
            flags: flags(&directory)?,
            directory,
            image: recovery_image::image_id(&descriptor)?,
            descriptor,
            members,
            kernel_epoch: files::identity(&kernel.metadata()?),
            kernel_mount: mount_identity::id(kernel.as_fd(), true)?,
            kernel_flags: flags(&kernel)?,
            kernel,
            release,
            process,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.scope.require_ram_member(&self.directory)?;
        self.process.recheck()?;
        let named = files::directory(Path::new(DIRECTORY), Some(0))?;
        require(
            files::identity(&self.directory.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && flags(&self.directory)? == self.flags
                && names(&self.directory)? == self.members.keys().cloned().collect(),
            "original native image directory changed or covered",
        )?;
        for (name, original) in &self.members {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&original.file.metadata()?) == original.epoch
                    && files::identity(&named.metadata()?) == original.epoch
                    && flags(&original.file)? == original.flags
                    && mount_identity::id(original.file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && stream_copy::hash_borrowed(&original.file, MAX_FILE, Some(0))?.1
                        == original.sha,
                "original native image member replaced, edited or covered",
            )?;
        }
        let kernel = files::open_beneath(
            self.scope.original_proc()?,
            Path::new("sys/kernel/osrelease"),
        )?;
        require(
            files::identity(&self.kernel.metadata()?) == self.kernel_epoch
                && files::identity(&kernel.metadata()?) == self.kernel_epoch
                && mount_identity::id(self.kernel.as_fd(), true)? == self.kernel_mount
                && mount_identity::id(kernel.as_fd(), true)? == self.kernel_mount
                && flags(&self.kernel)? == self.kernel_flags
                && files::read_file(&self.kernel, 4096, Some(0), false)? == self.release
                && files::read_file(&kernel, 4096, Some(0), false)? == self.release,
            "original running kernel release changed",
        )?;
        self.scope.recheck()
    }
    pub fn matches_record(&self, record: &Value) -> Result<()> {
        self.recheck()?;
        crate::root_retirement_record::validate(record, records::text(record, "id")?)?;
        require(
            record["coordinator"]["image"] == self.image,
            "retirement record differs from actual running native image",
        )?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"image":self.image,"kernel_release":self.descriptor["kernel_release"],"original_native_policy_bytes_verified":true,"actual_pid1_image_verified":true,"execution_authorized":false,"published_artifacts_verified":false}),
        )
    }
}
