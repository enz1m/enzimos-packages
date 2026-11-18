// SPDX-License-Identifier: MIT
//! Actual original Root remote inputs: the public share configuration, the
//! repository password and the share password. Credential bytes are never
//! read or hashed here; only the remote worker's mount child uses the share
//! password.
use crate::{backup_remote_endpoint as endpoint, storage_runtime::Guard};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const NAMES: [&str; 3] = [
    "backup-remote.json",
    "backup-remote.password",
    "backup-remote.share-password",
];
type Shape = (u64, u64, u32, u32, u32);
fn shape(parent: &File) -> Result<Shape> {
    let m = parent.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected remote input parent required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub struct Inputs {
    parent: File,
    shape: Shape,
    mount: u64,
    source: Value,
    files: [File; 3],
    epochs: [files::FileIdentity; 3],
    flags: [i32; 3],
    configuration: Value,
    configuration_bytes: Vec<u8>,
    binding: Value,
}
impl Inputs {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub fn observe(guard: &Guard) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let source = guard.backup_root_binding()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.root_mount_id(),
            "remote input parent outside configured live root",
        )?;
        // The public configuration first: an SFTP setup from before SMB is
        // refused with its own status, not as a missing share password.
        let public = files::open_relative(&parent, Path::new(NAMES[0]))?;
        let configuration_bytes = files::read_file(&public, 32768, Some(0), true)?;
        let configuration = json::decode(&configuration_bytes, 32768)?;
        endpoint::validate(&configuration)?;
        let files = [
            public,
            files::open_relative(&parent, Path::new(NAMES[1]))?,
            files::open_relative(&parent, Path::new(NAMES[2]))?,
        ];
        let mut objects = std::collections::BTreeSet::new();
        for (i, file) in files.iter().enumerate() {
            let m = file.metadata()?;
            require(
                m.is_file()
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o022 == 0
                    && (i == 0 || m.mode() & 0o077 == 0)
                    && m.len() > 0
                    && m.len() <= if i == 0 { 32768 } else { 4096 }
                    && m.dev() == guard.root_device()
                    && mount_identity::id(file.as_fd(), true)? == mount
                    && objects.insert((m.dev(), m.ino())),
                "protected distinct remote input objects required",
            )?;
        }
        let epochs = [
            files::identity(&files[0].metadata()?),
            files::identity(&files[1].metadata()?),
            files::identity(&files[2].metadata()?),
        ];
        let nanos = |seconds: i64, ns: i64| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(ns))
                .ok_or_else(|| {
                    enzimos_platform::Error("remote credential timestamp overflow".into())
                })
        };
        let mut credentials = serde_json::Map::new();
        for i in [1, 2] {
            let e = epochs[i];
            credentials.insert(
                format!("/etc/enzimos/{}", NAMES[i]),
                value!([e.0, e.1, e.2, nanos(e.3, e.4)?, nanos(e.5, e.6)?]),
            );
        }
        let binding = value!({"configuration_sha256":json::sha256(&configuration_bytes),"credentials":credentials});
        let mut flags = [0; 3];
        for (i, file) in files.iter().enumerate() {
            flags[i] = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            require(
                flags[i] >= 0
                    && flags[i] & libc::O_ACCMODE == libc::O_RDONLY
                    && flags[i] & libc::O_PATH == 0,
                "original remote read-only descriptors required",
            )?;
        }
        let original = Self {
            shape: shape(&parent)?,
            parent,
            mount,
            source,
            files,
            epochs,
            flags,
            configuration,
            configuration_bytes,
            binding,
        };
        original.recheck(guard)?;
        Ok(original)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub fn recheck(&self, guard: &Guard) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            guard.backup_root_binding()? == self.source
                && shape(&parent)? == self.shape
                && shape(&self.parent)? == self.shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && self.mount == guard.root_mount_id(),
            "original remote parent/source replaced/remounted",
        )?;
        for (i, file) in self.files.iter().enumerate() {
            let named = files::open_relative(&self.parent, Path::new(NAMES[i]))?;
            require(
                files::identity(&file.metadata()?) == self.epochs[i]
                    && files::identity(&named.metadata()?) == self.epochs[i]
                    && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } == self.flags[i]
                    && mount_identity::id(file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount,
                "original remote input replaced/changed; no adoption",
            )?;
        }
        require(
            files::read_file(&self.files[0], 32768, Some(0), true)? == self.configuration_bytes,
            "original public remote configuration changed",
        )
    }
    pub(crate) fn descriptors(&self, guard: &Guard) -> Result<[std::os::fd::BorrowedFd<'_>; 3]> {
        self.recheck(guard)?;
        Ok(self.files.each_ref().map(|file| file.as_fd()))
    }
    pub fn configuration(&self, guard: &Guard) -> Result<&Value> {
        self.recheck(guard)?;
        Ok(&self.configuration)
    }
    pub fn binding(&self, guard: &Guard) -> Result<&Value> {
        self.recheck(guard)?;
        Ok(&self.binding)
    }
    pub fn evidence(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        Ok(
            value!({"configuration":self.configuration,"binding":self.binding,"original_epochs":self.epochs,
            "parent":self.shape,"mount":self.mount,"source":self.source,"credential_bytes_read":false}),
        )
    }
}
