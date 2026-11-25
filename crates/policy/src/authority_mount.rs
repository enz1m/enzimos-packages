// SPDX-License-Identifier: MIT
//! Read-only mount of the package authority subvolume, retained by its mount and subvolume identity.
use crate::{authority, filesystem, storage_runtime, subvolume};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
/// Mount point of the package authority.
pub const PATH: &str = "/etc/pacman.d/gnupg";
/// The read-only package authority mount, retained by its subvolume and mount identity.
pub struct Authority {
    directory: File,
    unique: u64,
    normal: u64,
    root: String,
    filesystem: Value,
    subvolume: (Value, bool),
    inode: (u64, u64, u32, u32, u32),
}
impl Authority {
    /// Observe the authority subvolume mounted at [`PATH`] on `guard`'s filesystem.
    ///
    /// # Errors
    ///
    /// Fails when the authority is not a private, independent mount of the configured subvolume.
    pub fn observe(guard: &storage_runtime::Guard) -> Result<Self> {
        guard.recheck()?;
        let directory = files::directory(Path::new(PATH), Some(0))?;
        let m = directory.metadata()?;
        require(
            m.uid() == 0 && m.mode() & 0o7777 == 0o700,
            "private independent package authority required",
        )?;
        let root = format!(
            "/{}",
            guard.configuration["authority_subvol"]
                .as_str()
                .ok_or_else(|| Error("authority subvolume missing".into()))?
        );
        let filesystem = filesystem::observe(directory.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "package authority filesystem mismatch",
        )?;
        let this = Self {
            unique: mount_identity::id(directory.as_fd(), true)?,
            normal: mount_identity::id(directory.as_fd(), false)?,
            subvolume: subvolume::observe(
                directory.as_fd(),
                root.strip_prefix('/')
                    .ok_or_else(|| Error("absolute package authority root required".into()))?,
            )?,
            inode: (m.dev(), m.ino(), m.uid(), m.gid(), m.mode()),
            directory,
            root,
            filesystem,
        };
        require(!this.subvolume.1, "package authority is read-only")?;
        this.recheck(guard)?;
        Ok(this)
    }
    /// Verify the mount and subvolume are unchanged and no alternate keybox exists.
    ///
    /// # Errors
    ///
    /// Fails when the mount changed or a keybox file appeared.
    pub fn recheck(&self, guard: &storage_runtime::Guard) -> Result<()> {
        guard.recheck()?;
        let named = files::directory(Path::new(PATH), Some(0))?;
        for file in [&named, &self.directory] {
            let m = file.metadata()?;
            require(
                (m.dev(), m.ino(), m.uid(), m.gid(), m.mode()) == self.inode
                    && mount_identity::id(file.as_fd(), true)? == self.unique
                    && filesystem::observe(file.as_fd())? == self.filesystem
                    && subvolume::observe(
                        file.as_fd(),
                        self.root.strip_prefix('/').unwrap_or_default(),
                    )? == self.subvolume,
                "package authority mount or subvolume changed",
            )?;
        }
        storage_runtime::mount_row(
            &storage_runtime::rows()?,
            PATH,
            Some(&self.root),
            self.normal,
        )?;
        // GPG must not prefer an unmeasured keybox over the legacy public ring.
        match std::fs::symlink_metadata(Path::new(PATH).join("pubring.kbx")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => {
                return Err(Error(
                    "alternate package authority keybox requires review".into(),
                ));
            }
        }
        Ok(())
    }
    /// The authority files by name.
    ///
    /// # Errors
    ///
    /// Fails when a file is missing or unsafe.
    pub fn files(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut result = BTreeMap::new();
        for name in authority::FILES {
            let file = files::open_relative(&self.directory, Path::new(name))?;
            require(
                mount_identity::id(file.as_fd(), true)? == self.unique,
                "independently mounted package authority file",
            )?;
            result.insert(
                name.into(),
                files::read_file(&file, 8 * 1024 * 1024, Some(0), true)?,
            );
        }
        Ok(result)
    }
    /// SHA-256 of each authority file.
    ///
    /// # Errors
    ///
    /// As [`Authority::files`].
    pub fn hashes(&self) -> Result<Value> {
        Ok(value!(
            self.files()?
                .iter()
                .map(|(name, body)| (name.clone(), json::sha256(body)))
                .collect::<BTreeMap<_, _>>()
        ))
    }
    /// JSON identity of the authority mount.
    pub fn identity(&self) -> Value {
        value!({"filesystem_uuid":self.filesystem["filesystem_uuid"],"subvolume":self.subvolume.0,"mount":self.unique,"inode":self.inode})
    }
}
