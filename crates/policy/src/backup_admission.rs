// SPDX-License-Identifier: MIT
//! Opt-in is checked before source entry; existing repositories require their original pin.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
#[path = "backup_ram_pin.rs"]
pub(crate) mod ram;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "private backup control directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) struct Document {
    path: PathBuf,
    parent: File,
    shape: Shape,
    mount: u64,
    owner: u32,
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
}
impl Document {
    pub(crate) fn matches(&self, file: &File) -> Result<()> {
        self.recheck()?;
        require(
            files::identity(&file.metadata()?) == self.identity
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "backup document differs from original publication descriptor",
        )
    }
    /// Revoke only the original opt-in. Keep its bytes in a protected, one-use
    /// retirement name so no unknown or replaced inode is ever unlinked here.
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub(crate) fn retire_schedule(mut self, id: &str) -> Result<Self> {
        use std::os::fd::AsRawFd;
        crate::namespaces::initial()?;
        crate::operation::root_only()?;
        require(
            self.owner == 0
                && self.path == Path::new(crate::operation::CONTROL).join("backup.enabled")
                && id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "fixed original schedule retirement required",
        )?;
        self.recheck()?;
        let source = std::ffi::CString::new("backup.enabled")
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        let retired = format!(".backup-enabled-revoked-{id}");
        let destination = std::ffi::CString::new(retired.as_str())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            // SAFETY: Both names are NUL-terminated and the parent descriptor stays open.
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    source.as_ptr(),
                    self.parent.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "schedule retirement collision or failure; no automatic replay",
        )?;
        // rename changes this inode's ctime. No other field may advance, and
        // the original description remains retained across this known change.
        let after = files::identity(&self.file.metadata()?);
        retired_epoch(&self.identity, &after)?;
        self.path = Path::new(crate::operation::CONTROL).join(retired);
        self.identity = after;
        self.parent.sync_all()?;
        self.recheck()?;
        require(
            files::optional_relative(&self.parent, Path::new("backup.enabled"))?.is_none(),
            "schedule opt-in reappeared during original retirement",
        )?;
        Ok(self)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub(crate) fn retire_repository(mut self, id: &str) -> Result<Self> {
        use std::os::fd::AsRawFd;
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.recheck()?;
        require(
            self.owner == 0
                && self.path
                    == Path::new(crate::operation::CONTROL).join("backup-destination.json")
                && id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "fixed original repository pin retirement required",
        )?;
        let retired = format!(".backup-destination-retired-{id}");
        let source = std::ffi::CString::new("backup-destination.json")
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        let destination = std::ffi::CString::new(retired.as_str())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            // SAFETY: Both names are NUL-terminated and the parent descriptor stays open.
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    source.as_ptr(),
                    self.parent.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "original repository pin retirement collision/failure; no replay",
        )?;
        let after = files::identity(&self.file.metadata()?);
        retired_epoch(&self.identity, &after)?;
        self.identity = after;
        self.path = Path::new(crate::operation::CONTROL).join(retired);
        self.parent.sync_all()?;
        self.recheck()?;
        require(
            files::optional_relative(&self.parent, Path::new("backup-destination.json"))?.is_none(),
            "active repository pin reappeared during retirement",
        )?;
        Ok(self)
    }
    pub(crate) fn optional(path: &Path, owner: u32) -> Result<Option<Self>> {
        let parent = files::directory(
            path.parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(owner),
        )?;
        let parent_shape = shape(&parent, owner)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let Some(file) = files::optional_relative(
            &parent,
            Path::new(
                path.file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?
        else {
            return Ok(None);
        };
        let m = file.metadata()?;
        require(
            m.uid() == owner
                && m.gid() == parent.metadata()?.gid()
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && mount_identity::id(file.as_fd(), true)? == mount,
            "private original backup binding required",
        )?;
        let this = Self {
            path: path.into(),
            parent,
            shape: parent_shape,
            mount,
            owner,
            identity: files::identity(&m),
            bytes: files::read_file(&file, crate::backup_configuration::LIMIT, Some(owner), true)?,
            file,
        };
        this.recheck()?;
        Ok(Some(this))
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let parent = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(self.owner),
        )?;
        let named = files::open_relative(
            &self.parent,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        require(
            shape(&parent, self.owner)? == self.shape
                && shape(&self.parent, self.owner)? == self.shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::read_file(
                    &self.file,
                    crate::backup_configuration::LIMIT,
                    Some(self.owner),
                    true,
                )? == self.bytes,
            "original backup binding changed or replaced",
        )
    }
    pub(crate) fn bytes(&self) -> Result<&[u8]> {
        self.recheck()?;
        Ok(&self.bytes)
    }
    pub(crate) fn mount(&self) -> u64 {
        self.mount
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"path":self.path,"inode":self.identity,"mount":self.mount,"sha256":json::sha256(&self.bytes)}),
        )
    }
    fn duplicate(&self) -> Result<Self> {
        self.recheck()?;
        let this = Self {
            path: self.path.clone(),
            parent: self.parent.try_clone()?,
            shape: self.shape,
            mount: self.mount,
            owner: self.owner,
            file: self.file.try_clone()?,
            identity: self.identity,
            bytes: self.bytes.clone(),
        };
        this.recheck()?;
        Ok(this)
    }
}
fn retired_epoch(before: &files::FileIdentity, after: &files::FileIdentity) -> Result<()> {
    require(
        (
            before.0, before.1, before.2, before.3, before.4, before.7, before.8, before.9,
            before.10,
        ) == (
            after.0, after.1, after.2, after.3, after.4, after.7, after.8, after.9, after.10,
        ) && (after.5, after.6) >= (before.5, before.6),
        "original opt-in changed outside known retirement rename",
    )
}
pub struct Repository<'a, 'g> {
    destination: &'a crate::backup_destination::Destination<'g>,
    document: Document,
}
impl<'a, 'g> Repository<'a, 'g> {
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.document.file)
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        self.document.evidence()
    }
    pub fn open(destination: &'a crate::backup_destination::Destination<'g>) -> Result<Self> {
        destination.recheck()?;
        let document = Document::optional(
            &Path::new(crate::operation::CONTROL).join("backup-destination.json"),
            0,
        )?
        .ok_or_else(|| {
            enzimos_platform::Error("existing backup repository must be explicitly bound".into())
        })?;
        require(
            document.mount == destination.storage().control_mount_id()
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
    pub fn recheck(&self) -> Result<()> {
        self.destination.recheck()?;
        self.document.recheck()
    }
    pub fn public_bytes(&self) -> Result<&[u8]> {
        self.recheck()?;
        Ok(&self.document.bytes)
    }
    pub(crate) fn storage(&self) -> &crate::storage_runtime::Guard {
        self.destination.storage()
    }
}
/// Read-only public repository binding. This retains only the existing control
/// document; it neither opens a repository nor grants mount/capture authority.
pub struct StoredPin<'a> {
    configuration: &'a crate::backup_configuration::Configuration,
    storage: &'a crate::storage_runtime::Guard,
    document: Document,
}
impl<'a> StoredPin<'a> {
    pub fn open(
        configuration: &'a crate::backup_configuration::Configuration,
        storage: &'a crate::storage_runtime::Guard,
    ) -> Result<Self> {
        configuration.recheck()?;
        storage.recheck()?;
        let document = Document::optional(
            &Path::new(crate::operation::CONTROL).join("backup-destination.json"),
            0,
        )?
        .ok_or_else(|| enzimos_platform::Error("existing backup destination pin missing".into()))?;
        let value = crate::backup_binding::pin(document.bytes()?)?;
        require(
            document.mount() == storage.control_mount_id()
                && value["filesystem_uuid"] == configuration.value()["destination_uuid"]
                && value["filesystem_uuid"] != storage.configuration["filesystem_uuid"],
            "stored backup pin differs from configuration or original control mount",
        )?;
        let this = Self {
            configuration,
            storage,
            document,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.configuration.recheck()?;
        self.storage.recheck()?;
        self.document.recheck()
    }
    pub fn public_bytes(&self) -> Result<&[u8]> {
        self.recheck()?;
        self.document.bytes()
    }
    /// Same control-document evidence as `Repository::evidence`.
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        self.document.evidence()
    }
    pub(crate) fn storage(&self) -> &crate::storage_runtime::Guard {
        self.storage
    }
}
pub struct OptIn {
    document: Document,
}
fn validate_marker(bytes: &[u8]) -> Result<()> {
    let v = json::decode(bytes, crate::backup_configuration::LIMIT)?;
    json::fields(
        &v,
        if v.get("destination").is_some() {
            "schema destination configuration_sha256 destination_pin_sha256 schedule opt_in"
        } else {
            "schema configuration_sha256 destination_pin_sha256 schedule opt_in"
        },
    )?;
    require(
        v.get("destination").is_none_or(|d| d == "share"),
        "closed backup schedule destination",
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["schedule"] == crate::backup_binding::SCHEDULE
            && v["opt_in"] == true,
        "explicit backup schedule opt-in required",
    )?;
    for key in ["configuration_sha256", "destination_pin_sha256"] {
        crate::identity::sha(
            v[key]
                .as_str()
                .ok_or_else(|| enzimos_platform::Error("backup schedule digest required".into()))?,
        )?;
    }
    Ok(())
}
impl OptIn {
    /// None means disabled and must return before configuration/source discovery.
    pub fn open() -> Result<Option<Self>> {
        crate::namespaces::initial()?;
        Self::retained(
            &Path::new(crate::operation::CONTROL).join("backup.enabled"),
            0,
        )
    }
    fn retained(path: &Path, owner: u32) -> Result<Option<Self>> {
        let Some(document) = Document::optional(path, owner)? else {
            return Ok(None);
        };
        validate_marker(&document.bytes)?;
        Ok(Some(Self { document }))
    }
    pub fn recheck(&self) -> Result<()> {
        self.document.recheck()
    }
    pub fn verify(
        &self,
        configuration: &crate::backup_configuration::Configuration,
        repository: &Repository<'_, '_>,
    ) -> Result<()> {
        self.recheck()?;
        require(
            self.document.mount == repository.document.mount
                && self.document.shape == repository.document.shape,
            "backup opt-in belongs to a different control directory",
        )?;
        crate::backup_binding::verify_schedule(
            &self.document.bytes,
            configuration.public_bytes()?,
            repository.public_bytes()?,
        )?;
        self.recheck()
    }
    /// Report the bound opt-in even while the destination is absent. This is a
    /// status check and cannot authorize repository traversal or backup capture.
    pub fn verify_stored(
        &self,
        configuration: &crate::backup_configuration::Configuration,
        pin: &StoredPin<'_>,
    ) -> Result<()> {
        self.recheck()?;
        pin.recheck()?;
        require(
            self.document.mount == pin.document.mount && self.document.shape == pin.document.shape,
            "backup schedule belongs to another original control directory",
        )?;
        crate::backup_binding::verify_schedule(
            self.document.bytes()?,
            configuration.public_bytes()?,
            pin.public_bytes()?,
        )?;
        self.recheck()?;
        pin.recheck()
    }
    /// Whether this opt-in is bound to the NAS share (a setup without a
    /// backup drive) rather than to a drive.
    ///
    /// # Errors
    /// The opt-in document changed.
    pub fn share(&self) -> Result<bool> {
        self.recheck()?;
        Ok(
            json::decode(self.document.bytes()?, crate::backup_configuration::LIMIT)?
                .get("destination")
                .is_some(),
        )
    }
    /// Verify the opt-in against the NAS share configuration bytes and the
    /// share repository pin of a setup without a backup drive.
    ///
    /// # Errors
    /// A drive opt-in, or a binding that no longer matches.
    pub fn verify_share(&self, configuration: &[u8], pin: &Value) -> Result<()> {
        self.recheck()?;
        crate::backup_binding::verify_schedule_share(self.document.bytes()?, configuration, pin)?;
        self.recheck()
    }
    /// Caller must separately verify fresh recovery-copy confirmation before
    /// capture. A schedule document alone never grants recovery or source authority.
    pub fn admit<F: FnOnce(&Self) -> Result<Value>>(body: F) -> Result<Value> {
        match Self::open()? {
            None => Ok(serde_json::json!({"status":"disabled-no-source-scan"})),
            Some(marker) => {
                marker.recheck()?;
                body(&marker)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn a_share_opt_in_names_its_destination_and_nothing_else() {
        let configuration = br#"{"folder":"enzimos/laptop","schema":2,"server":"192.0.2.4","share":"backups","user":"ann"}"#;
        let pin = serde_json::json!({"schema":2,"repository_id":"c".repeat(64),
            "configuration_sha256":json::sha256(configuration)});
        let marker = crate::backup_binding::schedule_share(configuration, &pin).unwrap();
        validate_marker(&json::canonical(&marker).unwrap()).unwrap();
        crate::backup_binding::verify_schedule_share(
            &json::canonical(&marker).unwrap(),
            configuration,
            &pin,
        )
        .unwrap();
        let mut other = pin.clone();
        other["repository_id"] = serde_json::json!("d".repeat(64));
        assert!(
            crate::backup_binding::verify_schedule_share(
                &json::canonical(&marker).unwrap(),
                configuration,
                &other,
            )
            .is_err()
        );
        let mut stale = pin;
        stale["configuration_sha256"] = serde_json::json!("e".repeat(64));
        assert!(crate::backup_binding::schedule_share(configuration, &stale).is_err());
        for destination in ["drive", "cloud"] {
            let mut foreign = marker.clone();
            foreign["destination"] = serde_json::json!(destination);
            assert!(validate_marker(&json::canonical(&foreign).unwrap()).is_err());
        }
    }
    fn fixture() -> tempfile::TempDir {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap()
    }
    #[test]
    fn actual_opt_in_refuses_dangling_links_and_same_bytes_replacement() {
        let dir = fixture();
        let path = dir.path().join("backup.enabled");
        let owner = enzimos_platform::process_identity::real_uid();
        assert!(OptIn::retained(&path, owner).unwrap().is_none());
        symlink("absent", &path).unwrap();
        assert!(OptIn::retained(&path, owner).is_err());
        std::fs::remove_file(&path).unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({"schema":1,"configuration_sha256":"a".repeat(64),"destination_pin_sha256":"b".repeat(64),"schedule":crate::backup_binding::SCHEDULE,"opt_in":true})).unwrap();
        files::atomic(&path, &bytes, 0o600, Some(owner), false).unwrap();
        let marker = OptIn::retained(&path, owner).unwrap().unwrap();
        files::atomic(
            &dir.path().join("replacement"),
            &bytes,
            0o600,
            Some(owner),
            false,
        )
        .unwrap();
        std::fs::rename(dir.path().join("replacement"), &path).unwrap();
        assert!(marker.recheck().is_err());
    }
}
