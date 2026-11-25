// SPDX-License-Identifier: MIT
//! Installed owner authority keeps original credential inodes and firmware state.
use crate::{
    operation,
    secure_boot::{self, Material},
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) struct Owner {
    enabled: bool,
    firmware: Value,
    control: File,
    control_shape: Value,
    directory: Option<(File, Value)>,
    files: Vec<(&'static str, File, files::FileIdentity)>,
    database: Option<String>,
    material: Option<Material>,
}
fn shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "installed owner authority requires a private Root directory",
    )?;
    Ok(
        value!({"inode":[m.dev(),m.ino(),m.mode(),m.uid(),m.gid()],"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
fn database() -> Result<Option<String>> {
    if secure_boot::firmware()?["uefi"] == false {
        return Ok(None);
    }
    Ok(files::read_optional(
        &Path::new(secure_boot::EFI).join(secure_boot::DB),
        1024 * 1024,
        Some(0),
        false,
    )?
    .map(|body| json::sha256(&body)))
}
impl Owner {
    pub(crate) fn observe() -> Result<Self> {
        Self::observe_inner(false)
    }
    /// Explicit signing also uses staged credentials before owner-UKI policy
    /// activation, retaining the same inodes rather than rereading a new key.
    pub(crate) fn credentials() -> Result<Self> {
        Self::observe_inner(true)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (getrlimit, prctl).")]
    fn observe_inner(required: bool) -> Result<Self> {
        operation::root_only()?;
        let enabled = secure_boot::configured()?;
        let firmware = secure_boot::firmware()?;
        let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
        let control_shape = shape(&control)?;
        let mut this = Self {
            enabled,
            firmware,
            control,
            control_shape,
            directory: None,
            files: Vec::new(),
            database: None,
            material: None,
        };
        if enabled || required {
            // SAFETY: `libc::rlimit` is a plain C struct, for which all-zero bytes are a valid
            // value.
            let mut limits: libc::rlimit = unsafe { std::mem::zeroed() };
            require(
                unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0
                    && unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) } == 0
                    && limits.rlim_cur == 0
                    && limits.rlim_max == 0,
                "owner credentials require disabled dumps before reading",
            )?;
            let directory = files::directory(Path::new(secure_boot::DIRECTORY), Some(0))?;
            let directory_shape = shape(&directory)?;
            require(
                directory_shape["mount"] == this.control_shape["mount"],
                "owner credential directory cannot cross another mount",
            )?;
            let names = if enabled {
                &["owner.key", "owner.crt", "owner.cer", "config.json"][..]
            } else {
                &["owner.key", "owner.crt", "owner.cer"][..]
            };
            for &name in names {
                let file = files::open_relative(&directory, Path::new(name))?;
                let m = file.metadata()?;
                require(
                    m.is_file()
                        && m.uid() == 0
                        && m.gid() == 0
                        && m.nlink() == 1
                        && m.len() > 0
                        && m.len() <= 16384
                        && if name == "owner.key" {
                            m.mode() & 0o7777 == 0o600
                        } else {
                            matches!(m.mode() & 0o7777, 0o600 | 0o644)
                        }
                        && mount_identity::id(file.as_fd(), true)?
                            == enzimos_platform::json::unsigned(&directory_shape["mount"])?,
                    "original installed owner credential protection, size or mount differs",
                )?;
                this.files.push((name, file, files::identity(&m)));
            }
            this.database = database()?;
            this.material = Some(secure_boot::credentials_at(Path::new(
                secure_boot::DIRECTORY,
            ))?);
            this.directory = Some((directory, directory_shape));
        }
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.recheck_credentials()?;
        if self.directory.is_some() {
            require(
                database()? == self.database,
                "original enrolled firmware database changed",
            )?;
        }
        Ok(())
    }
    fn recheck_credentials(&self) -> Result<()> {
        require(
            secure_boot::configured()? == self.enabled,
            "original owner policy changed",
        )?;
        self.recheck_material()
    }
    fn recheck_material(&self) -> Result<()> {
        require(
            secure_boot::firmware()? == self.firmware
                && shape(&self.control)? == self.control_shape
                && shape(&files::directory(Path::new(operation::CONTROL), Some(0))?)?
                    == self.control_shape,
            "original owner policy, control mount or firmware flags changed",
        )?;
        if let Some((held, expected)) = &self.directory {
            require(
                shape(held)? == *expected
                    && shape(&files::directory(
                        Path::new(secure_boot::DIRECTORY),
                        Some(0),
                    )?)? == *expected,
                "original installed owner directory replaced or remounted",
            )?;
            for (name, file, identity) in &self.files {
                let named = files::open_relative(held, Path::new(name))?;
                require(
                    files::identity(&file.metadata()?) == *identity
                        && files::identity(&named.metadata()?) == *identity
                        && mount_identity::id(file.as_fd(), true)?
                            == enzimos_platform::json::unsigned(&expected["mount"])?
                        && mount_identity::id(named.as_fd(), true)?
                            == enzimos_platform::json::unsigned(&expected["mount"])?,
                    "original installed owner credential inode replaced or changed",
                )?;
            }
        }
        Ok(())
    }
    pub(crate) fn accept_configuration(
        &mut self,
        created: &enzimos_platform::publication::Committed,
    ) -> Result<()> {
        if self.enabled {
            self.recheck()?;
            let directory = &self
                .directory
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                .0;
            created.require_destination(directory, Path::new("config.json"))?;
            let original = self
                .files
                .iter()
                .find(|(name, _, _)| *name == "config.json")
                .ok_or_else(|| {
                    enzimos_platform::Error("original configured owner member missing".into())
                })?;
            require(
                files::identity(&created.file()?.metadata()?) == original.2,
                "owner policy callback differs from actual accepted publication",
            )?;
            return created.recheck();
        }
        require(
            !self.enabled && self.material.is_some(),
            "owner policy transition cannot replay",
        )?;
        self.recheck_material()?;
        require(
            database()? == self.database,
            "original firmware database changed during policy transition",
        )?;
        let directory = &self
            .directory
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .0;
        created.require_destination(directory, Path::new("config.json"))?;
        let file = created.file()?.try_clone()?;
        require(
            json::decode(&files::read_file(&file, 4096, Some(0), true)?, 4096)?
                == value!({"schema":1,"mode":"owner-uki"})
                && secure_boot::configured()?,
            "actual owner policy publication differs",
        )?;
        self.files.push((
            "config.json",
            file.try_clone()?,
            files::identity(&file.metadata()?),
        ));
        self.enabled = true;
        self.recheck()
    }
    pub(crate) fn certificate_hash(&self) -> Option<String> {
        self.material.as_ref().map(|m| json::sha256(&m.pem))
    }
    pub(crate) fn material(&self) -> Option<&Material> {
        self.material.as_ref()
    }
    pub(crate) fn identity(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"control":self.control_shape,"directory":self.directory.as_ref().map(|(_,shape)|shape),
            "files":self.files.iter().map(|(name,_,identity)|((*name).to_owned(),identity)).collect::<std::collections::BTreeMap<_,_>>(),
            "certificate_sha256":self.certificate_hash(),"database_sha256":self.database,"firmware":self.firmware,"configured":self.enabled}),
        )
    }
}

#[path = "secure_boot_enrollment.rs"]
pub mod enrollment;
