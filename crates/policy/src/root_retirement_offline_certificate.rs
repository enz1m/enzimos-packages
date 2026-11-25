// SPDX-License-Identifier: MIT
//! Original public owner certificate/policy for offline UKI verification.
//! The private signing key is never opened, read, retained or measured here.
use crate::{control_record::Retained, root_retirement_offline_control::Control};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use openssl::x509::X509;
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "secure-boot";
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original public certificate read-only description required",
    )?;
    Ok(flags)
}
fn directory(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let metadata = file.metadata()?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o700
            && mount_identity::id(file.as_fd(), true)? == mount,
        "actual original Root-private owner certificate directory required",
    )?;
    Ok(files::identity(&metadata))
}
fn names(file: &File) -> Result<BTreeSet<String>> {
    files::directory_names(file, 4)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| Error("owner certificate member encoding".into()))?;
            require(
                ["owner.key", "owner.crt", "owner.cer", "config.json"].contains(&name.as_str()),
                "unknown or interrupted owner public policy member",
            )?;
            Ok(name)
        })
        .collect()
}
struct PublicFile {
    name: &'static str,
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    bytes: Vec<u8>,
}
impl PublicFile {
    fn observe(folder: &File, name: &'static str, mount: u64) -> Result<Self> {
        require(
            matches!(name, "owner.crt" | "owner.cer"),
            "only public certificate formats may be read",
        )?;
        let file = files::open_relative(folder, Path::new(name))?;
        let metadata = file.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.nlink() == 1
                && metadata.len() > 0
                && metadata.len() <= 16384
                && matches!(metadata.mode() & 0o7777, 0o600 | 0o644)
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original public owner certificate protection, size or mount differs",
        )?;
        let bytes = files::read_file(&file, 16384, Some(0), true)?;
        let result = Self {
            name,
            epoch: files::identity(&metadata),
            flags: flags(&file)?,
            file,
            bytes,
        };
        result.recheck(folder, mount)?;
        Ok(result)
    }
    fn recheck(&self, folder: &File, mount: u64) -> Result<()> {
        let named = files::open_relative(folder, Path::new(self.name))?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == mount
                && mount_identity::id(named.as_fd(), true)? == mount
                && flags(&self.file)? == self.flags
                && files::read_file(&self.file, 16384, Some(0), true)? == self.bytes
                && files::identity(&self.file.metadata()?) == self.epoch,
            "original public owner certificate changed, replaced or covered",
        )
    }
}
fn pair(pem: &[u8], der: &[u8]) -> Result<()> {
    let certificate = X509::from_pem(pem)
        .map_err(|_| Error("original public owner PEM certificate invalid".into()))?;
    require(
        certificate
            .to_der()
            .map_err(|_| Error("original public owner DER certificate invalid".into()))?
            == der,
        "original public PEM/DER certificates differ",
    )
}
pub struct Certificate<'a, 's> {
    control: &'a Control<'a, 's>,
    parent: File,
    parent_epoch: files::FileIdentity,
    parent_flags: i32,
    mount: u64,
    folder: Option<File>,
    epoch: Option<files::FileIdentity>,
    flags: Option<i32>,
    members: BTreeSet<String>,
    policy: Option<Retained>,
    policy_flags: Option<i32>,
    public: Vec<PublicFile>,
}
impl<'a, 's> Certificate<'a, 's> {
    pub fn observe(control: &'a Control<'a, 's>) -> Result<Self> {
        control.recheck()?;
        let mount = control.mount_id()?;
        let folder =
            files::optional_directory_relative(control.descriptor()?, Path::new(FOLDER), Some(0))?;
        let parent = control.descriptor()?.try_clone()?;
        let mut result = Self {
            control,
            parent_epoch: files::identity(&parent.metadata()?),
            parent_flags: flags(&parent)?,
            parent,
            mount,
            folder,
            epoch: None,
            flags: None,
            members: BTreeSet::new(),
            policy: None,
            policy_flags: None,
            public: Vec::new(),
        };
        if let Some(folder) = &result.folder {
            result.epoch = Some(directory(folder, mount)?);
            result.flags = Some(flags(folder)?);
            result.members = names(folder)?;
            let policy = Retained::optional_open(folder, Path::new("config.json"), 4096, mount)?;
            if let Some(policy) = &policy {
                require(
                    policy.value()? == &value!({"schema":1,"mode":"owner-uki"}),
                    "unsupported original public owner policy",
                )?;
                result.policy_flags = Some(flags(policy.checkpoint_descriptor()?)?);
                for name in ["owner.crt", "owner.cer"] {
                    result
                        .public
                        .push(PublicFile::observe(folder, name, mount)?);
                }
                pair(&result.public[0].bytes, &result.public[1].bytes)?;
            }
            result.policy = policy;
        }
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_original_control(&self, control: &Control<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.control, control),
            "original public certificate belongs to another control actor",
        )?;
        self.recheck()
    }
    pub(crate) fn public_pem(&self) -> Result<&[u8]> {
        self.recheck()?;
        require(
            self.policy.is_some() && self.public.len() == 2,
            "configured original owner public certificate unavailable",
        )?;
        Ok(&self.public[0].bytes)
    }
    pub(crate) fn configured(&self) -> Result<bool> {
        self.recheck()?;
        Ok(self.policy.is_some())
    }
    pub fn recheck(&self) -> Result<()> {
        self.control.recheck()?;
        self.recheck_public_descriptions()?;
        self.control.recheck()
    }
    /// Readonly checkpoint while an exact owned verifier child is alive. The
    /// full no-other-userspace Scope is checked before spawn and after reaping.
    pub(crate) fn recheck_public_descriptions(&self) -> Result<()> {
        let mount = self.mount;
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch
                && flags(&self.parent)? == self.parent_flags
                && mount_identity::id(self.parent.as_fd(), true)? == mount,
            "original public certificate parent description changed",
        )?;
        let named = files::optional_directory_relative(&self.parent, Path::new(FOLDER), Some(0))?;
        match (&self.folder, named) {
            (None, None) => require(
                self.policy.is_none() && self.public.is_empty() && self.members.is_empty(),
                "missing owner policy acquired authority",
            )?,
            (Some(held), Some(named)) => {
                require(
                    Some(directory(held, mount)?) == self.epoch
                        && Some(directory(&named, mount)?) == self.epoch
                        && Some(flags(held)?) == self.flags
                        && names(held)? == self.members
                        && names(&named)? == self.members,
                    "original public owner directory or membership changed",
                )?;
                if let Some(policy) = &self.policy {
                    policy.recheck()?;
                    require(
                        Some(flags(policy.checkpoint_descriptor()?)?) == self.policy_flags
                            && policy.value()? == &value!({"schema":1,"mode":"owner-uki"}),
                        "original public owner policy changed",
                    )?;
                    for public in &self.public {
                        public.recheck(held, mount)?;
                    }
                    require(
                        self.public.len() == 2,
                        "incomplete original public owner certificate pair",
                    )?;
                    pair(&self.public[0].bytes, &self.public[1].bytes)?;
                } else {
                    require(
                        !self.members.contains("config.json") && self.public.is_empty(),
                        "unconfigured policy acquired public certificate authority",
                    )?;
                }
            }
            _ => {
                return Err(Error(
                    "original public owner directory appeared/disappeared/replaced".into(),
                ));
            }
        }
        Ok(())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"original_public_owner_policy_retained":true,"configured":self.policy.is_some(),
            "public_certificate_sha256":self.public.first().map(|f| json::sha256(&f.bytes)),"private_key_read":false,"execution_authorized":false}),
        )
    }
}
