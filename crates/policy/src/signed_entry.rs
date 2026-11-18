// SPDX-License-Identifier: MIT
//! Content-bound owner UKIs. Existing output is verified, never silently rebuilt.
use crate::{
    boot_entries, boot_volume::Volume, identity, operation, secure_artifacts, secure_boot,
};
use enzimos_platform::{Error, Result, files, json, memfile, require};
use serde_json::json as value;
use std::{collections::BTreeMap, os::fd::AsFd, path::Path, time::Duration};
type Fields = BTreeMap<String, String>;
fn field<'a>(fields: &'a Fields, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Error("incomplete signed boot entry".into()))
}
pub fn digest(kernel: &str, initrd: &str, options: &str, certificate: &str) -> Result<String> {
    identity::sha(kernel)?;
    identity::sha(initrd)?;
    identity::sha(certificate)?;
    crate::recovery_records::command_line(options)?;
    require(!options.is_empty(), "empty signed boot command line")?;
    json::fingerprint(
        &value!({"kernel":kernel,"initrd":initrd,"options":options,"certificate":certificate}),
    )
}
pub fn rewrite(text: &str, relative: &str) -> Result<String> {
    secure_boot::source_path(relative)?;
    let fields = boot_entries::fields(text, false)?;
    for key in ["linux", "initrd", "options"] {
        field(&fields, key)?;
    }
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("uki ") {
            continue;
        }
        if trimmed.starts_with("linux ") || trimmed.starts_with("initrd ") {
            lines.push(format!("# enzimos-source-{trimmed}"));
        } else {
            lines.push(line.into());
        }
    }
    lines.push(format!("uki {relative}"));
    let body = format!("{}\n", lines.join("\n"));
    let after = boot_entries::fields(&body, false)?;
    for key in ["linux", "initrd", "options"] {
        require(
            after.get(key) == fields.get(key),
            "signed entry rewrite changed source bindings",
        )?;
    }
    require(
        after.get("uki").map(String::as_str) == Some(relative),
        "signed entry rewrite failed",
    )?;
    Ok(body)
}
struct Binding {
    volume: Volume,
    kernel: crate::boot_volume::Artifact,
    initrd: crate::boot_volume::Artifact,
    owner: crate::secure_owner_source::Owner,
    options: String,
    relative: String,
}
impl Binding {
    fn observe(fields: &Fields) -> Result<Self> {
        let owner = crate::secure_owner_source::Owner::credentials()?;
        let volume = Volume::observe()?;
        let kernel_path = secure_boot::source_path(field(fields, "linux")?)?;
        let initrd_path = secure_boot::source_path(field(fields, "initrd")?)?;
        let kernel = volume.artifact(
            kernel_path
                .strip_prefix("/boot")
                .map_err(|_| Error("signed source outside boot volume".into()))?,
            256 * 1024 * 1024,
        )?;
        let initrd = volume.artifact(
            initrd_path
                .strip_prefix("/boot")
                .map_err(|_| Error("signed source outside boot volume".into()))?,
            256 * 1024 * 1024,
        )?;
        let options = field(fields, "options")?.to_owned();
        let id = digest(
            &kernel.sha,
            &initrd.sha,
            &options,
            &json::sha256(
                &owner
                    .material()
                    .ok_or_else(|| Error("owner credentials absent".into()))?
                    .pem,
            ),
        )?;
        Ok(Self {
            volume,
            kernel,
            initrd,
            owner,
            options,
            relative: format!("/enzimos/secure-boot/{id}.efi"),
        })
    }
    fn recheck(&self) -> Result<()> {
        self.volume.recheck()?;
        self.kernel.recheck()?;
        self.initrd.recheck()?;
        self.owner.recheck()
    }
    fn verify(&self) -> Result<crate::boot_volume::Artifact> {
        self.recheck()?;
        let output = self.volume.artifact(
            Path::new(self.relative.trim_start_matches('/')),
            256 * 1024 * 1024,
        )?;
        let bytes = files::read_file(&output.file, 256 * 1024 * 1024, Some(0), true)?;
        secure_artifacts::verify_payload(
            &bytes,
            &self.kernel.sha,
            &self.initrd.sha,
            &self.options,
        )?;
        let cert = memfile::sealed(
            "enzimos-entry-certificate",
            &self
                .owner
                .material()
                .ok_or_else(|| Error("owner credentials absent".into()))?
                .pem,
        )?;
        let verify =
            crate::settings_command::Command::open_boot(crate::settings_command::BootTool::Verify)?;
        let result = verify.run_fds_authorized(
            &["--cert", "@fd:0", "@fd:1"],
            Duration::from_secs(600),
            16384,
            &[cert.as_fd(), output.file.as_fd()],
            &mut || {
                self.recheck()?;
                output.recheck()
            },
        )?;
        require(result.status.success(), "owner UKI signature refused")?;
        output.recheck()?;
        self.recheck()?;
        Ok(output)
    }
}
/// Retain exactly the signed image and authority that passed verification.
pub struct Verification {
    binding: Binding,
    output: crate::boot_volume::Artifact,
}
impl Verification {
    pub(crate) fn descriptor(&self) -> Result<&std::fs::File> {
        self.recheck()?;
        Ok(&self.output.file)
    }
    pub(crate) fn relative(&self) -> &str {
        &self.binding.relative
    }
    pub fn recheck(&self) -> Result<()> {
        self.binding.recheck()?;
        self.output.recheck()
    }
    /// Original owner and volume remain live while independently retained source
    /// artifacts may cross only their actual owned removal. Keep this verifier
    /// through completion, including after a known empty parent retirement.
    pub(crate) fn recheck_owned_retirements(
        &self,
        retired: &BTreeMap<std::path::PathBuf, crate::boot_volume::RetiredArtifact>,
    ) -> Result<()> {
        self.binding.volume.recheck()?;
        self.binding.owner.recheck()?;
        for artifact in [&self.binding.kernel, &self.binding.initrd, &self.output] {
            match retired.get(&artifact.path) {
                Some(removed) => removed.require_original(artifact)?,
                None => artifact.recheck()?,
            }
        }
        self.binding.owner.recheck()?;
        self.binding.volume.recheck()
    }
}
pub fn retain(fields: &Fields) -> Result<Option<Verification>> {
    if !secure_boot::configured()? {
        require(
            !fields
                .get("uki")
                .is_some_and(|s| s.starts_with("/enzimos/secure-boot/")),
            "signed entry without configured owner authority",
        )?;
        return Ok(None);
    }
    if !fields.contains_key("linux") {
        return Ok(None);
    }
    let binding = Binding::observe(fields)?;
    require(
        fields.get("uki") == Some(&binding.relative),
        "signed boot entry binding mismatch",
    )?;
    let output = binding.verify()?;
    Ok(Some(Verification { binding, output }))
}
pub fn verify(fields: &Fields) -> Result<()> {
    retain(fields).map(|_| ())
}
/// Actual original source/owner verification and optional owned signed output.
/// Text or serialized metadata cannot construct this retained publication proof.
pub struct Wrapped {
    text: String,
    binding: Option<Binding>,
    verified: Option<crate::boot_volume::Artifact>,
    created: Option<secure_artifacts::Uki>,
}
impl Wrapped {
    /// Join an actual signer output to its independently retained namespace.
    /// Returns an observation comparison; authority stays with the live actors.
    pub(crate) fn namespace_output(
        &self,
        parent: &std::fs::File,
        before: files::FileIdentity,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<(String, files::FileIdentity, bool)>> {
        self.recheck(authorize)?;
        let Some(binding) = &self.binding else {
            return Ok(None);
        };
        let leaf = binding
            .relative
            .strip_prefix("/enzimos/secure-boot/")
            .ok_or_else(|| Error("signed entry belongs to another namespace".into()))?;
        crate::identity::sha(
            leaf.strip_suffix(".efi")
                .ok_or_else(|| Error("signed namespace suffix".into()))?,
        )?;
        let output = self.verified.as_ref().unwrap();
        let named = files::open_relative(parent, Path::new(leaf))?;
        require(
            files::identity(&named.metadata()?) == files::identity(&output.file.metadata()?)
                && enzimos_platform::mount_identity::id(parent.as_fd(), true)?
                    == binding.volume.unique
                && enzimos_platform::mount_identity::id(named.as_fd(), true)?
                    == binding.volume.unique,
            "signed output differs from independently retained namespace",
        )?;
        if let Some(created) = &self.created {
            created.require_original_parent(parent, before, leaf, authorize)?;
        }
        self.recheck(authorize)?;
        Ok(Some((
            leaf.into(),
            files::identity(&output.file.metadata()?),
            self.created.is_some(),
        )))
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        require(
            self.binding.is_some() == self.verified.is_some()
                && (self.created.is_none() || self.binding.is_some()),
            "incomplete actual signed entry publication",
        )?;
        if let Some(binding) = &self.binding {
            binding.recheck()?;
        }
        if let Some(verified) = &self.verified {
            verified.recheck()?;
        }
        if let Some(created) = &self.created {
            created.recheck(authorize)?;
            require(
                files::identity(&created.file(authorize)?.metadata()?)
                    == files::identity(&self.verified.as_ref().unwrap().file.metadata()?),
                "retained signed entry differs from actual owned UKI output",
            )?;
        }
        authorize()
    }
    pub fn require_original_entry(
        &self,
        expected: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        if let Some(binding) = &self.binding {
            let fields = boot_entries::fields(expected, false)?;
            require(
                binding.kernel.path == secure_boot::source_path(field(&fields, "linux")?)?
                    && binding.initrd.path == secure_boot::source_path(field(&fields, "initrd")?)?
                    && binding.options == field(&fields, "options")?
                    && self.text == rewrite(expected, &binding.relative)?,
                "retained signer differs from exact original coordinator entry",
            )?;
        } else {
            require(
                self.text == expected,
                "unsigned entry differs from exact original coordinator entry",
            )?;
        }
        self.recheck(authorize)
    }
    pub fn text(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&str> {
        self.recheck(authorize)?;
        Ok(&self.text)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<serde_json::Value> {
        self.recheck(authorize)?;
        Ok(
            serde_json::json!({"entry":self.text,"signed":self.binding.is_some(),
            "created":self.created.as_ref().map(|uki| uki.evidence(authorize)).transpose()?,
            "output_epoch":self.verified.as_ref().map(|artifact| artifact.file.metadata().map(|m| files::identity(&m))).transpose()?,
            "execution_authorized":false}),
        )
    }
}
pub fn wrap_locked(text: &str, lock: &files::Lock) -> Result<String> {
    let wrapped = wrap_retained_authorized(text, lock, &mut || lock.recheck())?;
    Ok(wrapped.text(&mut || lock.recheck())?.to_owned())
}
pub fn wrap_retained_authorized(
    text: &str,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Wrapped> {
    wrap_inner(text, lock, authorize, false)
}
fn wrap_inner(
    text: &str,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
    preparing_owner: bool,
) -> Result<Wrapped> {
    operation::root_only()?;
    let authorization = std::cell::RefCell::new(authorize);
    let permission = || {
        lock.recheck()?;
        (authorization.borrow_mut())()
    };
    permission()?;
    if !preparing_owner && !secure_boot::configured()? {
        return Ok(Wrapped {
            text: text.into(),
            binding: None,
            verified: None,
            created: None,
        });
    }
    let fields = boot_entries::fields(text, false)?;
    if !fields.contains_key("linux") {
        return Ok(Wrapped {
            text: text.into(),
            binding: None,
            verified: None,
            created: None,
        });
    }
    let binding = Binding::observe(&fields)?;
    binding.volume.writable()?;
    let directory = Path::new("/boot/enzimos/secure-boot");
    // Existing boot ancestors must already be installed; this never creates a
    // replacement ESP or silently adopts an interrupted destination.
    permission()?;
    let mode = files::public_directory_mode(&binding.volume.directory)?;
    let parent = files::ensure_directory(directory, mode, 0)?;
    permission()?;
    require(
        enzimos_platform::mount_identity::id(parent.as_fd(), true)? == binding.volume.unique,
        "UKI directory crosses another mount",
    )?;
    let destination = secure_boot::source_path(&binding.relative)?;
    let mut created = None;
    match std::fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            require(
                std::fs::read_dir(directory)?.take(129).count() < 128,
                "owner UKI retention bound requires review",
            )?;
            let temporary = destination.with_file_name(format!(
                "{}.new",
                destination.file_name().unwrap().to_str().unwrap()
            ));
            require(
                matches!(std::fs::symlink_metadata(temporary), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "interrupted owner UKI publication requires review",
            )?;
            binding.recheck()?;
            created = Some(secure_artifacts::build_uki_retained_authorized(
                &binding.kernel.path,
                &binding.initrd.path,
                &binding.options,
                &destination,
                lock,
                &mut || {
                    permission()?;
                    binding.recheck()
                },
            )?);
        }
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    if let Some(uki) = &created {
        uki.recheck(&mut || {
            permission()?;
            binding.recheck()
        })?;
    }
    permission()?;
    let verified = binding.verify()?;
    permission()?;
    if let Some(uki) = &created {
        require(
            files::identity(&verified.file.metadata()?)
                == files::identity(
                    &uki.file(&mut || {
                        permission()?;
                        binding.recheck()
                    })?
                    .metadata()?,
                ),
            "verified UKI differs from actual owned publication",
        )?;
    }
    let rewritten = rewrite(text, &binding.relative)?;
    verified.recheck()?;
    binding.recheck()?;
    if let Some(uki) = &created {
        uki.recheck(&mut || permission())?;
    }
    let result = Wrapped {
        text: rewritten,
        binding: Some(binding),
        verified: Some(verified),
        created,
    };
    result.recheck(&mut || permission())?;
    Ok(result)
}
/// Observation and activation resume must never create missing UKIs.
pub fn render_existing(text: &str) -> Result<String> {
    operation::root_only()?;
    if !secure_boot::configured()? {
        return Ok(text.into());
    }
    let fields = boot_entries::fields(text, false)?;
    if !fields.contains_key("linux") {
        return Ok(text.into());
    }
    let binding = Binding::observe(&fields)?;
    binding.verify()?;
    rewrite(text, &binding.relative)
}

#[path = "secure_boot_enable.rs"]
pub mod enable;
