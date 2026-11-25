// SPDX-License-Identifier: MIT
//! Whole original current loader entry set, over the actual restored ESP actor.
//! Unsupported entry grammar refuses; no interpreted row grants filesystem action.
use crate::{
    boot_entries, boot_volume::Artifact, root_retirement_boot_artifacts::Restored,
    root_retirement_offline_catalog::Catalog, root_retirement_offline_control::Control,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
const MAX_ENTRIES: usize = 256;
const MAX_ASSETS: usize = 512;
const MAX_ASSET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline loader read-only descriptor required",
    )?;
    Ok(flags)
}
struct Automatic {
    efi: Option<(File, files::FileIdentity, i32)>,
    linux: Option<(File, files::FileIdentity, i32)>,
}
fn automatic_directory(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let metadata = file.metadata()?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o022 == 0
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original protected automatically discovered image directory required",
    )?;
    Ok(files::identity(&metadata))
}
impl Automatic {
    fn observe(volume: &crate::boot_volume::Volume) -> Result<Self> {
        let efi = files::optional_directory_relative(&volume.directory, Path::new("EFI"), Some(0))?;
        let linux = match &efi {
            Some(efi) => files::optional_directory_relative(efi, Path::new("Linux"), Some(0))?,
            None => None,
        };
        if let Some(linux) = &linux {
            require(
                files::directory_names(linux, 128)?.is_empty(),
                "unowned automatically discovered UKIs protect offline retirement",
            )?;
        }
        let keep = |file: File| -> Result<_> {
            Ok((
                automatic_directory(&file, volume.unique)?,
                flags(&file)?,
                file,
            ))
        };
        let efi = efi
            .map(keep)
            .transpose()?
            .map(|(epoch, flags, file)| (file, epoch, flags));
        let linux = linux
            .map(keep)
            .transpose()?
            .map(|(epoch, flags, file)| (file, epoch, flags));
        let result = Self { efi, linux };
        result.recheck(volume)?;
        Ok(result)
    }
    fn recheck(&self, volume: &crate::boot_volume::Volume) -> Result<()> {
        let named =
            files::optional_directory_relative(&volume.directory, Path::new("EFI"), Some(0))?;
        match (&self.efi, named) {
            (None, None) => require(
                self.linux.is_none(),
                "incomplete original automatic image observation",
            ),
            (Some((efi, epoch, original_flags)), Some(named)) => {
                require(
                    automatic_directory(efi, volume.unique)? == *epoch
                        && automatic_directory(&named, volume.unique)? == *epoch
                        && flags(efi)? == *original_flags,
                    "original EFI directory changed, replaced or covered",
                )?;
                let named = files::optional_directory_relative(efi, Path::new("Linux"), Some(0))?;
                match (&self.linux, named) {
                    (None, None) => Ok(()),
                    (Some((linux, epoch, original_flags)), Some(named)) => require(
                        automatic_directory(linux, volume.unique)? == *epoch
                            && automatic_directory(&named, volume.unique)? == *epoch
                            && flags(linux)? == *original_flags
                            && files::directory_names(linux, 128)?.is_empty()
                            && files::directory_names(&named, 128)?.is_empty(),
                        "original automatically discovered image directory changed",
                    ),
                    _ => Err(Error(
                        "automatic image directory appeared or disappeared".into(),
                    )),
                }
            }
            _ => Err(Error(
                "original EFI directory appeared or disappeared".into(),
            )),
        }
    }
}
fn names(file: &File) -> Result<BTreeSet<String>> {
    files::directory_names(file, MAX_ENTRIES)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| Error("original loader entry filename encoding".into()))?;
            crate::recovery_records::literal_entry(&name)?;
            require(
                name.ends_with(".conf"),
                "unknown/interrupted original loader entry member",
            )?;
            Ok(name)
        })
        .collect()
}
fn asset(value: &str, bios: bool) -> Result<PathBuf> {
    let value = if bios {
        value
            .strip_prefix("boot():")
            .ok_or_else(|| Error("unsupported original BIOS artifact origin".into()))?
    } else {
        value
    };
    let relative = value
        .strip_prefix('/')
        .ok_or_else(|| Error("absolute ESP artifact reference required".into()))?;
    let path = Path::new(relative);
    require(
        !relative.is_empty()
            && relative.len() <= 4096
            && relative
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
            && !relative
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '\\' | '"' | '\''))
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "canonical original ESP artifact reference required",
    )?;
    Ok(path.to_owned())
}
struct Signed {
    kernel: PathBuf,
    initrd: PathBuf,
    uki: PathBuf,
    options: String,
}
fn entry(text: &str, bios: bool) -> Result<(Vec<PathBuf>, Option<String>, Option<Signed>)> {
    let fields = boot_entries::fields(text, bios)?;
    let known: &[&str] = if bios {
        &["protocol", "path", "module_path", "cmdline"]
    } else {
        &[
            "title",
            "version",
            "machine-id",
            "sort-key",
            "architecture",
            "linux",
            "initrd",
            "options",
            "uki",
        ]
    };
    require(
        fields.keys().all(|key| known.contains(&key.as_str())),
        "unparsed or unsupported original loader field requires review",
    )?;
    if bios {
        require(
            fields.get("protocol").is_some_and(|v| v == "linux"),
            "unqualified original BIOS protocol",
        )?;
    }
    let get = |key: &str| {
        fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| Error(format!("missing original loader field {key}")))
    };
    let mut paths = if bios {
        vec![
            asset(get("path")?, true)?,
            asset(get("module_path")?, true)?,
        ]
    } else {
        vec![asset(get("linux")?, false)?, asset(get("initrd")?, false)?]
    };
    let options = get(if bios { "cmdline" } else { "options" })?;
    require(
        options.len() <= 8192 && !options.chars().any(char::is_control),
        "original loader command-line grammar",
    )?;
    let root = if options
        .split_whitespace()
        .any(|word| word.starts_with("root=") || word.starts_with("rootflags="))
    {
        Some(crate::boot_options::subvolume_from_options(options)?)
    } else {
        None
    };
    let signed = if let Some(uki) = fields.get("uki") {
        let uki = asset(uki, false)?;
        let name = uki
            .strip_prefix("enzimos/secure-boot")
            .ok()
            .and_then(|p| p.to_str())
            .and_then(|p| p.strip_suffix(".efi"))
            .ok_or_else(|| Error("content-bound original owner UKI path required".into()))?;
        crate::identity::sha(name)?;
        let signed = Signed {
            kernel: paths[0].clone(),
            initrd: paths[1].clone(),
            uki: uki.clone(),
            options: options.into(),
        };
        paths.push(uki);
        Some(signed)
    } else {
        None
    };
    Ok((paths, root, signed))
}
/// Closed loader grammar shared with original online protection observations.
/// This returns comparison data and cannot validate a signature or create an actor.
pub(crate) fn root_reference(text: &str, bios: bool) -> Result<Option<String>> {
    Ok(entry(text, bios)?.1)
}
fn signed_identity(signed: &Signed, kernel: &str, initrd: &str, pem: &[u8]) -> Result<()> {
    let id = crate::signed_entry::digest(
        kernel,
        initrd,
        &signed.options,
        &enzimos_platform::json::sha256(pem),
    )?;
    require(
        signed.uki == format!("enzimos/secure-boot/{id}.efi"),
        "original signed UKI content/certificate/options binding differs",
    )
}
pub(crate) fn unmentioned(roots: &BTreeSet<String>, targets: &Value) -> Result<()> {
    let targets = targets
        .as_array()
        .filter(|v| (1..=64).contains(&v.len()))
        .ok_or_else(|| Error("original loader target bound".into()))?;
    let root = targets
        .last()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["path"]
        .as_str()
        .ok_or_else(|| Error("original final root target path".into()))?;
    for path in roots {
        require(
            path != root
                && !path.starts_with(&format!("{root}/"))
                && !targets.iter().any(|row| row["path"] == *path),
            "original loader entry protects retirement target",
        )?;
    }
    Ok(())
}
pub struct Loaders<'a, 's> {
    automatic: Automatic,
    control: &'a Control<'a, 's>,
    catalog: &'a Catalog<'a, 's>,
    boot: &'a Restored<'a, 's>,
    entries: File,
    entries_epoch: files::FileIdentity,
    entries_flags: i32,
    entries_mount: u64,
    members: BTreeMap<String, (Artifact, i32)>,
    assets: BTreeMap<PathBuf, (Artifact, i32)>,
    roots: BTreeSet<String>,
    bios_epoch: files::FileIdentity,
    bios_flags: i32,
    bios_body: Vec<u8>,
    certificate: &'a crate::root_retirement_offline_certificate::Certificate<'a, 's>,
    verifier: Option<crate::settings_command::Command>,
    signed_verified: usize,
}
impl<'a, 's> Loaders<'a, 's> {
    pub(crate) fn require_original_ledgers(
        &self,
        ledgers: &crate::root_retirement_offline_ledgers::Ledgers<'a, 's>,
    ) -> Result<()> {
        self.catalog.require_original_ledgers(ledgers)?;
        self.recheck()
    }
    pub(crate) fn require_original_boot(&self, boot: &Restored<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.boot, boot),
            "original loader set belongs to another restored ESP actor",
        )?;
        self.recheck()
    }
    pub(crate) fn published_image(&self, row: &Value) -> Result<()> {
        self.recheck()?;
        let id = crate::recovery_records::text(row, "id")?;
        crate::recovery_image::validate(row, id)?;
        let (name, title) = crate::recovery_image::entry_names(id)?;
        let (uefi, bios) =
            crate::recovery_image::entry_texts(id, crate::recovery_records::text(row, "options")?)?;
        let member = self
            .members
            .get(&name)
            .ok_or_else(|| Error("ready recovery image UEFI entry missing".into()))?;
        let bytes = files::read_file(&member.0.file, boot_entries::MAX_TEXT, Some(0), true)?;
        let actual = boot_entries::fields(
            std::str::from_utf8(&bytes).map_err(|_| Error("ready image UEFI encoding".into()))?,
            false,
        )?;
        let expected = boot_entries::fields(&uefi, false)?;
        require(
            expected
                .iter()
                .all(|(key, value)| actual.get(key) == Some(value))
                && actual
                    .keys()
                    .all(|key| expected.contains_key(key) || key == "uki"),
            "ready image UEFI publication differs from immutable intent",
        )?;
        let menu = boot_entries::menu(
            std::str::from_utf8(&self.bios_body)
                .map_err(|_| Error("ready image BIOS encoding".into()))?,
        )?;
        let matches = menu
            .entries
            .iter()
            .filter(|entry| entry.title == title)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1
                && boot_entries::fields(&matches[0].text, true)?
                    == boot_entries::fields(&bios, true)?,
            "ready image BIOS publication differs from immutable intent",
        )?;
        self.recheck()
    }
    pub(crate) fn observe(
        control: &'a Control<'a, 's>,
        catalog: &'a Catalog<'a, 's>,
        boot: &'a Restored<'a, 's>,
        certificate: &'a crate::root_retirement_offline_certificate::Certificate<'a, 's>,
    ) -> Result<Self> {
        catalog.require_original_control(control)?;
        boot.require_original_control(control)?;
        certificate.require_original_control(control)?;
        let configured = certificate.configured()?;
        let volume = boot.original_volume()?;
        let automatic = Automatic::observe(volume)?;
        let entries = volume.directory(Path::new("loader/entries"))?;
        let metadata = entries.metadata()?;
        require(
            metadata.is_dir()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0,
            "original protected ESP loader entry directory required",
        )?;
        let mut members = BTreeMap::new();
        let mut references = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut text_bytes = 0;
        let mut signed = Vec::new();
        for name in names(&entries)? {
            let member = volume.artifact(
                &Path::new("loader/entries").join(&name),
                boot_entries::MAX_TEXT as u64,
            )?;
            let body = files::read_file(&member.file, boot_entries::MAX_TEXT, Some(0), true)?;
            text_bytes += body.len();
            require(
                text_bytes <= 8 * 1024 * 1024,
                "whole original loader entry text budget exceeded",
            )?;
            let (paths, root, binding) = entry(
                std::str::from_utf8(&body)
                    .map_err(|_| Error("original UEFI entry encoding".into()))?,
                false,
            )?;
            references.extend(paths);
            require(
                !configured || binding.is_some(),
                "configured original owner policy requires signed UEFI entries",
            )?;
            if let Some(binding) = binding {
                signed.push(binding);
            }
            if let Some(root) = root {
                roots.insert(root);
            }
            members.insert(name, (member, 0));
        }
        let bios = boot.original_bios()?;
        let bios_body = files::read_file(bios, boot_entries::MAX_TEXT, Some(0), true)?;
        let menu = boot_entries::menu(
            std::str::from_utf8(&bios_body)
                .map_err(|_| Error("original BIOS menu encoding".into()))?,
        )?;
        for item in menu.entries {
            let (paths, root, _) = entry(&item.text, true)?;
            references.extend(paths);
            if let Some(root) = root {
                roots.insert(root);
            }
        }
        require(
            !members.is_empty() && references.len() <= MAX_ASSETS,
            "complete original loader asset bound",
        )?;
        let mut assets = BTreeMap::new();
        let mut asset_bytes = 0;
        for path in references {
            let artifact = volume.artifact(&path, 128 * 1024 * 1024)?;
            asset_bytes += artifact.bytes;
            require(
                asset_bytes <= MAX_ASSET_BYTES,
                "complete original loader artifact byte budget exceeded",
            )?;
            let original_flags = flags(&artifact.file)?;
            assets.insert(path, (artifact, original_flags));
        }
        for (member, original_flags) in members.values_mut() {
            *original_flags = flags(&member.file)?;
        }
        let verifier = if signed.is_empty() {
            None
        } else {
            Some(crate::settings_command::Command::open_boot(
                crate::settings_command::BootTool::Verify,
            )?)
        };
        let mut verified = BTreeSet::new();
        let started = Instant::now();
        for binding in signed {
            certificate.require_original_control(control)?;
            let pem = certificate.public_pem()?;
            let kernel = &assets[&binding.kernel].0;
            let initrd = &assets[&binding.initrd].0;
            let output = &assets[&binding.uki].0;
            signed_identity(&binding, &kernel.sha, &initrd.sha, pem)?;
            if verified.contains(&binding.uki) {
                continue;
            }
            let body = files::read_file(&output.file, 128 * 1024 * 1024, Some(0), true)?;
            crate::secure_artifacts::verify_payload(
                &body,
                &kernel.sha,
                &initrd.sha,
                &binding.options,
            )?;
            let certificate_file =
                enzimos_platform::memfile::sealed("enzimos-offline-public-certificate", pem)?;
            let remaining = Duration::from_secs(600)
                .checked_sub(started.elapsed())
                .ok_or_else(|| {
                    Error("original signed loader verification aggregate deadline".into())
                })?;
            require(
                !remaining.is_zero(),
                "original signed loader verification deadline exhausted",
            )?;
            control.original_scope()?.recheck()?;
            let result = verifier
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                .run_fds_authorized(
                    &["--cert", "@fd:0", "@fd:1"],
                    remaining.min(Duration::from_secs(60)),
                    16384,
                    &[certificate_file.as_fd(), output.file.as_fd()],
                    &mut || {
                        certificate.recheck_public_descriptions()?;
                        for (artifact, original_flags) in assets.values() {
                            artifact.recheck()?;
                            require(
                                flags(&artifact.file)? == *original_flags,
                                "original signed loader artifact description changed",
                            )?;
                        }
                        for (artifact, original_flags) in members.values() {
                            artifact.recheck()?;
                            require(
                                flags(&artifact.file)? == *original_flags,
                                "original signed loader entry description changed",
                            )?;
                        }
                        Ok(())
                    },
                )?;
            // Fully reaped verifier; only now require the sole-userspace census.
            control.original_scope()?.recheck()?;
            certificate.require_original_control(control)?;
            require(
                result.status.success(),
                "original owner UKI signature refused",
            )?;
            verified.insert(binding.uki);
        }
        let result = Self {
            automatic,
            control,
            catalog,
            boot,
            entries_epoch: files::identity(&metadata),
            entries_flags: flags(&entries)?,
            entries_mount: mount_identity::id(entries.as_fd(), true)?,
            entries,
            members,
            assets,
            roots,
            bios_epoch: files::identity(&bios.metadata()?),
            bios_flags: flags(bios)?,
            bios_body,
            certificate,
            verifier,
            signed_verified: verified.len(),
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn require_original_catalog(&self, catalog: &Catalog<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.catalog, catalog),
            "original offline loaders belong to another catalog actor",
        )?;
        self.recheck()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.catalog.require_original_control(self.control)?;
        self.certificate.require_original_control(self.control)?;
        self.automatic.recheck(self.boot.original_volume()?)?;
        if let Some(verifier) = &self.verifier {
            verifier.recheck()?;
        }
        self.boot.require_original_control(self.control)?;
        let volume = self.boot.original_volume()?;
        let named = volume.directory(Path::new("loader/entries"))?;
        let expected = self.members.keys().cloned().collect::<BTreeSet<_>>();
        require(
            files::identity(&self.entries.metadata()?) == self.entries_epoch
                && files::identity(&named.metadata()?) == self.entries_epoch
                && flags(&self.entries)? == self.entries_flags
                && mount_identity::id(self.entries.as_fd(), true)? == self.entries_mount
                && mount_identity::id(named.as_fd(), true)? == self.entries_mount
                && self.entries_mount == volume.unique
                && names(&self.entries)? == expected
                && names(&named)? == expected,
            "original whole loader entry directory or membership changed",
        )?;
        for (member, original_flags) in self.members.values().chain(self.assets.values()) {
            member.recheck()?;
            require(
                flags(&member.file)? == *original_flags,
                "original loader artifact shared descriptor flags changed",
            )?;
        }
        let bios = self.boot.original_bios()?;
        require(
            files::identity(&bios.metadata()?) == self.bios_epoch
                && flags(bios)? == self.bios_flags
                && files::read_file(bios, boot_entries::MAX_TEXT, Some(0), true)? == self.bios_body
                && files::identity(&bios.metadata()?) == self.bios_epoch,
            "original restored BIOS menu changed",
        )?;
        self.catalog.require_original_control(self.control)
    }
    pub(crate) fn require_unmentioned(
        &self,
        targets: &crate::root_retirement_offline_targets::Targets<'a, 's>,
    ) -> Result<()> {
        self.recheck()?;
        targets.require_original_catalog(self.catalog)?;
        unmentioned(&self.roots, targets.rows()?)?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"whole_current_uefi_and_bios_entry_set_retained":true,"entries":self.members.len(),"assets":self.assets.len(),
            "signed_uki_entries_supported":true,"original_signed_ukis_verified":self.signed_verified,"private_signing_key_read":false,"historical_publication_loader_closure_verified":false,"execution_authorized":false}),
        )
    }
}
