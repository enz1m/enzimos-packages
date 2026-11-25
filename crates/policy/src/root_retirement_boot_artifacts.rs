// SPDX-License-Identifier: MIT
//! Actual ESP originals joined to original kernel boot and native RAM image.
//! The encrypted published-image receipt remains a separate prerequisite.
use crate::{
    boot_entries,
    boot_volume::{Artifact, ReplacedArtifact, Volume},
    initramfs, recovery_image, root_retirement_boot_contract as contract,
    root_retirement_kernel_boot,
    root_retirement_offline_scope::Scope,
    root_retirement_running_image,
};
use enzimos_platform::{Error, Result, files, json, publication::Prepared, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original ESP artifact read-only descriptor",
    )?;
    Ok(value)
}
fn assembly(bytes: &[u8], descriptor: &Value) -> Result<()> {
    let mut body = json::canonical(descriptor)?;
    body.push(b'\n');
    let appended = initramfs::newc(crate::recovery_image_build::DESCRIPTOR, &body, 0o100644)?;
    require(
        bytes.len() > appended.len() && bytes.ends_with(&appended),
        "actual initrd lacks exact final native descriptor archive",
    )?;
    let prefix = bytes.len() - appended.len();
    require(
        prefix.is_multiple_of(4),
        "actual native descriptor archive alignment",
    )?;
    let matching = (0..=3)
        .filter(|padding| {
            prefix > *padding
                && bytes[prefix - padding..prefix].iter().all(|b| *b == 0)
                && descriptor["base_initrd_sha256"].as_str()
                    == Some(json::sha256(&bytes[..prefix - padding]).as_str())
        })
        .count();
    require(
        matching == 1,
        "exact actual base initrd digest/alignment differs",
    )
}
fn text(artifact: &Artifact) -> Result<String> {
    artifact.recheck()?;
    let bytes = files::read_file(&artifact.file, boot_entries::MAX_TEXT, Some(0), true)?;
    artifact.recheck()?;
    String::from_utf8(bytes).map_err(|_| Error("actual retirement boot artifact encoding".into()))
}
enum TextState {
    Original(Artifact),
    Replaced(ReplacedArtifact),
}
struct BootText {
    state: TextState,
    original_description: File,
    original_flags: i32,
    current_flags: i32,
    body: String,
}
impl BootText {
    fn observe(artifact: Artifact) -> Result<Self> {
        let body = text(&artifact)?;
        let original_flags = flags(&artifact.file)?;
        Ok(Self {
            original_description: artifact.file.try_clone()?,
            original_flags,
            current_flags: original_flags,
            state: TextState::Original(artifact),
            body,
        })
    }
    fn file(&self) -> Result<&File> {
        match &self.state {
            TextState::Original(artifact) => {
                artifact.recheck()?;
                Ok(&artifact.file)
            }
            TextState::Replaced(artifact) => artifact.file(),
        }
    }
    fn recheck(&self) -> Result<()> {
        let file = self.file()?;
        require(
            flags(&self.original_description)? == self.original_flags
                && enzimos_platform::files::status_flags(&file) == self.current_flags
                && files::read_file(file, boot_entries::MAX_TEXT, Some(0), true)?
                    == self.body.as_bytes(),
            "original or actual owned loader text/descriptor flags changed",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn publish(self, next: &str, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Self> {
        authorize()?;
        self.recheck()?;
        if next == self.body {
            return Ok(self);
        }
        let TextState::Original(artifact) = self.state else {
            return Err(Error("loader restoration cannot publish twice".into()));
        };
        let pending = Prepared::write_authorized(&artifact.path, next.as_bytes(), 0, authorize)?;
        artifact.require_original_publication(&pending)?;
        artifact.recheck()?;
        authorize()?;
        require(
            flags(&self.original_description)? == self.original_flags,
            "original loader description changed before publication",
        )?;
        let committed = pending.commit_retained(true)?;
        let replaced = artifact.into_replaced(committed)?;
        // SAFETY: F_GETFL takes no pointers; it only reads the flags of an open descriptor.
        let current_flags = unsafe { libc::fcntl(replaced.file()?.as_raw_fd(), libc::F_GETFL) };
        require(
            current_flags >= 0 && current_flags & libc::O_ACCMODE == libc::O_RDWR,
            "actual owned loader writer descriptor required",
        )?;
        let result = Self {
            state: TextState::Replaced(replaced),
            original_description: self.original_description,
            original_flags: self.original_flags,
            current_flags,
            body: next.into(),
        };
        result.recheck()?;
        authorize()?;
        Ok(result)
    }
}
pub struct Original<'a, 's> {
    scope: &'s Scope,
    kernel_boot: &'a root_retirement_kernel_boot::Original<'s>,
    running: &'a root_retirement_running_image::Original<'s>,
    volume: Volume,
    folder: File,
    folder_epoch: files::FileIdentity,
    folder_flags: i32,
    artifact_flags: Vec<i32>,
    defaults: Option<BootText>,
    bios: Option<BootText>,
    entry: Artifact,
    previous: Artifact,
    kernel: Artifact,
    initrd: Artifact,
    identity: Artifact,
    plan: contract::Restoration,
}
impl<'a, 's> Original<'a, 's> {
    pub fn observe(
        scope: &'s Scope,
        kernel_boot: &'a root_retirement_kernel_boot::Original<'s>,
        running: &'a root_retirement_running_image::Original<'s>,
    ) -> Result<Self> {
        kernel_boot.require_original_scope(scope)?;
        running.require_original_scope(scope)?;
        let p = kernel_boot.parameters()?;
        let volume = Volume::observe()?;
        scope.recheck()?; // Fixed query child is already reaped.
        require(
            volume.uuid.eq_ignore_ascii_case(&p.esp),
            "actual retirement ESP differs from kernel parameters",
        )?;
        let defaults = volume.artifact(
            Path::new("loader/loader.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        let bios = volume.artifact(
            Path::new("limine/limine.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        let entry = volume.artifact(
            Path::new(&format!(
                "loader/entries/enzimos-root-retire-{}.conf",
                &p.id[5..21]
            )),
            boot_entries::MAX_TEXT as u64,
        )?;
        let previous = volume.artifact(
            Path::new(&format!("loader/entries/{}", p.uefi_previous)),
            boot_entries::MAX_TEXT as u64,
        )?;
        let options = boot_entries::fields(&text(&entry)?, false)?
            .get("options")
            .cloned()
            .ok_or_else(|| Error("actual coordinator options missing".into()))?;
        let image = running.identifier()?;
        let plan = contract::restore_original(
            p,
            image,
            &options,
            &text(&defaults)?,
            &text(&bios)?,
            &text(&entry)?,
        )?;
        let relative = format!("enzimos/recovery-images/{image}");
        let folder = volume.directory(Path::new(&relative))?;
        require(
            files::directory_names(&folder, 3)?
                .into_iter()
                .collect::<BTreeSet<_>>()
                == ["kernel", "initrd.img", "identity.json"]
                    .map(std::ffi::OsString::from)
                    .into_iter()
                    .collect(),
            "actual retirement ESP image membership differs",
        )?;
        let kernel = volume.artifact(
            Path::new(&format!("{relative}/kernel")),
            recovery_image::MAX_IMAGE,
        )?;
        let initrd = volume.artifact(
            Path::new(&format!("{relative}/initrd.img")),
            recovery_image::MAX_IMAGE,
        )?;
        let identity = volume.artifact(
            Path::new(&format!("{relative}/identity.json")),
            2 * 1024 * 1024,
        )?;
        let descriptor = running.descriptor()?;
        require(
            kernel.sha == enzimos_platform::json::string(&descriptor["kernel_sha256"])?
                && json::decode(
                    &files::read_file(&identity.file, 2 * 1024 * 1024, Some(0), true)?,
                    2 * 1024 * 1024,
                )? == *descriptor,
            "actual ESP kernel/descriptor differs from running native image",
        )?;
        let bytes = files::read_file(
            &initrd.file,
            recovery_image::MAX_IMAGE as usize,
            Some(0),
            true,
        )?;
        assembly(&bytes, descriptor)?;
        let wanted = enzimos_platform::json::object(&descriptor["policy_files"])?
            .keys()
            .map(|name| format!("usr/lib/enzimos-native/{name}"))
            .chain(std::iter::once(
                crate::recovery_image_build::DESCRIPTOR.into(),
            ))
            .collect();
        let members = initramfs::inventory(&bytes, &wanted)?;
        for (name, digest) in enzimos_platform::json::object(&descriptor["policy_files"])? {
            let member = members
                .get(&format!("usr/lib/enzimos-native/{name}"))
                .ok_or_else(|| Error("actual ESP initrd native policy member missing".into()))?;
            require(
                member.sha.as_deref() == digest.as_str()
                    && member.mode & libc::S_IFMT == libc::S_IFREG
                    && member.mode & 0o022 == 0
                    && (!name.starts_with("enzimos-") || member.mode & 0o111 == 0o111),
                "actual ESP initrd native policy bytes/mode differ",
            )?;
        }
        let artifact_flags = [&entry, &previous, &kernel, &initrd, &identity]
            .iter()
            .map(|artifact| flags(&artifact.file))
            .collect::<Result<Vec<_>>>()?;
        let result = Self {
            scope,
            kernel_boot,
            running,
            folder_epoch: files::identity(&folder.metadata()?),
            folder_flags: flags(&folder)?,
            artifact_flags,
            folder,
            volume,
            defaults: Some(BootText::observe(defaults)?),
            bios: Some(BootText::observe(bios)?),
            entry,
            previous,
            kernel,
            initrd,
            identity,
            plan,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.sources_recheck()?;
        let defaults = self
            .defaults
            .as_ref()
            .ok_or_else(|| Error("original loader restoration is in progress".into()))?;
        let bios = self
            .bios
            .as_ref()
            .ok_or_else(|| Error("original BIOS restoration is in progress".into()))?;
        defaults.recheck()?;
        bios.recheck()?;
        let options = boot_entries::fields(&text(&self.entry)?, false)?
            .get("options")
            .cloned()
            .ok_or_else(|| Error("original coordinator options disappeared".into()))?;
        let plan = contract::restore_original(
            self.kernel_boot.parameters()?,
            self.running.identifier()?,
            &options,
            &defaults.body,
            &bios.body,
            &text(&self.entry)?,
        )?;
        require(
            plan.defaults == self.plan.defaults
                && plan.bios == self.plan.bios
                && plan.image == self.plan.image,
            "original actual retirement restoration plan changed",
        )?;
        self.scope.recheck()
    }
    fn sources_recheck(&self) -> Result<()> {
        self.kernel_boot.require_original_scope(self.scope)?;
        self.running.require_original_scope(self.scope)?;
        self.volume.recheck()?;
        for (artifact, expected_flags) in [
            &self.entry,
            &self.previous,
            &self.kernel,
            &self.initrd,
            &self.identity,
        ]
        .into_iter()
        .zip(&self.artifact_flags)
        {
            artifact.recheck()?;
            require(
                flags(&artifact.file)? == *expected_flags,
                "original ESP artifact descriptor flags changed",
            )?;
        }
        let folder = self.volume.directory(Path::new(&format!(
            "enzimos/recovery-images/{}",
            self.plan.image
        )))?;
        require(
            files::identity(&self.folder.metadata()?) == self.folder_epoch
                && files::identity(&folder.metadata()?) == self.folder_epoch
                && self.folder.metadata()?.uid() == 0
                && flags(&self.folder)? == self.folder_flags,
            "original retirement ESP image directory replaced or changed",
        )?;
        self.scope.recheck()
    }
    /// Consume actual original loader descriptions into their actual publications.
    /// An uncertain write leaves evidence for review; no Drop cleanup or retry.
    pub fn restore_defaults(mut self) -> Result<Restored<'a, 's>> {
        self.recheck()?;
        self.volume.writable()?;
        let defaults = self
            .defaults
            .take()
            .ok_or_else(|| Error("original loader defaults missing".into()))?;
        let defaults = defaults.publish(&self.plan.defaults, &mut || {
            self.sources_recheck()?;
            self.bios
                .as_ref()
                .ok_or_else(|| Error("original BIOS menu missing".into()))?
                .recheck()
        })?;
        self.defaults = Some(defaults);
        self.recheck()?;
        let bios = self
            .bios
            .take()
            .ok_or_else(|| Error("original BIOS menu missing".into()))?;
        let bios = bios.publish(&self.plan.bios, &mut || {
            self.sources_recheck()?;
            self.defaults
                .as_ref()
                .ok_or_else(|| Error("owned loader defaults missing".into()))?
                .recheck()
        })?;
        self.bios = Some(bios);
        for folder in ["loader", "limine"] {
            self.volume.directory(Path::new(folder))?.sync_all()?;
        }
        let restored = Restored { original: self };
        restored.recheck()?;
        Ok(restored)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"image":self.plan.image,"actual_esp_image_bytes_verified":true,"original_loader_entries_verified":true,"published_image_receipt_verified":false,"defaults_restored":false,"execution_authorized":false}),
        )
    }
}
pub struct Restored<'a, 's> {
    original: Original<'a, 's>,
}
impl Restored<'_, '_> {
    pub(crate) fn restoration_status(&self) -> Result<Value> {
        self.recheck()?;
        let state = |text: &BootText| match &text.state {
            TextState::Original(_) => "already-restored",
            TextState::Replaced(_) => "restored",
        };
        Ok(
            value!({"uefi":state(self.original.defaults.as_ref().ok_or_else(|| enzimos_platform::Error("missing value".into()))?),
            "bios":state(self.original.bios.as_ref().ok_or_else(|| enzimos_platform::Error("missing value".into()))?)}),
        )
    }
    pub(crate) fn previous_root(&self) -> Result<String> {
        self.recheck()?;
        let fields = boot_entries::fields(&text(&self.original.previous)?, false)?;
        let options = fields
            .get("options")
            .ok_or_else(|| Error("original previous loader options missing".into()))?;
        crate::boot_options::subvolume_from_options(options)
    }
    pub(crate) fn original_volume(&self) -> Result<&Volume> {
        self.recheck()?;
        Ok(&self.original.volume)
    }
    pub(crate) fn original_bios(&self) -> Result<&File> {
        self.recheck()?;
        self.original
            .bios
            .as_ref()
            .ok_or_else(|| Error("original restored BIOS text absent".into()))?
            .file()
    }
    pub(crate) fn require_original_kernel_boot(
        &self,
        kernel: &root_retirement_kernel_boot::Original<'_>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.original.kernel_boot, kernel),
            "original restored boot/kernel actor differs",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_control(
        &self,
        control: &crate::root_retirement_offline_control::Control<'_, '_>,
    ) -> Result<()> {
        self.recheck()?;
        control.require_original_kernel_boot(self.original.kernel_boot)
    }
    pub(crate) fn identifier(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.original.plan.image)
    }
    pub(crate) fn require_published_record(&self, record: &Value) -> Result<()> {
        self.recheck()?;
        recovery_image::validate(record, &self.original.plan.image)?;
        let p = self.original.kernel_boot.parameters()?;
        require(
            record["phase"] == "ready"
                && record["boot_uuid"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&self.original.volume.uuid))
                && record["filesystem_uuid"] == p.filesystem
                && record["inputs"]["identity"] == *self.original.running.descriptor()?
                && record["inputs"]["files"]["kernel"]["bytes"].as_u64()
                    == Some(self.original.kernel.bytes)
                && record["inputs"]["files"]["kernel"]["sha256"] == self.original.kernel.sha
                && record["inputs"]["files"]["initrd.img"]["bytes"].as_u64()
                    == Some(self.original.initrd.bytes)
                && record["inputs"]["files"]["initrd.img"]["sha256"] == self.original.initrd.sha,
            "actual ready published image receipt differs from original ESP/running image bytes",
        )?;
        self.recheck()
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()?;
        require(
            self.original
                .defaults
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                .body
                == self.original.plan.defaults
                && self
                    .original
                    .bios
                    .as_ref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                    .body
                    == self.original.plan.bios,
            "actual owned loader restoration readback differs",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"image":self.original.plan.image,"defaults_restored":true,"original_or_owned_publications_retained":true,"published_image_receipt_verified":false,"execution_authorized":false}),
        )
    }
}
