// SPDX-License-Identifier: MIT
//! Fresh owner-signature and payload closure, including detached candidate UKIs.
use super::*;
use crate::{boot_retirement_context::SignedInventory, secure_owner_source::Owner, signed_entry};
pub(super) struct Signed {
    inventory: SignedInventory,
    orphans: Vec<signed_entry::Verification>,
    owner: Option<Owner>,
}
fn fields(
    generation: &str,
    flavor: &str,
    options: &str,
    relative: &str,
) -> Result<BTreeMap<String, String>> {
    identity::safe_id(generation)?;
    require(
        matches!(flavor, "linux" | "linux-lts"),
        "fixed signed continuation flavor required",
    )?;
    require(
        crate::boot_options::generation_options(options, generation)? == options,
        "registered signed continuation options required",
    )?;
    require(
        relative.starts_with("/enzimos/secure-boot/") && relative.ends_with(".efi"),
        "owned signed continuation output required",
    )?;
    identity::sha(
        relative
            .trim_start_matches("/enzimos/secure-boot/")
            .trim_end_matches(".efi"),
    )?;
    Ok(BTreeMap::from([
        (
            "linux".into(),
            format!("/enzimos/generations/{generation}/vmlinuz-{flavor}"),
        ),
        (
            "initrd".into(),
            format!("/enzimos/generations/{generation}/initramfs-{flavor}.img"),
        ),
        ("options".into(), options.into()),
        ("uki".into(), relative.into()),
    ]))
}
impl Signed {
    pub(super) fn observe(admission: &Admission<'_>) -> Result<Self> {
        let loaders = admission
            .loaders
            .as_ref()
            .ok_or_else(|| Error("original loader closure required".into()))?;
        let mut permission = || {
            admission.guard.recheck()?;
            admission.lock.recheck()?;
            admission.record.recheck()?;
            admission.catalog.recheck()?;
            loaders.recheck(admission)
        };
        let inventory =
            SignedInventory::observe(&admission.volume, loaders.texts(), &mut permission)?;
        let evidence = inventory.evidence(&admission.volume, &mut permission)?;
        let referenced: BTreeSet<_> = enzimos_platform::json::object(&evidence["entries"])?
            .values()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let generation =
            enzimos_platform::json::string(&admission.record.value()?["intent"]["id"])?
                .strip_prefix("boot-")
                .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?;
        let mut orphans = Vec::new();
        let mut owner = None;
        for (path, artifact) in &admission.artifacts {
            if !path.starts_with("enzimos/secure-boot") {
                continue;
            }
            let relative = format!("/{}", path.display());
            if referenced.contains(&relative) {
                continue;
            }
            if owner.is_none() {
                owner = Some(Owner::credentials()?);
            }
            let authority = owner
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?;
            authority.recheck()?;
            let cert = authority
                .certificate_hash()
                .ok_or_else(|| Error("original owner certificate required".into()))?;
            let row = admission.catalog.data["generations"]
                .get(generation)
                .ok_or_else(|| {
                    Error("orphan candidate UKI requires original registered material".into())
                })?;
            let options = row["material"]["options"]
                .as_str()
                .ok_or_else(|| Error("original registered signed options required".into()))?;
            let mut matches = Vec::new();
            for flavor in ["linux", "linux-lts"] {
                let kernel =
                    PathBuf::from(format!("enzimos/generations/{generation}/vmlinuz-{flavor}"));
                let initrd = PathBuf::from(format!(
                    "enzimos/generations/{generation}/initramfs-{flavor}.img"
                ));
                let kernel = admission.artifacts.get(&kernel).ok_or_else(|| {
                    Error("detached UKI lacks original retained source kernel".into())
                })?;
                let initrd = admission.artifacts.get(&initrd).ok_or_else(|| {
                    Error("detached UKI lacks original retained source initramfs".into())
                })?;
                kernel.recheck()?;
                initrd.recheck()?;
                if format!(
                    "/enzimos/secure-boot/{}.efi",
                    signed_entry::digest(&kernel.sha, &initrd.sha, options, &cert)?
                ) == relative
                {
                    matches.push(flavor);
                }
            }
            require(
                matches.len() == 1,
                "detached UKI source/owner binding is ambiguous or changed",
            )?;
            let fields = fields(generation, matches[0], options, &relative)?;
            let verified = signed_entry::retain(&fields)?
                .ok_or_else(|| Error("actual detached UKI owner verification required".into()))?;
            require(
                verified.relative() == relative
                    && files::identity(&verified.descriptor()?.metadata()?)
                        == files::identity(&artifact.file.metadata()?),
                "detached UKI verification differs from original continuation inode",
            )?;
            permission()?;
            authority.recheck()?;
            orphans.push(verified);
        }
        let this = Self {
            inventory,
            orphans,
            owner,
        };
        this.recheck(admission)?;
        Ok(this)
    }
    pub(super) fn retire_original_image(
        &mut self,
        volume: &Volume,
        relative: &Path,
        retired: &crate::boot_volume::RetiredArtifact,
    ) -> Result<()> {
        self.inventory
            .retire_original_image(volume, &format!("/{}", relative.display()), retired)
    }
    pub(super) fn recheck_owned(
        &self,
        admission: &Admission<'_>,
        journal: &ContinuationJournal,
        retired: &BTreeMap<PathBuf, crate::boot_volume::RetiredArtifact>,
    ) -> Result<()> {
        let mut permission = || {
            admission.guard.recheck()?;
            admission.lock.recheck()?;
            journal.recheck()?;
            admission.catalog.recheck()
        };
        self.inventory
            .recheck_owned(&admission.volume, retired, &mut permission)?;
        for orphan in &self.orphans {
            orphan.recheck_owned_retirements(retired)?;
        }
        if let Some(owner) = &self.owner {
            owner.recheck()?;
        }
        permission()
    }
    pub(super) fn recheck(&self, admission: &Admission<'_>) -> Result<()> {
        let mut permission = || {
            admission.guard.recheck()?;
            admission.lock.recheck()?;
            admission.record.recheck()?;
            admission.catalog.recheck()?;
            admission
                .loaders
                .as_ref()
                .ok_or_else(|| Error("original loader closure missing".into()))?
                .recheck(admission)
        };
        self.inventory.recheck(&admission.volume, &mut permission)?;
        for orphan in &self.orphans {
            orphan.recheck()?;
        }
        if let Some(owner) = &self.owner {
            owner.recheck()?;
        }
        permission()
    }
    pub(super) fn evidence(&self, admission: &Admission<'_>) -> Result<Value> {
        self.recheck(admission)?;
        let inventory = self.inventory.evidence(&admission.volume, &mut || {
            admission.guard.recheck()?;
            admission.lock.recheck()
        })?;
        let result = value!({"inventory":inventory,"detached_candidate_outputs":self.orphans.iter().map(super::super::signed_entry::Verification::relative).collect::<Vec<_>>(),"owner":self.owner.as_ref().map(Owner::identity).transpose()?,"execution_authorized":false});
        self.recheck(admission)?;
        Ok(result)
    }
}
