// SPDX-License-Identifier: MIT
//! Detach exactly the loader-started attempt before encrypted storage is opened.
use crate::{
    boot_entries, recovery_boot, recovery_records as records, recovery_run_parameters::Parameters,
};
use enzimos_platform::{Error, Result, require};
use std::collections::BTreeMap;
pub struct Detachment {
    pub(crate) defaults: String,
    pub(crate) bios: String,
    pub remove_uefi: bool,
    pub(crate) image: Option<String>,
}
fn bound_image(fields: &BTreeMap<String, String>, bios: bool, p: &Parameters) -> Result<String> {
    let get = |name: &str| {
        fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| Error("recovery run entry field missing".into()))
    };
    require(
        Parameters::parse(get(if bios { "cmdline" } else { "options" })?)? == *p,
        "run entry parameters differ from actual boot",
    )?;
    let kernel = get(if bios { "path" } else { "linux" })?;
    let kernel = if bios {
        kernel
            .strip_prefix("boot():")
            .ok_or_else(|| Error("run BIOS kernel path".into()))?
    } else {
        kernel
    };
    let image = kernel
        .strip_prefix("/enzimos/recovery-images/")
        .and_then(|s| s.strip_suffix("/kernel"))
        .ok_or_else(|| Error("run image kernel path".into()))?;
    crate::recovery_image::identifier(image)?;
    let initrd = format!(
        "{}/enzimos/recovery-images/{image}/initrd.img",
        if bios { "boot():" } else { "" }
    );
    require(
        get(if bios { "module_path" } else { "initrd" })? == initrd,
        "run image initrd path differs",
    )?;
    if bios {
        require(get("protocol")? == "linux", "run BIOS protocol differs")?;
    }
    Ok(image.to_owned())
}
pub(crate) fn plan(
    p: &Parameters,
    defaults: &str,
    bios: &str,
    uefi: Option<&str>,
) -> Result<Detachment> {
    let (name, title) = records::run_entry_names(&p.id)?;
    let loader = boot_entries::fields(defaults, false)?;
    let selected = loader
        .get("default")
        .ok_or_else(|| Error("run UEFI default missing".into()))?;
    require(
        selected == &p.uefi_previous || selected == &name,
        "run UEFI default drift",
    )?;
    let next = if selected == &name {
        recovery_boot::replace_default(defaults, "default ", &p.uefi_previous)?
    } else {
        defaults.to_owned()
    };
    let mut image = None;
    if let Some(body) = uefi {
        let fields = boot_entries::fields(body, false)?;
        require(
            fields.get("title") == Some(&title),
            "run UEFI title differs",
        )?;
        image = Some(bound_image(&fields, false, p)?);
    }
    let menu = boot_entries::menu(bios)?;
    require(
        menu.selected == p.bios_previous || menu.selected == p.bios_own,
        "run BIOS default drift",
    )?;
    let owned = menu.entries.iter().position(|row| row.title == title);
    let bios = if let Some(index) = owned {
        require(
            menu.entries.len() == p.bios_own && index + 1 == p.bios_own,
            "run BIOS entry is not the last recorded entry",
        )?;
        let actual_image = bound_image(
            &boot_entries::fields(&menu.entries[index].text, true)?,
            true,
            p,
        )?;
        require(
            image.as_ref().is_none_or(|s| s == &actual_image),
            "run loader images disagree",
        )?;
        image = Some(actual_image);
        let header = if menu.selected == p.bios_own {
            recovery_boot::replace_default(
                &menu.header,
                "default_entry: ",
                &p.bios_previous.to_string(),
            )?
        } else {
            menu.header
        };
        header
            + &menu.entries[..index]
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>()
    } else {
        require(
            menu.selected == p.bios_previous && menu.entries.len() + 1 == p.bios_own,
            "detached run BIOS baseline differs",
        )?;
        bios.to_owned()
    };
    boot_entries::menu(&bios)?;
    Ok(Detachment {
        defaults: next,
        bios,
        remove_uefi: uefi.is_some(),
        image,
    })
}
