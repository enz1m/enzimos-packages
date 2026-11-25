// SPDX-License-Identifier: MIT
//! Exact native loader entries and default restoration, without mutation grants.
use crate::{
    boot_entries, recovery_boot, recovery_image, recovery_records as records,
    root_retirement_parameters::Parameters,
};
use enzimos_platform::{Error, Result, require};
pub const INIT: &str = "/usr/lib/enzimos-native/enzimos-recovery-run-init";
pub struct Entries {
    pub uefi: String,
    pub bios: String,
}
pub struct Restoration {
    pub defaults: String,
    pub bios: String,
    pub image: String,
}
fn native_options(options: &str) -> Result<Parameters> {
    records::command_line(options)?;
    let parameters = Parameters::parse(options)?;
    let init = options
        .split_whitespace()
        .filter(|word| word.starts_with("rdinit="))
        .collect::<Vec<_>>();
    require(
        init == [format!("rdinit={INIT}")]
            && options.split_whitespace().all(|word| {
                word.starts_with("enzimos.")
                    || word == format!("rdinit={INIT}")
                    || matches!(word, "console=tty0" | "console=ttyS0,115200")
            }),
        "exact native retirement init without alternate root/init required",
    )?;
    Ok(parameters)
}
pub fn entries(options: &str, image: &str) -> Result<Entries> {
    let p = native_options(options)?;
    recovery_image::identifier(image)?;
    let title = format!(
        "enzimOS root retirement {}",
        p.id.get(5..21).unwrap_or_default()
    );
    let prefix = format!("/enzimos/recovery-images/{image}");
    Ok(Entries {
        uefi: format!(
            "title {title}\nlinux {prefix}/kernel\ninitrd {prefix}/initrd.img\noptions {options}\n"
        ),
        bios: format!(
            "/{title}\n protocol: linux\n path: boot():{prefix}/kernel\n module_path: boot():{prefix}/initrd.img\n cmdline: {options}\n"
        ),
    })
}
fn exact(actual: &str, expected: &str, bios: bool) -> Result<()> {
    let text = actual;
    let mut actual = boot_entries::fields(actual, bios)?;
    let expected = boot_entries::fields(expected, bios)?;
    if !bios && let Some(path) = actual.remove("uki") {
        let digest = path
            .strip_prefix("/enzimos/secure-boot/")
            .and_then(|path| path.strip_suffix(".efi"))
            .ok_or_else(|| {
                Error("native retirement UKI must use canonical owner image path".into())
            })?;
        crate::identity::sha(digest)?;
        require(
            !text
                .lines()
                .any(|line| matches!(line.split_whitespace().next(), Some("linux" | "initrd"))),
            "signed retirement entry must retain commented sources, not alternate executable fields",
        )?;
        // This is only an entry comparison. The original Loaders actor
        // separately verifies content binding, payload and owner signature.
    }
    require(
        actual == expected,
        "retirement loader fields differ from exact native entry",
    )
}
pub fn restore(
    record: &serde_json::Value,
    defaults: &str,
    bios: &str,
    uefi: &str,
) -> Result<Restoration> {
    let coordinator = &record["coordinator"];
    let options = records::text(coordinator, "options")?;
    let p = native_options(options)?;
    p.matches_record(record)?;
    let image = records::text(coordinator, "image")?;
    restore_original(&p, image, options, defaults, bios, uefi)
}
/// Data comparison for actual original kernel/image observers. No write grant.
pub(crate) fn restore_original(
    p: &Parameters,
    image: &str,
    options: &str,
    defaults: &str,
    bios: &str,
    uefi: &str,
) -> Result<Restoration> {
    require(
        native_options(options)? == *p,
        "loader retirement parameters differ from actual kernel boot",
    )?;
    let expected = entries(options, image)?;
    exact(uefi, &expected.uefi, false)?;
    let name = format!(
        "enzimos-root-retire-{}.conf",
        p.id.get(5..21).unwrap_or_default()
    );
    let loader = boot_entries::fields(defaults, false)?;
    let selected = loader
        .get("default")
        .ok_or_else(|| Error("retirement UEFI default missing".into()))?;
    require(
        selected == &name || selected == &p.uefi_previous,
        "foreign UEFI default prevents retirement",
    )?;
    let menu = boot_entries::menu(bios)?;
    require(
        menu.entries.len() == p.bios_own
            && matches!(menu.selected, n if n == p.bios_own || n == p.bios_previous)
            && menu.entries[p.bios_own - 1].title
                == format!(
                    "enzimOS root retirement {}",
                    p.id.get(5..21).unwrap_or_default()
                ),
        "original last retirement BIOS entry/default differs",
    )?;
    exact(&menu.entries[p.bios_own - 1].text, &expected.bios, true)?;
    let next_defaults = if selected == &name {
        recovery_boot::replace_default(defaults, "default ", &p.uefi_previous)?
    } else {
        defaults.into()
    };
    let next_bios = if menu.selected == p.bios_own {
        recovery_boot::replace_default(bios, "default_entry: ", &p.bios_previous.to_string())?
    } else {
        bios.into()
    };
    require(
        boot_entries::menu(&next_bios)?.selected == p.bios_previous
            && boot_entries::fields(&next_defaults, false)?.get("default")
                == Some(&p.uefi_previous),
        "retirement restore plan readback differs",
    )?;
    Ok(Restoration {
        defaults: next_defaults,
        bios: next_bios,
        image: image.into(),
    })
}

/// Online finish derives cleanup from the original deleted receipt and loader
/// bytes. Foreign selections are preserved; an owned entry must match exactly.
/// This data plan cannot authorize a write or adopt a completed cleanup.
pub struct Finish {
    pub defaults: String,
    pub bios: String,
    pub remove_uefi: bool,
    pub clear_one_shot: bool,
}
pub fn finish(
    record: &serde_json::Value,
    defaults: &str,
    bios: &str,
    uefi: Option<&str>,
    one_shot: Option<&[u8]>,
) -> Result<Finish> {
    let id = records::text(record, "id")?;
    crate::root_retirement_record::validate(record, id)?;
    require(
        record["phase"] == "deleted",
        "online cleanup requires actual deleted phase",
    )?;
    let coordinator = &record["coordinator"];
    require(coordinator.is_object(), "finish coordinator absent")?;
    let options = records::text(coordinator, "options")?;
    let parameters = native_options(options)?;
    parameters.matches_record(record)?;
    let expected = entries(options, records::text(coordinator, "image")?)?;
    let own = records::text(coordinator, "uefi_entry")?;
    if let Some(body) = uefi {
        exact(body, &expected.uefi, false)?;
    }
    let fields = boot_entries::fields(defaults, false)?;
    let selected = fields
        .get("default")
        .ok_or_else(|| Error("finish UEFI default missing".into()))?;
    let next_defaults = if selected == own {
        recovery_boot::replace_default(defaults, "default ", &parameters.uefi_previous)?
    } else {
        defaults.into()
    };
    let menu = boot_entries::menu(bios)?;
    let title = records::text(coordinator, "bios_title")?;
    let owned = menu.entries.iter().position(|row| row.title == title);
    let next_bios = if let Some(index) = owned {
        exact(&menu.entries[index].text, &expected.bios, true)?;
        require(
            index + 1 == parameters.bios_own,
            "finish owned BIOS position differs from receipt",
        )?;
        let selected_title = &menu.entries[menu.selected - 1].title;
        let target = if selected_title == title {
            menu.entries
                .get(parameters.bios_previous - 1)
                .ok_or_else(|| Error("finish previous BIOS entry absent".into()))?
                .title
                .as_str()
        } else {
            selected_title
        };
        require(target != title, "finish cannot select removed coordinator")?;
        let remaining = menu
            .entries
            .iter()
            .filter(|row| row.title != title)
            .collect::<Vec<_>>();
        let number = remaining
            .iter()
            .position(|row| row.title == target)
            .ok_or_else(|| Error("finish selected BIOS entry absent".into()))?
            + 1;
        let header =
            recovery_boot::replace_default(&menu.header, "default_entry: ", &number.to_string())?;
        let next = header
            + &remaining
                .iter()
                .map(|row| row.text.as_str())
                .collect::<String>();
        let result = boot_entries::menu(&next)?;
        require(
            result.entries[result.selected - 1].title == target
                && result.entries.iter().all(|row| row.title != title),
            "finish BIOS cleanup readback differs",
        )?;
        next
    } else {
        bios.into()
    };
    let clear_one_shot = match one_shot {
        Some(bytes) => boot_entries::efi_string(bytes)? == own,
        None => false,
    };
    Ok(Finish {
        defaults: next_defaults,
        bios: next_bios,
        remove_uefi: uefi.is_some(),
        clear_one_shot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (serde_json::Value, String, String, String) {
        let options = format!(
            "console=tty0 rdinit={INIT} enzimos.root-retirement=root-0123456789abcdef0123456789abcdef enzimos.luks=01234567-89ab-cdef-0123-456789abcdef enzimos.fs=11234567-89ab-cdef-0123-456789abcdef enzimos.control=control enzimos.esp=ABCD-1234 enzimos.uefi-restore=enzimos.conf enzimos.bios-restore=1:2"
        );
        let image = format!("ri-{}", "a".repeat(64));
        let entry = entries(&options, &image).unwrap();
        let mut record = json!({"schema":2,"id":"root-0123456789abcdef0123456789abcdef","phase":"prepared","filesystem_uuid":"11234567-89ab-cdef-0123-456789abcdef","created_boot":"31234567-89ab-cdef-0123-456789abcdef","birth":"birth-one","targets":[{"role":"root-subvolume","path":"retired","id":300,"uuid":"21234567-89ab-cdef-0123-456789abcdef","parent_uuid":null}],"next_step":0,"inflight":null,"plan_sha256":"0".repeat(64),"coordinator":{"image":image,"uefi_entry":"enzimos-root-retire-0123456789abcdef.conf","uefi_previous":"enzimos.conf","bios_title":"enzimOS root retirement 0123456789abcdef","bios_previous":1,"bios_own":2,"options":options}});
        record["plan_sha256"] = json!(enzimos_platform::json::fingerprint(&json!({"filesystem_uuid":record["filesystem_uuid"],"birth":record["birth"],"targets":record["targets"]})).unwrap());
        (
            record,
            "default enzimos-root-retire-0123456789abcdef.conf\ntimeout 5\n".into(),
            format!(
                "default_entry: 2\n/Previous\n protocol: linux\n path: boot():/previous\n{}",
                entry.bios
            ),
            entry.uefi,
        )
    }
    fn deleted_fixture() -> (serde_json::Value, String, String, String) {
        let (mut record, defaults, bios, entry) = fixture();
        record["phase"] = json!("deleted");
        record["next_step"] = json!(record["targets"].as_array().unwrap().len());
        record["coordinator"]["uefi_mode"] = json!("default");
        (record, defaults, bios, entry)
    }
    #[test]
    fn finish_removes_exact_coordinator_and_restores_only_owned_defaults() {
        let (record, defaults, bios, entry) = deleted_fixture();
        let next = finish(&record, &defaults, &bios, Some(&entry), None).unwrap();
        assert!(next.remove_uefi);
        assert!(!next.clear_one_shot);
        assert_eq!(
            boot_entries::fields(&next.defaults, false).unwrap()["default"],
            "enzimos.conf"
        );
        let menu = boot_entries::menu(&next.bios).unwrap();
        assert_eq!(menu.entries.len(), 1);
        assert_eq!(menu.selected, 1);
    }
}
