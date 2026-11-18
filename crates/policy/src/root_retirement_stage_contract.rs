// SPDX-License-Identifier: MIT
//! Exact native coordinator staging comparisons. Metadata grants no write authority.
use crate::{
    boot_entries, recovery_boot, recovery_image, recovery_records as records,
    root_retirement_boot_contract as contract, root_retirement_parameters::Parameters,
};
use enzimos_platform::{Result, require};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
pub enum UefiMode {
    Default,
    OneShot,
}
pub struct Stage {
    pub record: Value,
    pub uefi: String,
    pub bios: String,
    pub defaults: String,
}
pub fn prepare(
    record: &Value,
    image: &Value,
    luks_uuid: &str,
    control: &str,
    esp: &str,
    loader: &str,
    bios: &str,
    exit: &str,
    mode: UefiMode,
) -> Result<Stage> {
    let id = records::text(record, "id")?;
    crate::root_retirement_record::validate(record, id)?;
    crate::identity::uuid(luks_uuid)?;
    crate::identity::safe_id(control)?;
    records::fat_uuid(esp)?;
    require(
        record["schema"] == 1
            && record["phase"] == "prepared"
            && record.get("coordinator").is_none(),
        "one original prepared Root receipt without a coordinator required",
    )?;
    let root = record["targets"].as_array().unwrap().last().unwrap();
    require(
        id == format!("root-{}", records::text(root, "uuid")?.replace('-', "")),
        "coordinator receipt must identify exact original Root",
    )?;
    let image_id = records::text(image, "id")?;
    recovery_image::validate(image, image_id)?;
    require(
        image["phase"] == "ready"
            && image["inputs"]["identity"]["schema"] == 2
            && image["filesystem_uuid"] == record["filesystem_uuid"]
            && image["boot_uuid"] == esp
            && image["control"]["path"] == control,
        "ready native image must match Root filesystem, control and ESP",
    )?;
    require(
        matches!(exit, "reboot" | "poweroff"),
        "closed coordinator exit mode required",
    )?;
    let short = &id[5..21];
    let entry = format!("enzimos-root-retire-{short}.conf");
    let title = format!("enzimOS root retirement {short}");
    let fields = boot_entries::fields(loader, false)?;
    let previous = fields.get("default").ok_or_else(|| {
        enzimos_platform::Error("one original literal UEFI default required".into())
    })?;
    records::literal_entry(previous)?;
    require(
        previous != &entry,
        "coordinator cannot adopt its own existing default",
    )?;
    let menu = boot_entries::menu(bios)?;
    require(
        menu.entries.len() < 256 && menu.entries.iter().all(|item| item.title != title),
        "coordinator must be a new bounded final BIOS entry",
    )?;
    let own = menu.entries.len() + 1;
    let console = records::text(image, "options")?
        .split_whitespace()
        .filter(|word| word.starts_with("console="))
        .collect::<Vec<_>>();
    require(
        console.len() <= 2
            && console
                .iter()
                .all(|word| matches!(*word, "console=tty0" | "console=ttyS0,115200"))
            && console
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == console.len(),
        "native coordinator supports only exact independent console options",
    )?;
    let options = format!(
        "{}rdinit={} enzimos.root-retirement={} enzimos.luks={} enzimos.fs={} enzimos.control={} enzimos.esp={} enzimos.uefi-restore={} enzimos.bios-restore={}:{} enzimos.coordinator-exit={}",
        if console.is_empty() {
            String::new()
        } else {
            format!("{} ", console.join(" "))
        },
        contract::INIT,
        id,
        luks_uuid,
        records::text(record, "filesystem_uuid")?,
        control,
        esp,
        previous,
        menu.selected,
        own,
        exit
    );
    let mut staged = record.clone();
    staged["schema"] = json!(2);
    staged["coordinator"] = json!({"image":image_id,"uefi_entry":entry,"uefi_previous":previous,
        "bios_title":title,"bios_previous":menu.selected,"bios_own":own,"options":options,
        "uefi_mode":match mode {UefiMode::Default=>"default",UefiMode::OneShot=>"one-shot"}});
    crate::root_retirement_record::validate(&staged, id)?;
    Parameters::parse(&options)?.matches_record(&staged)?;
    let entries = contract::entries(&options, image_id)?;
    let appended = format!("{}\n{}", bios.trim_end(), entries.bios);
    let bios = recovery_boot::replace_default(&appended, "default_entry: ", &own.to_string())?;
    let defaults = match mode {
        UefiMode::Default => recovery_boot::replace_default(loader, "default ", &entry)?,
        UefiMode::OneShot => loader.into(),
    };
    // The same offline grammar must restore the exact original defaults before unlock.
    let restoration = contract::restore(&staged, &defaults, &bios, &entries.uefi)?;
    require(
        boot_entries::fields(&restoration.defaults, false)? == boot_entries::fields(loader, false)?
            && boot_entries::menu(&restoration.bios)?.selected == menu.selected,
        "staged native coordinator does not restore exact original selection",
    )?;
    Ok(Stage {
        record: staged,
        uefi: entries.uefi,
        bios,
        defaults,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const FS: &str = "11111111-1111-4111-8111-111111111111";
    const ROOT: &str = "22222222-2222-4222-8222-222222222222";
    const LUKS: &str = "33333333-3333-4333-8333-333333333333";
    const ESP: &str = "ABCD-1234";
    fn fixture() -> (Value, Value, String, String) {
        let targets = json!([{"role":"root-subvolume","path":"old-root","id":400,"uuid":ROOT,"parent_uuid":null}]);
        let sha = enzimos_platform::json::fingerprint(
            &json!({"filesystem_uuid":FS,"birth":"superseded-job9","targets":targets}),
        )
        .unwrap();
        let root = json!({"schema":1,"id":format!("root-{}",ROOT.replace('-',"")),"phase":"prepared",
            "filesystem_uuid":FS,"created_boot":LUKS,"birth":"superseded-job9","targets":targets,
            "next_step":0,"inflight":null,"plan_sha256":sha});
        let descriptor = json!({"schema":2,"kernel_release":"6.18.1","kernel_sha256":"e".repeat(64),
            "base_initrd_sha256":"f".repeat(64),"policy_files":{"enzimos-policy":"a".repeat(64),
            "enzimos-recovery-image-init":"b".repeat(64),"enzimos-recovery-run-init":"c".repeat(64),"recovery-pacman.conf":"d".repeat(64)}});
        let id = recovery_image::image_id(&descriptor).unwrap();
        let image = json!({"schema":1,"id":id,"phase":"ready","created_boot":LUKS,"filesystem_uuid":FS,
            "control":{"path":"control","id":260,"uuid":"44444444-4444-4444-8444-444444444444","parent_uuid":null},
            "boot_uuid":ESP,"inputs":{"schema":1,"identity":descriptor,"files":{"kernel":{"bytes":200,"sha256":"e".repeat(64)},
            "initrd.img":{"bytes":300,"sha256":"f".repeat(64)}}},"options":format!("console=tty0 console=ttyS0,115200 enzimos.recovery={id}"),"observations":{}});
        let loader = "default normal.conf\ntimeout 3\n".into();
        let bios="default_entry: 1\n/Normal\n protocol: linux\n path: boot():/kernel\n module_path: boot():/initrd\n cmdline: root=UUID=x rootflags=subvol=live\n".into();
        (root, image, loader, bios)
    }
    #[test]
    fn stage_refuses_foreign_unready_legacy_images_and_receipt_replay() {
        let (root, image, loader, bios) = fixture();
        let run = |root: &Value, image: &Value| {
            prepare(
                root,
                image,
                LUKS,
                "control",
                ESP,
                &loader,
                &bios,
                "reboot",
                UefiMode::OneShot,
            )
        };
        for (key, changed) in [
            ("phase", json!("intent")),
            ("filesystem_uuid", json!(LUKS)),
            ("boot_uuid", json!("EEEE-FFFF")),
        ] {
            let mut bad = image.clone();
            bad[key] = changed;
            assert!(run(&root, &bad).is_err());
        }
        let mut bad = image.clone();
        bad["control"]["path"] = json!("foreign-control");
        assert!(run(&root, &bad).is_err());
        let mut bad = image.clone();
        bad["inputs"]["identity"]["schema"] = json!(1);
        assert!(run(&root, &bad).is_err());
        let staged = run(&root, &image).unwrap();
        assert!(run(&staged.record, &image).is_err());
        let mut deleted = root.clone();
        deleted["phase"] = json!("deleted");
        deleted["next_step"] = json!(1);
        assert!(run(&deleted, &image).is_err());
        assert!(
            prepare(
                &root,
                &image,
                LUKS,
                "control",
                ESP,
                &loader,
                &bios,
                "halt",
                UefiMode::Default
            )
            .is_err()
        );
    }
}
