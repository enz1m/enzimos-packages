// SPDX-License-Identifier: MIT
//! Generation of the boot menu material from installed loader entries.
use enzimos_platform::{Error, Result, files, require};
use std::collections::BTreeMap;
use std::path::Path;

/// Fields of a loader configuration file, by key.
pub fn parse(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::<String, Vec<String>>::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(index) = line.find(char::is_whitespace) {
            let (key, value) = line.split_at(index);
            let value = value.trim();
            if !value.is_empty() {
                result
                    .entry(key.to_owned())
                    .or_default()
                    .push(value.to_owned());
            }
        }
    }
    result
}
fn entry_name(s: &str) -> bool {
    s.ends_with(".conf")
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._@+-".contains(&c))
}
fn read(path: &Path) -> Result<String> {
    String::from_utf8(files::read(path, 65536, Some(0), true)?)
        .map_err(|_| Error("invalid boot entry text".into()))
}
fn tools(names: &[&str]) -> Vec<String> {
    let mut names = names.to_vec();
    names.resize(23, "gptsync");
    vec![
        format!("showtools {}", names.join(",")),
        "dont_scan_tools gptsync.efi,gptsync_x64.efi,gptsync_ia32.efi,gptsync_aa64.efi".into(),
    ]
}
fn lines(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}
/// Boot menu files for the ESP at `boot`, optionally with a pending restore entry.
///
/// # Errors
///
/// Fails unless the caller is Root, or when the loader configuration or entries are missing or
/// ambiguous.
pub fn material(boot: &Path, restore_pending: bool) -> Result<BTreeMap<String, Vec<u8>>> {
    require(
        enzimos_platform::process_identity::effective_uid() == 0,
        "Root boot configuration writer required",
    )?;
    let directory = boot.join("EFI/enzimos");
    files::directory(&directory, Some(0))?;
    let config = parse(&read(&boot.join("loader/loader.conf"))?);
    require(
        config
            .get("default")
            .is_some_and(|values| values.len() == 1),
        "One literal loader default required",
    )?;
    let mut default = config
        .get("default")
        .and_then(|v| v.first())
        .map_or("linux.conf", String::as_str)
        .to_owned();
    if restore_pending && default.starts_with("enzimos-recovery-run-") {
        let runs =
            crate::recovery_journal::Journal::open(crate::recovery_journal::Kind::Runs, false)?;
        let matching = runs
            .records
            .values()
            .filter(|run| run["phase"] == "staged" && run["entry"]["uefi_entry"] == default)
            .collect::<Vec<_>>();
        require(
            matching.len() == 1,
            "Exact pending recovery run default required",
        )?;
        default = crate::recovery_records::text(&matching[0]["entry"], "uefi_previous")?.into();
        runs.unchanged()?;
    }
    require(entry_name(&default), "Unsupported loader default")?;
    let entries = boot.join("loader/entries");
    read(&entries.join(&default))?;
    menus(&default, |candidate| {
        let path = entries.join(candidate);
        if !path.is_file() {
            return Ok(false);
        }
        read(&path)?;
        Ok(true)
    })
}
/// Render the three rEFInd menus for a selected loader entry. `alternate` reports
/// whether the other kernel flavor's entry exists and is readable.
fn menus(
    default: &str,
    alternate: impl FnOnce(&str) -> Result<bool>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut main = lines(&[
        // Space held during startup reveals the chooser; normal boots proceed immediately.
        "timeout -1",
        "resolution max",
        "use_graphics_for linux,windows,grub,elilo,osx",
        "enable_mouse",
        "scanfor manual,internal,external,optical",
        "scan_all_linux_kernels false",
        "selection_big icons/selection-big.png",
        "selection_small icons/selection-small.png",
        "font icons/font.png",
        "hideui hints,arrows,badges",
        "banner background.png",
        "banner_scale fillscreen",
        "icons_dir icons",
        "big_icon_size 128",
        "small_icon_size 48",
        "default_selection \"Start enzimOS\"",
        "menuentry \"Start enzimOS\" {",
        " icon /EFI/enzimos/icons/os_enzimos.png",
        " loader /EFI/systemd/systemd-bootx64.efi",
        " graphics on",
        "}",
        "dont_scan_dirs +,enzimos-esp:EFI/enzimos,enzimos-esp:EFI/systemd,enzimos-esp:EFI/BOOT",
        "dont_scan_files +,enzimos-esp:/vmlinuz-linux,enzimos-esp:/vmlinuz-linux-lts",
    ]);
    main.extend(tools(&[]));
    let (flavor, label, candidate) = if let Some(prefix) = default.strip_suffix("linux-lts.conf") {
        ("linux", "Standard kernel", format!("{prefix}linux.conf"))
    } else if let Some(prefix) = default.strip_suffix("linux.conf") {
        (
            "linux-lts",
            "Long-term support kernel",
            format!("{prefix}linux-lts.conf"),
        )
    } else {
        return Err(Error("unsupported selected kernel entry".into()));
    };
    if alternate(&candidate)? {
        main.extend([
            format!("menuentry \"enzimOS - {label}\" {{"),
            format!(
                " icon /EFI/enzimos/icons/{}.png",
                if flavor == "linux-lts" {
                    "kernel-lts"
                } else {
                    "kernel"
                }
            ),
            " graphics on".into(),
            " loader /EFI/enzimos/select-entry.efi".into(),
            format!(" options \"{flavor}\""),
            "}".into(),
        ]);
    }
    for (label, icon, name) in [
        ("System Recovery", "tool_rescue", "recovery.conf"),
        ("Power", "menu-power", "power.conf"),
    ] {
        main.extend([
            format!("menuentry \"{label}\" {{"),
            format!(" icon /EFI/enzimos/icons/{icon}.png"),
            " graphics on".into(),
            " loader /EFI/enzimos/refind_x64.efi".into(),
            format!(" options \"refind -c {name}\""),
            "}".into(),
        ]);
    }
    let common = lines(&[
        "timeout 0",
        "resolution max",
        "enable_mouse",
        "scanfor manual",
        "scan_all_linux_kernels false",
        "selection_big icons/selection-big.png",
        "selection_small icons/selection-small.png",
        "font icons/font.png",
        "hideui hints,arrows,badges,label",
        "banner background.png",
        "banner_scale fillscreen",
        "icons_dir icons",
        "big_icon_size 128",
        "small_icon_size 128",
    ]);
    let mut recovery = common.clone();
    recovery.push("banner icons/recovery-background.png".into());
    recovery.extend(tools(&["exit"]));
    for (label, icon, mode) in [
        ("Graphical recovery", "recovery-graphical", "recovery"),
        (
            "Command-line recovery",
            "recovery-console",
            "recovery-console",
        ),
    ] {
        recovery.extend([
            format!("menuentry \"{label}\" {{"),
            format!(" icon /EFI/enzimos/icons/{icon}.png"),
            " graphics on".into(),
            " loader /EFI/enzimos/select-entry.efi".into(),
            format!(" options \"{mode}\""),
            "}".into(),
        ]);
    }
    let mut power = common;
    power.push("banner icons/power-background.png".into());
    power.extend(tools(&["reboot", "shutdown", "firmware", "exit"]));
    Ok([
        ("recovery.conf", recovery),
        ("power.conf", power),
        ("refind.conf", main),
    ]
    .into_iter()
    .map(|(name, content)| (name.into(), (content.join("\n") + "\n").into_bytes()))
    .collect())
}
/// Write the boot menu files to the ESP at `boot`.
///
/// # Errors
///
/// Fails when the material is incomplete or a file cannot be written.
pub fn render(boot: &Path, restore_pending: bool) -> Result<()> {
    let mut contents = material(boot, restore_pending)?;
    let directory = files::directory(&boot.join("EFI/enzimos"), Some(0))?;
    let mode = files::public_file_mode(&directory)?;
    // Publish the parent menu last, after both child menus are durable.
    for name in ["recovery.conf", "power.conf", "refind.conf"] {
        let content = contents
            .remove(name)
            .ok_or_else(|| Error("boot menu material incomplete".into()))?;
        files::atomic_relative(
            &directory,
            Path::new(name),
            &content,
            mode,
            Some(0),
            true,
            65536,
        )?;
    }
    Ok(())
}
/// Write the boot menu files to the retained ESP `volume`.
///
/// # Errors
///
/// Fails when the volume changed, the material is incomplete, or a file cannot be written.
pub fn render_live(volume: &crate::boot_volume::Volume, restore_pending: bool) -> Result<()> {
    volume.writable()?;
    volume.directory(Path::new("EFI/enzimos"))?;
    volume.directory(Path::new("loader/entries"))?;
    render(Path::new("/boot"), restore_pending)?;
    volume.recheck()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refind_excludes_duplicate_loaders_only_from_the_enzimos_esp() {
        let material = menus("linux.conf", |_| Ok(true)).unwrap();
        let menu = std::str::from_utf8(&material["refind.conf"]).unwrap();
        assert!(menu.contains("scanfor manual,internal,external,optical"));
        for directive in ["dont_scan_dirs", "dont_scan_files"] {
            let exclusions = menu
                .lines()
                .find(|line| line.starts_with(directive))
                .unwrap();
            assert!(
                exclusions
                    .split_once("+,")
                    .unwrap()
                    .1
                    .split(',')
                    .all(|entry| { entry.starts_with("enzimos-esp:") })
            );
        }
    }
}
