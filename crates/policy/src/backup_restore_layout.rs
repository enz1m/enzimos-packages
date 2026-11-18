// SPDX-License-Identifier: MIT
//! Fresh complete-recovery identities; captured mount configuration is discarded.
use enzimos_platform::{Result, require};
use serde_json::{Value, json};
const OPTIONS: &str = "noatime,compress=zstd:3,discard=async";
const QUIET: &str = "zswap.enabled=0 quiet splash plymouth.ignore-serial-consoles loglevel=0 rd.systemd.show_status=false systemd.show_status=false rd.udev.log_level=0 udev.log_level=0 vt.global_cursor_default=0";
pub fn layout(filesystem: &str, boot: &str, luks: Option<&str>, diagnostic: bool) -> Result<Value> {
    crate::identity::uuid(filesystem)?;
    require(
        boot.len() == 9
            && boot.as_bytes()[4] == b'-'
            && boot
                .bytes()
                .enumerate()
                .all(|(i, c)| i == 4 || c.is_ascii_hexdigit()),
        "fresh EFI filesystem UUID required",
    )?;
    if let Some(uuid) = luks {
        crate::identity::uuid(uuid)?;
    }
    let storage = json!({"filesystem_uuid":filesystem,"root_subvol":"enzimos-root","home_subvol":"enzimos-home","control_subvol":"enzimos-control","authority_subvol":"enzimos-authority","legacy_boot_entries":{"uefi":["linux.conf","linux-lts.conf"],"bios":["enzimOS linux","enzimOS linux-lts"]}});
    let fstab = format!(
        "UUID={filesystem} / btrfs subvol=enzimos-root,{OPTIONS} 0 0\nUUID={filesystem} /home btrfs subvol=enzimos-home,{OPTIONS} 0 0\nUUID={filesystem} /var/lib/enzimos-control btrfs subvol=enzimos-control,noatime 0 0\nUUID={filesystem} /etc/pacman.d/gnupg btrfs subvol=enzimos-authority,noatime 0 0\nUUID={filesystem} /swap btrfs subvol=enzimos-swap,noatime 0 0\nUUID={boot} /boot vfat fmask=0177,dmask=0077 0 2\n"
    );
    let (root, crypttab) = match luks {
        None => (format!("root=UUID={filesystem}"), String::new()),
        Some(uuid) => (
            format!(
                "rd.luks.name={uuid}=enzimos-crypt rd.luks.options={uuid}=discard root=/dev/mapper/enzimos-crypt"
            ),
            format!("enzimos-crypt UUID={uuid} none luks,discard,x-initrd.attach\n"),
        ),
    };
    let mut options = format!(
        "{root} rootflags=subvol=enzimos-root rw lsm=landlock,lockdown,yama,integrity,apparmor,bpf {QUIET}"
    );
    if diagnostic {
        options.push_str(" console=ttyS0,115200");
    }
    Ok(
        json!({"schema":1,"storage":storage,"fstab":fstab,"crypttab":crypttab,"boot_options":options,"authority_replayed":false,"automatic_backup_enabled":false}),
    )
}
