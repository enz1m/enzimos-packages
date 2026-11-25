// SPDX-License-Identifier: MIT
//! Verified artifacts and an unlock key are sealed in RAM for one kexec attempt.
use crate::{
    boot_entries, boot_volume::Volume, identity, initramfs, recovery_activation, recovery_boot,
    recovery_records as records, recovery_run_parameters::Parameters,
};
use enzimos_platform::{Error, Result, files, json, memfile, require};
use serde_json::{Value, json as value};
use std::{ffi::CString, os::fd::AsRawFd, path::Path};
pub(crate) const KEY: &str = "enzimos-recovery-unlock.key";
pub(crate) fn options(id: &str, activation: &Value, luks: &str) -> Result<String> {
    records::job_id(id)?;
    identity::uuid(luks)?;
    recovery_activation::validate(activation, id)?;
    require(
        matches!(activation["phase"].as_str(), Some("selected" | "adopted")),
        "selected native activation required for handoff",
    )?;
    let flavor = records::text(&activation["selection"], "flavor")?;
    let name = recovery_activation::entry_names(id, flavor)?.0;
    let entries = recovery_boot::entries(&activation["intent"]["job"])?;
    let fields = boot_entries::fields(&entries.uefi[&name], false)?;
    let options = fields
        .get("options")
        .ok_or_else(|| Error("staged handoff options missing".into()))?;
    require(
        !options.split_whitespace().any(|w| {
            [
                "rd.luks.key=",
                "luks.key=",
                "enzimos.handoff=",
                "rd.luks.crypttab=",
            ]
            .iter()
            .any(|prefix| w.starts_with(prefix))
        }),
        "conflicting recovery handoff options",
    )?;
    let result = format!(
        "{options} quiet loglevel=0 rd.systemd.show_status=false systemd.show_status=false enzimos.handoff={id} rd.luks.crypttab=no rd.luks.key={luks}=/{KEY}"
    );
    records::command_line(&result)?;
    Ok(result)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
pub(crate) fn load(id: &str, activation: &Value, luks: &str, secret: &[u8]) -> Result<Value> {
    crate::recovery_bootstrap::quiet()?;
    require(
        std::env::consts::ARCH == "x86_64" && !secret.is_empty() && secret.len() < 1000,
        "qualified RAM handoff architecture and key bound required",
    )?;
    require(
        activation["intent"]["schema"] == 2,
        "native handoff policy required",
    )?;
    let command = options(id, activation, luks)?;
    let flavor = records::text(&activation["selection"], "flavor")?;
    let plan = &activation["intent"]["job"]["plan"];
    let volume = Volume::observe()?;
    require(
        volume.uuid == plan["boot_uuid"],
        "handoff ESP differs from selected plan",
    )?;
    let artifact = |name: &str| -> Result<(crate::boot_volume::Artifact, Vec<u8>)> {
        let expected = plan["material"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .ok_or_else(|| Error("handoff artifact is not recorded".into()))?;
        let path = format!(
            "enzimos/generations/{}/{name}",
            records::text(plan, "generation")?
        );
        let file = volume.artifact(Path::new(&path), crate::recovery_image::MAX_IMAGE)?;
        require(
            file.bytes == expected["bytes"].as_u64().unwrap()
                && file.sha == records::text(expected, "sha256")?,
            "handoff artifact binding differs",
        )?;
        let body = files::read_file(
            &file.file,
            crate::recovery_image::MAX_IMAGE as usize,
            Some(0),
            true,
        )?;
        require(
            json::sha256(&body) == file.sha,
            "handoff artifact readback differs",
        )?;
        file.recheck()?;
        Ok((file, body))
    };
    let (kernel, kernel_body) = artifact(&format!("vmlinuz-{flavor}"))?;
    let (base, base_body) = artifact(&format!("initramfs-{flavor}.img"))?;
    let initrd = initramfs::append_private(&base_body, KEY, secret, 0o100600)?;
    let kernel_fd = memfile::sealed("enzimos-restored-kernel", &kernel_body)?;
    let initrd_fd = memfile::sealed("enzimos-restored-initrd", &initrd)?;
    let command_c =
        CString::new(command.as_str()).map_err(|_| Error("handoff command line NUL".into()))?;
    kernel.recheck()?;
    base.recheck()?;
    volume.recheck()?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_kexec_file_load,
            kernel_fd.as_raw_fd(),
            initrd_fd.as_raw_fd(),
            command.len() + 1,
            command_c.as_ptr(),
            0 as libc::c_ulong,
        )
    };
    require(result == 0, "kernel declined RAM recovery handoff")?;
    Ok(
        value!({"cmdline_sha256":json::sha256(command.as_bytes()),"kernel_sha256":kernel.sha,"base_initrd_sha256":base.sha}),
    )
}
pub(crate) fn validate(
    id: &str,
    activation: &Value,
    run: &Value,
    command: &str,
    selected: Option<&str>,
) -> Result<()> {
    records::run(run, id)?;
    let p = Parameters::parse(records::text(&run["entry"], "options")?)?;
    p.matches_record(run, &activation["intent"]["job"])?;
    require(
        p.id == id
            && p.automatic
            && matches!(run["phase"].as_str(), Some("executed" | "complete"))
            && run["plan_sha256"] == activation["intent"]["job"]["plan"]["plan_sha256"],
        "no explicitly authorized executed handoff",
    )?;
    let expected = options(id, activation, &p.luks)?;
    require(
        command.trim() == expected,
        "actual handoff command line differs",
    )?;
    let receipt = &run["result"]["handoff"];
    json::fields(receipt, "cmdline_sha256 kernel_sha256 base_initrd_sha256")?;
    require(
        receipt["cmdline_sha256"] == json::sha256(expected.as_bytes()),
        "handoff command receipt differs",
    )?;
    let flavor = records::text(&activation["selection"], "flavor")?;
    for (key, name) in [
        ("kernel_sha256", format!("vmlinuz-{flavor}")),
        ("base_initrd_sha256", format!("initramfs-{flavor}.img")),
    ] {
        let material = activation["intent"]["job"]["plan"]["material"]["files"]
            .as_array()
            .unwrap();
        let artifact = material
            .iter()
            .find(|v| v["name"] == name)
            .ok_or_else(|| Error("handoff artifact receipt missing".into()))?;
        require(
            receipt[key] == artifact["sha256"],
            "handoff artifact receipt differs",
        )?;
    }
    let source_entry = records::run_entry_names(id)?.0;
    require(
        selected.is_none_or(|s| s == source_entry),
        "handoff EFI origin differs",
    )
}
