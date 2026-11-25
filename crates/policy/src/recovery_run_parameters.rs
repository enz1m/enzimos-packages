// SPDX-License-Identifier: MIT
//! Kernel-supplied run identity is bounded and unambiguous before device access.
use crate::{identity, recovery_records as records};
use enzimos_platform::{Error, Result, require};
use std::collections::BTreeMap;
/// Recovery run identity read from the kernel command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    /// Recovery job identifier.
    pub id: String,
    /// LUKS UUID of the encrypted root.
    pub luks: String,
    /// Btrfs filesystem UUID.
    pub filesystem: String,
    /// Control subvolume.
    pub control: String,
    /// Authority subvolume.
    pub authority: String,
    /// ESP filesystem UUID.
    pub esp: String,
    /// UEFI loader entry to restore afterwards.
    pub uefi_previous: String,
    /// Index of the BIOS menu entry to restore afterwards.
    pub bios_previous: usize,
    /// Index of this run's own BIOS menu entry.
    pub bios_own: usize,
    /// Power action after the run (`reboot` or `poweroff`).
    pub exit: String,
    /// Whether the run was started automatically.
    pub automatic: bool,
}
impl Parameters {
    /// Parse the `enzimos.*` parameters of a kernel command line.
    ///
    /// # Errors
    ///
    /// Fails when the command line is too long, a parameter is missing, duplicated, malformed or
    /// unknown.
    pub fn parse(command_line: &str) -> Result<Self> {
        require(
            command_line.len() <= 65536 && !command_line.contains('\0'),
            "recovery kernel command line bound",
        )?;
        let mut fields = BTreeMap::new();
        for word in command_line.split_whitespace() {
            if word.starts_with("enzimos.") {
                let (name, body) = word
                    .split_once('=')
                    .ok_or_else(|| Error("recovery kernel parameter requires value".into()))?;
                require(
                    !body.is_empty() && fields.len() < 64 && fields.insert(name, body).is_none(),
                    "duplicate or excess recovery kernel parameter",
                )?;
            }
        }
        require(
            ![
                "enzimos.staged",
                "enzimos.recovery",
                "enzimos.handoff",
                "enzimos.root-retirement",
            ]
            .iter()
            .any(|key| fields.contains_key(key)),
            "conflicting recovery boot family marker",
        )?;
        let field = |key| {
            fields
                .get(key)
                .copied()
                .ok_or_else(|| Error("required recovery run parameter missing".into()))
        };
        let id = records::job_id(field("enzimos.recovery-run")?)?.to_owned();
        let luks = identity::uuid(field("enzimos.luks")?)?.to_owned();
        let filesystem = identity::uuid(field("enzimos.fs")?)?.to_owned();
        let control = identity::safe_id(field("enzimos.control")?)?.to_owned();
        let authority = identity::safe_id(field("enzimos.authority")?)?.to_owned();
        require(control != authority, "recovery persistent volumes overlap")?;
        let esp = field("enzimos.esp")?.to_owned();
        records::fat_uuid(&esp)?;
        let uefi_previous = field("enzimos.uefi-restore")?.to_owned();
        records::literal_entry(&uefi_previous)?;
        require(
            uefi_previous != records::run_entry_names(&id)?.0,
            "run entry cannot restore itself",
        )?;
        let (previous, own) = field("enzimos.bios-restore")?
            .split_once(':')
            .ok_or_else(|| Error("recovery BIOS restore pair".into()))?;
        let number = |raw: &str| -> Result<usize> {
            require(
                !raw.is_empty() && raw.len() <= 3 && raw.bytes().all(|b| b.is_ascii_digit()),
                "recovery BIOS restore integer",
            )?;
            raw.parse::<usize>()
                .ok()
                .filter(|n| (1..=256).contains(n))
                .ok_or_else(|| Error("recovery BIOS restore bound".into()))
        };
        let bios_previous = number(previous)?;
        let bios_own = number(own)?;
        require(
            bios_previous < bios_own,
            "recovery own BIOS entry must follow previous entries",
        )?;
        let exit = field("enzimos.run-exit")?.to_owned();
        require(
            matches!(exit.as_str(), "reboot" | "poweroff"),
            "recovery exit mode",
        )?;
        let automatic = match fields.get("enzimos.restore-ui") {
            None => false,
            Some(&"1") => true,
            _ => return Err(Error("invalid graphical recovery parameter".into())),
        };
        Ok(Self {
            id,
            luks,
            filesystem,
            control,
            authority,
            esp,
            uefi_previous,
            bios_previous,
            bios_own,
            exit,
            automatic,
        })
    }
    /// Require that these parameters match the recorded run and its plan.
    ///
    /// # Errors
    ///
    /// Fails when any parameter differs from the records.
    pub fn matches_record(&self, run: &serde_json::Value, job: &serde_json::Value) -> Result<()> {
        records::run(run, &self.id)?;
        records::job(job, &self.id)?;
        require(
            Self::parse(records::text(&run["entry"], "options")?)? == *self
                && run["plan_sha256"] == job["plan"]["plan_sha256"]
                && job["plan"]["filesystem_uuid"] == self.filesystem
                && job["plan"]["boot_uuid"] == self.esp
                && job["plan"]["storage"]["control_subvol"] == self.control
                && job["plan"]["storage"]["authority_subvol"] == self.authority,
            "actual run boot parameters differ from recorded plan",
        )
    }
}
