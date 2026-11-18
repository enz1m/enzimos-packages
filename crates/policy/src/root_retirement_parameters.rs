// SPDX-License-Identifier: MIT
//! Closed retirement boot parameters. Parsed data never grants execution.
use crate::{identity, recovery_records as records, root_retirement_record};
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct Parameters {
    pub id: String,
    pub luks: String,
    pub filesystem: String,
    pub control: String,
    pub esp: String,
    pub uefi_previous: String,
    pub bios_previous: usize,
    pub bios_own: usize,
    pub exit: String,
}
impl Parameters {
    pub fn parse(body: &str) -> Result<Self> {
        require(
            body.len() <= 65536 && !body.contains('\0'),
            "retirement kernel command line bound",
        )?;
        let allowed = [
            "enzimos.root-retirement",
            "enzimos.luks",
            "enzimos.fs",
            "enzimos.control",
            "enzimos.esp",
            "enzimos.uefi-restore",
            "enzimos.bios-restore",
            "enzimos.coordinator-exit",
        ];
        let mut fields = BTreeMap::new();
        for word in body
            .split_whitespace()
            .filter(|w| w.starts_with("enzimos."))
        {
            let (name, value) = word
                .split_once('=')
                .ok_or_else(|| Error("retirement parameter requires value".into()))?;
            require(
                allowed.contains(&name)
                    && !value.is_empty()
                    && fields.insert(name, value).is_none(),
                "unknown, duplicate or empty retirement parameter",
            )?;
        }
        let field = |name| {
            fields
                .get(name)
                .copied()
                .ok_or_else(|| Error("required retirement parameter missing".into()))
        };
        let id = field("enzimos.root-retirement")?;
        require(
            id.len() == 37
                && id.starts_with("root-")
                && id[5..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "retirement boot identity",
        )?;
        let uefi_previous = field("enzimos.uefi-restore")?;
        records::literal_entry(uefi_previous)?;
        require(
            uefi_previous != format!("enzimos-root-retire-{}.conf", &id[5..21]),
            "retirement entry cannot restore itself",
        )?;
        let (previous, own) = field("enzimos.bios-restore")?
            .split_once(':')
            .ok_or_else(|| Error("retirement BIOS restore pair".into()))?;
        let number = |raw: &str| -> Result<usize> {
            require(
                !raw.is_empty() && raw.len() <= 3 && raw.bytes().all(|b| b.is_ascii_digit()),
                "retirement BIOS integer",
            )?;
            raw.parse::<usize>()
                .ok()
                .filter(|n| (1..=256).contains(n))
                .ok_or_else(|| Error("retirement BIOS default bound".into()))
        };
        let bios_previous = number(previous)?;
        let bios_own = number(own)?;
        require(
            bios_previous < bios_own,
            "retirement appended BIOS entry must follow previous default",
        )?;
        let exit = fields
            .get("enzimos.coordinator-exit")
            .copied()
            .unwrap_or("reboot");
        require(
            matches!(exit, "reboot" | "poweroff"),
            "retirement exit mode",
        )?;
        let esp = field("enzimos.esp")?;
        records::fat_uuid(esp)?;
        Ok(Self {
            id: id.into(),
            luks: identity::uuid(field("enzimos.luks")?)?.into(),
            filesystem: identity::uuid(field("enzimos.fs")?)?.into(),
            control: identity::safe_id(field("enzimos.control")?)?.into(),
            esp: esp.into(),
            uefi_previous: uefi_previous.into(),
            bios_previous,
            bios_own,
            exit: exit.into(),
        })
    }
    pub fn matches_record(&self, record: &Value) -> Result<()> {
        root_retirement_record::validate(record, &self.id)?;
        let coordinator = &record["coordinator"];
        require(
            Self::parse(records::text(coordinator, "options")?)? == *self
                && record["filesystem_uuid"] == self.filesystem
                && coordinator["uefi_entry"]
                    == format!("enzimos-root-retire-{}.conf", &self.id[5..21])
                && coordinator["uefi_previous"] == self.uefi_previous
                && coordinator["bios_previous"].as_u64() == Some(self.bios_previous as u64)
                && coordinator["bios_own"].as_u64() == Some(self.bios_own as u64),
            "actual retirement parameters differ from original coordinator record",
        )
    }
}
