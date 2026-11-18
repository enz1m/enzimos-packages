// SPDX-License-Identifier: MIT
//! Validate original caller inputs before starting a fresh service or sending FDs.
use enzimos_platform::{Result, json, mount_identity, require};
use serde_json::Value;
use std::{fs::File, os::fd::AsFd};
pub struct Inputs<'a> {
    pub repository: &'a File,
    pub credential: &'a File,
    pub restic: &'a File,
    pub outer: Option<&'a File>,
    pub configuration: Option<&'a File>,
    pub temporary: Option<&'a File>,
}
impl Inputs<'_> {
    pub fn recheck(
        &self,
        request: &Value,
        source: &crate::storage_runtime::Guard,
        owned: &crate::backup_setup_mount::Scope<'_, '_, '_>,
        root: &File,
    ) -> Result<()> {
        use crate::backup_worker_handoff::{command, identity, readonly};
        crate::namespaces::initial()?;
        crate::backup_worker_request::executable(request)?;
        owned.recheck()?;
        require(
            owned.evidence()? == request["mount"],
            "caller original owned mount differs from request",
        )?;
        crate::backup_worker_scope::recheck(request, source, root, self.repository)?;
        if !request["header"].is_null() {
            let header = crate::backup_repository_header::Header::observe(self.repository)?;
            require(
                header.evidence(self.repository)? == request["header"],
                "caller original encrypted header differs from request",
            )?;
        }
        identity(self.credential, &request["credential"]["identity"])?;
        if request["credential"]["kind"] == "sealed-caller-input" {
            enzimos_platform::secret::retain(
                self.credential.as_fd(),
                request["plan"]["owner_uid"].as_u64().unwrap() as u32,
            )?
            .recheck()?;
            let reader = crate::settings_command::Command::open(
                "/usr/lib/enzimos-backend/enzimos-secret-validator",
            )?;
            require(
                reader.evidence()? == request["reader"],
                "caller input reader differs from original admission",
            )?;
        } else {
            readonly(self.credential)?;
        }
        command(self.restic, &request["restic"])?;
        for (file, key, mount) in [
            (self.outer, "outer", source.control_mount_id()),
            (self.configuration, "configuration", source.root_mount_id()),
        ] {
            require(
                file.is_some() == !request[key].is_null(),
                "caller public document presence differs from stage",
            )?;
            if let Some(file) = file {
                readonly(file)?;
                identity(file, &request[key]["identity"])?;
                require(
                    mount_identity::id(file.as_fd(), true)? == mount,
                    "caller public document left original source mount",
                )?;
                let bytes = enzimos_platform::files::read_file(file, 65536, Some(0), true)?;
                require(
                    json::sha256(&bytes) == request[key]["sha256"],
                    "caller original public document changed",
                )?;
            }
        }
        require(
            self.temporary.is_some() == !request["consumer_input"].is_null(),
            "caller temporary presence differs from stage",
        )?;
        if let Some(file) = self.temporary {
            crate::backup_auth_input::borrowed(
                &request["consumer_input"],
                request["id"].as_str().unwrap(),
                request["credential"]["identity"][2].as_u64().unwrap(),
                file,
            )?;
        }
        owned.recheck()?;
        source.recheck()
    }
}
