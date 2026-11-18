// SPDX-License-Identifier: MIT
pub mod accounts;
pub mod alpm_sections;
pub mod backup_rules;
pub mod backup_worker_scope;
pub mod diagnostic;
pub mod directory_entry;
pub mod fd_packet;
pub mod files;
pub mod flock_identity;
pub mod fsview;
pub mod json;
pub mod local_restic;
pub mod memfile;
pub mod mount_identity;
pub mod mountinfo;
pub mod named_retirement;
pub mod packet_socket;
pub mod peer_lifetime;
pub mod process;
pub mod process_identity;
pub mod publication;
pub mod secret;
pub mod stream_copy;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("filesystem or process operation failed".into())
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid JSON document".into())
    }
}
pub fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}

pub mod backup_command;
pub mod backup_mount_child;

pub mod delivery_name;

pub mod remote_mount_child;

pub mod remote_restic;

pub mod copy_publication;

pub mod receipt_registry;

pub mod created_directory;

pub mod credential_retirement;

pub mod system_contract;

pub mod recovery_boot_child;
mod recovery_boot_devices;
pub mod recovery_boot_group;
