// SPDX-License-Identifier: MIT
//! Root system service: System1 bus API, job ledgers, workers and user switching.
pub mod authority;
#[cfg(feature = "update-worker")]
pub mod backup_cli;
#[cfg(feature = "update-worker")]
mod backup_create_coordinator;
#[cfg(feature = "update-worker")]
mod backup_credential_client;
#[cfg(feature = "update-worker")]
mod backup_credential_coordinator;
#[cfg(feature = "update-worker")]
mod backup_handoff_wait;
#[cfg(feature = "update-worker")]
mod backup_input_attempt;
#[cfg(feature = "update-worker")]
mod backup_provision_attempt;
#[cfg(feature = "update-worker")]
mod backup_recovery_coordinator;
#[cfg(feature = "update-worker")]
mod backup_remote_share_coordinator;
#[cfg(feature = "update-worker")]
mod backup_selective_client;
#[cfg(feature = "update-worker")]
mod backup_selective_coordinator;
#[cfg(feature = "update-worker")]
mod backup_setup_coordinator;
#[cfg(feature = "update-worker")]
mod backup_setup_failure;
#[cfg(feature = "update-worker")]
mod backup_setup_jobs;
#[cfg(feature = "update-worker")]
mod backup_setup_provider;
#[cfg(feature = "update-worker")]
mod backup_setup_record;
#[cfg(feature = "update-worker")]
mod backup_setup_store;
#[cfg(feature = "update-worker")]
mod backup_setup_wire;
#[cfg(feature = "update-worker")]
mod backup_status_query;
#[cfg(feature = "update-worker")]
mod backup_status_records;
#[cfg(feature = "update-worker")]
mod backup_transfer_client;
#[cfg(feature = "update-worker")]
mod backup_worker_checkpoint;
#[cfg(feature = "update-worker")]
mod backup_worker_client;
#[cfg(feature = "update-worker")]
pub mod backup_worker_service;
// CLOEXEC closes inherited locks at exec, not at fork. Coordinate the private
// daemon's fork with fixtures that deliberately release and reopen a flock.
#[cfg(test)]
pub(crate) static LOCK_FIXTURE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub mod history;
#[cfg(feature = "update-worker")]
mod history_jobs;
mod jobs;
mod operation_record;
mod operation_result;
mod operation_store;
pub mod secret;
#[cfg(feature = "update-worker")]
pub mod system_api;
#[cfg(feature = "update-worker")]
mod system_header;
#[cfg(feature = "update-worker")]
mod system_jobs;
#[cfg(feature = "update-worker")]
pub mod system_manager;
#[cfg(feature = "update-worker")]
mod system_provider;
mod system_selection;
#[cfg(feature = "update-worker")]
pub mod system_service;
pub mod system_wire;
#[cfg(feature = "update-worker")]
pub mod update_worker_cgroup;
#[cfg(feature = "update-worker")]
pub mod update_worker_contract;
#[cfg(feature = "update-worker")]
pub mod update_worker_manager;
#[cfg(feature = "update-worker")]
pub use update_worker_cgroup as native_worker_cgroup;
#[cfg(feature = "update-worker")]
pub use update_worker_contract as native_worker_contract;
#[cfg(feature = "update-worker")]
pub use update_worker_manager as native_worker_manager;

#[cfg(feature = "update-worker")]
mod own_file_restore_coordinator;

#[cfg(feature = "update-worker")]
mod backup_remote_rotation_coordinator;
#[cfg(feature = "update-worker")]
mod backup_rotation_coordinator;

#[cfg(feature = "update-worker")]
mod backup_remote_client;
#[cfg(feature = "update-worker")]
mod backup_remote_coordinator;

#[cfg(feature = "update-worker")]
mod boot_retirement_coordinator;
#[cfg(feature = "update-worker")]
mod root_retirement_prepare_coordinator;
#[cfg(feature = "update-worker")]
mod root_retirement_stage_coordinator;

#[cfg(feature = "update-worker")]
mod root_retirement_finish_coordinator;

#[cfg(feature = "update-worker")]
pub mod root_command;

#[cfg(feature = "update-worker")]
mod backup_destination_scope;

#[cfg(feature = "update-worker")]
pub mod user_switch;
