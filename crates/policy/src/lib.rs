// SPDX-License-Identifier: MIT
pub mod authority;
pub mod authority_build;
pub mod authority_check;
pub mod authority_hook_proxy;
pub mod authority_identity;
pub mod authority_mount;
pub mod authority_publish;
pub mod authority_record;
pub mod backup_admission;
pub mod backup_archive_inputs;
pub mod backup_attempt;
pub mod backup_auth_input;
pub mod backup_binding;
pub mod backup_boot_capture;
pub mod backup_candidates;
pub mod backup_capture_runtime;
pub mod backup_capture_scope;
pub mod backup_configuration;
pub mod backup_credential;
pub mod backup_credential_candidate;
pub mod backup_credential_checkpoint;
pub mod backup_credential_context;
pub mod backup_credential_control;
pub mod backup_credential_handoff;
pub mod backup_credential_journal;
pub mod backup_credential_observation;
pub mod backup_credential_record;
pub mod backup_credential_report;
pub mod backup_credential_request;
pub mod backup_credential_reservation;
pub mod backup_credential_review;
pub mod backup_database_export;
pub mod backup_database_sources;
pub mod backup_destination;
pub mod backup_destination_attach;
mod backup_existing_repository_wire;
pub mod backup_flatpak_capture;
pub mod backup_history;
pub mod backup_input_authentication;
pub mod backup_inventory_stage;
pub mod backup_mount_review;
pub mod backup_package_capture;
mod backup_private_area;
pub mod backup_provisioned;
mod backup_publication_identity;
pub mod backup_published_credential;
mod backup_ram_quiet;
mod backup_ram_source;
pub mod backup_readonly_trees;
pub mod backup_recovery_confirmation;
mod backup_repository_header;
pub mod backup_restic_result;
pub mod backup_restic_runtime;
pub mod backup_restore_layout;
pub mod backup_retention;
mod backup_review_mount;
mod backup_review_store;
pub mod backup_schedule;
pub mod backup_secret_input;
pub mod backup_secret_persistence;
pub mod backup_setup_binding;
pub mod backup_setup_configuration;
pub mod backup_setup_context;
mod backup_setup_image;
pub mod backup_setup_mount;
pub mod backup_setup_plan;
pub mod backup_setup_repository;
pub mod backup_setup_reset;
pub mod backup_signature;
pub mod backup_snapshot_creation;
pub mod backup_source;
pub mod backup_source_capture;
pub mod backup_source_inventory;
pub mod backup_source_layout;
pub mod backup_source_offer;
pub mod backup_source_offer_wire;
pub mod backup_status;
pub mod backup_transfer_caller;
pub mod backup_worker_builder;
pub mod backup_worker_checkpoint;
pub mod backup_worker_handoff;
pub mod backup_worker_intent;
pub mod backup_worker_observation;
pub mod backup_worker_producer;
pub mod backup_worker_request;
pub mod backup_worker_result;
pub mod backup_worker_scope;
pub mod backup_worker_task;
pub mod birth;
pub mod birth_runtime;
pub mod block;
mod boot_capture_member;
pub mod boot_entries;
pub mod boot_menu;
pub mod boot_options;
pub mod boot_volume;
pub mod catalog;
pub mod control_record;
pub mod control_registry;
pub mod control_retention;
pub mod coordinator_seal;
pub mod deferred;
pub mod deferred_runtime;
pub mod deferred_start;
mod development_agent;
mod development_agent_owner;
pub mod development_signer;
pub mod diagnostic;
pub mod fallback;
pub mod file_overlay;
pub mod filesystem;
pub mod flatpak_plan;
pub mod flatpak_state;
pub mod generation_confirmation;
mod generation_destination;
pub mod generation_pending;
pub mod generation_publication;
pub mod generation_publish_runtime;
pub mod generation_stage;
pub mod history;
pub mod home_history_auto;
pub mod home_history_control;
pub mod home_history_create;
pub mod home_history_source;
pub mod home_retention;
pub mod identity;
pub mod initramfs;
pub mod installer_mount_area;
pub mod installer_volume_device;
pub mod maintenance;
pub mod media_auth;
pub mod media_origin;
pub mod media_password;
pub mod media_plan;
pub mod media_receipt;
pub mod media_rescue;
pub mod memory;
pub mod module_inventory;
pub mod module_view;
pub mod module_view_record;
mod mount_rollback;
pub mod namespaces;
pub mod native_boot_dispatch;
pub mod native_policy_files;
pub mod network_trust;
pub mod operation;
pub mod package_archive;
pub mod package_database;
pub mod package_signature;
pub mod pacman_lock;
pub mod pe;
pub mod power;
mod private_bind;
pub mod recovery_activation;
pub mod recovery_activation_runtime;
pub mod recovery_adoption;
pub mod recovery_boot;
pub mod recovery_bootstrap;
pub mod recovery_build_source;
pub mod recovery_confirmation;
pub mod recovery_context;
pub mod recovery_detachment;
pub mod recovery_detachment_runtime;
pub mod recovery_devices;
pub mod recovery_handoff;
pub mod recovery_image;
pub mod recovery_image_build;
pub mod recovery_image_publish;
pub mod recovery_journal;
pub mod recovery_mounts;
pub mod recovery_plan;
pub mod recovery_prepare;
pub mod recovery_publication;
pub mod recovery_publication_runtime;
pub mod recovery_records;
pub mod recovery_run_boot;
pub mod recovery_run_control;
pub mod recovery_run_finish;
pub mod recovery_run_parameters;
pub mod recovery_run_stage;
pub mod recovery_stage;
pub mod recovery_unlock;
pub mod recovery_workflow;
pub mod restore_history;
pub mod retirement_journal;
pub mod root_rebind_apply;
pub mod root_rebind_boot;
pub mod root_rebind_plan;
pub mod root_rebind_record;
pub mod root_rebind_runtime;
pub mod root_rebind_verify;
pub mod root_retirement_auto;
pub mod root_retirement_boot;
pub mod root_retirement_boot_artifacts;
pub mod root_retirement_boot_contract;
pub mod root_retirement_cli_stage;
mod root_retirement_conclusions;
pub mod root_retirement_cursor;
pub mod root_retirement_delete_observation;
pub mod root_retirement_dm_control;
pub mod root_retirement_exclusive_claim;
pub mod root_retirement_firmware_publication;
pub mod root_retirement_first_delete;
pub mod root_retirement_image_receipt;
pub mod root_retirement_kernel_boot;
pub mod root_retirement_kernel_helpers;
pub mod root_retirement_kernel_inventory;
pub mod root_retirement_loader_publication;
pub mod root_retirement_objects;
pub mod root_retirement_offline_catalog;
pub mod root_retirement_offline_certificate;
pub mod root_retirement_offline_control;
pub mod root_retirement_offline_inventory;
pub mod root_retirement_offline_journal;
pub mod root_retirement_offline_ledgers;
pub mod root_retirement_offline_loaders;
pub mod root_retirement_offline_mount;
pub mod root_retirement_offline_origins;
pub mod root_retirement_offline_protection;
pub mod root_retirement_offline_publications;
pub mod root_retirement_offline_scope;
pub mod root_retirement_offline_targets;
pub mod root_retirement_online_boot;
pub mod root_retirement_online_delete;
pub mod root_retirement_online_encryption;
pub mod root_retirement_online_finish_origin;
pub mod root_retirement_online_image;
pub mod root_retirement_online_intent;
pub mod root_retirement_online_inventory;
pub mod root_retirement_online_journal;
pub mod root_retirement_online_stage_publication;
pub mod root_retirement_online_stage_targets;
pub mod root_retirement_parameters;
pub mod root_retirement_record;
pub mod root_retirement_references;
pub mod root_retirement_running_image;
pub mod root_retirement_seal;
pub mod root_retirement_signed_namespace;
pub mod root_retirement_stage_contract;
pub mod root_retirement_unlock_source;
pub mod secure_artifacts;
pub mod secure_boot;
pub mod secure_loader_refresh;
pub mod secure_owner_source;
mod settings_command;
mod settings_file;
pub mod signed_entry;
pub mod snapshot_queries;
pub mod storage;
mod storage_configuration;
pub mod storage_runtime;
pub mod subvolume;
pub mod system_query;
pub mod tmp_storage;
pub mod topology;
pub mod transition_idle;
pub mod update_admission;
pub mod update_apply_lease;
pub mod update_apply_pending;
pub mod update_apply_record;
pub mod update_apply_runtime;
pub mod update_apply_store;
pub mod update_boot_stage;
pub mod update_cohort;
pub mod update_cohort_root;
pub mod update_plan;
pub mod update_resolution;
pub mod update_resources;
pub mod update_worker_launch;
pub mod update_worker_record;

pub mod backup_points;
pub mod backup_removals;
pub mod backup_run_status;
pub mod backup_selective_checkpoint;
pub mod backup_selective_context;
pub mod backup_selective_control;
mod backup_selective_copy;
pub mod backup_selective_export;
pub mod backup_selective_handoff;
pub mod backup_selective_observation;
pub mod backup_selective_report;
pub mod backup_selective_request;
pub mod backup_selective_reservation;
pub mod backup_selective_result;
pub mod backup_selective_review;
mod backup_tree_result;

pub mod delivery_cancel;

mod delivery_account;
mod delivery_export;
pub mod delivery_grant;

pub mod delivery_copy;

pub mod delivery_copy_request;

pub mod delivery_copy_worker;

pub mod delivery_worker_group;

pub mod delivery_child;
pub mod delivery_control;
pub mod delivery_handoff;

pub mod backup_source_receiver;

pub mod update_actor;

pub mod backup_transfer_context;

pub mod backup_transfer_request;

pub mod backup_transfer_reservation;

pub mod backup_transfer_handoff;

pub mod backup_transfer_checkpoint;

pub mod backup_transfer_observation;

pub mod backup_transfer_control;

pub mod backup_completion;
pub mod backup_create_review;

pub mod own_file_restore;

pub mod backup_rotation_record;

pub mod backup_rotation_context;
mod backup_rotation_mount;

mod backup_rotation_objects;

mod backup_rotation_layout;

pub mod backup_rotation_review;

mod backup_rotation_epoch;

pub mod backup_remote_endpoint;

pub mod backup_remote_inputs;

pub mod backup_remote_record;

pub mod backup_remote_context;

pub mod backup_remote_points;

pub mod backup_remote_copy_context;

pub mod backup_remote_request;

pub mod backup_remote_reservation;

pub mod backup_remote_handoff;

pub mod backup_remote_observation;

pub mod backup_remote_checkpoint;

pub mod backup_remote_receipt;

pub mod backup_remote_report;

pub mod backup_remote_completion;

pub mod backup_remote_control;
pub mod backup_remote_launch;

pub mod boot_retirement_plan;
pub mod generation_pins;

pub mod boot_retirement_cli;
pub mod boot_retirement_context;
pub mod generation_retention;

pub mod boot_retirement_references;

pub mod boot_backend_references;

pub mod recovery_conclusions;

pub mod backup_remote_rotation_inputs;

pub mod backup_remote_rotation_context;

pub mod backup_remote_rotation_journal;

pub mod backup_remote_rotation_review;

pub mod backup_remote_initialize;

pub mod lifecycle;

pub mod backup_recovery_print;
pub mod backup_recovery_save;

pub mod backup_rotation_prepare;

pub mod boot_inventory;

pub mod desktop_crash_reports;
pub mod desktop_gaming_check;
pub mod desktop_setup;
pub mod login_appearance;
mod login_image;
pub mod user_switch_policy;

pub mod boot_inventory_legacy;

pub mod boot_retirement_continuation;

pub(crate) mod boot_inventory_families;
pub(crate) mod recovery_reference_diagnostic;
pub(crate) mod root_reference_diagnostic;
