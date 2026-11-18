// SPDX-License-Identifier: MIT
//! Candidate PID1 worker. The caller owns temporary input and terminal cleanup.
use crate::{native_worker_contract::Definition, native_worker_manager, system_manager::Manager};
use enzimos_platform::{Error, Result, packet_socket, require};
use enzimos_policy::{
    backup_restic_runtime::Runtime, backup_worker_checkpoint::Checkpoint,
    backup_worker_handoff::Handoff, backup_worker_task::Work,
};
use serde_json::json as value;
use std::{path::Path, time::Duration};
pub fn serve(id: &str) -> Result<()> {
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .map_err(|_| Error("backup worker runtime unavailable".into()))?;
    let manager = runtime.block_on(Manager::new())?;
    let definition = Definition::backup(id)?;
    let owner = runtime.block_on(native_worker_manager::current_for(&manager, &definition))?;
    let socket = Path::new("/run/enzimos/backup-native/attempts")
        .join(id)
        .join("handoff.socket");
    let channel = packet_socket::connect(&socket, 0, Duration::from_secs(10))?;
    runtime.block_on(native_worker_manager::recheck_for(
        &manager,
        &definition,
        &owner,
    ))?;
    let invocation = owner
        .state
        .invocation
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    channel.send(
        &enzimos_platform::json::canonical(
            &value!({"schema":1,"id":id,"kind":"ready","invocation":invocation}),
        )?,
        &[],
        Duration::from_secs(2),
    )?;
    let scope = owner.backup_scope(id)?;
    let peer = channel.peer_credentials()?;
    require(
        peer.uid == 0 && peer.gid == 0,
        "original Root backup caller required",
    )?;
    let stat_path = std::path::PathBuf::from(format!("/proc/{}/stat", peer.pid));
    let stat_body = enzimos_platform::files::read_kernel(&stat_path, 8192)?;
    let stat_text =
        std::str::from_utf8(&stat_body).map_err(|_| Error("backup caller stat encoding".into()))?;
    let stat = enzimos_platform::process_identity::parse_stat(stat_text, peer.pid)?;
    let caller = enzimos_platform::process_identity::Retained::open(
        peer.pid,
        stat.start_ticks,
        0,
        &[std::path::PathBuf::from(
            "/usr/lib/enzimos-backend/enzimos-system-backend",
        )],
    )?;
    crate::backup_handoff_wait::wait(
        &channel,
        &caller,
        crate::backup_handoff_wait::PREPARATION_LIMIT,
        &mut || {
            runtime.block_on(native_worker_manager::recheck_for(
                &manager,
                &definition,
                &owner,
            ))?;
            scope.binding().map(|_| ())
        },
    )?;
    // Packet admission keeps its original deadline, wire and descriptor counts.
    let message = channel
        .receive_counts(
            65536,
            &[
                10,
                11,
                13,
                enzimos_policy::backup_remote_request::DESCRIPTORS,
            ],
            Duration::from_secs(10),
        )
        .map_err(|error| Error(format!("initial backup offer: {error}")))?;
    let frame = enzimos_platform::json::decode(&message.body, 65536)?;
    if frame["kind"] == "remote-copy" {
        return remote_copy(
            &runtime,
            &manager,
            &definition,
            &owner,
            id,
            channel,
            &scope,
            message,
        );
    }
    if matches!(
        frame["kind"].as_str(),
        Some("selective-file-export" | "selective-tree-export")
    ) {
        return selective_file(
            &runtime,
            &manager,
            &definition,
            &owner,
            id,
            channel,
            &scope,
            message,
        );
    }
    if frame["kind"] == "credential-review" {
        return credential_review(
            &runtime,
            &manager,
            &definition,
            &owner,
            id,
            channel,
            &scope,
            message,
        );
    }
    if frame["kind"] == "captured-backup-transfer" {
        return transfer(
            &runtime,
            &manager,
            &definition,
            &owner,
            id,
            channel,
            &scope,
            message,
        );
    }
    require(
        frame.get("kind").is_none(),
        "unknown worker handoff role; no fallback",
    )?;
    let handoff = Handoff::receive(message, &scope)?;
    let request = handoff.request()?.clone();
    require(
        request["id"] == id,
        "worker handoff differs from registered PID1 attempt",
    )?;
    let mut checkpoint = Checkpoint::new(channel);
    let mut boundary = || {
        runtime.block_on(native_worker_manager::recheck_for(
            &manager,
            &definition,
            &owner,
        ))?;
        checkpoint
            .recheck(&handoff)
            .map_err(|error| Error(format!("captured transfer checkpoint: {error}")))?;
        runtime.block_on(native_worker_manager::recheck_for(
            &manager,
            &definition,
            &owner,
        ))
    };
    boundary()?;
    let scratch = Runtime::create(id, &mut boundary)?;
    require(
        scratch.image_evidence()? == request["restic"],
        "worker consumer image differs from original request",
    )?;
    let task = Work::parse(request["task"].as_str().unwrap())?;
    let result = scratch.workflow(
        task,
        handoff.repository_descriptor()?,
        handoff.consumer_descriptor()?,
        &mut boundary,
    )?;
    boundary()?;
    checkpoint.report(&handoff, result.value()?, result.header_descriptor()?)?;
    result.value()?;
    // No temporary unlink, scratch deletion, mount close, enrollment or terminal
    // receipt. The caller must observe this original pidfd and entire cgroup closed.
    Ok(())
}
fn transfer(
    runtime: &tokio::runtime::Runtime,
    manager: &Manager,
    definition: &Definition,
    owner: &native_worker_manager::Owner,
    id: &str,
    channel: enzimos_platform::fd_packet::Packet,
    scope: &enzimos_platform::backup_worker_scope::Scope,
    message: enzimos_platform::fd_packet::Message,
) -> Result<()> {
    use enzimos_policy::{
        backup_source_receiver, backup_transfer_checkpoint, backup_transfer_handoff,
    };
    let handoff = backup_transfer_handoff::Handoff::receive(message, scope)
        .map_err(|error| Error(format!("captured transfer admission: {error}")))?;
    require(
        handoff.request()?["id"] == id,
        "transfer differs from original PID1 registration",
    )?;
    let mut checkpoint = backup_transfer_checkpoint::Checkpoint::new(channel);
    let mut boundary = || {
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))?;
        checkpoint
            .recheck(&handoff)
            .map_err(|error| Error(format!("captured transfer checkpoint: {error}")))?;
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))
    };
    boundary()?;
    // Source packets use a distinct channel. The caller must service fresh
    // checkpoint challenges while its owned sender delivers source chunks.
    let path = Path::new("/run/enzimos/backup-native/attempts")
        .join(id)
        .join("source.socket");
    let sources = packet_socket::connect(&path, 0, Duration::from_secs(10))
        .map_err(|error| Error(format!("captured source connection: {error}")))?;
    boundary()?;
    let scratch = Runtime::create(id, &mut boundary)?;
    let mut received =
        backup_source_receiver::Received::receive(&handoff, scope, &sources, &mut boundary)
            .map_err(|error| Error(format!("captured source receive: {error}")))?;
    let prepared = received.prepare_child(&mut boundary)?;
    let observed = prepared
        .run(&scratch, &mut boundary)
        .map_err(|error| Error(format!("captured vendor backup: {error}")))?;
    boundary()?;
    checkpoint.report(&handoff, &observed)?;
    // All original source and scratch descriptions survive through the report.
    // The caller retires the entire kernel worker scope before any cleanup.
    Ok(())
}

fn credential_review(
    runtime: &tokio::runtime::Runtime,
    manager: &Manager,
    definition: &Definition,
    owner: &native_worker_manager::Owner,
    id: &str,
    channel: enzimos_platform::fd_packet::Packet,
    scope: &enzimos_platform::backup_worker_scope::Scope,
    message: enzimos_platform::fd_packet::Message,
) -> Result<()> {
    use enzimos_policy::{backup_credential_checkpoint, backup_credential_handoff};
    let handoff = backup_credential_handoff::Handoff::receive(message, scope)?;
    require(
        handoff.request()?["id"] == id,
        "credential review differs from original PID1 registration",
    )?;
    let mut checkpoint = backup_credential_checkpoint::Checkpoint::new(channel);
    let mut boundary = || {
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))?;
        checkpoint.recheck(&handoff)?;
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))
    };
    boundary()?;
    let scratch = Runtime::create(id, &mut boundary)?;
    let observed = scratch.credential_review(&handoff, &mut boundary)?;
    boundary()?;
    checkpoint.report(&handoff, &observed)?;
    // Retain original inputs and scratch through the report. No key mutation,
    // credential export, journal completion or cleanup is authorized here.
    observed.recheck()?;
    Ok(())
}

fn selective_file(
    runtime: &tokio::runtime::Runtime,
    manager: &Manager,
    definition: &Definition,
    owner: &native_worker_manager::Owner,
    id: &str,
    channel: enzimos_platform::fd_packet::Packet,
    scope: &enzimos_platform::backup_worker_scope::Scope,
    message: enzimos_platform::fd_packet::Message,
) -> Result<()> {
    use enzimos_policy::{backup_selective_checkpoint, backup_selective_handoff};
    let handoff = backup_selective_handoff::Handoff::receive(message, scope)?;
    require(
        handoff.request()?["id"] == id,
        "selective export differs from original PID1 registration",
    )?;
    let mut checkpoint = backup_selective_checkpoint::Checkpoint::new(channel);
    let mut boundary = || {
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))?;
        checkpoint.recheck(&handoff)?;
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))
    };
    boundary()?;
    let scratch = Runtime::create(id, &mut boundary)?;
    let observed = scratch.selective_export(&handoff, &mut boundary)?;
    boundary()?;
    checkpoint.report(&handoff, &observed)?;
    // Retain actual inputs and private sealed data through the report. Parent
    // observes original pidfd and empty cgroup before any export publication.
    observed.recheck()?;
    Ok(())
}

fn remote_copy(
    runtime: &tokio::runtime::Runtime,
    manager: &Manager,
    definition: &Definition,
    owner: &native_worker_manager::Owner,
    id: &str,
    channel: enzimos_platform::fd_packet::Packet,
    scope: &enzimos_platform::backup_worker_scope::Scope,
    message: enzimos_platform::fd_packet::Message,
) -> Result<()> {
    let handoff = enzimos_policy::backup_remote_handoff::Handoff::receive(message, scope)?;
    require(
        handoff.request()?["id"] == id,
        "remote copy differs from original PID1 registration",
    )?;
    let mut checkpoint = enzimos_policy::backup_remote_checkpoint::Checkpoint::new(channel);
    let mut boundary = || {
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))?;
        checkpoint.recheck(&handoff)?;
        runtime.block_on(native_worker_manager::recheck_for(
            manager, definition, owner,
        ))
    };
    boundary()?;
    let scratch = Runtime::create(id, &mut boundary)?;
    let observed = scratch.remote_copy(&handoff, &mut boundary)?;
    boundary()?;
    checkpoint.report(&handoff, &observed)?;
    observed.recheck()?;
    Ok(())
}
