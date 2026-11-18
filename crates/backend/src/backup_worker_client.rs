// SPDX-License-Identifier: MIT
//! One fresh service; original caller retains mount/input until whole worker closure.
use crate::{
    backup_worker_checkpoint::{Caller, Event},
    native_worker_contract::Definition,
    native_worker_manager,
    system_manager::Manager,
};
use enzimos_platform::{
    Error, Result,
    backup_worker_scope::Closed,
    fd_packet::{Credentials, Packet},
    files, json, memfile, mount_identity,
    packet_socket::Listener,
    require,
};
use enzimos_policy::{
    backup_setup_mount::Scope, backup_worker_intent::Intent,
    backup_worker_observation::Observation, backup_worker_producer::Inputs,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{Duration, Instant},
};
pub struct Finished {
    pub closed: Closed,
    pub observation: Observation,
}
fn ready(v: &Value, sender: &Credentials, id: &str, pid: u32, invocation: &str) -> Result<()> {
    require(
        sender.pid == pid
            && sender.uid == 0
            && sender.gid == 0
            && *v == value!({"schema":1,"id":id,"kind":"ready","invocation":invocation}),
        "backup ready packet is not original measured PID1 invocation",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub async fn launch(
    intent: &mut Intent<'_>,
    owned: &Scope<'_, '_, '_>,
    inputs: &Inputs<'_>,
) -> Result<Finished> {
    enzimos_policy::namespaces::initial()?;
    intent.recheck()?;
    let prepared = intent.value()?;
    require(
        prepared["phase"] == "prepared",
        "backup launch cannot replay original entry",
    )?;
    let request = prepared["request"].clone();
    enzimos_policy::backup_worker_request::executable(&request)?;
    let id = request["id"].as_str().unwrap();
    let root = File::from(owned.descriptor()?.try_clone_to_owned()?);
    inputs.recheck(&request, intent.source()?, owned, &root)?;
    let sealed = memfile::sealed("backup-worker-request", &json::canonical(&request)?)?;
    let manager = Manager::new().await?;
    let definition = Definition::backup(id)?;
    // Starting precedes socket/attempt creation and the one-shot PID1 call.
    intent.starting()?;
    let run = files::directory(Path::new("/run/enzimos"), Some(0))?;
    let m = run.metadata()?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && unsafe { libc::fstatfs(run.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == 0x01021994,
        "backup caller IPC requires original Root-private tmpfs",
    )?;
    let mount = mount_identity::id(run.as_fd(), true)?;
    let base = files::ensure_directory_relative(&run, Path::new("backup-native"), 0o700, 0)?;
    intent.recheck()?;
    let attempts = files::ensure_directory_relative(&base, Path::new("attempts"), 0o700, 0)?;
    for directory in [&base, &attempts] {
        let m = directory.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o700
                && mount_identity::id(directory.as_fd(), true)? == mount,
            "backup caller IPC directory changed authority",
        )?;
    }
    let path = Path::new("/run/enzimos/backup-native/attempts").join(id);
    let directory = files::create_directory(&path, 0o700, 0)?;
    require(
        mount_identity::id(directory.as_fd(), true)? == mount,
        "fresh backup IPC left original tmpfs",
    )?;
    intent.recheck()?;
    inputs.recheck(&request, intent.source()?, owned, &root)?;
    let listener = Listener::bind(&path.join("handoff.socket"), 0)?;
    // If the manager cannot confirm start, no descriptors have been sent and
    // the partial starting record remains fenced. Never adopt or retry a unit.
    let owner = native_worker_manager::start_for(&manager, &definition).await?;
    let kernel = owner.backup_scope(id)?;
    let mut channel: Option<Packet> = None;
    let outcome = async {
        channel = Some(listener.accept(Duration::from_secs(10))?);
        let channel = channel.as_ref().unwrap();
        let message = channel.receive(4096,0,Duration::from_secs(5))?;
        let invocation = owner.state.invocation.iter().map(|b| format!("{b:02x}")).collect::<String>();
        ready(&json::decode(&message.body,4096)?,&message.sender,id,owner.state.pid,&invocation)?;
        native_worker_manager::recheck_for(&manager,&definition,&owner).await?;
        inputs.recheck(&request,intent.source()?,owned,&root)?;
        intent.attach_worker(&kernel)?;
        let (image,pidfd,lock) = intent.caller_descriptors()?;
        let mut descriptors = vec![sealed.as_fd(),intent.descriptor()?.as_fd(),lock.as_fd(),pidfd,image.as_fd(),
            root.as_fd(),inputs.repository.as_fd(),inputs.credential.as_fd(),inputs.restic.as_fd()];
        if let Some(file) = inputs.outer {descriptors.push(file.as_fd());}
        if let Some(file) = inputs.configuration {descriptors.push(file.as_fd());}
        if let Some(file) = inputs.temporary {descriptors.push(file.as_fd());}
        require(descriptors.len() == enzimos_policy::backup_worker_request::descriptors(&request)?,"backup caller handoff count changed")?;
        let frame = value!({"schema":enzimos_policy::backup_worker_request::FRAME_SCHEMA,"id":id,
            "request_sha256":json::fingerprint(&request)?,"descriptor_numbers":descriptors.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<_>>()});
        intent.recheck()?;owned.recheck()?;
        channel.send(&json::canonical(&frame)?,&descriptors,Duration::from_secs(2))?;
        let mut caller = Caller::new(intent,&owner,&kernel,&manager).await?;
        let deadline = Instant::now()+Duration::from_secs(definition.runtime_seconds()+20);
        let observation = loop {
            require(Instant::now() < deadline,"backup caller deadline; original unfinished intent retained")?;
            inputs.recheck(&request,intent.source()?,owned,&root)?;
            match caller.next(channel).await? {Event::Checkpoint=>{},Event::Observation(observation)=>break observation}
        };
        drop(caller);
        let deadline = Instant::now()+Duration::from_secs(definition.stop_seconds()+10);
        while !kernel.exited_and_empty()? {
            require(Instant::now() < deadline,"reported worker scope has not closed; no completion")?;
            intent.recheck()?;manager.recheck().await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        intent.recheck()?;owned.recheck()?;inputs.recheck(&request,intent.source()?,owned,&root)?;
        Ok::<_,Error>(observation)
    }.await;
    if let Err(error) = outcome {
        drop(channel.take());
        let stopped = native_worker_manager::stop_for(&manager, &definition, &owner).await;
        if stopped.is_err() {
            let deadline = Instant::now() + Duration::from_secs(definition.stop_seconds() + 10);
            while !kernel.exited_and_empty()? && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        // An error never yields a closure/observation token or retries work.
        // Outstanding original worker descriptors fence normal mount closure.
        return Err(error);
    }
    drop(channel.take());
    Ok(Finished {
        closed: kernel.close()?,
        observation: outcome.unwrap(),
    })
}
