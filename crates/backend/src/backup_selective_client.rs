// SPDX-License-Identifier: MIT
//! Original selective export launch; no setup grant, adoption, retry or cleanup.
use crate::{native_worker_contract::Definition, native_worker_manager, system_manager::Manager};
use enzimos_platform::{
    Error, Result, fd_packet::Credentials, files, json, mount_identity, packet_socket::Listener,
    require,
};
use enzimos_policy::{
    backup_selective_context::Context,
    backup_selective_control::{Event, State},
    backup_selective_report::{Closed, Reported},
    backup_selective_reservation::Reserved,
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

fn ready(v: &Value, sender: &Credentials, id: &str, pid: u32, invocation: &str) -> Result<()> {
    require(
        sender.pid == pid
            && sender.uid == 0
            && sender.gid == 0
            && *v == value!({"schema":1,"id":id,"kind":"ready","invocation":invocation}),
        "selective export readiness differs from measured original PID1 invocation",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
fn readable(channel: &enzimos_platform::fd_packet::Packet) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: channel.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` is one writable pollfd and the count is 1.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    require(
        rc >= 0
            && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0
            && (poll.revents & libc::POLLHUP == 0 || poll.revents & libc::POLLIN != 0),
        "original selective export control disconnected",
    )?;
    Ok(poll.revents & libc::POLLIN != 0)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn directory(id: &str) -> Result<(File, Listener)> {
    let run = files::directory(Path::new("/run/enzimos"), Some(0))?;
    let m = run.metadata()?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            // SAFETY: `fs` is a writable `libc::statfs` and `run` keeps the descriptor open.
            && unsafe { libc::fstatfs(run.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == 0x01021994,
        "selective export IPC requires original Root-private tmpfs",
    )?;
    let mount = mount_identity::id(run.as_fd(), true)?;
    let base = files::ensure_directory_relative(&run, Path::new("backup-native"), 0o700, 0)?;
    let attempts = files::ensure_directory_relative(&base, Path::new("attempts"), 0o700, 0)?;
    for directory in [&base, &attempts] {
        let m = directory.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o700
                && mount_identity::id(directory.as_fd(), true)? == mount,
            "selective export IPC parent changed",
        )?;
    }
    let path = Path::new("/run/enzimos/backup-native/attempts").join(id);
    let directory = files::create_directory(&path, 0o700, 0)?;
    require(
        mount_identity::id(directory.as_fd(), true)? == mount,
        "selective export IPC left original tmpfs",
    )?;
    let handoff = Listener::bind(&path.join("handoff.socket"), 0)?;
    Ok((directory, handoff))
}
/// Run on an owned blocking thread, outside an entered Tokio runtime. The fresh
/// authorization callback is invoked on the owning thread, never cached as a
/// Boolean grant. Original process and file actors stay on that thread.
pub(crate) fn launch<'a, 'g>(
    context: &Context<'a, 'g>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Closed<'g>> {
    enzimos_policy::namespaces::initial()?;
    let mut permission = || authorize();
    context.recheck(&mut permission)?;
    let original = context.evidence(&mut permission)?;
    let id = enzimos_platform::json::string(&original["id"])?.to_owned();
    let definition = Definition::backup(&id)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .map_err(|_| Error("selective export caller runtime unavailable".into()))?;
    let manager = runtime.block_on(Manager::new())?;
    let launch = context.enter_launch(&mut permission)?;
    let (_directory, handoff) = directory(&id)?;
    launch.recheck()?;
    context.recheck(&mut permission)?;
    // An uncertain start is fenced forever by this original durable launch.
    let owner = runtime.block_on(native_worker_manager::start_for(&manager, &definition))?;
    let kernel = match owner.backup_scope(&id) {
        Ok(kernel) => kernel,
        Err(error) => {
            let _ = runtime.block_on(native_worker_manager::stop_for(
                &manager,
                &definition,
                &owner,
            ));
            return Err(error);
        }
    };
    let outcome = (|| {
        let channel = handoff.accept(Duration::from_secs(10))?;
        let message = channel.receive(4096, 0, Duration::from_secs(5))?;
        let invocation = owner
            .state
            .invocation
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        ready(
            &json::decode(&message.body, 4096)?,
            &message.sender,
            &id,
            owner.state.pid,
            &invocation,
        )?;
        let mut boundary = || {
            authorize()?;
            launch.recheck()?;
            runtime.block_on(native_worker_manager::recheck_for(
                &manager,
                &definition,
                &owner,
            ))?;
            authorize()
        };
        let mut reserved = Reserved::enter(context, owner.backup_scope(&id)?, &mut boundary)?;
        let observation: Result<Reported> = (|| {
            reserved.send(&channel, &mut boundary)?;
            let mut control = State::new();
            let deadline = Instant::now() + Duration::from_secs(definition.runtime_seconds() + 20);
            loop {
                require(
                    Instant::now() < deadline,
                    "original selective export caller deadline",
                )?;
                boundary()?;
                if readable(&channel)? {
                    match control.receive(&reserved, &channel, &mut boundary)? {
                        Event::Checkpoint => {}
                        Event::Observed(observation) => {
                            break Ok(observation);
                        }
                    }
                }
                runtime.block_on(async { tokio::time::sleep(Duration::from_millis(5)).await });
            }
        })();
        // Retain the actual reservation until original whole kernel scope death,
        // including any partial handoff/control failure.
        if observation.is_err() {
            let _ = runtime.block_on(native_worker_manager::stop_for(
                &manager,
                &definition,
                &owner,
            ));
        }
        let closure = (|| {
            let deadline = Instant::now() + Duration::from_secs(definition.stop_seconds() + 10);
            while !kernel.exited_and_empty()? {
                require(
                    Instant::now() < deadline,
                    "original selective export worker scope did not close",
                )?;
                runtime.block_on(async { tokio::time::sleep(Duration::from_millis(100)).await });
            }
            Ok::<_, Error>(())
        })();
        if let Err(error) = closure {
            // Deliberately retain these actual descriptors until daemon exit if
            // whole-scope death cannot be proved. Durable intents forbid replay;
            // dropping them here would incorrectly retire a live reservation.
            #[expect(
                clippy::mem_forget,
                reason = "The reservation must outlive this error path."
            )]
            std::mem::forget(reserved);
            return Err(error);
        }
        let observation = observation?;
        let mut permission = || {
            authorize()?;
            launch.recheck()
        };
        context.recheck(&mut permission)?;
        let request = reserved.close(&mut permission)?;
        observation.close(request)
    })();
    if outcome.is_err() {
        let _ = runtime.block_on(native_worker_manager::stop_for(
            &manager,
            &definition,
            &owner,
        ));
    }
    outcome
}
