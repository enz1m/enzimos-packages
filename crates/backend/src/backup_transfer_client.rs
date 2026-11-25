// SPDX-License-Identifier: MIT
//! Original captured-transfer launch; no setup grant, adoption, retry or cleanup.
use crate::{native_worker_contract::Definition, native_worker_manager, system_manager::Manager};
use enzimos_platform::{
    Error, Result, fd_packet::Credentials, files, json, mount_identity, packet_socket::Listener,
    require,
};
use enzimos_policy::{
    backup_readonly_trees::{Prepared, ReleasedDescriptors},
    backup_source_offer::Offer,
    backup_transfer_context::Context,
    backup_transfer_control::{Event, State},
    backup_transfer_observation::Observation,
    backup_transfer_reservation::{ClosedRequest, Reserved},
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

/// A reported transfer and actual closed worker/source descriptions. This does
/// not authorize snapshot deletion or publish a completed backup.
pub(crate) struct Finished {
    observation: Observation,
    request: ClosedRequest,
    sources: ReleasedDescriptors,
}
impl Finished {
    /// Transfer only the three actual original actors to the cleanup owner.
    /// Their typed pairing still requires Observation::close; no JSON adoption.
    pub(crate) fn into_parts(self) -> (Observation, ClosedRequest, ReleasedDescriptors) {
        (self.observation, self.request, self.sources)
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.observation
            .closed_evidence(&self.request, &self.sources)
    }
}
fn ready(v: &Value, sender: &Credentials, id: &str, pid: u32, invocation: &str) -> Result<()> {
    require(
        sender.pid == pid
            && sender.uid == 0
            && sender.gid == 0
            && *v == value!({"schema":1,"id":id,"kind":"ready","invocation":invocation}),
        "transfer readiness differs from measured original PID1 invocation",
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
        "original transfer control disconnected",
    )?;
    Ok(poll.revents & libc::POLLIN != 0)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn directory(id: &str) -> Result<(File, Listener, Listener)> {
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
        "transfer IPC requires original Root-private tmpfs",
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
            "transfer IPC parent changed",
        )?;
    }
    let path = Path::new("/run/enzimos/backup-native/attempts").join(id);
    let directory = files::create_directory(&path, 0o700, 0)?;
    require(
        mount_identity::id(directory.as_fd(), true)? == mount,
        "transfer IPC left original tmpfs",
    )?;
    let handoff = Listener::bind(&path.join("handoff.socket"), 0)?;
    let source = Listener::bind(&path.join("source.socket"), 0)?;
    Ok((directory, handoff, source))
}
/// Run on an owned blocking thread, outside an entered Tokio runtime. The fresh
/// authorization callback is invoked on the owning thread, never cached as a
/// Boolean grant. Original process and file actors stay on that thread.
pub(crate) fn launch<'a, 'b, 'c, 's, 'cfg, 'g>(
    context: &Context<'a, 'b, 'c, 's, 'cfg, 'g>,
    trees: Prepared<'a, 'b, 'c, 's, 'cfg, 'g>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Finished> {
    enzimos_policy::namespaces::initial()?;
    let mut permission = || authorize();
    context.recheck(&mut permission)?;
    trees.recheck()?;
    let original = context.evidence(&mut permission)?;
    let sources = trees.evidence()?;
    require(
        sources["receipt"]["id"] == original["id"]
            && sources["receipt"]["input_sha256"] == original["input_sha256"],
        "original detached sources differ from actual transfer context",
    )?;
    let id = enzimos_platform::json::string(&original["id"])?.to_owned();
    let definition = Definition::backup(&id)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .map_err(|_| Error("transfer caller runtime unavailable".into()))?;
    let manager = runtime.block_on(Manager::new())?;
    let launch = context.enter_launch(&mut permission)?;
    let (_directory, handoff, source) = directory(&id)?;
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
        let sources = trees.reserve_worker(owner.backup_scope(&id)?, &mut boundary)?;
        let mut offer = Offer::enter(sources, context.caller(&mut boundary)?, &mut boundary)?;
        let observation: Result<Observation> = (|| {
            reserved.send(&channel, &mut boundary)?;
            let mut source_channel = None;
            let mut sent = false;
            let mut control = State::new();
            let deadline = Instant::now() + Duration::from_secs(definition.runtime_seconds() + 20);
            // The receiver validates the original handoff and exchanges fresh
            // checkpoints before connecting its source channel. Use the same
            // bounded preparation window as those checks, not a packet timeout.
            let mut connect_deadline =
                Instant::now() + crate::backup_handoff_wait::PREPARATION_LIMIT;
            loop {
                require(
                    Instant::now() < deadline,
                    "original transfer caller deadline",
                )?;
                boundary()?;
                if readable(&channel)? {
                    match control.receive(&reserved, &channel, &mut boundary)? {
                        Event::Checkpoint => {
                            // Only an authenticated, freshly authorized original
                            // worker advances preparation; the overall runtime
                            // deadline above continues to bound the whole job.
                            if source_channel.is_none() {
                                connect_deadline =
                                    Instant::now() + crate::backup_handoff_wait::PREPARATION_LIMIT;
                            }
                        }
                        Event::Observed(observation) => {
                            require(
                                sent,
                                "worker reported before original source chunks were sent",
                            )?;
                            break Ok(observation);
                        }
                    }
                }
                if source_channel.is_none() {
                    if source.pending()? {
                        source_channel = Some(source.accept(Duration::from_millis(1))?);
                    } else {
                        require(
                            Instant::now() < connect_deadline,
                            "original source connect deadline",
                        )?;
                    }
                }
                if !sent && let Some(data) = source_channel.as_ref() {
                    // Each bounded chunk is interleaved with control service.
                    sent = offer.send_next(data, &mut boundary)?;
                }
                runtime.block_on(async { tokio::time::sleep(Duration::from_millis(5)).await });
            }
        })();
        // Retain both actual reservations until the original whole kernel scope
        // is dead and empty, including on any partial source/control failure.
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
                    "original transfer worker scope did not close",
                )?;
                runtime.block_on(async { tokio::time::sleep(Duration::from_millis(100)).await });
            }
            Ok::<_, Error>(())
        })();
        if let Err(error) = closure {
            // Deliberately retain these actual descriptors until daemon exit if
            // whole-scope death cannot be proved. Durable intents forbid replay;
            // dropping them here would incorrectly retire a live reservation.
            #[expect(clippy::mem_forget, reason = "The offer must outlive this error path.")]
            std::mem::forget(offer);
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
        let sources = offer.close(&mut permission)?;
        observation.require_closed(&request, &sources)?;
        Ok(Finished {
            observation,
            request,
            sources,
        })
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
