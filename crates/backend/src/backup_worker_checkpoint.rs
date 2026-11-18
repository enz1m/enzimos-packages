// SPDX-License-Identifier: MIT
//! Caller acknowledgements couple fresh approval to the original PID1 worker.
use crate::{
    native_worker_contract::Definition,
    native_worker_manager::{self, Owner},
    system_manager::Manager,
};
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    json, require,
};
use enzimos_policy::backup_worker_intent::Intent;
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, time::Duration};
fn challenge(message: &Message, id: &str, sha: &str, worker: u32, sequence: u64) -> Result<Value> {
    require(
        message.files.is_empty()
            && message.sender.pid == worker
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "backup checkpoint is not from original Root worker",
    )?;
    let v = json::decode(&message.body, 4096)?;
    json::fields(&v, "schema id request_sha256 sequence nonce")?;
    require(
        v["schema"] == 1
            && v["id"] == id
            && v["request_sha256"] == sha
            && v["sequence"].as_u64() == Some(sequence)
            && v["nonce"]
                .as_str()
                .is_some_and(|s| enzimos_policy::backup_worker_request::id(s).is_ok()),
        "backup challenge changed, stale or malformed",
    )?;
    Ok(v)
}
pub enum Event {
    Checkpoint,
    Observation(enzimos_policy::backup_worker_observation::Observation),
}
pub struct Caller<'i, 'g> {
    intent: &'i Intent<'g>,
    worker: &'i Owner,
    scope: &'i enzimos_platform::backup_worker_scope::Scope,
    manager: &'i Manager,
    definition: Definition,
    id: String,
    sha: String,
    sequence: u64,
    nonces: BTreeSet<String>,
    failed: bool,
}
impl<'i, 'g> Caller<'i, 'g> {
    pub async fn new(
        intent: &'i Intent<'g>,
        worker: &'i Owner,
        scope: &'i enzimos_platform::backup_worker_scope::Scope,
        manager: &'i Manager,
    ) -> Result<Self> {
        intent.recheck()?;
        let v = intent.value()?;
        require(
            v["phase"] == "starting" && v["request"]["caller"]["pid"] == std::process::id(),
            "only original native caller's starting intent may acknowledge a worker",
        )?;
        enzimos_policy::backup_worker_request::executable(&v["request"])?;
        let id = v["id"].as_str().unwrap().to_owned();
        let definition = Definition::backup(&id)?;
        native_worker_manager::recheck_for(manager, &definition, worker).await?;
        let captured = scope.binding()?;
        require(
            captured["id"] == id
                && captured["worker"]["pid"] == worker.state.pid
                && captured["worker"]["start_ticks"] == worker.process.stat.start_ticks
                && captured["worker"]["executable_sha256"] == worker.executable_sha256
                && v["worker"] == *captured,
            "caller scope differs from original durable worker binding",
        )?;
        Ok(Self {
            intent,
            worker,
            scope,
            manager,
            definition,
            id,
            sha: v["request_sha256"].as_str().unwrap().into(),
            sequence: 0,
            nonces: BTreeSet::new(),
            failed: false,
        })
    }
    /// No positive reply is sent after approval/source/lock/provider loss. A
    /// partial or failed exchange permanently retires this original supervisor.
    pub async fn next(&mut self, channel: &Packet) -> Result<Event> {
        require(
            !self.failed && self.sequence < 10000,
            "backup caller checkpoint retired or bounded",
        )?;
        self.failed = true;
        self.intent.recheck()?;
        self.manager.recheck().await?;
        let original = self.intent.value()?;
        let message = match enzimos_policy::backup_worker_observation::receive(
            channel,
            self.scope,
            &original["request"],
            self.sequence,
        )? {
            enzimos_policy::backup_worker_observation::Incoming::Observation(observation) => {
                require(
                    self.nonces.insert(observation.nonce().to_owned()),
                    "report nonce reused an acknowledged checkpoint",
                )?;
                self.intent.recheck()?;
                self.manager.recheck().await?;
                native_worker_manager::recheck_for(self.manager, &self.definition, self.worker)
                    .await?;
                self.scope.binding()?;
                channel.send(
                    &json::canonical(&observation.receipt()?)?,
                    &[],
                    Duration::from_secs(2),
                )?;
                self.intent.recheck()?;
                return Ok(Event::Observation(observation));
            }
            enzimos_policy::backup_worker_observation::Incoming::Challenge(message) => message,
        };
        native_worker_manager::recheck_for(self.manager, &self.definition, self.worker).await?;
        let v = challenge(
            &message,
            &self.id,
            &self.sha,
            self.worker.state.pid,
            self.sequence + 1,
        )?;
        require(
            self.nonces.insert(v["nonce"].as_str().unwrap().into()),
            "worker checkpoint nonce replayed",
        )?;
        self.intent.recheck()?;
        native_worker_manager::recheck_for(self.manager, &self.definition, self.worker).await?;
        let original = self.intent.value()?;
        require(
            original["phase"] == "starting" && original["request_sha256"] == self.sha,
            "original worker request no longer starting",
        )?;
        self.intent.recheck()?;
        let mut reply = v;
        reply["authorized"] = value!(true);
        channel.send(&json::canonical(&reply)?, &[], Duration::from_secs(2))?;
        self.sequence += 1;
        self.failed = false;
        Ok(Event::Checkpoint)
    }
}
