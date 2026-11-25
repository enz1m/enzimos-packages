// SPDX-License-Identifier: MIT
//! Preparation is not packet admission. No request or descriptor is consumed
//! until the original live caller has completed its guarded source preparation.
use enzimos_platform::{Result, fd_packet::Packet, process_identity::Retained};
use std::time::Duration;
pub(crate) const PREPARATION_LIMIT: Duration = Duration::from_secs(120);
pub(crate) fn wait(
    channel: &Packet,
    caller: &Retained,
    timeout: Duration,
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    channel.wait_ready(caller, timeout, checkpoint)
}
