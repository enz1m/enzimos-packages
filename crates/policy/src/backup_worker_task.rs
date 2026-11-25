// SPDX-License-Identifier: MIT
//! Closed workflows; a composite provision attempt has one whole-worker barrier.
use enzimos_platform::{Result, local_restic::Task};
/// Work a backup worker performs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// One fixed local Restic task.
    Single(Task),
    /// Provision by initializing a new repository.
    ProvisionInitialize,
    /// Provision by adopting an existing repository.
    ProvisionAdopt,
}
impl Work {
    /// Parse a wire name produced by [`Work::name`].
    ///
    /// # Errors
    ///
    /// Fails for unknown names.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "provision-initialize" => Ok(Self::ProvisionInitialize),
            "provision-adopt" => Ok(Self::ProvisionAdopt),
            _ => Task::parse(name).map(Self::Single),
        }
    }
    pub(crate) fn input(self) -> bool {
        self == Self::Single(Task::AuthenticateInput)
    }
    /// Stable wire name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Single(task) => task.name(),
            Self::ProvisionInitialize => "provision-initialize",
            Self::ProvisionAdopt => "provision-adopt",
        }
    }
}
