// SPDX-License-Identifier: MIT
//! Closed workflows; a composite provision attempt has one whole-worker barrier.
use enzimos_platform::{Result, local_restic::Task};
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Single(Task),
    ProvisionInitialize,
    ProvisionAdopt,
}
impl Work {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "provision-initialize" => Ok(Self::ProvisionInitialize),
            "provision-adopt" => Ok(Self::ProvisionAdopt),
            _ => Task::parse(name).map(Self::Single),
        }
    }
    pub fn input(self) -> bool {
        self == Self::Single(Task::AuthenticateInput)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Single(task) => task.name(),
            Self::ProvisionInitialize => "provision-initialize",
            Self::ProvisionAdopt => "provision-adopt",
        }
    }
}
