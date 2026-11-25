// SPDX-License-Identifier: MIT
//! Closed boot-family decoding. This data grants no Root operation or replay.
use enzimos_platform::Result;
/// Kernel command line parameters of a native boot, by family.
pub enum Parameters {
    /// A recovery run.
    Recovery(crate::recovery_run_parameters::Parameters),
    /// A root retirement.
    Root(crate::root_retirement_parameters::Parameters),
}
/// Whether the command line describes a root retirement.
pub fn is_root(body: &str) -> bool {
    body.split_whitespace()
        .any(|word| word.split('=').next() == Some("enzimos.root-retirement"))
}
impl Parameters {
    /// Parse the command line of either family.
    ///
    /// # Errors
    ///
    /// Fails when the parameters of the detected family are invalid.
    pub fn parse(body: &str) -> Result<Self> {
        if is_root(body) {
            crate::root_retirement_parameters::Parameters::parse(body).map(Self::Root)
        } else {
            crate::recovery_run_parameters::Parameters::parse(body).map(Self::Recovery)
        }
    }
    /// Whether the system powers off afterwards.
    pub fn poweroff(&self) -> bool {
        match self {
            Self::Recovery(p) => p.exit == "poweroff",
            Self::Root(p) => p.exit == "poweroff",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> String {
        "console=tty0 enzimos.root-retirement=root-0123456789abcdef0123456789abcdef enzimos.luks=01234567-89ab-cdef-0123-456789abcdef enzimos.fs=11234567-89ab-cdef-0123-456789abcdef enzimos.control=control enzimos.esp=ABCD-1234 enzimos.uefi-restore=enzimos.conf enzimos.bios-restore=1:2 enzimos.coordinator-exit=poweroff".into()
    }

    #[test]
    fn decoded_valid_root_parameters_cannot_execute_on_a_normal_process() {
        if std::process::id() != 1 {
            let Parameters::Root(parameters) = Parameters::parse(&root()).unwrap() else {
                panic!()
            };
            assert!(crate::root_retirement_boot::run(&parameters).is_err());
        }
    }
}
