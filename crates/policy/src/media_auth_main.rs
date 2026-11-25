// SPDX-License-Identifier: MIT
//! Confined verifier of recovery media account passwords.
use std::io::Read;
use zeroize::Zeroizing;
fn run() -> enzimos_platform::Result<()> {
    enzimos_platform::require(
        std::env::args_os().count() == 1,
        "password verifier arguments refused",
    )?;
    enzimos_policy::media_password::constrain()?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(1025));
    std::io::stdin().lock().take(1025).read_to_end(&mut bytes)?;
    enzimos_policy::media_password::verify(&bytes)
}
fn main() {
    if run().is_err() {
        std::process::exit(2);
    }
}
