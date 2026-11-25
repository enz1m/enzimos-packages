// SPDX-License-Identifier: MIT
//! A bare coordinator image offers no shell and cannot start an unrecorded operation.
use enzimos_policy::recovery_bootstrap;
#[allow(unsafe_code, reason = "Linux syscall ABI (pause).")]
#[expect(
    clippy::print_stdout,
    reason = "The refusal is reported on the console."
)]
fn main() {
    if let Err(error) = recovery_bootstrap::initialize() {
        eprintln!("ENZIMOS_RECOVERY_IMAGE_BOOTSTRAP_REFUSED {error}");
        std::process::exit(2);
    }
    println!(
        "ENZIMOS_RECOVERY_IMAGE_REFUSED coordinator-only image; no general recovery environment"
    );
    if let Err(error) = recovery_bootstrap::power_off() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    loop {
        // SAFETY: pause takes no arguments.
        unsafe { libc::pause() };
    }
}
