// SPDX-License-Identifier: MIT
use enzimos_system_backend::secret;
use std::os::fd::BorrowedFd;
#[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
fn run() -> Result<(), ()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 || args[0] != "--fd" || args[2] != "--uid" {
        return Err(());
    }
    let fd = args[1].parse::<i32>().map_err(|_| ())?;
    let uid = args[3].parse::<u32>().map_err(|_| ())?;
    if fd < 3 {
        return Err(());
    }
    let retained = secret::retain(unsafe { BorrowedFd::borrow_raw(fd) }, uid).map_err(|_| ())?;
    secret::constrain_consumer(retained.fd().map_err(|_| ())?).map_err(|_| ())?;
    retained.validate_in_consumer().map_err(|_| ())
}
fn main() {
    if run().is_err() {
        std::process::exit(2);
    }
}
