// SPDX-License-Identifier: MIT
//! Install oo7 hooks in the login stacks already present on the target.
#[expect(
    clippy::print_stdout,
    reason = "The JSON result is the command's output."
)]
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--root" {
        eprintln!("usage: enzimos-keyring-setup --root ABSOLUTE_DIRECTORY");
        std::process::exit(2);
    }
    match enzimos_policy::desktop_setup::configure_keyring(std::path::Path::new(&args[1])) {
        Ok(result) => println!("{result}"),
        Err(error) => {
            eprintln!("enzimos-keyring-setup: {error}");
            std::process::exit(1);
        }
    }
}
