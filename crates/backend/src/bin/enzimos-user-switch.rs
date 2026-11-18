// SPDX-License-Identifier: MIT
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = enzimos_system_backend::user_switch::serve().await {
        eprintln!("{}", error.0);
        std::process::exit(1);
    }
}
