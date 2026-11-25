// SPDX-License-Identifier: MIT
//! Independent recovery entry points refuse ordinary processes.
#[test]
fn independent_entrypoints_refuse_ordinary_processes_before_kernel_mutations() {
    for binary in [
        env!("CARGO_BIN_EXE_enzimos-recovery-image-init"),
        env!("CARGO_BIN_EXE_enzimos-recovery-run-init"),
    ] {
        let output = std::process::Command::new(binary)
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("direct Root PID1")
        );
        assert!(output.stdout.is_empty());
    }
}
