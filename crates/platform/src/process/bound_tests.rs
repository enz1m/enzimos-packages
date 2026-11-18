use super::*;
fn sh(script: &str, limit: usize) -> Result<Output> {
    run(
        "/usr/bin/sh",
        &["-c", script],
        &[],
        Duration::from_secs(10),
        limit,
    )
}
#[test]
fn exceeded_bounds_name_the_command_and_stream() {
    let Err(error) = sh("head -c 5000 /dev/zero", 4096) else {
        panic!("stdout bound not enforced")
    };
    assert!(
        error
            .0
            .starts_with("command output bound exceeded: /usr/bin/sh stdout"),
        "{}",
        error.0
    );
    let Err(error) = sh("head -c 70000 /dev/zero >&2", 32) else {
        panic!("stderr bound not enforced")
    };
    assert!(error.0.contains("/usr/bin/sh stderr"), "{}", error.0);
}
