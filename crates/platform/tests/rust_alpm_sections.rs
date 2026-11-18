// SPDX-License-Identifier: MIT
use enzimos_platform::alpm_sections::parse;
#[test]
fn duplicate_sections_malformed_headers_and_control_bytes_are_refused() {
    for bytes in [
        b"%NAME%\na\n\n\n%NAME%\nb\n".as_slice(),
        b"%bad%\nx\n",
        b"%NAME%\r\nx\r\n",
        b"%NAME%\nx\0\n",
        b"\n\n",
        b"value\n\n%NAME%\na\n",
    ] {
        assert!(parse(bytes).is_err());
    }
    let too_many = (0..129)
        .map(|n| format!("%FIELD{n}%\nx\n\n"))
        .collect::<String>();
    assert!(parse(too_many.as_bytes()).is_err());
    assert!(parse(&vec![b' '; 512 * 1024 + 1]).is_err());
}
