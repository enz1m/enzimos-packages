// SPDX-License-Identifier: MIT
use enzimos_policy::package_signature;
const FP: &str = "1111111111111111111111111111111111111111";
const PRIMARY: &str = "2222222222222222222222222222222222222222";
fn valid() -> String {
    format!(
        "[GNUPG:] VALIDSIG {FP} 2026-10-09 1791504000 0 4 0 22 10 00 {PRIMARY}\n[GNUPG:] TRUST_FULLY 0 direct\n"
    )
}
#[test]
fn package_status_requires_one_trusted_primary_and_rejects_failed_or_expired_signatures() {
    let body = valid();
    assert_eq!(
        package_signature::status(body.as_bytes(), true).unwrap(),
        PRIMARY
    );
    assert!(package_signature::status(body.as_bytes(), false).is_err());
    for failure in [
        "BADSIG",
        "ERRSIG",
        "REVKEYSIG",
        "EXPKEYSIG",
        "EXPSIG",
        "NO_PUBKEY",
        "FAILURE",
        "ERROR",
    ] {
        assert!(
            package_signature::status(
                format!("{body}[GNUPG:] {failure} diagnostic\n").as_bytes(),
                true
            )
            .is_err()
        );
    }
    assert!(
        package_signature::status(
            body.replace("TRUST_FULLY", "TRUST_UNDEFINED").as_bytes(),
            true
        )
        .is_err()
    );
    assert!(package_signature::status(format!("{body}{body}").as_bytes(), true).is_err());
    assert!(package_signature::status(b"[GNUPG:] GOODSIG key TRUST_FULLY\n", true).is_err());
    let uid =
        body.replace("TRUST_FULLY", "TRUST_UNDEFINED") + "[GNUPG:] GOODSIG key User TRUST_FULLY\n";
    assert!(package_signature::status(uid.as_bytes(), true).is_err());
}
