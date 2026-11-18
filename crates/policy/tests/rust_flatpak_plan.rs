// SPDX-License-Identifier: MIT
use enzimos_policy::flatpak_plan::{self as plan, Source};
const REMOTE: &str = include_str!("fixtures/flathub.flatpakrepo");
#[test]
fn actual_public_flathub_export_is_accepted_but_signing_and_routing_overrides_refuse() {
    let reviewed = plan::remote(Source::Flathub, REMOTE.as_bytes()).unwrap();
    assert_eq!(reviewed["gpg_verify"], true);
    assert_eq!(reviewed["collection"], plan::COLLECTION);
    for changed in [
        REMOTE.replace(plan::URL, "https://foreign.invalid/repo/"),
        format!("{REMOTE}\nGPGVerify=false\n"),
        format!("{REMOTE}\nUrl={}\n", plan::URL),
        format!("{REMOTE}\nCollectionID=foreign.Collection\n"),
        format!("{REMOTE}\n[Flatpak Repo]\n"),
        format!("{REMOTE}\nAuthenticatorName=org.Foreign.Auth\n"),
    ] {
        assert!(plan::remote(Source::Flathub, changed.as_bytes()).is_err());
    }
    let encoded = REMOTE
        .lines()
        .find_map(|s| s.strip_prefix("GPGKey="))
        .unwrap();
    let public = openssl::base64::decode_block(encoded).unwrap();
    for changed in [
        public[..public.len() - 1].to_vec(),
        {
            let mut secret = public.clone();
            secret.extend_from_slice(&[0xc5, 1, 4]);
            secret
        },
        {
            let mut mixed = public.clone();
            mixed.extend_from_slice(&public);
            mixed
        },
        {
            let mut partial = public.clone();
            partial.extend_from_slice(&[0xc2, 224, 4]);
            partial
        },
    ] {
        let encoded_bad = openssl::base64::encode_block(&changed);
        assert!(
            plan::remote(
                Source::Flathub,
                REMOTE.replace(encoded, &encoded_bad).as_bytes()
            )
            .is_err()
        );
    }
}
