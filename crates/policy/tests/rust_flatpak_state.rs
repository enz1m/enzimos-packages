// SPDX-License-Identifier: MIT
use enzimos_policy::{flatpak_plan::Source, flatpak_state as state};
const CONFIG: &str = "[core]\nrepo_version=1\nmode=bare-user-only\n[remote \"flathub\"]\nurl=https://dl.flathub.org/repo/\ncollection-id=org.flathub.Stable\ngpg-verify=true\ngpg-verify-summary=true\nurl-is-set=true\nxa.authenticator-install=false\n";
const ENZIMOS: &str = "[remote \"enzimos\"]\nurl=https://flatpak.enzimos.invalid/repo/\nxa.title=enzimOS Apps\nxa.default-branch=stable\ngpg-verify=true\ncollection-id=org.enzimos.Apps\ngpg-verify-summary=true\nxa.authenticator-install=false\nxa.authenticator-install-is-set=true\n";
const BOTH: [Source; 2] = [Source::Flathub, Source::Enzimos];
#[test]
fn effective_remote_preserves_signatures_and_refuses_routing_or_authentication_changes() {
    state::remote(CONFIG.as_bytes(), &[Source::Flathub]).unwrap();
    let both = format!("{CONFIG}{ENZIMOS}");
    state::remote(both.as_bytes(), &BOTH).unwrap();
    for (body, sources) in [
        // The enzimOS remote is admitted only where the installer added it.
        (both.clone(), &[Source::Flathub][..]),
        (CONFIG.into(), &BOTH[..]),
        (
            both.replace("enzimos.invalid", "foreign.invalid"),
            &BOTH[..],
        ),
        (
            both.replace("org.enzimos.Apps", "org.flathub.Stable"),
            &BOTH[..],
        ),
        (
            format!(
                "{CONFIG}{}",
                ENZIMOS.replace("gpg-verify=true", "gpg-verify=false")
            ),
            &BOTH[..],
        ),
    ] {
        assert!(state::remote(body.as_bytes(), sources).is_err(), "{body}");
    }
    for body in [
        CONFIG.replace("gpg-verify=true", "gpg-verify=false"),
        CONFIG.replace("url-is-set=true", "url-is-set=false"),
        CONFIG.replace("org.flathub.Stable", "foreign.Collection"),
        format!("{CONFIG}xa.authenticator-name=org.Foreign.Auth\n"),
        format!("{CONFIG}gpg-verify=true\n"),
        CONFIG.replace(
            "mode=bare-user-only",
            "mode=bare-user-only\nparent=/host/repo",
        ),
        format!("{CONFIG}[remote \"foreign\"]\nurl=https://foreign.invalid\n"),
    ] {
        assert!(state::remote(body.as_bytes(), &[Source::Flathub]).is_err());
    }
}
