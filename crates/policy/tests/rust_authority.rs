// SPDX-License-Identifier: MIT
//! Package authority quorum over the pinned master keys.
use enzimos_policy::authority;
use std::collections::{BTreeMap, BTreeSet};
fn listing(fp: &str, uid: &str, validity: &str) -> String {
    format!("pub:f:2048:1:id:1:0:::::scSC:\nfpr:::::::::{fp}:\nuid:{validity}::::::::{uid}:\n")
}
fn packager() -> String {
    "ABCDEF0123456789ABCDEF0123456789ABCDEF01".into()
}
#[test]
fn independent_quorum_requires_three_pinned_masters_for_the_same_arch_identity() {
    let fp = packager();
    let uid = "Packager <maintainer@archlinux.org>";
    let mut contexts = authority::MASTERS
        .into_iter()
        .enumerate()
        .map(|(i, m)| {
            (
                m.into(),
                if i < 3 {
                    listing(&fp, uid, "f")
                } else {
                    String::new()
                },
            )
        })
        .collect::<BTreeMap<String, String>>();
    assert_eq!(
        authority::quorum(&contexts, &BTreeSet::new()).unwrap(),
        std::slice::from_ref(&fp)
    );
    contexts.insert(
        authority::MASTERS[2].into(),
        listing(&fp, "Other <different@archlinux.org>", "f"),
    );
    assert!(
        authority::quorum(&contexts, &BTreeSet::new())
            .unwrap()
            .is_empty()
    );
    contexts.insert(authority::MASTERS[2].into(), listing(&fp, uid, "m"));
    assert!(
        authority::quorum(&contexts, &BTreeSet::new())
            .unwrap()
            .is_empty()
    );
    contexts.insert(authority::MASTERS[2].into(), listing(&fp, uid, "f"));
    assert!(
        authority::quorum(&contexts, &BTreeSet::from([fp.clone()]))
            .unwrap()
            .is_empty()
    );
    assert!(authority::quorum(&contexts, &BTreeSet::from([authority::MASTERS[0].into()])).is_err());
    contexts.insert("rogue-master".into(), listing(&fp, uid, "f"));
    assert!(authority::quorum(&contexts, &BTreeSet::new()).is_err());
    contexts.remove("rogue-master");
    contexts.remove(authority::MASTERS[4]);
    assert!(authority::quorum(&contexts, &BTreeSet::new()).is_err());
}
