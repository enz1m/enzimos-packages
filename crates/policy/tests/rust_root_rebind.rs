// SPDX-License-Identifier: MIT
//! Root rebind planning and application.
use enzimos_platform::json;
use enzimos_policy::{
    boot_entries, catalog,
    root_rebind_plan::{self as plan, RecoveryOwners, Texts},
};
use serde_json::{Value, json as value};
use std::collections::BTreeMap;
use std::fmt::Write as _;
const FS: &str = "11111111-1111-4111-8111-111111111111";
const TARGET: &str = "22222222-2222-4222-8222-222222222222";
const BOOT: &str = "33333333-3333-4333-8333-333333333333";
fn seal(mut journal: Value) -> Value {
    journal
        .as_object_mut()
        .expect("test fixture")
        .remove("journal_sha256");
    let digest = json::fingerprint(&journal).expect("test fixture");
    journal["journal_sha256"] = value!(digest);
    journal
}
fn journal() -> Value {
    let files = fixture();
    let source = root("root", 256, FS);
    let target = root("fallback", 300, TARGET);
    let before = catalog::empty(FS).expect("test fixture");
    let result = plan::redirect(
        &before,
        &source,
        &target,
        &files,
        Some(&declaration()),
        &owners(),
        |s| Ok(s.into()),
    )
    .expect("test fixture");
    let hash = json::sha256(b"fixture");
    seal(
        value!({"schema":1,"id":"g1","phase":"prepared","filesystem_uuid":FS,"source":source,"target":target,
        "snapshot":{"number":1,"uuid":BOOT},"inventory_sha256":hash,"kernels":{"linux":"6.18","linux-lts":"6.12"},
        "kernel_hashes":{"linux":hash,"linux-lts":hash},"authority":{"pubring.gpg":hash,"gpg.conf":hash,"approved.trust":hash,"ownertrust":hash},
        "before_files":files,"replacements":result.replacements,"before_catalog":before,"after_catalog":result.catalog,"affected":result.affected}),
    )
}
struct Fixture {
    root: tempfile::TempDir,
    names: Vec<String>,
    catalog: Value,
    fail_boundary: bool,
    context_valid: bool,
    writes: usize,
    finished: bool,
}
impl Fixture {
    fn new(journal: &Value) -> Self {
        let root = tempfile::tempdir_in(std::env::var_os("ENZIMOS_TEST_TMPDIR").map_or_else(
            || std::env::current_dir().expect("test fixture"),
            std::path::PathBuf::from,
        ))
        .expect("test fixture");
        let names = journal["before_files"]
            .as_object()
            .expect("test fixture")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for name in &names {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().expect("test fixture")).expect("test fixture");
            enzimos_platform::files::atomic(
                &path,
                journal["before_files"][name]
                    .as_str()
                    .expect("test fixture")
                    .as_bytes(),
                0o600,
                Some(enzimos_platform::process_identity::effective_uid()),
                false,
            )
            .expect("test fixture");
        }
        Self {
            root,
            names,
            catalog: journal["before_catalog"].clone(),
            fail_boundary: false,
            context_valid: true,
            writes: 0,
            finished: false,
        }
    }
}
impl enzimos_policy::root_rebind_apply::Adapter for Fixture {
    fn verify(&mut self, _journal: &Value) -> enzimos_platform::Result<()> {
        enzimos_platform::require(
            self.context_valid,
            "fixture authority or root lineage changed",
        )
    }
    fn files(&mut self) -> enzimos_platform::Result<Texts> {
        self.names
            .iter()
            .map(|name| {
                let body = enzimos_platform::files::read(
                    &self.root.path().join(name),
                    boot_entries::MAX_TEXT,
                    Some(enzimos_platform::process_identity::effective_uid()),
                    true,
                )?;
                Ok((name.clone(), String::from_utf8(body).expect("test fixture")))
            })
            .collect()
    }
    fn catalog(&mut self) -> enzimos_platform::Result<Value> {
        Ok(self.catalog.clone())
    }
    fn write_file(&mut self, name: &str, body: &str) -> enzimos_platform::Result<()> {
        self.writes += 1;
        enzimos_platform::files::atomic(
            &self.root.path().join(name),
            body.as_bytes(),
            0o600,
            Some(enzimos_platform::process_identity::effective_uid()),
            true,
        )
    }
    fn write_catalog(&mut self, body: &Value) -> enzimos_platform::Result<()> {
        self.catalog = body.clone();
        Ok(())
    }
    fn finish(&mut self, _journal: &Value) -> enzimos_platform::Result<()> {
        self.finished = true;
        Ok(())
    }
    fn boundary(&mut self, name: &str, _journal: &Value) -> enzimos_platform::Result<()> {
        if self.fail_boundary && name.starts_with("file:") {
            return Err(enzimos_platform::Error(
                "owned fixture interruption after durable file write".into(),
            ));
        }
        Ok(())
    }
}
#[test]
fn completed_rebind_is_read_only_and_malformed_authority_or_affected_sets_are_refused() {
    use enzimos_policy::{root_rebind_apply::apply, root_rebind_record};
    let prepared = journal();
    let mut fixture = Fixture::new(&prepared);
    fixture.context_valid = false;
    let mut complete = prepared.clone();
    complete["phase"] = value!("complete");
    let result = apply(&seal(complete), &mut fixture).unwrap();
    assert_eq!(result["status"], "already-complete");
    assert_eq!(fixture.writes, 0);
    let mut malformed = prepared.clone();
    malformed["authority"]["ownertrust"] = value!(true);
    assert!(root_rebind_record::validate(&seal(malformed), "g1").is_err());
    malformed = prepared;
    malformed["affected"] = value!(["gen1", "gen1"]);
    assert!(root_rebind_record::validate(&seal(malformed), "g1").is_err());
}
fn root(path: &str, id: u64, uuid: &str) -> Value {
    value!({"path":path,"id":id,"uuid":uuid,"ownership":"not-established"})
}
fn declaration() -> Value {
    value!({"uefi":["linux.conf","linux-lts.conf"],"bios":["enzimOS linux","enzimOS linux-lts"]})
}
fn fixture() -> Texts {
    let mut files = Texts::from([
        (
            "loader/loader.conf".into(),
            "default linux.conf\ntimeout 3\n".into(),
        ),
        (
            "limine/limine.conf".into(),
            "timeout: 3\ndefault_entry: 1\n".into(),
        ),
    ]);
    for flavor in ["linux", "linux-lts"] {
        files.insert(format!("loader/entries/{flavor}.conf"),format!("title enzimOS {flavor}\nlinux /vmlinuz-{flavor}\ninitrd /initramfs-{flavor}.img\noptions root=UUID={FS} rootflags=compress=zstd,subvol=root quiet\n"));
        let _ = write!(
            files.get_mut("limine/limine.conf").expect("test fixture"),
            "/enzimOS {flavor}\n protocol: linux\n path: boot():/vmlinuz-{flavor}\n module_path: boot():/initramfs-{flavor}.img\n cmdline: root=UUID={FS} rootflags=compress=zstd,subvol=root quiet\n"
        );
    }
    files.insert("loader/entries/recovery.conf".into(),"title Independent enzimOS lab recovery\nlinux /enzimos-recovery/kernel\ninitrd /enzimos-recovery/initrd.img\noptions enzimos.recovery=1\n".into());
    files.get_mut("limine/limine.conf").expect("test fixture").push_str("/Independent enzimOS lab recovery\n protocol: linux\n path: boot():/enzimos-recovery/kernel\n module_path: boot():/enzimos-recovery/initrd.img\n cmdline: enzimos.recovery=1\n");
    files
}
fn owners() -> RecoveryOwners {
    RecoveryOwners::from_records(&BTreeMap::new(), &BTreeMap::new()).expect("test fixture")
}
