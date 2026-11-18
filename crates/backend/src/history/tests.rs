// SPDX-License-Identifier: MIT
use super::*;
use std::fs;
use std::os::unix::fs::MetadataExt;

fn info(number: u32, date: &str, description: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<snapshot>\n  <type>single</type>\n  <num>{number}</num>\n  <date>{date}</date>\n  <description>{description}</description>\n  <cleanup>timeline</cleanup>\n</snapshot>\n"
    )
}

struct Lab {
    dir: tempfile::TempDir,
    owner: Owner,
}
impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let uid = fs::metadata(dir.path()).expect("meta").uid();
        fs::create_dir_all(dir.path().join("home/alice")).expect("mkdir");
        Self {
            owner: Owner {
                uid,
                home: PathBuf::from("alice"),
            },
            dir,
        }
    }
    fn snapshot(&self, number: u32, date: &str, description: &str, files: &[(&str, &str)]) {
        let base = self.dir.path().join(format!("home/.snapshots/{number}"));
        fs::create_dir_all(base.join("snapshot/alice")).expect("mkdir");
        fs::write(base.join("info.xml"), info(number, date, description)).expect("info");
        for (path, text) in files {
            let p = base.join("snapshot/alice").join(path);
            fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            fs::write(&p, text).expect("write");
            // Distinct mtimes per content, like real edits.
            let when = std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(1_700_000_000 + text.len() as u64 * 100);
            fs::File::options()
                .write(true)
                .open(&p)
                .expect("open")
                .set_modified(when)
                .expect("mtime");
        }
    }
    fn snapshots(&self) -> fs::File {
        fs::File::open(self.dir.path().join("home/.snapshots")).expect("open")
    }
    fn home_root(&self) -> fs::File {
        fs::File::open(self.dir.path().join("home")).expect("open")
    }
}

#[test]
fn folders_list_deleted_files_and_hide_other_homes_and_symlink_escapes() {
    let lab = Lab::new();
    lab.snapshot(
        1,
        "2026-11-01 08:00:00",
        DESCRIPTION,
        &[("notes/a.txt", "a"), ("notes/gone.txt", "g")],
    );
    fs::create_dir_all(lab.dir.path().join("home/alice/notes")).expect("mkdir");
    fs::write(lab.dir.path().join("home/alice/notes/a.txt"), "a").expect("live");
    let base = lab.dir.path().join("home/.snapshots/1/snapshot");
    fs::create_dir_all(base.join("bob")).expect("bob");
    fs::write(base.join("bob/secret"), "x").expect("secret");
    std::os::unix::fs::symlink("../../bob", base.join("alice/notes/escape")).expect("symlink");
    let snapshots = lab.snapshots();
    let root = open_snapshot(&snapshots, 1).expect("snapshot");
    let live = live_folder(&lab.owner, &lab.home_root(), Some(Path::new("notes")));
    let items = folder(&lab.owner, &root, Some(Path::new("notes")), live.as_ref()).expect("folder");
    let summary: Vec<(&str, char, bool)> = items
        .iter()
        .map(|i| (i.name.as_str(), i.kind, i.exists))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("a.txt", 'f', true),
            ("escape", 'l', false),
            ("gone.txt", 'f', false)
        ],
        "deleted file shown as gone"
    );
    assert!(
        open(&lab.owner, &root, Path::new("notes/escape/secret")).is_err(),
        "no symlink escape"
    );
    assert!(
        open(&lab.owner, &root, Path::new("notes")).is_err(),
        "folders are not opened as files"
    );
    let bob = Owner {
        uid: lab.owner.uid,
        home: PathBuf::from("bob"),
    };
    assert!(
        bob.relative("/home/alice/notes/a.txt").is_err(),
        "another home's path is refused"
    );
}

#[test]
fn forgetting_removes_a_file_from_every_snapshot_but_keeps_others() {
    let lab = Lab::new();
    lab.snapshot(
        1,
        "2026-11-01 08:00:00",
        DESCRIPTION,
        &[("tax.pdf", "1"), ("keep.txt", "k")],
    );
    lab.snapshot(2, "2026-11-02 08:00:00", DESCRIPTION, &[("tax.pdf", "22")]);
    let snapshots = lab.snapshots();
    let list = list(&snapshots).expect("list");
    // A plain directory is not a subvolume, so the read-only toggle fails here;
    // the removal itself is exercised through remove() directly.
    for number in [1, 2] {
        let root = open_snapshot(&snapshots, number).expect("snapshot");
        let home = lab.owner.home_in(&root).expect("home");
        let (removed, kept) =
            super::prune::tests_remove(&home, Path::new("tax.pdf"), lab.owner.uid).expect("remove");
        assert_eq!((removed, kept), (1, 0), "removed from snapshot {number}");
    }
    let versions =
        versions(&lab.owner, &snapshots, &list, Path::new("tax.pdf"), None).expect("versions");
    assert!(versions.is_empty(), "no version left");
    assert!(
        lab.dir
            .path()
            .join("home/.snapshots/1/snapshot/alice/keep.txt")
            .exists(),
        "other files kept"
    );
}
