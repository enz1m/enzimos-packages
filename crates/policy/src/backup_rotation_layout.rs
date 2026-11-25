// SPDX-License-Identifier: MIT
//! Original bounded Restic directory inventory; not a recursive-delete shortcut.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};
const ROOT_NAMES: [&str; 6] = ["config", "keys", "data", "index", "snapshots", "locks"];
const MAXIMUM: usize = 1 << 20;
const MEMORY: usize = 48 * 1024 * 1024;
fn permitted(relative: &Path, directory: bool, partial: bool) -> bool {
    let Some(parts) = relative
        .components()
        .map(|p| p.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if parts.is_empty() || parts.len() > 3 {
        return false;
    }
    let name = *parts.last().unwrap();
    if directory {
        (parts.len() == 1 && ROOT_NAMES.contains(&name))
            || (parts.len() == 2
                && parts[0] == "data"
                && name.len() == 2
                && name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    } else {
        if parts.len() == 1 {
            return name == "config";
        }
        if !ROOT_NAMES.contains(&parts[0]) {
            return false;
        }
        let (hash, temp) = name
            .split_once("-tmp-")
            .map_or((name, None), |(h, t)| (h, Some(t)));
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && temp.is_none_or(|t| {
                partial && !t.is_empty() && t.len() <= 20 && t.bytes().all(|b| b.is_ascii_digit())
            })
    }
}
pub(crate) struct Layout {
    root: File,
    epoch: files::FileIdentity,
    mount: u64,
    owner: u32,
    partial: bool,
    objects: BTreeMap<PathBuf, files::FileIdentity>,
}
impl Layout {
    pub(crate) fn capture(root: &File, owner: u32, partial: bool) -> Result<Self> {
        let root = root.try_clone()?;
        let metadata = root.metadata()?;
        require(
            metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
            "protected original rotation layout root",
        )?;
        let epoch = files::identity(&metadata);
        let mount = mount_identity::id(root.as_fd(), true)?;
        let original = Self {
            root,
            epoch,
            mount,
            owner,
            partial,
            objects: BTreeMap::new(),
        };
        let objects = original.scan()?;
        let original = Self {
            objects,
            ..original
        };
        original.recheck()?;
        Ok(original)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
    fn scan(&self) -> Result<BTreeMap<PathBuf, files::FileIdentity>> {
        require(
            files::identity(&self.root.metadata()?) == self.epoch
                && mount_identity::id(self.root.as_fd(), true)? == self.mount,
            "original rotation layout root changed",
        )?;
        let mut todo = vec![PathBuf::new()];
        let mut objects = BTreeMap::new();
        let mut memory = 0usize;
        while let Some(relative) = todo.pop() {
            let directory = if relative.as_os_str().is_empty() {
                self.root.try_clone()?
            } else {
                files::directory_relative(&self.root, &relative, Some(self.owner))?
            };
            let before = files::identity(&directory.metadata()?);
            require(
                mount_identity::id(directory.as_fd(), true)? == self.mount,
                "rotation layout directory crossed mount",
            )?;
            for name in
                files::directory_names(&directory, (MAXIMUM - objects.len()).clamp(1, 131072))?
            {
                let path = relative.join(&name);
                let name = CString::new(name.as_os_str().as_bytes())
                    .map_err(|_| enzimos_platform::Error("rotation layout name NUL".into()))?;
                // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid
                // value.
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                require(
                    unsafe {
                        libc::fstatat(
                            directory.as_raw_fd(),
                            name.as_ptr(),
                            &mut stat,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    } == 0,
                    "original rotation layout entry unavailable",
                )?;
                let is_directory = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
                require(
                    stat.st_uid == self.owner
                        && stat.st_dev == self.epoch.0
                        && (is_directory
                            || (stat.st_mode & libc::S_IFMT == libc::S_IFREG
                                && stat.st_nlink == 1))
                        && permitted(&path, is_directory, self.partial),
                    "unknown/unsafe rotation layout entry",
                )?;
                let object = if is_directory {
                    files::directory_relative(&self.root, &path, Some(self.owner))?
                } else {
                    files::open_relative(&self.root, &path)?
                };
                let m = object.metadata()?;
                require(
                    m.ino() == stat.st_ino
                        && m.dev() == stat.st_dev
                        && m.mode() == stat.st_mode
                        && m.uid() == stat.st_uid
                        && m.gid() == stat.st_gid
                        && m.nlink() == stat.st_nlink
                        && m.mode() & 0o022 == 0
                        && mount_identity::id(object.as_fd(), true)? == self.mount,
                    "rotation layout object changed while opening",
                )?;
                memory = memory
                    .checked_add(path.as_os_str().as_bytes().len() + 128)
                    .ok_or_else(|| {
                        enzimos_platform::Error("rotation layout memory overflow".into())
                    })?;
                require(
                    objects.len() < MAXIMUM && memory <= MEMORY,
                    "rotation layout count/memory bound",
                )?;
                objects.insert(path.clone(), files::identity(&m));
                if is_directory {
                    todo.push(path);
                }
            }
            require(
                files::identity(&directory.metadata()?) == before,
                "rotation layout directory changed while observing",
            )?;
        }
        require(
            files::identity(&self.root.metadata()?) == self.epoch,
            "rotation layout root changed while observing",
        )?;
        Ok(objects)
    }
    /// Consume only the original captured members. Each syscall uses the held
    /// parent and exact original inode; unknown members are retained on refusal.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub(crate) fn empty_original(
        mut self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        require(
            enzimos_platform::process_identity::effective_uid() == self.owner,
            "original layout writer authority",
        )?;
        self.recheck()?;
        let mut paths = self.objects.keys().cloned().collect::<Vec<_>>();
        paths.sort_by(|a, b| {
            b.components()
                .count()
                .cmp(&a.components().count())
                .then(a.cmp(b))
        });
        for path in paths {
            authorize()?;
            let expected = *self.objects.get(&path).unwrap();
            let directory = expected.7 & libc::S_IFMT == libc::S_IFDIR;
            let parent_path = path.parent().unwrap();
            require(
                files::identity(&self.root.metadata()?) == self.epoch
                    && mount_identity::id(self.root.as_fd(), true)? == self.mount,
                "original removal root changed",
            )?;
            // Recheck every original ancestor before opening this member.
            let mut ancestor = PathBuf::new();
            for part in parent_path.components() {
                ancestor.push(part.as_os_str());
                let fd = files::directory_relative(&self.root, &ancestor, Some(self.owner))?;
                require(
                    self.objects.get(&ancestor) == Some(&files::identity(&fd.metadata()?))
                        && mount_identity::id(fd.as_fd(), true)? == self.mount,
                    "original removal ancestor changed",
                )?;
            }
            let parent = if parent_path.as_os_str().is_empty() {
                self.root.try_clone()?
            } else {
                files::directory_relative(&self.root, parent_path, Some(self.owner))?
            };
            let parent_before = files::identity(&parent.metadata()?);
            let object = if directory {
                files::directory_relative(&self.root, &path, Some(self.owner))?
            } else {
                files::open_relative(&self.root, &path)?
            };
            require(
                files::identity(&object.metadata()?) == expected
                    && mount_identity::id(object.as_fd(), true)? == self.mount,
                "original removal member replaced/changed",
            )?;
            if directory {
                require(
                    files::directory_is_empty(&object)?,
                    "original removal directory contains unknown members",
                )?;
            }
            let name = Path::new(path.file_name().unwrap());
            let entry = enzimos_platform::directory_entry::Entry::observe(&parent, name)?;
            entry.matches(&object)?;
            let mut names = files::directory_names(&parent, 131072)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            require(
                names.remove(name.as_os_str()),
                "original removal name unavailable",
            )?;
            let name = CString::new(name.as_os_str().as_bytes()).unwrap();
            authorize()?;
            entry.recheck()?;
            require(
                files::identity(&object.metadata()?) == expected,
                "original removal epoch changed at syscall boundary",
            )?;
            require(
                unsafe {
                    libc::unlinkat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        if directory { libc::AT_REMOVEDIR } else { 0 },
                    )
                } == 0,
                "original removal failed; no automatic replay",
            )?;
            let after = files::identity(&object.metadata()?);
            if directory {
                require(
                    after.0 == expected.0
                        && after.1 == expected.1
                        && after.7 == expected.7
                        && after.8 == expected.8
                        && after.9 == expected.9
                        && after.10 == 0,
                    "original directory was not retired",
                )?;
            } else {
                crate::backup_rotation_epoch::unlinked(expected, after)?;
            }
            let parent_after = files::identity(&parent.metadata()?);
            crate::backup_rotation_epoch::parent_changed(parent_before, parent_after, directory)?;
            require(
                files::directory_names(&parent, 131072)?
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    == names,
                "removal parent changed beyond original member",
            )?;
            self.objects.remove(&path);
            if parent_path.as_os_str().is_empty() {
                self.epoch = parent_after;
            } else {
                *self.objects.get_mut(parent_path).ok_or_else(|| {
                    enzimos_platform::Error("original removal parent missing".into())
                })? = parent_after;
            }
            parent.sync_all()?;
            authorize()?;
        }
        self.recheck()?;
        require(
            self.objects.is_empty() && files::directory_is_empty(&self.root)?,
            "original repository not empty",
        )?;
        Ok(self)
    }
    pub(crate) fn require_root(&self, file: &File) -> Result<()> {
        self.recheck()?;
        require(
            files::identity(&file.metadata()?) == self.epoch
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "removal layout differs from actual original repository",
        )
    }
    pub(crate) fn renamed_root(&mut self) -> Result<()> {
        let after = files::identity(&self.root.metadata()?);
        crate::backup_rotation_epoch::renamed(self.epoch, after)?;
        self.epoch = after;
        self.recheck()
    }
    pub(crate) fn storage_bytes(&self) -> Result<u64> {
        self.recheck()?;
        self.objects
            .values()
            .filter(|v| v.7 & libc::S_IFMT == libc::S_IFREG)
            .try_fold(0u64, |sum, v| {
                sum.checked_add(v.2).ok_or_else(|| {
                    enzimos_platform::Error("rotation repository size overflow".into())
                })
            })
    }
    pub(crate) fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"root_epoch":self.epoch,"mount":self.mount,"entries":self.objects.len(),
            "objects_sha256":enzimos_platform::json::fingerprint(&serde_json::to_value(&self.objects)?)?}),
        )
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        require(
            self.scan()? == self.objects,
            "original rotation layout changed; no replacement adoption",
        )
    }
}
