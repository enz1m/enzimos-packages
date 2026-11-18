// SPDX-License-Identifier: MIT
//! One new durable receipt, with all other original registry members retained.
//! Checkpoints accept only this actor's actual publication chain. No adoption,
//! replay or destructor cleanup follows an incomplete publication.
use crate::{Error, Result, files, json, mount_identity, publication, require};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};
const LIMIT: usize = 2 * 1024 * 1024;
const TOTAL: usize = 16 * 1024 * 1024;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o7777 == 0o700,
        "original private receipt registry required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn leaf(name: &str) -> Result<()> {
    require(
        name.len() <= 128
            && name.ends_with(".json")
            && Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(Component::Normal(_))
            )
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "fixed receipt registry leaf",
    )
}
fn names(parent: &File) -> Result<BTreeSet<String>> {
    files::directory_names(parent, 256)?
        .into_iter()
        .map(|n| {
            let n = n
                .into_string()
                .map_err(|_| Error("receipt registry filename encoding".into()))?;
            leaf(&n)?;
            Ok(n)
        })
        .collect()
}
struct Original {
    file: File,
    epoch: files::FileIdentity,
    sha: String,
}
pub struct Registry {
    parent: File,
    path: PathBuf,
    shape: Shape,
    epoch: files::FileIdentity,
    mount: u64,
    owner: u32,
    leaf: String,
    names: BTreeSet<String>,
    others: BTreeMap<String, Original>,
    own: Option<publication::Chain>,
}
impl Registry {
    /// Caller independently validates the fixed registry schemas and source
    /// before admitting this actual original directory. Existing own rows refuse.
    pub fn observe(path: &Path, parent: &File, own_leaf: &str, owner: u32) -> Result<Self> {
        leaf(own_leaf)?;
        let parent = parent.try_clone()?;
        let named = files::directory(path, Some(owner))?;
        let original_shape = shape(&parent, owner)?;
        let epoch = files::identity(&parent.metadata()?);
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            shape(&named, owner)? == original_shape
                && files::identity(&named.metadata()?) == epoch
                && mount_identity::id(named.as_fd(), true)? == mount,
            "named original receipt registry differs",
        )?;
        let names = names(&parent)?;
        require(
            !names.contains(own_leaf) && names.len() < 256,
            "existing receipt cannot be adopted or replayed",
        )?;
        let mut others = BTreeMap::new();
        let mut bytes = 0usize;
        for name in &names {
            let file = files::open_relative(&parent, Path::new(name))?;
            let m = file.metadata()?;
            require(
                m.is_file()
                    && m.uid() == owner
                    && m.gid() == owner
                    && matches!(m.mode() & 0o7777, 0o400 | 0o600)
                    && m.nlink() == 1
                    && mount_identity::id(file.as_fd(), true)? == mount,
                "original receipt registry record protection/mount",
            )?;
            let body = files::read_file(&file, LIMIT, Some(owner), true)?;
            bytes = bytes
                .checked_add(body.len())
                .ok_or_else(|| Error("receipt registry byte overflow".into()))?;
            require(bytes <= TOTAL, "original receipt registry byte budget")?;
            others.insert(
                name.clone(),
                Original {
                    epoch: files::identity(&file.metadata()?),
                    sha: json::sha256(&body),
                    file,
                },
            );
        }
        let this = Self {
            parent,
            path: path.into(),
            shape: original_shape,
            epoch,
            mount,
            owner,
            leaf: own_leaf.into(),
            names,
            others,
            own: None,
        };
        this.recheck()?;
        Ok(this)
    }
    fn inspect(&self, exact_epoch: bool) -> Result<()> {
        let named = files::directory(&self.path, Some(self.owner))?;
        for parent in [&self.parent, &named] {
            require(
                shape(parent, self.owner)? == self.shape
                    && mount_identity::id(parent.as_fd(), true)? == self.mount
                    && (!exact_epoch || files::identity(&parent.metadata()?) == self.epoch),
                "original receipt registry changed/covered",
            )?;
            let mut expected = self.names.clone();
            if self.own.is_some() {
                expected.insert(self.leaf.clone());
            }
            require(
                names(parent)? == expected,
                "original receipt registry membership changed",
            )?;
        }
        for (name, original) in &self.others {
            let named = files::open_relative(&self.parent, Path::new(name))?;
            require(
                files::identity(&original.file.metadata()?) == original.epoch
                    && files::identity(&named.metadata()?) == original.epoch
                    && mount_identity::id(original.file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && json::sha256(&files::read_file(
                        &original.file,
                        LIMIT,
                        Some(self.owner),
                        true,
                    )?) == original.sha,
                "original other receipt changed/replaced",
            )?;
        }
        if let Some(own) = &self.own {
            own.require_destination(&self.parent, Path::new(&self.leaf))?;
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        self.inspect(true)?;
        self.inspect(true)
    }
    /// Fresh callback checks independent original source/authorization barriers;
    /// this actor itself validates its known pending/committed transition.
    pub fn publish(
        &mut self,
        bytes: &[u8],
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.recheck()?;
        require(bytes.len() <= LIMIT, "owned receipt byte bound")?;
        match &mut self.own {
            Some(chain) => chain.replace(bytes, authorize)?,
            None => {
                let pending = publication::Prepared::write_authorized(
                    &self.path.join(&self.leaf),
                    bytes,
                    self.owner,
                    authorize,
                )?;
                self.own = Some(publication::Chain::new(
                    pending.commit_retained_authorized(false, authorize)?,
                )?);
            }
        }
        // Only the actual exclusive publication above permits this directory's
        // known epoch delta. All original other files and exact members recheck.
        self.inspect(false)?;
        self.epoch = files::identity(&self.parent.metadata()?);
        self.recheck()?;
        authorize()
    }
    /// Join this actor to the caller's original directory description and
    /// fixed leaf. This is an actual descriptor comparison, not an evidence grant.
    pub fn require_directory(&self, original: &File, own_leaf: &str) -> Result<()> {
        self.recheck()?;
        require(
            self.leaf == own_leaf
                && shape(original, self.owner)? == self.shape
                && files::identity(&original.metadata()?) == self.epoch
                && mount_identity::id(original.as_fd(), true)? == self.mount,
            "receipt registry requires original directory and exact leaf",
        )?;
        self.recheck()
    }
    /// Join this retained registry to the caller's independently held original
    /// records. An equal-byte replacement cannot satisfy the descriptor epochs.
    pub fn require_original_members(&self, original: &BTreeMap<String, &File>) -> Result<()> {
        self.recheck()?;
        require(
            original.keys().cloned().collect::<BTreeSet<_>>() == self.names,
            "original receipt registry source membership differs",
        )?;
        for (name, file) in original {
            require(
                files::identity(&file.metadata()?) == self.others[name].epoch
                    && mount_identity::id(file.as_fd(), true)? == self.mount,
                "receipt registry requires independently held original record",
            )?;
        }
        self.recheck()
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        self.own
            .as_ref()
            .ok_or_else(|| Error("original receipt not yet published".into()))?
            .file()
    }
    pub fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"directory":self.epoch,"mount":self.mount,"own_leaf":self.leaf,
            "others":self.others.iter().map(|(n,v)| (n.clone(),v.epoch)).collect::<BTreeMap<_,_>>(),
            "own":self.own.as_ref().map(super::publication::Chain::evidence).transpose()?}),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileExt, PermissionsExt};
    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(
                std::env::var_os("ENZIMOS_TEST_TMPDIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::env::current_dir().unwrap()),
            )
            .unwrap()
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn original_registry_refuses_unrelated_writer_and_interrupted_pending_members() {
        let temp = fixture();
        let uid = unsafe { libc::geteuid() };
        let other = temp.path().join("other.json");
        std::fs::write(&other, b"old").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        let parent = files::directory(temp.path(), Some(uid)).unwrap();
        let mut registry = Registry::observe(temp.path(), &parent, "own.json", uid).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&other)
            .unwrap();
        writer.write_at(b"bad", 0).unwrap();
        assert!(registry.publish(b"prepared", &mut || Ok(())).is_err());
        assert!(!temp.path().join("own.json").exists());
        std::fs::write(temp.path().join("own.json.new"), b"pending").unwrap();
        assert!(Registry::observe(temp.path(), &parent, "own.json", uid).is_err());
    }
}
