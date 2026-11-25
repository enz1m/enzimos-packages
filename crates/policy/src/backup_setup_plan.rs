// SPDX-License-Identifier: MIT
//! Server-made initial setup plans retain original source, review and executable.
use crate::{backup_mount_review::Review, backup_setup_image::Image, identity};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
/// Whether setup creates a new repository or adopts an existing one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Create a new repository.
    Initialize,
    /// Adopt an existing repository.
    Adopt,
}
impl Mode {
    /// Parse a wire name produced by [`Mode::name`].
    ///
    /// # Errors
    ///
    /// Fails for any other name.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "initialize" => Ok(Self::Initialize),
            "adopt" => Ok(Self::Adopt),
            _ => Err(Error("setup mode unavailable".into())),
        }
    }
    /// Stable wire name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Adopt => "adopt",
        }
    }
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected original setup configuration parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn absent(parent: &File, names: &[&str]) -> Result<()> {
    for name in names {
        require(
            files::optional_relative(parent, Path::new(name))?.is_none(),
            "existing initial setup state requires inspection; no replay",
        )?;
    }
    Ok(())
}
fn topology(v: &Value, root: crate::topology::Device) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    json::fields(v, "nodes leaves")?;
    let nodes = v["nodes"]
        .as_array()
        .ok_or_else(|| Error("setup topology nodes required".into()))?;
    let leaves = v["leaves"]
        .as_array()
        .ok_or_else(|| Error("setup topology leaves required".into()))?;
    require(
        (1..=64).contains(&nodes.len()) && (1..=64).contains(&leaves.len()),
        "setup topology bounds",
    )?;
    let device = |v: &Value| -> Result<crate::topology::Device> {
        let a = v
            .as_array()
            .ok_or_else(|| Error("setup topology device required".into()))?;
        require(
            a.len() == 2
                && a[0].as_u64().is_some_and(|n| n < 1 << 12)
                && a[1].as_u64().is_some_and(|n| n < 1 << 20),
            "setup topology device bounds",
        )?;
        Ok((
            enzimos_platform::json::unsigned(&a[0])? as u32,
            enzimos_platform::json::unsigned(&a[1])? as u32,
        ))
    };
    let mut observed = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for row in nodes {
        json::fields(row, "device path dependencies disk_sequence")?;
        let path = row["path"]
            .as_str()
            .ok_or_else(|| Error("setup kernel node path required".into()))?;
        require(
            path.starts_with("/sys/devices/")
                && path.len() <= 4096
                && path
                    .split('/')
                    .skip(1)
                    .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
                && paths.insert(path.to_owned()),
            "setup kernel path is ambiguous",
        )?;
        let dependencies = row["dependencies"]
            .as_array()
            .ok_or_else(|| Error("setup node dependencies required".into()))?;
        require(dependencies.len() <= 64, "setup dependency bound")?;
        let dependencies = dependencies
            .iter()
            .map(device)
            .collect::<Result<Vec<_>>>()?;
        require(
            dependencies.iter().copied().collect::<BTreeSet<_>>().len() == dependencies.len(),
            "duplicate setup dependency",
        )?;
        let sequence = if row["disk_sequence"].is_null() {
            None
        } else {
            Some(
                row["disk_sequence"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| Error("setup kernel disk sequence required".into()))?,
            )
        };
        require(
            !dependencies.is_empty()
                || (sequence.is_some() && !path.starts_with("/sys/devices/virtual")),
            "unsupported setup virtual/unsequenced leaf",
        )?;
        require(
            observed
                .insert(
                    device(&row["device"])?,
                    crate::topology::Node {
                        path: path.into(),
                        dependencies,
                        disk_sequence: sequence,
                    },
                )
                .is_none(),
            "duplicate setup kernel node",
        )?;
    }
    let graph = crate::topology::walk(&[root], |d| {
        observed
            .get(&d)
            .cloned()
            .ok_or_else(|| Error("setup graph dependency missing".into()))
    })?;
    let expected = leaves.iter().map(device).collect::<Result<Vec<_>>>()?;
    require(
        graph.nodes == observed
            && expected.iter().copied().collect::<BTreeSet<_>>() == graph.leaves
            && expected.len() == graph.leaves.len(),
        "setup graph has unreachable nodes or false/duplicate leaves",
    )
}
/// Validate an initial setup plan document.
///
/// # Errors
///
/// Fails when a field is missing or invalid.
pub fn validate(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema operation id owner_uid mode selection_id review_id source destination implementation_sha256",
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["operation"] == "backup-initial-setup"
            && v["owner_uid"]
                .as_u64()
                .is_some_and(|n| (1000..i32::MAX as u64).contains(&n)),
        "initial setup plan role/owner invalid",
    )?;
    for k in ["id", "review_id"] {
        identity::safe_id(
            v[k].as_str()
                .ok_or_else(|| Error("setup plan identifier required".into()))?,
        )?;
    }
    for k in ["selection_id", "implementation_sha256"] {
        identity::sha(
            v[k].as_str()
                .ok_or_else(|| Error("setup plan digest required".into()))?,
        )?;
    }
    let mode = Mode::parse(
        v["mode"]
            .as_str()
            .ok_or_else(|| Error("setup mode required".into()))?,
    )?;
    crate::backup_secret_persistence::root_binding(&v["source"])?;
    let d = &v["destination"];
    json::fields(d, "filesystem_uuid device topology repository")?;
    identity::uuid(
        d["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| Error("setup destination UUID required".into()))?,
    )?;
    let synthetic = value!({"schema":2,"phase":"complete","id":v["review_id"],"selection_id":v["selection_id"],
        "boot_id":v["source"]["boot_id"],"filesystem_uuid":d["filesystem_uuid"],"device":d["device"],
        "mount_scope":"detached-file-descriptor","mount_options":"ro,rescue=nologreplay,nodev,nosuid,noexec,subvolid=5","descriptor_scope_closed":true,
        "result":{"schema":1,"readonly_mount_reviewed":true,"filesystem_uuid":d["filesystem_uuid"],"filesystem_verified":false,
            "credential_enrolled":false,"automatic_backup_enabled":false,"repository":d["repository"]}});
    crate::backup_mount_review::validate_receipt(
        &synthetic,
        enzimos_platform::json::string(&v["review_id"])?,
    )?;
    require(
        d["filesystem_uuid"] != v["source"]["configuration"]["filesystem_uuid"],
        "setup destination aliases protected source filesystem",
    )?;
    topology(
        &d["topology"],
        (
            enzimos_platform::json::unsigned(&d["device"]["major"])? as u32,
            enzimos_platform::json::unsigned(&d["device"]["minor"])? as u32,
        ),
    )?;
    require(
        match mode {
            Mode::Initialize => {
                matches!(d["repository"]["state"].as_str(), Some("absent" | "empty"))
            }
            Mode::Adopt => d["repository"]["state"] == "existing",
        },
        "initialization/adoption differs from original repository review",
    )
}
/// A server-made setup plan bound to its review, owner and configuration state.
pub struct Plan<'a, 'r, 'd> {
    review: &'a Review<'r, 'd>,
    image: Image,
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    original: Value,
}
impl<'a, 'r, 'd> Plan<'a, 'r, 'd> {
    /// Build the plan for setup `id` by `uid` from `review`.
    ///
    /// # Errors
    ///
    /// Fails when the owner is invalid, the configuration is not on the original Root mount, or
    /// `authorize` fails.
    pub fn observe(
        review: &'a Review<'r, 'd>,
        id: &str,
        uid: u32,
        mode: Mode,
        lock: &files::Lock,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        identity::safe_id(id)?;
        require(
            (1000..i32::MAX as u32).contains(&uid),
            "setup owner invalid",
        )?;
        review.recheck()?;
        lock.recheck()?;
        authorize()?;
        crate::transition_idle::Snapshot::online()?.recheck()?;
        let image = Image::open()?;
        let guard = review.selection().guard();
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            parent_mount == guard.root_mount_id()
                && parent.metadata()?.dev() == guard.root_device(),
            "setup configuration outside original Root mount",
        )?;
        let observed = review.original();
        let destination = value!({"filesystem_uuid":observed["filesystem_uuid"],"device":observed["device"],
            "topology":review.selection().evidence()?["topology"],"repository":review.repository()?});
        let original = value!({"schema":1,"operation":"backup-initial-setup","id":id,"owner_uid":uid,"mode":mode.name(),
            "selection_id":observed["selection_id"],"review_id":review.id(),"source":guard.backup_root_binding()?,
            "destination":destination,"implementation_sha256":image.sha()?});
        validate(&original)?;
        require(
            json::canonical(&original)?.len() <= 32768,
            "setup plan bound",
        )?;
        let this = Self {
            review,
            image,
            parent_shape: shape(&parent)?,
            parent_mount,
            parent,
            original,
        };
        this.recheck_initial()?;
        lock.recheck()?;
        authorize()?;
        Ok(this)
    }
    /// Verify that no backup configuration exists yet.
    ///
    /// # Errors
    ///
    /// Fails when any configuration file or setup record exists.
    pub fn recheck_initial(&self) -> Result<()> {
        self.review.recheck()?;
        self.recheck_identity()?;
        absent(
            &self.parent,
            &[
                "backup.json",
                "backup.password",
                ".backup-password-input",
                ".backup-setup-config",
            ],
        )?;
        absent(
            self.review.selection().guard().control(),
            &[
                "backup-destination.json",
                "backup.enabled",
                "backup-initial-setup.json",
                "backup-secret-input.json",
                "backup-setup.json",
            ],
        )
    }
    pub(crate) fn recheck_identity(&self) -> Result<()> {
        self.review.document_recheck()?;
        self.review.selection().recheck_device()?;
        self.image.recheck()?;
        let guard = self.review.selection().guard();
        let named = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            shape(&named)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(named.as_fd(), true)? == self.parent_mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && guard.backup_root_binding()? == self.original["source"],
            "original setup plan source/parent changed",
        )
    }
    /// The plan document.
    ///
    /// # Errors
    ///
    /// Fails on [`Plan::recheck_initial`].
    pub fn value(&self) -> Result<Value> {
        self.recheck_initial()?;
        Ok(self.original.clone())
    }
    /// SHA-256 of the canonical plan document.
    ///
    /// # Errors
    ///
    /// Fails on [`Plan::recheck_initial`].
    pub fn digest(&self) -> Result<String> {
        self.recheck_initial()?;
        Ok(json::sha256(&json::canonical(&self.original)?))
    }
    pub(crate) fn original(&self) -> &Value {
        &self.original
    }
    pub(crate) fn guard(&self) -> &crate::storage_runtime::Guard {
        self.review.selection().guard()
    }
    pub(crate) fn actor(&self) -> Result<Value> {
        self.recheck_identity()?;
        self.image.actor()
    }
    /// The source storage guard.
    ///
    /// # Errors
    ///
    /// Fails when the plan's inputs changed.
    pub fn source_guard(&self) -> Result<&crate::storage_runtime::Guard> {
        self.recheck_identity()?;
        Ok(self.guard())
    }
    /// The setup mode.
    ///
    /// # Errors
    ///
    /// Fails when the plan's inputs changed.
    pub fn mode(&self) -> Result<Mode> {
        self.recheck_identity()?;
        Mode::parse(enzimos_platform::json::string(&self.original["mode"])?)
    }
    /// The review the plan was built from.
    ///
    /// # Errors
    ///
    /// Fails when the plan's inputs changed.
    pub fn review(&self) -> Result<&'a Review<'r, 'd>> {
        self.recheck_identity()?;
        Ok(self.review)
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    const SOURCE: &str = "11111111-2222-3333-4444-555555555555";
    const DESTINATION: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    pub(crate) fn plan() -> Value {
        value!({"schema":1,"operation":"backup-initial-setup","id":"setup-1","owner_uid":1000,"mode":"initialize","selection_id":"a".repeat(64),"review_id":"review-1",
            "source":{"configuration":{"root_subvol":"enzimos-root","home_subvol":"enzimos-home","authority_subvol":"enzimos-authority","control_subvol":"enzimos-control","filesystem_uuid":SOURCE},
                "mount":{"mount_id":1,"unique_mount_id":2,"device":"0:30","root":"/enzimos-root","target":"/","fstype":"btrfs"},
                "root":{"path":"enzimos-root","id":256,"uuid":SOURCE,"parent_uuid":null},"boot_id":SOURCE},
            "destination":{"filesystem_uuid":DESTINATION,"device":{"major":8,"minor":17,"device_inode":1,"device_filesystem":2,"disk_sequence":3,"bytes":4096,"read_only":false},
                "topology":{"nodes":[{"device":[8,0],"path":"/sys/devices/pci/block/sda","dependencies":[],"disk_sequence":3},{"device":[8,17],"path":"/sys/devices/pci/block/sda/sda1","dependencies":[[8,0]],"disk_sequence":null}],"leaves":[[8,0]]},
                "repository":{"state":"absent","configuration_sha256":null}},"implementation_sha256":"b".repeat(64)})
    }
    #[test]
    fn setup_plan_never_confuses_adoption_initialization_or_client_supplied_secret_material() {
        let v = plan();
        validate(&v).unwrap();
        let mut adopt = v.clone();
        adopt["mode"] = value!("adopt");
        assert!(validate(&adopt).is_err());
        adopt["destination"]["repository"] =
            value!({"state":"existing","configuration_sha256":"c".repeat(64)});
        validate(&adopt).unwrap();
        adopt["mode"] = value!("initialize");
        assert!(validate(&adopt).is_err());
        for (key, bad) in [
            ("owner_uid", value!(true)),
            ("schema", value!(true)),
            ("selection_id", value!("/dev/vdb1")),
            ("implementation_sha256", value!("unbound")),
            ("mode", value!("format")),
        ] {
            let mut changed = v.clone();
            changed[key] = bad;
            assert!(validate(&changed).is_err());
        }
        let mut changed = v.clone();
        changed["destination"]["filesystem_uuid"] = value!(SOURCE);
        assert!(validate(&changed).is_err());
        let mut changed = v;
        changed["password"] = value!("fixture");
        assert!(validate(&changed).is_err());
    }
}
