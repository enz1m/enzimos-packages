// SPDX-License-Identifier: MIT
//! Complete the run receipt only after measuring the restored live Root and retired entries.
use crate::{
    boot_entries,
    boot_volume::{Artifact, Volume},
    operation,
    recovery_journal::{Journal, Kind},
    recovery_records as records,
    storage_runtime::Guard,
    subvolume,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
struct Protected {
    role: &'static str,
    path: &'static str,
    file: File,
    shape: (u64, u64, u32, u32, u32),
    mount: u64,
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Protected {
    fn open(role: &'static str, path: &'static str) -> Result<Self> {
        let file = files::directory(Path::new(path), Some(0))?;
        Ok(Self {
            role,
            path,
            shape: shape(&file)?,
            mount: enzimos_platform::mount_identity::id(file.as_fd(), true)?,
            file,
        })
    }
    fn recheck(&self) -> Result<()> {
        let named = files::directory(Path::new(self.path), Some(0))?;
        require(
            shape(&self.file)? == self.shape
                && shape(&named)? == self.shape
                && enzimos_platform::mount_identity::id(self.file.as_fd(), true)? == self.mount
                && enzimos_platform::mount_identity::id(named.as_fd(), true)? == self.mount,
            "original protected recovery path was replaced or covered",
        )
    }
}
struct Scope {
    id: String,
    guard: Guard,
    volume: Volume,
    loader: Artifact,
    bios: Artifact,
    entries: File,
    protected: Vec<Protected>,
    runs: Journal,
    jobs: Journal,
    workflows: Journal,
    activations: Journal,
}
fn row<'a>(journal: &'a Journal, id: &str) -> Result<&'a Value> {
    journal
        .records
        .get(id)
        .ok_or_else(|| Error("matching recovery receipt missing".into()))
}
fn id(body: &Value) -> Result<&str> {
    json::fields(body, "id")?;
    let id = records::text(body, "id")?;
    records::job_id(id)?;
    Ok(id)
}
fn completed_run(run: &Value, job: &Value, workflow: &Value, activation: &Value) -> Result<()> {
    require(
        job["phase"] == "staged"
            && workflow["state"] == "complete"
            && workflow["plan_sha256"] == run["plan_sha256"]
            && workflow["flavor"] == run["flavor"]
            && job["plan"]["plan_sha256"] == run["plan_sha256"]
            && activation["intent"]["schema"] == 2
            && activation["intent"]["job"] == *job
            && matches!(activation["phase"].as_str(), Some("selected" | "adopted"))
            && activation["intent"]["intent_sha256"] == workflow["activation_sha256"]
            && activation["selection"]["flavor"] == run["flavor"],
        "recovery run/workflow/selection receipts differ",
    )?;
    require(
        run["result"]["status"] == "recovery-workflow-disk-defaults-selected"
            && run["result"]["flavor"] == run["flavor"]
            && run["result"]["home_overwritten"] == false
            && run["result"]["authority_overwritten"] == false,
        "executed native recovery outcome required",
    )
}
impl Scope {
    fn open(id: &str) -> Result<Self> {
        crate::namespaces::initial()?;
        records::job_id(id)?;
        let guard = Guard::observe()?;
        let volume = Volume::observe()?;
        let loader = volume.artifact(
            Path::new("loader/loader.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        let bios = volume.artifact(
            Path::new("limine/limine.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        let entries = volume.directory(Path::new("loader/entries"))?;
        let protected = vec![
            Protected::open("home", "/home")?,
            Protected::open("authority", "/etc/pacman.d/gnupg")?,
        ];
        let this = Self {
            id: id.into(),
            guard,
            volume,
            loader,
            bios,
            entries,
            protected,
            runs: Journal::open(Kind::Runs, false)?,
            jobs: Journal::open(Kind::Jobs, false)?,
            workflows: Journal::open(Kind::Workflows, false)?,
            activations: Journal::open(Kind::Activations, false)?,
        };
        this.view(false)?;
        Ok(this)
    }
    fn view(&self, complete: bool) -> Result<Value> {
        self.guard.recheck()?;
        self.volume.recheck()?;
        self.loader.recheck()?;
        self.bios.recheck()?;
        for journal in [&self.runs, &self.jobs, &self.workflows, &self.activations] {
            journal.unchanged()?;
        }
        let confirmed = crate::recovery_confirmation::observe_current()?;
        require(
            confirmed["id"] == self.id,
            "actual restored boot identifies another recovery run",
        )?;
        let run = row(&self.runs, &self.id)?;
        let job = row(&self.jobs, &self.id)?;
        let workflow = row(&self.workflows, &self.id)?;
        let activation = row(&self.activations, &self.id)?;
        require(
            run["phase"] == if complete { "complete" } else { "executed" },
            "executed unused recovery run required",
        )?;
        completed_run(run, job, workflow, activation)?;
        let live = self.guard.backup_root_binding()?;
        let mut configuration = job["plan"]["storage"].clone();
        configuration["root_subvol"] = job["root"]["path"].clone();
        require(
            live["root"] == job["root"]
                && live["configuration"] == configuration
                && live["boot_id"] != run["created_boot"]
                && self.volume.uuid == job["plan"]["boot_uuid"],
            "actual restored live Root or boot identity differs",
        )?;
        let kernel = files::read_kernel(Path::new("/proc/sys/kernel/osrelease"), 4096)?;
        let kernel = std::str::from_utf8(&kernel)
            .map_err(|_| Error("restored kernel encoding".into()))?
            .trim();
        require(
            job["plan"]["material"]["kernels"][records::text(run, "flavor")?] == kernel,
            "actual restored selected kernel differs",
        )?;
        for protected in &self.protected {
            protected.recheck()?;
            let path = records::text(&configuration, &format!("{}_subvol", protected.role))?;
            require(
                subvolume::observe(protected.file.as_fd(), path)?.0
                    == job["plan"]["protected"][protected.role],
                "original protected recovery subvolume changed",
            )?;
        }
        require(
            subvolume::observe(
                self.guard.control().as_fd(),
                records::text(&configuration, "control_subvol")?,
            )?
            .0 == job["plan"]["protected"]["control"],
            "original protected recovery control changed",
        )?;
        let named = self.volume.directory(Path::new("loader/entries"))?;
        let a = self.entries.metadata()?;
        let b = named.metadata()?;
        require(
            files::identity(&a) == files::identity(&b)
                && enzimos_platform::mount_identity::id(self.entries.as_fd(), true)?
                    == self.volume.unique,
            "original recovery entry directory changed",
        )?;
        require(
            files::optional_relative(
                &self.entries,
                Path::new(records::text(&run["entry"], "uefi_entry")?),
            )?
            .is_none(),
            "recovery run UEFI entry still present or unsafe",
        )?;
        let bios = files::read_file(&self.bios.file, boot_entries::MAX_TEXT, Some(0), true)?;
        let menu = boot_entries::menu(
            std::str::from_utf8(&bios).map_err(|_| Error("recovery BIOS encoding".into()))?,
        )?;
        let title = records::text(&run["entry"], "bios_title")?;
        require(
            menu.entries.iter().all(|entry| entry.title != title),
            "recovery run BIOS entry still present",
        )?;
        let result = value!({"run":run,"job":job,"workflow":workflow,"activation":activation,"live":live,
            "boot_uuid":self.volume.uuid,"boot_mount":self.volume.unique,"loader_sha256":self.loader.sha,
            "bios_sha256":self.bios.sha,"kernel":kernel,"confirmed_boot":confirmed,
            "receipt_epochs":{"runs":self.runs.evidence()?,"jobs":self.jobs.evidence()?,"workflows":self.workflows.evidence()?,"activations":self.activations.evidence()?}});
        self.guard.recheck()?;
        self.volume.recheck()?;
        self.loader.recheck()?;
        self.bios.recheck()?;
        for protected in &self.protected {
            protected.recheck()?;
        }
        Ok(result)
    }
}
pub fn observation(body: &Value) -> Result<Value> {
    Scope::open(id(body)?)?.view(false)
}
pub fn finish<F: FnMut() -> Result<()>>(
    body: &Value,
    expected: &Value,
    mut authorize: F,
) -> Result<Value> {
    let id = id(body)?;
    let lock = operation::lock()?;
    let mut scope = Scope::open(id)?;
    require(
        scope.view(false)? == *expected,
        "recovery completion plan changed",
    )?;
    authorize()?;
    lock.recheck()?;
    require(
        scope.view(false)? == *expected,
        "recovery completion changed before publication",
    )?;
    let before = row(&scope.runs, id)?.clone();
    let mut next = before.clone();
    next["phase"] = value!("complete");
    scope.runs.save(id, next, Some(&before), &lock)?;
    scope.view(true)?;
    lock.recheck()?;
    completion(id)
}
/// Closed System1 result, independent of the more detailed policy CLI response.
pub(crate) fn completion(id: &str) -> Result<Value> {
    records::job_id(id)?;
    Ok(value!({"id":id,"status":"recovery-run-complete","old_roots_retired":false}))
}
