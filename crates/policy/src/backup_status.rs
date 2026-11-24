// SPDX-License-Identifier: MIT
//! Redacted backup status observes existing files and mounts; it creates nothing.
use crate::{
    backup_admission::{OptIn, Repository, StoredPin},
    backup_configuration::Configuration,
    backup_destination::Destination,
    storage_runtime::Guard,
};
use chrono::{DateTime, SecondsFormat, Utc};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
use zeroize::Zeroizing;

struct PublicFile {
    path: &'static str,
    parent: File,
    parent_identity: files::FileIdentity,
    mount: u64,
    file: Option<File>,
    identity: Option<files::FileIdentity>,
    body: Option<Zeroizing<Vec<u8>>>,
}
impl PublicFile {
    fn observe(path: &'static str) -> Result<Self> {
        require(
            matches!(
                path,
                "/etc/enzimos/backup.json" | "/etc/enzimos/backup-remote.json"
            ),
            "backup status public configuration registry",
        )?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let m = parent.metadata()?;
        require(
            m.gid() == 0 && m.mode() & 0o022 == 0,
            "backup status protected configuration parent required",
        )?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let file =
            files::optional_relative(&parent, Path::new(Path::new(path).file_name().unwrap()))?;
        let (identity, body) = if let Some(file) = &file {
            let m = file.metadata()?;
            require(
                m.uid() == 0
                    && m.gid() == 0
                    && matches!(m.mode() & 0o7777, 0o600 | 0o644)
                    && m.nlink() == 1
                    && mount_identity::id(file.as_fd(), true)? == mount,
                "backup status original public configuration protection",
            )?;
            let identity = files::identity(&m);
            let bytes = Zeroizing::new(files::read_file(file, 32768, Some(0), true)?);
            public_configuration(&bytes)?;
            require(
                files::identity(&file.metadata()?) == identity,
                "backup status configuration changed during read",
            )?;
            (Some(identity), Some(bytes))
        } else {
            (None, None)
        };
        let result = Self {
            path,
            parent_identity: files::identity(&m),
            parent,
            mount,
            file,
            identity,
            body,
        };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&self) -> Result<()> {
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            files::identity(&parent.metadata()?) == self.parent_identity
                && files::identity(&self.parent.metadata()?) == self.parent_identity
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount,
            "backup status configuration directory changed",
        )?;
        let named = files::optional_relative(
            &self.parent,
            Path::new(Path::new(self.path).file_name().unwrap()),
        )?;
        match (&self.file, named, self.identity, &self.body) {
            (None, None, None, None) => Ok(()),
            (Some(file), Some(named), Some(identity), Some(bytes)) => require(
                files::identity(&file.metadata()?) == identity
                    && files::identity(&named.metadata()?) == identity
                    && mount_identity::id(file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && Zeroizing::new(files::read_file(file, 32768, Some(0), true)?).as_slice()
                        == bytes.as_slice(),
                "backup status original configuration changed or replaced",
            ),
            _ => Err(Error("backup status configuration presence changed".into())),
        }
    }
}
pub struct Status<'a> {
    guard: &'a Guard,
    local: PublicFile,
    remote: PublicFile,
    configuration: Option<Configuration>,
}
impl<'a> Status<'a> {
    pub fn observe(guard: &'a Guard) -> Result<Self> {
        guard.recheck()?;
        let local = PublicFile::observe("/etc/enzimos/backup.json")?;
        let remote = PublicFile::observe("/etc/enzimos/backup-remote.json")?;
        let configuration = if let Some(body) = &local.body {
            let configuration = Configuration::open()?;
            require(
                configuration.public_bytes()? == body.as_slice(),
                "backup status configuration observation differs",
            )?;
            Some(configuration)
        } else {
            None
        };
        let result = Self {
            guard,
            local,
            remote,
            configuration,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.local.recheck()?;
        self.remote.recheck()?;
        if let Some(configuration) = &self.configuration {
            configuration.recheck()?;
        }
        Ok(())
    }
    pub fn configured(&self) -> bool {
        self.configuration.is_some()
    }
    pub fn schedule_enabled(&self) -> Result<bool> {
        self.recheck()?;
        let Some(configuration) = &self.configuration else {
            return self.share_schedule_enabled();
        };
        let Some(opt) = OptIn::open()? else {
            return Ok(false);
        };
        let pin = StoredPin::open(configuration, self.guard)?;
        opt.verify_stored(configuration, &pin)?;
        self.recheck()?;
        Ok(true)
    }
    /// A setup without a backup drive: an opt-in bound to the current share
    /// configuration and pin. One bound to anything else reads as disabled
    /// (the scheduled run then refuses it), so a reconfigured share never
    /// takes the status page down.
    fn share_schedule_enabled(&self) -> Result<bool> {
        use crate::backup_share_destination as share;
        if share::primary() != Some(share::SHARE) {
            return Ok(false);
        }
        let Some(opt) = OptIn::open()? else {
            return Ok(false);
        };
        let verified = (|| {
            let scope = share::ShareScope::open()?;
            opt.verify_share(scope.public_bytes()?, &share::pin(self.guard)?)
        })();
        self.recheck()?;
        Ok(opt.share()? && verified.is_ok())
    }
    /// Snapshot display is separate from provisioning, capture and restore authority.
    /// It never mounts a repository, creates runtime state, or reads credential bytes here.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    pub fn points(&self) -> Result<Value> {
        use crate::{backup_credential::Credential, settings_command::Command};
        use std::os::fd::AsRawFd;
        self.recheck()?;
        let Some(configuration) = &self.configuration else {
            self.recheck()?;
            return Ok(value!([]));
        };
        // This reader never mounts; System1's `backup-points` attaches the
        // pinned drive around it. Unmounted here is a typed refusal.
        // A temporary attachment is the private stub with the drive over it,
        // which `mounted()` reports as ambiguous; `Destination::open` below
        // accepts exactly that stack and refuses anything else stacked there.
        require(
            crate::backup_destination_attach::mounted().unwrap_or(true),
            crate::backup_destination_attach::NOT_MOUNTED,
        )?;
        let destination = Destination::open(configuration, self.guard)?;
        let repository = Repository::open(&destination)?;
        let credential = Credential::open()?;
        let credential_binding = credential.binding(self.guard)?;
        let image = Command::open("/usr/bin/restic")?;
        let scratch = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let scratch_identity = files::identity(&scratch.metadata()?);
        let scratch_mount = mount_identity::id(scratch.as_fd(), true)?;
        let m = scratch.metadata()?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            m.gid() == 0
                && m.mode() & 0o7777 == 0o700
                && unsafe { libc::fstatfs(scratch.as_raw_fd(), &mut fs) } == 0
                && fs.f_type == 0x01021994,
            "backup points existing protected tmpfs required",
        )?;
        let mut boundary = || {
            self.recheck()?;
            repository.recheck()?;
            image.recheck()?;
            require(
                credential.binding(self.guard)? == credential_binding,
                "backup points original credential binding changed",
            )?;
            let named = files::directory(Path::new("/run/enzimos"), Some(0))?;
            require(
                files::identity(&scratch.metadata()?) == scratch_identity
                    && files::identity(&named.metadata()?) == scratch_identity
                    && mount_identity::id(scratch.as_fd(), true)? == scratch_mount
                    && mount_identity::id(named.as_fd(), true)? == scratch_mount,
                "backup points original runtime directory changed",
            )
        };
        boundary()?;
        let repository_file =
            File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
        let credential_file = File::from(credential.descriptor()?.try_clone_to_owned()?);
        let output = enzimos_platform::local_restic::points(
            image.descriptor()?,
            &repository_file,
            &credential_file,
            &scratch,
            &mut boundary,
        )?;
        boundary()?;
        let result = crate::backup_points::rows(output.status.code(), &output.stdout)?;
        boundary()?;
        Ok(result)
    }
    /// next_run is separately obtained from the pinned initial PID1 manager.
    /// This display document is never an operation admission or receipt.
    pub fn report(&self, last_backup: Value, next_run: Option<String>) -> Result<Value> {
        self.recheck()?;
        let enabled = self.schedule_enabled()?;
        require(
            enabled || next_run.is_none(),
            "disabled backup schedule cannot claim next run",
        )?;
        let mut result = value!({"local_configured":self.configuration.is_some(),"remote_configured":self.remote.file.is_some(),
            "schedule_enabled":enabled,"last_backup":last_backup,"next_run":next_run,
            "recovery_copy":{"state":"not-configured","user_attested_independent_copy":false,"physical_copy_verified":false},
            "destination_available":false,"destination_label":null,"destination_free_bytes":null,"repository_bytes":null});
        // Where "Back up now" and the schedule write: `drive`, `share` (no
        // drive; the NAS share holds the backups) or null (neither is ready).
        result["primary"] = value!(crate::backup_share_destination::primary());
        // The filesystem a recovery copy must not be saved on (`backup-recovery
        // save --backup-filesystem-uuid`): the drive, or the system disk.
        result["recovery_save_exclude_uuid"] = match &self.configuration {
            Some(configuration) => configuration.value()["destination_uuid"].clone(),
            None => self.guard.configuration["filesystem_uuid"].clone(),
        };
        result["running"] = crate::backup_running::read();
        result["remote_copy"] = crate::backup_run_status::remote_copy();
        result["remote"] = remote_summary(self.remote.body.as_deref().map(Vec::as_slice));
        // What NAS share setup will use as the repository password: the local
        // backup's (one recovery key for both copies) or one to enter.
        result["remote"]["repository_password_source"] = value!(
            if crate::backup_restic_runtime::remote_share::local_backup_configured() {
                "local-backup"
            } else {
                "input"
            }
        );
        // Only a share this OS can use counts as configured; an SFTP setup
        // from before SMB shows as `remote.state = reconfigure-as-smb`.
        result["remote_configured"] = value!(result["remote"]["state"] == "configured");
        if result["primary"] == crate::backup_share_destination::SHARE {
            result["recovery_copy"] =
                crate::backup_recovery_confirmation::share_status(self.guard)?;
            result["run"] = crate::backup_run_status::read();
            let policy = crate::backup_retention::policy();
            result["retention"] = value!({"policy":policy.as_ref().ok(),"policy_valid":policy.is_ok(),
                "last_cleanup":crate::backup_retention::status().unwrap_or(Value::Null)});
        }
        if let Some(configuration) = &self.configuration {
            result["destination_uuid"] = configuration.value()["destination_uuid"].clone();
            // An unreadable policy file must not take the whole status page down.
            let policy = crate::backup_retention::policy();
            result["retention"] = value!({"policy":policy.as_ref().ok(),"policy_valid":policy.is_ok(),
                "last_cleanup":crate::backup_retention::status().unwrap_or(Value::Null)});
            result["recovery_copy"] =
                crate::backup_recovery_confirmation::status(configuration, self.guard)?;
            // Only a mounted, identity-checked destination with its pinned
            // repository is "available". A detached drive, the Root's empty
            // stub, or a setup that has not bound its pin yet is reported as
            // not connected (false), never as a query failure.
            let observed = Destination::open(configuration, self.guard).and_then(|destination| {
                let repository = Repository::open(&destination)?;
                let status = destination.status()?;
                repository.recheck()?;
                Ok(status)
            });
            if let Ok(status) = observed {
                for (key, value) in status.as_object().unwrap() {
                    result[key] = value.clone();
                }
            }
            // How the last run ended (waiting for the drive, failed, ok), the
            // space measured at the last cleanup and queued removals.
            result["run"] = crate::backup_run_status::read();
            result["pending_removals"] = value!(crate::backup_removals::pending().len());
            let last = result["retention"]["last_cleanup"]["local"].clone();
            result["repository_bytes_measured"] = last["used_bytes"].clone();
            result["repository_measured_at"] = last["at_unix"].clone();
            result["budget"] = last["budget"].clone();
        }
        self.recheck()?;
        Ok(result)
    }
}
/// The NAS share as Settings shows it: where it is and whether it works with
/// this OS. `state` is `not-configured`, `configured`, `reconfigure-as-smb`
/// (an SFTP setup from before SMB) or `invalid`; a configured share adds
/// `share_password_ready`, `repository_password_ready`, `repository_ready` and
/// `repository_id`. Passwords never appear.
fn remote_summary(body: Option<&[u8]>) -> Value {
    let Some(bytes) = body else {
        return value!({"state":"not-configured"});
    };
    let Ok(v) = json::decode(bytes, 32768) else {
        return value!({"state":"invalid"});
    };
    if crate::backup_remote_endpoint::sftp(&v) {
        return value!({"state":"reconfigure-as-smb","transport":"sftp"});
    }
    if crate::backup_remote_endpoint::validate(&v).is_err() {
        return value!({"state":"invalid"});
    }
    let mut summary = value!({"state":"configured","transport":"smb","server":v["server"],"share":v["share"],
        "folder":v["folder"],"user":v["user"],"domain":v.get("domain").cloned().unwrap_or(Value::Null)});
    // Metadata only: whether the share password, the repository password and
    // the pinned repository (for exactly this configuration) are in place.
    for (key, ready) in crate::backup_restic_runtime::remote_share::readiness(bytes)
        .as_object()
        .unwrap()
    {
        summary[key] = ready.clone();
    }
    summary["location"] = value!(format!(
        "smb://{}/{}/{}",
        v["server"].as_str().unwrap_or_default(),
        v["share"].as_str().unwrap_or_default(),
        v["folder"].as_str().unwrap_or_default()
    ));
    summary
}
fn public_configuration(bytes: &[u8]) -> Result<()> {
    require(
        json::decode(bytes, 32768)?.is_object(),
        "backup status configuration must be an object",
    )
}
pub fn timestamp(seconds: i64, nanoseconds: i64) -> Result<String> {
    require(
        (0..253402300799).contains(&seconds) && (0..1_000_000_000).contains(&nanoseconds),
        "backup status timestamp bound",
    )?;
    let whole = nanoseconds / 1000;
    let remainder = nanoseconds % 1000;
    let micros = whole + i64::from(remainder > 500 || (remainder == 500 && whole % 2 != 0));
    let seconds = seconds + micros / 1_000_000;
    require(
        seconds < 253402300799,
        "backup status rounded timestamp bound",
    )?;
    let nanos = (micros % 1_000_000 * 1000) as u32;
    let date = DateTime::<Utc>::from_timestamp(seconds, nanos)
        .ok_or_else(|| Error("backup status UTC date invalid".into()))?;
    Ok(date.to_rfc3339_opts(
        if nanos == 0 {
            SecondsFormat::Secs
        } else {
            SecondsFormat::Micros
        },
        true,
    ))
}
