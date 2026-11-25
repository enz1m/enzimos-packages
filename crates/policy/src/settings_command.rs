// SPDX-License-Identifier: MIT
//! Fixed vendor images remain original across a settings operation.
use enzimos_platform::{Error, Result, files, mount_identity, process, require, stream_copy};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
/// Internal boot tools have a separate closed role from settings/Restic evidence.
pub(crate) enum BootTool {
    CopyModules,
    CopyRestore,
    PublicAuthority,
    RestoreModules,
    Sign,
    Verify,
    ModuleProbe,
}
impl BootTool {
    fn path(self) -> &'static str {
        match self {
            Self::CopyModules | Self::CopyRestore => "/usr/bin/cp",
            Self::PublicAuthority => "/usr/bin/gpg",
            Self::RestoreModules => "/usr/bin/rsync",
            Self::Sign => "/usr/bin/sbsign",
            Self::Verify => "/usr/bin/sbverify",
            Self::ModuleProbe => "/usr/bin/kmod",
        }
    }
}
pub(crate) struct Command {
    file: File,
    path: PathBuf,
    identity: files::FileIdentity,
    mount: u64,
    sha: String,
}
pub(crate) fn validate(v: &Value) -> Result<()> {
    enzimos_platform::json::fields(v, "path inode mount sha256")?;
    require(
        matches!(
            v["path"].as_str(),
            Some(
                "/usr/bin/nmcli"
                    | "/usr/bin/pacman"
                    | "/usr/bin/systemctl"
                    | "/usr/bin/snapper"
                    | "/usr/bin/btrfs"
                    | "/usr/bin/fstrim"
                    | "/usr/bin/findmnt"
                    | "/usr/bin/lsblk"
                    | "/usr/bin/blkid"
                    | "/usr/bin/restic"
                    | "/usr/lib/enzimos-backend/enzimos-secret-validator"
            )
        ),
        "settings provider receipt role",
    )?;
    crate::identity::sha(
        v["sha256"]
            .as_str()
            .ok_or_else(|| Error("settings provider digest".into()))?,
    )?;
    let a = v["inode"]
        .as_array()
        .ok_or_else(|| Error("settings provider inode".into()))?;
    require(
        a.len() == 11
            && a.iter().all(|n| n.is_u64() || n.is_i64())
            && a[0].as_u64().is_some_and(|n| n > 0)
            && a[1].as_u64().is_some_and(|n| n > 0)
            && a[2].as_u64().is_some_and(|n| {
                n > 0 && n <= process::executable_limit(v["path"].as_str().unwrap())
            })
            && a[7].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFREG
                    && n & 0o022 == 0
                    && n & 0o111 == 0o111
            })
            && a[8] == 0
            && a[9] == 0
            && a[10] == 1
            && v["mount"].as_u64().is_some_and(|n| n > 0),
        "settings provider protected identity",
    )
}
fn module_alias(alias: &str) -> bool {
    if alias.is_empty()
        || alias.len() > 4096
        || alias.starts_with('-')
        || !alias.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return false;
    }
    if !alias.contains('/') {
        return true;
    }
    // Kernel DMI modalias payloads include BIOS dates with slashes. This fixed
    // bus prefix distinguishes them from a module file pathname.
    alias.starts_with("dmi:")
}
impl Command {
    /// Retain the actual ELF while supplying modprobe's fixed compatibility
    /// argv0. The modprobe symlink itself is never an executable authority.
    pub(crate) fn run_module_probe(&self, aliases: &[&str]) -> Result<()> {
        crate::recovery_bootstrap::quiet()?;
        require(
            self.path == Path::new("/usr/bin/kmod")
                && (1..=64).contains(&aliases.len())
                && aliases.iter().all(|alias| module_alias(alias)),
            "closed original module-probe role and bounded aliases required",
        )?;
        self.recheck()?;
        let mut args = vec!["-q", "-a", "--"];
        args.extend_from_slice(aliases);
        let output = process::run_pinned(
            "/usr/bin/modprobe",
            &self.file,
            &args,
            &[],
            Duration::from_secs(120),
            65536,
            &[],
        )?;
        self.recheck()?;
        require(
            matches!(output.status.code(), Some(0 | 1)),
            "module probe failed outside optional module absence; no retry",
        )?;
        crate::recovery_bootstrap::quiet()
    }
    pub(crate) fn open(program: &str) -> Result<Self> {
        require(
            matches!(
                program,
                "/usr/bin/nmcli"
                    | "/usr/bin/pacman"
                    | "/usr/bin/systemctl"
                    | "/usr/bin/snapper"
                    | "/usr/bin/btrfs"
                    | "/usr/bin/fstrim"
                    | "/usr/bin/findmnt"
                    | "/usr/bin/lsblk"
                    | "/usr/bin/blkid"
                    | "/usr/bin/restic"
                    | "/usr/lib/enzimos-backend/enzimos-secret-validator"
            ),
            "settings provider outside fixed registry",
        )?;
        Self::open_image(program)
    }
    pub(crate) fn open_boot(tool: BootTool) -> Result<Self> {
        Self::open_image(tool.path())
    }
    fn open_image(program: &str) -> Result<Self> {
        let path = Path::new(program);
        let directory = files::directory(
            path.parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let file = files::open_relative(
            &directory,
            Path::new(
                path.file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o022 == 0
                && m.mode() & 0o111 == 0o111
                && m.nlink() == 1,
            "protected native settings provider required",
        )?;
        let mut head = [0u8; 64];
        require(
            file.read_at(&mut head, 0)? == 64
                && head[..7] == *b"\x7fELF\x02\x01\x01"
                && u16::from_le_bytes(
                    head[18..20]
                        .try_into()
                        .map_err(|_| enzimos_platform::Error("value out of range".into()))?,
                ) == 62,
            "x86-64 native settings provider required",
        )?;
        let (_, sha) =
            stream_copy::hash_borrowed(&file, process::executable_limit(program), Some(0))?;
        let this = Self {
            identity: files::identity(&m),
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            path: path.into(),
            sha,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let directory = files::directory(
            self.path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let named = files::open_relative(
            &directory,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
            ),
        )?;
        require(
            files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original settings provider replaced or remounted",
        )
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let v =
            json!({"path":self.path,"inode":self.identity,"mount":self.mount,"sha256":self.sha});
        validate(&v)?;
        Ok(v)
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub(crate) fn run_fds_authorized(
        &self,
        args: &[&str],
        timeout: Duration,
        limit: usize,
        fds: &[std::os::fd::BorrowedFd<'_>],
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<process::Output> {
        require(
            !timeout.is_zero() && timeout <= Duration::from_secs(600),
            "boot command deadline",
        )?;
        process::run_pinned_with_checkpoint(
            self.path
                .to_str()
                .ok_or_else(|| Error("boot command path encoding".into()))?,
            self.descriptor()?,
            args,
            &[],
            timeout,
            limit,
            fds,
            &mut || {
                authorize()?;
                self.recheck()
            },
        )
    }
    pub(crate) fn run(&self, args: &[&str], codes: &[i32], limit: usize) -> Result<Vec<u8>> {
        self.run_timeout(args, codes, limit, Duration::from_secs(30))
    }
    pub(crate) fn run_timeout(
        &self,
        args: &[&str],
        codes: &[i32],
        limit: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.run_fds(args, codes, limit, timeout, &[])
    }
    pub(crate) fn run_fds(
        &self,
        args: &[&str],
        codes: &[i32],
        limit: usize,
        timeout: Duration,
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> Result<Vec<u8>> {
        Ok(self.execute(args, codes, limit, timeout, fds)?.stdout)
    }
    pub(crate) fn descriptor_query(
        &self,
        args: &[&str],
        limit: usize,
        timeout: Duration,
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> Result<(Vec<u8>, Vec<String>)> {
        let out = self.execute(args, &[0], limit, timeout, fds)?;
        Ok((out.stdout, out.descriptor_aliases))
    }
    fn execute(
        &self,
        args: &[&str],
        codes: &[i32],
        limit: usize,
        timeout: Duration,
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> Result<process::Output> {
        require(
            !timeout.is_zero() && timeout <= Duration::from_secs(30),
            "settings command deadline exhausted",
        )?;
        self.recheck()?;
        let out = process::run_pinned(
            self.path
                .to_str()
                .ok_or_else(|| Error("settings provider path encoding".into()))?,
            &self.file,
            args,
            &[],
            timeout,
            limit,
            fds,
        )?;
        self.recheck()?;
        if !out.status.code().is_some_and(|n| codes.contains(&n)) {
            return Err(Error(format!(
                "settings provider failed; outcome may be uncertain, no automatic retry: {}",
                process::refusal(self.path.to_str().unwrap_or("command"), &out)
            )));
        }
        Ok(out)
    }
}
