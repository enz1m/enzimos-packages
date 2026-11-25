// SPDX-License-Identifier: MIT
//! Independent recovery coldplug and retained UUID-selected block identity.
use crate::{identity, operation, recovery_bootstrap, topology};
use enzimos_platform::{Error, Result, files, require};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub(crate) fn coldplug() -> Result<()> {
    recovery_bootstrap::quiet()?;
    let mut pending = vec![PathBuf::from("/sys/devices")];
    let mut aliases = BTreeSet::new();
    let mut visited = 0;
    while let Some(folder) = pending.pop() {
        visited += 1;
        require(visited <= 65536, "kernel device directory bound")?;
        let held = files::directory(&folder, Some(0))?;
        let before = files::identity(&held.metadata()?);
        let mut count = 0;
        for row in std::fs::read_dir(&folder)? {
            count += 1;
            require(count <= 4096, "kernel device child bound")?;
            let row = row?;
            let kind = row.file_type()?;
            if kind.is_dir() {
                pending.push(row.path());
                require(pending.len() <= 65536, "kernel device traversal bound")?;
            } else if row.file_name() == "modalias" && kind.is_file() {
                let bytes = files::read_kernel(&row.path(), 4096)?;
                let alias = std::str::from_utf8(&bytes)
                    .map_err(|_| Error("kernel modalias encoding".into()))?
                    .trim();
                require(
                    alias.len() <= 4096
                        && alias.bytes().all(|b| b.is_ascii_graphic())
                        && !alias.starts_with('-'),
                    "kernel modalias syntax",
                )?;
                if !alias.is_empty() {
                    aliases.insert(alias.to_owned());
                    require(aliases.len() <= 4096, "kernel modalias count bound")?;
                }
            }
        }
        require(
            files::identity(&held.metadata()?) == before,
            "kernel devices changed during coldplug inventory",
        )?;
    }
    let aliases = aliases.into_iter().collect::<Vec<_>>();
    let command = crate::settings_command::Command::open_boot(
        crate::settings_command::BootTool::ModuleProbe,
    )?;
    for chunk in aliases.chunks(64) {
        // Unavailable optional drivers are expected on some qualified hardware;
        // execution errors/deadlines still stop recovery.
        command.run_module_probe(&chunk.iter().map(String::as_str).collect::<Vec<_>>())?;
        recovery_bootstrap::quiet()?;
    }
    command.run_module_probe(&["dm_crypt", "btrfs", "vfat", "nls_cp437", "nls_iso8859_1"])?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while std::fs::read_dir("/sys/class/block")?.next().is_none() {
        require(
            Instant::now() < deadline,
            "no block devices after recovery coldplug",
        )?;
        std::thread::sleep(Duration::from_millis(200));
    }
    recovery_bootstrap::quiet()
}
fn installed_disk_group() -> Result<u32> {
    let body = files::read(Path::new("/etc/group"), 256 * 1024, Some(0), true)?;
    let text = std::str::from_utf8(&body).map_err(|_| Error("installed group encoding".into()))?;
    let mut groups = text.lines().filter(|line| line.starts_with("disk:"));
    let row = groups
        .next()
        .ok_or_else(|| Error("installed disk group missing".into()))?;
    require(groups.next().is_none(), "ambiguous installed disk group")?;
    let fields = row.split(':').collect::<Vec<_>>();
    require(fields.len() == 4, "installed disk group record shape")?;
    let gid = fields[2]
        .parse::<u32>()
        .map_err(|_| Error("installed disk group ID".into()))?;
    require(
        gid.to_string() == fields[2],
        "noncanonical installed disk group ID",
    )?;
    Ok(gid)
}
pub struct Block {
    pub path: PathBuf,
    pub file: File,
    identity: files::FileIdentity,
    device: topology::Device,
    graph: topology::Graph,
}
impl Block {
    pub fn by_device(device: topology::Device) -> Result<Self> {
        crate::storage_runtime::initial_namespace()?;
        let node = topology::kernel_node(device)?;
        let name = node
            .path
            .file_name()
            .ok_or_else(|| Error("kernel block node name missing".into()))?;
        let block = Self::open_role(&Path::new("/dev").join(name), true)?;
        require(
            block.device == device,
            "mounted block device identity differs",
        )?;
        require(
            topology::kernel_node(device)? == node,
            "kernel block node changed during open",
        )?;
        Ok(block)
    }
    pub fn by_uuid(uuid: &str, fat: bool) -> Result<Self> {
        if fat {
            crate::recovery_records::fat_uuid(uuid)?;
        } else {
            identity::uuid(uuid)?;
        }
        let selector = format!("UUID={uuid}");
        let bytes = operation::query(
            "/usr/bin/blkid",
            &["-t", &selector, "-o", "device"],
            Duration::from_secs(30),
            4096,
            &[0],
        )?;
        let body =
            std::str::from_utf8(&bytes).map_err(|_| Error("block UUID query encoding".into()))?;
        let paths = body.split_whitespace().collect::<Vec<_>>();
        require(
            paths.len() == 1,
            "unique UUID-selected recovery block required",
        )?;
        Self::open(Path::new(paths[0]))
    }
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_role(path, false)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (major, minor, openat).")]
    fn open_role(path: &Path, mounted: bool) -> Result<Self> {
        require(
            path.parent() == Some(Path::new("/dev"))
                || path.parent() == Some(Path::new("/dev/mapper")),
            "fixed recovery device location required",
        )?;
        let parent = files::directory(path.parent().unwrap(), Some(0))?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| Error("block device filename".into()))?
                .as_encoded_bytes(),
        )
        .map_err(|_| Error("block device filename".into()))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        require(fd >= 0, "recovery block descriptor unavailable")?;
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata()?;
        require(
            m.mode() & libc::S_IFMT == libc::S_IFBLK
                && m.uid() == 0
                && m.mode() & 0o7000 == 0
                && (m.mode() & 0o022 == 0
                    // Only this Root-only mounted read probe accepts the
                    // installed privileged disk group. Its ID is allocated by
                    // sysusers; recovery unlock keeps private devnode modes.
                    || mounted && m.mode() & 0o002 == 0
                        && (m.gid() == 0 || m.gid() == installed_disk_group()?)),
            "Root-owned recovery block required",
        )?;
        let device = (libc::major(m.rdev()), libc::minor(m.rdev()));
        let graph = topology::observe(&[device])?;
        let block = Self {
            path: path.into(),
            file,
            identity: files::identity(&m),
            device,
            graph,
        };
        block.recheck()?;
        Ok(block)
    }
    pub fn recheck(&self) -> Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        require(
            files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named) == self.identity
                && topology::observe(&[self.device])? == self.graph,
            "recovery device node or backing disk replaced",
        )
    }
}
