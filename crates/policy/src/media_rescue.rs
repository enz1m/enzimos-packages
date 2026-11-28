// SPDX-License-Identifier: MIT
//! Installer-media rescue from an independent RAM root; installed programs never run.
use crate::{
    media_auth, media_origin, media_plan, operation, recovery_bootstrap, recovery_devices, storage,
    storage_runtime::IndependentGuard,
};
use enzimos_platform::{Error, Result, files, json, process, require};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

const MAPPER: &str = "enzimos-media-rescue";
const AUTHORITY: &str = "/etc/pacman.d/gnupg";

/// The attended display terminal, with a best-effort serial copy of everything
/// except typed input. Secrets are read with echo disabled and never mirrored.
pub(crate) struct Console {
    input: std::io::BufReader<File>,
    display: File,
    serial: Option<File>,
}
impl Console {
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (dup2, getpid, getsid, ioctl and others)."
    )]
    pub(crate) fn attach() -> Result<Self> {
        let path = if Path::new("/dev/tty1").exists() {
            c"/dev/tty1"
        } else {
            c"/dev/console"
        };
        // SAFETY: `path` is a NUL-terminated CString.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        require(fd >= 0, "rescue console unavailable")?;
        // SAFETY: getsid, getpid, setsid, dup2 and TIOCSCTTY take only integers, and `fd` is open.
        unsafe {
            if libc::getsid(0) != libc::getpid() {
                libc::setsid();
            }
            libc::ioctl(fd, libc::TIOCSCTTY, 1);
            for target in [0, 1, 2] {
                require(
                    libc::dup2(fd, target) == target,
                    "rescue console setup failed",
                )?;
            }
        }
        // SAFETY: `fd` was just returned by open and is owned by nothing else.
        let display = unsafe { File::from_raw_fd(fd) };
        let input = std::io::BufReader::new(display.try_clone()?);
        let serial = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open("/dev/ttyS0")
            .ok();
        Ok(Self {
            input,
            display,
            serial,
        })
    }
    pub(crate) fn say(&mut self, text: &str) {
        let _ = self.display.write_all(text.as_bytes());
        let _ = self.display.write_all(b"\n");
        if let Some(serial) = self.serial.as_mut() {
            let _ = serial.write_all(text.as_bytes());
            let _ = serial.write_all(b"\n");
        }
    }
    fn prompt(&mut self, text: &str) -> Result<()> {
        self.display.write_all(text.as_bytes())?;
        self.display.flush()?;
        if let Some(serial) = self.serial.as_mut() {
            let _ = serial.write_all(text.as_bytes());
        }
        Ok(())
    }
    pub(crate) fn ask(&mut self, text: &str) -> Result<String> {
        self.prompt(text)?;
        let mut line = String::new();
        require(
            self.input.by_ref().take(1024).read_line(&mut line)? > 0,
            "rescue console closed",
        )?;
        Ok(line.trim().to_owned())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (tcgetattr, tcsetattr).")]
    pub(crate) fn secret(&mut self, text: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.prompt(text)?;
        let fd = self.display.as_raw_fd();
        // SAFETY: `libc::termios` is a plain C struct, for which all-zero bytes are a valid value.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `saved` is a writable termios and `fd` is the open console.
            unsafe { libc::tcgetattr(fd, &mut saved) } == 0,
            "rescue terminal required",
        )?;
        let mut quiet = saved;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
        require(
            // SAFETY: `quiet` is a fully initialized termios and `fd` is the open console.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } == 0,
            "rescue echo suppression failed",
        )?;
        let mut line = Zeroizing::new(Vec::with_capacity(1024));
        let read = self.input.by_ref().take(1024).read_until(b'\n', &mut line);
        // SAFETY: `saved` is the termios read from `fd` above.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        let _ = self.display.write_all(b"\n");
        require(read? > 0, "rescue console closed")?;
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        require(
            !line.is_empty() && line.len() < 1000 && !line.contains(&0),
            "password size bound",
        )?;
        Ok(line)
    }
    pub(crate) fn select(&mut self, rows: &[String], label: &str) -> Result<usize> {
        require(!rows.is_empty(), &format!("no {label} found"))?;
        for (number, row) in rows.iter().enumerate() {
            self.say(&format!("{}. {row}", number + 1));
        }
        let answer = self.ask(&format!("Choose {label} number: "))?;
        selection(&answer, rows.len()).ok_or_else(|| Error("invalid selection".into()))
    }
}
pub(crate) fn selection(answer: &str, count: usize) -> Option<usize> {
    let number = answer.parse::<usize>().ok()?;
    (1..=count).contains(&number).then(|| number - 1)
}
fn device_path(path: &str) -> bool {
    path.strip_prefix("/dev/").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.contains("..")
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b))
    })
}
/// Partitions from `lsblk --json --paths --output NAME,TYPE,SIZE`.
pub(crate) fn partitions(lsblk: &[u8]) -> Result<Vec<(String, String)>> {
    let tree = json::decode(lsblk, 4 * 1024 * 1024)?;
    let mut pending = tree["blockdevices"].as_array().cloned().unwrap_or_default();
    let mut result = Vec::new();
    while let Some(row) = pending.pop() {
        require(
            pending.len() + result.len() <= 1024,
            "block device listing bound",
        )?;
        if let Some(children) = row["children"].as_array() {
            pending.extend(children.iter().cloned());
        }
        if row["type"] == "part" {
            let name = row["name"].as_str().unwrap_or("");
            require(device_path(name), "invalid partition path")?;
            let size = match &row["size"] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            result.push((name.to_owned(), size));
        }
    }
    require(result.len() <= 128, "partition discovery bound")?;
    result.sort();
    Ok(result)
}
/// The installation's ESP UUID from its own fstab, never the first FAT partition found.
pub(crate) fn esp_uuid(fstab: &str) -> Result<String> {
    let rows = fstab
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 3 && fields[1] == "/boot" && fields[2] == "vfat")
                .then(|| fields[0].strip_prefix("UUID="))
                .flatten()
        })
        .collect::<Vec<_>>();
    require(
        rows.len() == 1
            && rows[0].len() == 9
            && rows[0].bytes().enumerate().all(|(i, b)| {
                if i == 4 {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }),
        "explicit installed ESP binding required",
    )?;
    Ok(rows[0].to_owned())
}
pub(crate) fn installation_name(name: &str) -> bool {
    name == "enzimos-root"
        || name.strip_prefix("enzimos-recovered-").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

fn tool(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = process::run(
        program,
        args,
        &[],
        Duration::from_secs(120),
        4 * 1024 * 1024,
    )?;
    require(
        output.status.success(),
        &format!("{} refused", program.rsplit('/').next().unwrap_or(program)),
    )?;
    Ok(output.stdout)
}
fn probe(path: &str, tag: &str) -> Result<Option<String>> {
    let output = process::run(
        "/usr/bin/blkid",
        &["-p", "-s", tag, "-o", "value", path],
        &[],
        Duration::from_secs(30),
        4096,
    )?;
    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        )),
        Some(2) => Ok(None),
        _ => Err(Error(format!("partition signature probe failed: {path}"))),
    }
}
fn mount(args: &[&str]) -> Result<()> {
    tool("/usr/bin/mount", args).map(|_| ())
}

/// Mounts and the unlocked mapper this attempt owns; released in reverse order.
struct Owned {
    mounts: Vec<PathBuf>,
    mapper: bool,
}
impl Drop for Owned {
    #[allow(unsafe_code, reason = "Linux syscall ABI (sync).")]
    fn drop(&mut self) {
        // SAFETY: sync takes no arguments and cannot fail.
        unsafe { libc::sync() };
        for target in self.mounts.drain(..).rev() {
            let _ = process::run(
                "/usr/bin/umount",
                &[&target.to_string_lossy()],
                &[],
                Duration::from_secs(60),
                65536,
            );
        }
        if self.mapper {
            let _ =
                process::recovery_cryptsetup(&["close", MAPPER], &[], Duration::from_secs(60), &[]);
        }
    }
}

fn unlock(console: &mut Console, source: &str) -> Result<String> {
    let device = File::open(source)?;
    loop {
        let secret = console.secret("Disk password: ")?;
        let result = process::recovery_cryptsetup(
            &["open", "--key-file", "-", "@fd:0", MAPPER],
            &secret,
            Duration::from_secs(120),
            &[device.as_fd()],
        )?;
        if result.status.success() {
            return Ok(format!("/dev/mapper/{MAPPER}"));
        }
        console.say("Disk password incorrect, or disk cannot be unlocked. Try again.");
    }
}

fn installation(top: &Path, filesystem: &str) -> Result<Vec<(String, Value)>> {
    let mut found = Vec::new();
    for row in std::fs::read_dir(top)?.take(4097) {
        let name = row?.file_name().to_string_lossy().into_owned();
        if !installation_name(&name) {
            continue;
        }
        let config = (|| -> Result<Value> {
            let body = files::read(
                &top.join(&name).join("etc/enzimos/storage.json"),
                16384,
                Some(0),
                true,
            )?;
            let config = json::decode(&body, 16384)?;
            storage::validate(&config)?;
            require(
                config["filesystem_uuid"] == filesystem && config["root_subvol"] == name.as_str(),
                "installation storage binding differs",
            )?;
            Ok(config)
        })();
        if let Ok(config) = config {
            found.push((name, config));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

fn authenticate(console: &mut Console, root: &Path) -> Result<()> {
    loop {
        let username = console.ask("Administrator account: ")?;
        let attempt = media_auth::Observation::observe(root, &username).and_then(|observation| {
            let password = console.secret("Administrator password: ")?;
            observation.authenticate(&password)
        });
        match attempt {
            Ok(()) => return Ok(()),
            Err(error) => console.say(&error.to_string()),
        }
    }
}

#[allow(unsafe_code, reason = "Linux syscall ABI (waitpid).")]
fn reap_orphans() {
    // SAFETY: A null status pointer is allowed by waitpid.
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
}

fn terminal(console: &mut Console, root: &Path, home: &Path) {
    console.say(&format!(
        "The installed system is mounted read-only at {}\nPersonal files: {}\n\
         Use lsblk -f to find an external USB partition.\n\
         Example: mkdir -p /run/backup; mount -o nodev,nosuid,noexec /dev/USB_PARTITION /run/backup\n\
         Copy without overwriting: cp -an SOURCE /run/backup/\n\
         Run sync and umount /run/backup before disconnecting. Type exit to return.\n\
         Do not chroot into the broken system; the media provides trusted tools.",
        root.display(),
        home.display()
    ));
    let _ = std::process::Command::new("/usr/bin/bash")
        .args(["--noprofile", "--norc"])
        .env_clear()
        .envs([
            ("PATH", "/usr/bin"),
            ("LANG", "C.UTF-8"),
            ("TERM", "linux"),
            ("HOME", "/run"),
            ("PS1", "Rescue \\w # "),
        ])
        .status();
    reap_orphans();
}

/// One attended rescue session. Returns the restore result, or null when the
/// user chose to reboot without restoring.
pub(crate) fn run(console: &mut Console) -> Result<Value> {
    // Hold the operation lock before any installed control state is visible.
    let lock = operation::lock()?;
    let mut owned = Owned {
        mounts: Vec::new(),
        mapper: false,
    };
    let listing = tool(
        "/usr/bin/lsblk",
        &["--json", "--paths", "--output", "NAME,TYPE,SIZE"],
    )?;
    // No udev runs in this RAM root, so probe partition signatures directly.
    let mut candidates = Vec::new();
    for (path, size) in partitions(&listing)? {
        if let Some(kind) = probe(&path, "TYPE")?
            && matches!(kind.as_str(), "crypto_LUKS" | "btrfs")
        {
            candidates.push((path, kind, size));
        }
    }
    require(candidates.len() <= 64, "installation partition count bound")?;
    console.say("\nenzimOS installer rescue\nUnlock and authenticate an existing installation. No installed programs are executed.\n");
    let labels = candidates
        .iter()
        .map(|(path, kind, size)| format!("{path}  {kind}  {size}"))
        .collect::<Vec<_>>();
    let (path, kind, _) = &candidates[console.select(&labels, "system partition")?];
    let source = if kind == "crypto_LUKS" {
        let mapped = unlock(console, path)?;
        owned.mapper = true;
        mapped
    } else {
        path.clone()
    };
    let filesystem = probe(&source, "UUID")?.unwrap_or_default();
    crate::identity::uuid(&filesystem)?;
    require(
        probe(&source, "TYPE")?.as_deref() == Some("btrfs"),
        "enzimOS Btrfs filesystem required",
    )?;
    let top = Path::new(IndependentGuard::TOP);
    files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
    files::ensure_directory(top, 0o700, 0)?;
    mount(&[
        "-t",
        "btrfs",
        "-o",
        "ro,subvolid=5,nodiscard,nosuid,nodev",
        &source,
        IndependentGuard::TOP,
    ])?;
    owned.mounts.push(top.into());
    let installations = installation(top, &filesystem)?;
    let names = installations
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>();
    let (name, config) = &installations[console.select(&names, "installation")?];
    let root = top.join(name);
    authenticate(console, &root)?;
    let fstab = files::read(&root.join("etc/fstab"), 256 * 1024, Some(0), true)?;
    let esp = esp_uuid(&String::from_utf8_lossy(&fstab))?;
    files::ensure_directory(Path::new("/boot"), 0o755, 0)?;
    mount(&[
        "-t",
        "vfat",
        "-o",
        "ro,nosuid,nodev,noexec",
        &format!("UUID={esp}"),
        "/boot",
    ])?;
    owned.mounts.push("/boot".into());
    for (role, target) in [("control", operation::CONTROL), ("authority", AUTHORITY)] {
        let subvol = config[format!("{role}_subvol")]
            .as_str()
            .unwrap_or_default();
        files::ensure_directory(Path::new(target), 0o700, 0)?;
        mount(&["--bind", &top.join(subvol).to_string_lossy(), target])?;
        owned.mounts.push(target.into());
    }
    let home = top.join(config["home_subvol"].as_str().unwrap_or_default());
    loop {
        console.say("\n1. Restore a system snapshot\n2. Open a recovery terminal / copy files to an external drive\n3. Reboot");
        match console.ask("Choose action number: ")?.as_str() {
            "1" => break,
            "2" => terminal(console, &root, &home),
            "3" => return Ok(Value::Null),
            _ => console.say("Choose 1, 2 or 3."),
        }
    }
    let choices = media_plan::choices(config)?;
    require(
        !choices.is_empty(),
        "no qualified retained system snapshots; reboot and choose the terminal to retrieve files",
    )?;
    let descriptions = choices
        .iter()
        .map(|c| {
            format!(
                "{}  {}",
                c["generation"].as_str().unwrap_or(""),
                c["kernels"]
            )
        })
        .collect::<Vec<_>>();
    let choice = &choices[console.select(&descriptions, "snapshot")?];
    console.say("Restore this system snapshot. Personal files and package authority stay intact.\nPrevious roots are retained. The recovered system starts on the next boot.");
    require(
        console.ask("Type RESTORE to continue: ")? == "RESTORE",
        "cancelled; no restoration performed",
    )?;
    mount(&["-o", "remount,rw", IndependentGuard::TOP])?;
    mount(&["-o", "remount,rw", "/boot"])?;
    for target in [operation::CONTROL, AUTHORITY] {
        mount(&["-o", "remount,bind,rw", target])?;
    }
    let plan = media_plan::prepare_locked(
        config,
        choice["birth"].as_str().unwrap_or_default(),
        choice["generation"].as_str().unwrap_or_default(),
        &lock,
    )?;
    let result = media_plan::execute_locked(&plan, &lock, |phase, _| {
        console.say(&format!("Restore phase: {phase}"));
        Ok(())
    })?;
    console.say(&format!("ENZIMOS_MEDIA_RESTORE_PASS {result}"));
    console.say("Restore complete. Rebooting into the recovered system.");
    drop(owned);
    Ok(result)
}

/// Direct PID1 entry: prepare the RAM root, record the media origin, load
/// drivers, run one attended session, then reboot. Nothing retries automatically.
#[allow(unsafe_code, reason = "Linux syscall ABI (pause).")]
pub fn main() -> ! {
    let prepared = recovery_bootstrap::initialize()
        .and_then(|()| media_origin::initialize().map(|_| ()))
        .and_then(|()| recovery_devices::coldplug());
    let mut console = Console::attach();
    let outcome = prepared.and_then(|()| match console.as_mut() {
        Ok(console) => run(console).map(|_| ()),
        Err(error) => Err(Error(error.to_string())),
    });
    if let Err(error) = outcome {
        let message = format!("{error}\nENZIMOS_INSTALLER_RESCUE_FAILED; no automatic replay");
        match console.as_mut() {
            Ok(console) => {
                console.say(&message);
                let _ = console.ask("Press Enter to reboot: ");
            }
            Err(_) => eprintln!("{message}"),
        }
    }
    let _ = recovery_bootstrap::reboot(false);
    loop {
        // SAFETY: pause takes no arguments.
        unsafe { libc::pause() };
    }
}
