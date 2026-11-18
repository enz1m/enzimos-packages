// SPDX-License-Identifier: MIT
use crate::{operation, settings_command::Command, settings_file::Config};
use enzimos_platform::{Error, Result, files, json, process_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};
const CONFIG: &str = "/etc/enzimos/memory-pressure.json";
const UNIT: &str = "earlyoom.service";
pub const PROTECTED: &[&str] = &[
    "enz-hyprland",
    "Hyprland",
    "enzui-shell",
    "enzui-lock",
    "enzui-greeter",
    "enzui-polkit-ag",
    "enzui-network-s",
    "enzui-portal",
    "enzui-wallpaper",
    "enzimos-install",
    "enzimos-recover",
    "systemd",
    "systemd-journal",
    "systemd-logind",
    "systemd-resolve",
    "systemd-udevd",
    "dbus-broker",
    "NetworkManager",
    "polkitd",
    "udisksd",
];
pub fn validate_selection(v: &Value) -> Result<()> {
    json::fields(v, "mode risk_acknowledged")?;
    require(
        matches!(v["mode"].as_str(), Some("balanced" | "responsive" | "off"))
            && v["risk_acknowledged"].as_bool() == Some(v["mode"] == "off"),
        "memory policy risk acknowledgement mismatch",
    )
}
pub fn validate_document(v: &Value) -> Result<()> {
    json::fields(v, "schema mode")?;
    require(
        v["schema"].as_u64() == Some(1)
            && matches!(v["mode"].as_str(), Some("balanced" | "responsive" | "off")),
        "invalid memory policy document",
    )
}
/// Keep absolute ceilings valid on machines smaller than a preset. earlyoom
/// chooses the lower relative/absolute threshold; clamping a ceiling to total
/// capacity therefore preserves the selected percentages on small machines.
pub fn arguments_for_capacity(mode: &str, memory_kib: u64, swap_kib: u64) -> Result<Vec<String>> {
    require(
        memory_kib > 0,
        "memory policy requires positive kernel capacity",
    )?;
    let (memory, memory_cap, swap, swap_cap) = match mode {
        "balanced" => ("10,5", (1048576, 524288), "20,10", (1048576, 524288)),
        "responsive" => ("15,8", (1572864, 786432), "40,20", (2097152, 1048576)),
        _ => return Err(Error("disabled or unknown memory guard".into())),
    };
    let cap =
        |(term, kill): (u64, u64), total: u64| format!("{},{}", term.min(total), kill.min(total));
    let mut args = vec![
        "/usr/bin/earlyoom".into(),
        "-m".into(),
        memory.into(),
        "-M".into(),
        cap(memory_cap, memory_kib),
        "-s".into(),
        swap.into(),
    ];
    if swap_kib > 0 {
        args.extend(["-S".into(), cap(swap_cap, swap_kib)]);
    }
    args.extend([
        "-r".into(),
        "3600".into(),
        "--ignore".into(),
        format!("^({})$", PROTECTED.join("|")),
    ]);
    Ok(args)
}
/// Kernel capacity (MemTotal, SwapTotal in KiB) that sizes the presets.
fn capacity() -> Result<(u64, u64)> {
    let bytes = files::read_kernel(Path::new("/proc/meminfo"), 65536)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error("memory capacity kernel encoding".into()))?;
    let field = |name: &str| -> Result<u64> {
        let rows = text
            .lines()
            .filter(|line| line.starts_with(name))
            .collect::<Vec<_>>();
        require(rows.len() == 1, "memory capacity field absent or ambiguous")?;
        let fields = rows[0].split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 3 && fields[2] == "kB",
            "memory capacity units differ",
        )?;
        fields[1]
            .parse()
            .map_err(|_| Error("memory capacity numeric type".into()))
    };
    Ok((field("MemTotal:")?, field("SwapTotal:")?))
}
pub fn arguments(mode: &str) -> Result<Vec<String>> {
    let (memory, swap) = capacity()?;
    arguments_for_capacity(mode, memory, swap)
}

/// systemd's fixed DynamicUser= allocation range (systemd.exec(5)). The vendor
/// earlyoom.service runs under DynamicUser=yes and the enzimOS drop-in keeps it,
/// so the daemon's procfs entries belong to a transient UID from this range.
pub const DYNAMIC_USERS: std::ops::RangeInclusive<u32> = 61184..=65519;
/// The only cgroup v2 membership the manager-reported MainPID may have.
pub const UNIT_CGROUP: &str = "0::/system.slice/earlyoom.service";
/// Admit the earlyoom task's owner: Root, or one transient DynamicUser= UID.
/// Login users (1000+) and fixed system accounts are refused.
pub fn admitted_owner(uid: u32) -> bool {
    uid == 0 || DYNAMIC_USERS.contains(&uid)
}
/// The task must sit in exactly the fixed unit's cgroup in the unified
/// hierarchy. Legacy controller lines (`N:controllers:/path`, e.g. a mounted
/// net_cls on hybrid hosts) are admitted but grant nothing.
pub fn unit_cgroup(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let lines = text
        .strip_suffix('\n')
        .map(|t| t.split('\n').collect::<Vec<_>>());
    let Some(lines) = lines.filter(|l| body.len() <= 4096 && l.len() <= 32) else {
        return false;
    };
    let legacy = |line: &str| {
        let mut parts = line.splitn(3, ':');
        let (Some(id), Some(_), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        !id.is_empty()
            && !id.starts_with('0')
            && id.bytes().all(|b| b.is_ascii_digit())
            && path.starts_with('/')
    };
    lines.iter().filter(|l| l.starts_with("0:")).count() == 1
        && lines.contains(&UNIT_CGROUP)
        && lines.iter().all(|l| *l == UNIT_CGROUP || legacy(l))
}
/// Map an observed NUL-separated argv to the exact preset that produced it.
/// Only a byte-identical command line built for this kernel's capacity counts.
pub fn effective_mode(cmdline: &[u8], memory_kib: u64, swap_kib: u64) -> Option<&'static str> {
    ["balanced", "responsive"].into_iter().find(|mode| {
        arguments_for_capacity(mode, memory_kib, swap_kib).is_ok_and(|args| {
            let mut expected = args.join("\0").into_bytes();
            expected.push(0);
            expected == cmdline
        })
    })
}
/// Typed `systemctl show` fields. Unset or infinite metrics become null, never 0.
pub fn parse_service(text: &str) -> Result<Value> {
    let mut state = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error("memory service state field".into()))?;
        require(
            state.insert(key, value).is_none(),
            "duplicate memory service state",
        )?;
    }
    require(
        state.len() == 5
            && [
                "ActiveState",
                "SubState",
                "MainPID",
                "MemoryCurrent",
                "CPUUsageNSec",
            ]
            .iter()
            .all(|key| state.contains_key(key)),
        "memory service state fields",
    )?;
    let decimal = |key: &str| -> Result<Option<u64>> {
        let text = state[key];
        if text == "[not set]" {
            return Ok(None);
        }
        require(
            !text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit()),
            "memory service metric encoding",
        )?;
        let number = text
            .parse::<u64>()
            .map_err(|_| Error("memory service metric encoding".into()))?;
        Ok((number != u64::MAX).then_some(number))
    };
    let pid = decimal("MainPID")?
        .filter(|pid| *pid < i32::MAX as u64)
        .ok_or_else(|| Error("memory service MainPID".into()))?;
    for key in ["ActiveState", "SubState"] {
        require(
            !state[key].is_empty()
                && state[key].len() <= 32
                && state[key]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'-'),
            "memory service state encoding",
        )?;
    }
    Ok(value!({
        "ActiveState": state["ActiveState"],
        "SubState": state["SubState"],
        "MainPID": pid,
        "MemoryCurrent": decimal("MemoryCurrent")?,
        "CPUUsageNSec": decimal("CPUUsageNSec")?,
        "EffectiveMode": Value::Null,
    }))
}

fn read() -> Result<(Value, Vec<u8>)> {
    let b = Config::open(CONFIG, 1024)?.body;
    let v = json::decode(&b, 1024)?;
    validate_document(&v)?;
    Ok((v, b))
}
pub fn service_state() -> Result<Value> {
    service_state_with(&Command::open("/usr/bin/systemctl")?)
}
/// Read the command line of the manager-reported MainPID only after binding it
/// with a pidfd to the fixed earlyoom ELF, one consistent UID set and the
/// unit's own cgroup. A launcher that has not yet exec'd earlyoom is refused.
fn running_command_line(pid: u32) -> Result<Vec<u8>> {
    let folder = Path::new("/proc").join(pid.to_string());
    let owner = files::directory(&folder, None)?.metadata()?.uid();
    require(admitted_owner(owner), "memory process owner refused")?;
    let stat = files::read_kernel_owned(&folder.join("stat"), 8192, owner)?;
    let stat = process_identity::parse_stat(
        std::str::from_utf8(&stat).map_err(|_| Error("memory process identity encoding".into()))?,
        pid,
    )?;
    let status = files::read_kernel_owned(&folder.join("status"), 65536, owner)?;
    let uids = process_identity::parse_uids(
        std::str::from_utf8(&status).map_err(|_| Error("memory process UID encoding".into()))?,
    )?;
    require(
        uids.iter().all(|uid| *uid == owner),
        "memory process UID differs",
    )?;
    let retained = process_identity::Retained::open(
        pid,
        stat.start_ticks,
        owner,
        &[Path::new("/usr/bin/earlyoom").into()],
    )?;
    require(
        unit_cgroup(&files::read_kernel_owned(
            &folder.join("cgroup"),
            4096,
            owner,
        )?),
        "memory process outside its unit",
    )?;
    let body = files::read_kernel_owned(&folder.join("cmdline"), 4096, owner)?;
    retained.recheck()?;
    Ok(body)
}
fn service_state_with(command: &Command) -> Result<Value> {
    let b = command.run_timeout(
        &[
            "show",
            UNIT,
            "--property=ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec",
            "--no-pager",
        ],
        &[0],
        16384,
        Duration::from_secs(5),
    )?;
    let mut v = parse_service(
        std::str::from_utf8(&b).map_err(|_| Error("memory service state encoding".into()))?,
    )?;
    let pid = v["MainPID"].as_u64().unwrap() as u32;
    // An unconfirmed task leaves EffectiveMode null: unknown is never a mode.
    if pid > 0
        && let Ok(body) = running_command_line(pid)
    {
        let (memory, swap) = capacity()?;
        v["EffectiveMode"] = value!(effective_mode(&body, memory, swap));
    }
    Ok(v)
}
pub fn policy() -> Result<Value> {
    let (v, b) = read()?;
    Ok(
        value!({"schema":1,"mode":v["mode"],"available_modes":["balanced","responsive","off"],"default_mode":"balanced","config_sha256":json::sha256(&b),"service":service_state()?,"protected_process_names":PROTECTED,"presets":{"balanced":["-m","10,5","-M","1048576,524288","-s","20,10","-S","1048576,524288"],"responsive":["-m","15,8","-M","1572864,786432","-s","40,20","-S","2097152,1048576"]},"effective_after":"immediate","off_requires_risk_acknowledgement":true,"owner":"earlyoom","zram_managed_separately":true}),
    )
}
/// Whether the observed service state proves `mode` is the running policy.
pub fn converged(mode: &str, state: &Value) -> bool {
    if mode == "off" {
        state["ActiveState"] == "inactive"
    } else {
        state["ActiveState"] == "active" && state["EffectiveMode"] == mode
    }
}
/// Side effects of one policy change. The pure transition below is unit-tested.
pub trait Effects {
    /// Fresh caller authorization; refusal must precede every mutation.
    fn authorize(&mut self) -> Result<()>;
    /// Recheck the retained configuration, provider and lock identities.
    fn recheck(&mut self) -> Result<()>;
    fn publish(&mut self, body: &[u8]) -> Result<()>;
    fn restart(&mut self) -> Result<()>;
    fn state(&mut self) -> Result<Value>;
    /// Start a fresh confirmation window.
    fn begin(&mut self);
    /// Wait one poll interval; false once the confirmation window has passed.
    fn wait(&mut self) -> bool;
}
fn settle(mode: &str, fx: &mut dyn Effects) -> Result<()> {
    fx.restart()?;
    fx.begin();
    loop {
        fx.recheck()?;
        if converged(mode, &fx.state()?) {
            return Ok(());
        }
        require(fx.wait(), "memory protection did not take effect")?;
    }
}
/// Publish `mode`, restart and confirm it running. On any failure after
/// publication the previous document is restored, restarted and confirmed; the
/// error states which of those happened. Nothing is touched before authorization.
pub fn transition(mode: &str, before: &[u8], fx: &mut dyn Effects) -> Result<Value> {
    let previous = json::decode(before, 1024)?;
    validate_document(&previous)?;
    let previous = previous["mode"].as_str().unwrap().to_owned();
    let body = json::canonical(&value!({"schema":1,"mode":mode}))?;
    validate_document(&json::decode(&body, 1024)?)?;
    fx.authorize()?;
    fx.recheck()?;
    fx.publish(&body)?;
    if let Err(error) = settle(mode, fx) {
        let restored = fx.recheck().and_then(|()| fx.publish(before));
        return Err(Error(match restored {
            Err(e) => format!("{error}; previous memory policy could not be restored: {e}"),
            Ok(()) => match settle(&previous, fx) {
                Ok(()) => format!(
                    "{error}; previous memory policy {previous} restored and confirmed running"
                ),
                Err(e) => format!(
                    "{error}; previous memory policy {previous} restored but not confirmed running: {e}"
                ),
            },
        }));
    }
    fx.recheck()?;
    Ok(value!({"mode":mode,"applied_live":true,"reboot_required":false}))
}
struct Live<'a, F: FnMut() -> Result<()>> {
    authorization: F,
    config: Config,
    command: Command,
    lock: &'a files::Lock,
    deadline: Instant,
}
impl<F: FnMut() -> Result<()>> Effects for Live<'_, F> {
    fn authorize(&mut self) -> Result<()> {
        (self.authorization)()
    }
    fn recheck(&mut self) -> Result<()> {
        self.config.recheck()?;
        self.command.recheck()?;
        self.lock.recheck()
    }
    fn publish(&mut self, body: &[u8]) -> Result<()> {
        self.config.publish(body)
    }
    fn restart(&mut self) -> Result<()> {
        restart(&self.command)
    }
    fn state(&mut self) -> Result<Value> {
        service_state_with(&self.command)
    }
    fn begin(&mut self) {
        // The launcher validates the ELF before execveat; allow a slow VM.
        self.deadline = Instant::now() + Duration::from_secs(5);
    }
    fn wait(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
        true
    }
}
fn restart(command: &Command) -> Result<()> {
    command.run_timeout(&["restart", UNIT], &[0], 16384, Duration::from_secs(10))?;
    Ok(())
}
pub fn set_policy<F: FnMut() -> Result<()>>(v: &Value, authorization: F) -> Result<Value> {
    operation::root_only()?;
    validate_selection(v)?;
    let lock = operation::lock()?;
    let config = Config::open(CONFIG, 1024)?;
    validate_document(&json::decode(&config.body, 1024)?)?;
    let before = config.body.clone();
    let command = Command::open("/usr/bin/systemctl")?;
    let mut live = Live {
        authorization,
        config,
        command,
        lock: &lock,
        deadline: Instant::now(),
    };
    transition(v["mode"].as_str().unwrap(), &before, &mut live)
}
pub fn plan() -> Result<Value> {
    let lock = operation::lock()?;
    let body = observation()?;
    lock.recheck()?;
    Ok(body)
}
/// Read-only binding also used inside the original setter's existing lock.
pub fn observation() -> Result<Value> {
    let config = Config::open(CONFIG, 1024)?;
    let mut state = policy()?;
    state.as_object_mut().unwrap().remove("service");
    let command = Command::open("/usr/bin/systemctl")?;
    config.recheck()?;
    Ok(value!({"state":state,"configuration":config.evidence()?,"provider":command.evidence()?}))
}
pub fn configured_arguments() -> Result<Option<Vec<String>>> {
    let (v, _) = read()?;
    if v["mode"] == "off" {
        Ok(None)
    } else {
        Ok(Some(arguments(v["mode"].as_str().unwrap())?))
    }
}

/// Service entry point: retains the configuration and vendor ELF until execveat.
/// Runs with the existing service identity; it does not acquire a Root mutation lock.
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
pub fn launch(action: &str) -> Result<Value> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsFd, AsRawFd},
            unix::fs::MetadataExt,
        },
    };
    require(
        matches!(action, "condition" | "run"),
        "fixed memory launch action required",
    )?;
    let config = Config::open(CONFIG, 1024)?;
    let document = json::decode(&config.body, 1024)?;
    validate_document(&document)?;
    config.recheck()?;
    if action == "condition" {
        return Ok(
            value!({"status":if document["mode"]=="off" {"memory-policy-disabled"} else {"memory-policy-enabled"}}),
        );
    }
    let args = arguments(document["mode"].as_str().unwrap())?;
    let parent = files::directory(Path::new("/usr/bin"), Some(0))?;
    let executable = files::open_relative(&parent, Path::new("earlyoom"))?;
    let epoch = files::identity(&executable.metadata()?);
    let mount = enzimos_platform::mount_identity::id(executable.as_fd(), true)?;
    let body = files::read_file(&executable, 32 * 1024 * 1024, Some(0), true)?;
    require(
        body.len() >= 20
            && body.starts_with(b"\x7fELF")
            && body[4] == 2
            && body[5] == 1
            && u16::from_le_bytes(body[18..20].try_into().unwrap()) == 62
            && executable.metadata()?.mode() & 0o111 == 0o111
            && executable.metadata()?.gid() == 0,
        "original x86_64 earlyoom executable required",
    )?;
    let arguments: Vec<_> = args
        .iter()
        .map(|a| CString::new(a.as_str()).map_err(|_| Error("memory argument encoding".into())))
        .collect::<Result<_>>()?;
    let mut argv: Vec<_> = arguments.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let environment = [
        CString::new("PATH=/usr/bin").unwrap(),
        CString::new("LANG=C.UTF-8").unwrap(),
    ];
    let mut env: Vec<_> = environment.iter().map(|a| a.as_ptr()).collect();
    env.push(std::ptr::null());
    config.recheck()?;
    let named_parent = files::directory(Path::new("/usr/bin"), Some(0))?;
    require(
        files::identity(&parent.metadata()?) == files::identity(&named_parent.metadata()?)
            && files::identity(&executable.metadata()?) == epoch
            && files::identity(
                &files::open_relative(&named_parent, Path::new("earlyoom"))?.metadata()?,
            ) == epoch
            && enzimos_platform::mount_identity::id(executable.as_fd(), true)? == mount,
        "original earlyoom identity changed",
    )?;
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            executable.as_raw_fd(),
            c"".as_ptr(),
            argv.as_ptr(),
            env.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    Err(std::io::Error::last_os_error().into())
}
