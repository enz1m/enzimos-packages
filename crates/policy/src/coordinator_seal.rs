// SPDX-License-Identifier: MIT
//! Exact x86-64 offline PID1 coordinator filter; installation is never a host action.
use enzimos_platform::{Error, Result, files, require};
pub const ARCH: u32 = 0xc000003e;
pub const ALLOW: u32 = 0x7fff0000;
pub const DENY: u32 = 0x00050000 | libc::EPERM as u32;
pub const KILL: u32 = 0x80000000;
pub(crate) const BASE: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 17, 19, 20, 21, 24, 25, 28, 32, 33, 35, 39,
    60, 63, 72, 74, 75, 78, 79, 89, 96, 97, 98, 99, 102, 104, 107, 108, 110, 137, 138, 162, 165,
    166, 169, 186, 202, 217, 219, 228, 229, 230, 231, 257, 262, 267, 273, 302, 318, 332,
];
const RENAME: &[u32] = &[82, 264, 316];
const REQUESTS: &[u32] = &[0x81f8943c, 0x5000940f];
fn row(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
pub fn program() -> Vec<libc::sock_filter> {
    let mut out = vec![
        row(0x20, 0, 0, 4),
        row(0x15, 1, 0, ARCH),
        row(0x06, 0, 0, KILL),
        row(0x20, 0, 0, 0),
    ];
    for nr in BASE.iter().chain(RENAME) {
        out.extend([row(0x15, 0, 1, *nr), row(0x06, 0, 0, ALLOW)]);
    }
    let mut check = vec![
        row(0x20, 0, 0, 28),
        row(0x15, 0, (REQUESTS.len() * 2 + 1) as u8, 0),
        row(0x20, 0, 0, 24),
    ];
    for req in REQUESTS {
        check.extend([row(0x15, 0, 1, *req), row(0x06, 0, 0, ALLOW)]);
    }
    check.push(row(0x06, 0, 0, DENY));
    out.push(row(0x15, 0, check.len() as u8, 16));
    out.extend(check);
    out.push(row(0x06, 0, 0, DENY));
    out
}
pub fn evaluate(nr: u32, arch: u32, arg1: u64) -> Result<u32> {
    let rows = program();
    let mut pc = 0;
    let mut acc = 0;
    for _ in 0..rows.len() {
        let r = rows
            .get(pc)
            .ok_or_else(|| Error("invalid filter jump".into()))?;
        match r.code {
            0x20 => {
                acc = match r.k {
                    0 => nr,
                    4 => arch,
                    24 => arg1 as u32,
                    28 => (arg1 >> 32) as u32,
                    _ => return Err(Error("invalid filter load".into())),
                };
                pc += 1;
            }
            0x15 => pc += 1 + if acc == r.k { r.jt } else { r.jf } as usize,
            0x06 => return Ok(r.k),
            _ => return Err(Error("invalid filter instruction".into())),
        }
    }
    Err(Error("unterminated filter".into()))
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (geteuid, getpid, getppid, prctl)."
)]
pub fn install() -> Result<()> {
    require(
        cfg!(target_arch = "x86_64") && std::mem::size_of::<usize>() == 8,
        "exact x86-64 ABI required",
    )?;
    require(
        unsafe { libc::getpid() } == 1
            && unsafe { libc::getppid() } == 0
            && unsafe { libc::geteuid() } == 0,
        "guest direct PID1 only",
    )?;
    require(
        std::fs::read_dir("/proc/self/task")?.take(2).count() == 1,
        "single-threaded coordinator required",
    )?;
    let mut rows = program();
    let filter = libc::sock_fprog {
        len: rows.len() as u16,
        filter: rows.as_mut_ptr(),
    };
    require(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
            && unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &filter) }
                == 0,
        "coordinator filter unavailable",
    )?;
    // /proc/self is an intentional kernel alias. Resolve it to this process's
    // numeric directory before using the protected pseudo-file reader.
    let status = files::read_kernel(
        &std::path::Path::new("/proc")
            .join(unsafe { libc::getpid() }.to_string())
            .join("status"),
        16384,
    )?;
    let text =
        std::str::from_utf8(&status).map_err(|_| Error("coordinator state encoding".into()))?;
    require(
        text.lines().any(|s| s == "NoNewPrivs:\t1") && text.lines().any(|s| s == "Seccomp:\t2"),
        "coordinator filter not active",
    )
}
