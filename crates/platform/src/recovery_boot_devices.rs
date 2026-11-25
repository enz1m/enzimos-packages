// SPDX-License-Identifier: MIT
//! Owned cgroup device policy: image node creation, never physical device I/O.
use crate::{Result, require};
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
};
#[repr(C)]
#[derive(Clone, Copy)]
struct Instruction {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}
const fn ins(code: u8, registers: u8, offset: i16, immediate: i32) -> Instruction {
    Instruction {
        code,
        registers,
        offset,
        immediate,
    }
}
// linux/bpf.h bpf_cgroup_dev_ctx: access_type, major, minor. MKNOD-only
// events can describe initramfs nodes. READ/WRITE is restricted to four basic
// character devices; creating an arbitrary block node never grants access.
const PROGRAM: [Instruction; 17] = [
    ins(0x61, 0x12, 0, 0),
    ins(0x77, 0x02, 0, 16),
    ins(0x15, 0x02, 12, 1),
    ins(0x61, 0x12, 0, 0),
    ins(0x57, 0x02, 0, 0xffff),
    ins(0x55, 0x02, 7, 2),
    ins(0x61, 0x12, 4, 0),
    ins(0x55, 0x02, 5, 1),
    ins(0x61, 0x12, 8, 0),
    ins(0x15, 0x02, 5, 3),
    ins(0x15, 0x02, 4, 5),
    ins(0x15, 0x02, 3, 8),
    ins(0x15, 0x02, 2, 9),
    ins(0xb7, 0x00, 0, 0),
    ins(0x95, 0x00, 0, 0),
    ins(0xb7, 0x00, 0, 1),
    ins(0x95, 0x00, 0, 0),
];
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, syscall).")]
pub(crate) fn attach(group: &File) -> Result<File> {
    require(
        crate::process_identity::effective_uid() == 0,
        "Root complete boot device policy required",
    )?;
    #[repr(C)]
    struct Load {
        kind: u32,
        count: u32,
        instructions: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log: u64,
        kernel_version: u32,
        flags: u32,
        name: [u8; 16],
        interface: u32,
        expected_attach: u32,
    }
    let mut log = [0u8; 16384];
    let load = Load {
        kind: 15,
        count: PROGRAM.len() as u32,
        instructions: PROGRAM.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log: log.as_mut_ptr() as u64,
        kernel_version: 0,
        flags: 0,
        name: *b"enzim_boot_dev\0\0",
        interface: 0,
        expected_attach: 6,
    };
    // SAFETY: `load` is a repr(C) bpf_attr prefix passed with its exact size, and its pointers
    // reference live buffers.
    let fd = unsafe { libc::syscall(libc::SYS_bpf, 5, &load, std::mem::size_of::<Load>()) } as i32;
    require(
        fd >= 0,
        "complete boot kernel device policy load failed; no execution fallback",
    )?;
    // SAFETY: `fd` was just returned by bpf and is owned by nothing else.
    let program = unsafe { File::from_raw_fd(fd) };
    require(
        // SAFETY: F_SETFD takes no pointers and `program` owns the descriptor.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "complete boot device policy descriptor flags",
    )?;
    #[repr(C)]
    struct Attach {
        target: u32,
        program: u32,
        kind: u32,
        flags: u32,
        replace: u32,
    }
    let attach = Attach {
        target: group.as_raw_fd() as u32,
        program: fd as u32,
        kind: 6,
        flags: 0,
        replace: 0,
    };
    require(
        // SAFETY: `attach` is a repr(C) bpf_attr prefix passed with its exact size.
        unsafe { libc::syscall(libc::SYS_bpf, 8, &attach, std::mem::size_of::<Attach>()) } == 0,
        "complete boot kernel device policy attach failed; no execution fallback",
    )?;
    Ok(program)
}
