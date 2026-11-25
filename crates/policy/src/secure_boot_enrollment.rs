// SPDX-License-Identifier: MIT
//! One append-only Setup Mode attempt, retaining credentials, namespace and db.
//! Durable JSON records the attempt; it cannot reconstruct execution authority.
use super::Owner;
use crate::{operation, secure_boot, storage_runtime, transition_idle};
use enzimos_platform::{
    Error, Result, files, json, mount_identity, mountinfo, publication, require,
};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

const X509: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
const OWNER: [u8; 16] = [
    0x97, 0xe4, 0xa5, 0x26, 0x29, 0x29, 0xc1, 0x4a, 0xa6, 0xb9, 0xf7, 0xc4, 0x93, 0x86, 0x97, 0xc4,
];
const PKCS7: [u8; 16] = [
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
];
const IMMUTABLE: libc::c_long = 0x10;

fn signature_list(der: &[u8]) -> Result<Vec<u8>> {
    require(
        !der.is_empty() && der.len() <= 16384,
        "owner certificate bound",
    )?;
    let mut bytes = X509.to_vec();
    for n in [(44 + der.len()) as u32, 0, (16 + der.len()) as u32] {
        bytes.extend(n.to_le_bytes());
    }
    bytes.extend(OWNER);
    bytes.extend(der);
    Ok(bytes)
}
fn append_packet(esl: &[u8], time: &libc::tm) -> Result<Vec<u8>> {
    let year = time
        .tm_year
        .checked_add(1900)
        .ok_or_else(|| Error("EFI time overflow".into()))?;
    require(
        (1900..=9999).contains(&year)
            && (0..12).contains(&time.tm_mon)
            && (1..=31).contains(&time.tm_mday)
            && (0..24).contains(&time.tm_hour)
            && (0..60).contains(&time.tm_min)
            && (0..60).contains(&time.tm_sec),
        "EFI append timestamp",
    )?;
    // NV|BS|RT|TIME_BASED_AUTH|APPEND. Empty PKCS7 authentication is valid
    // only in Setup Mode. Firmware removes this envelope from the stored db.
    let mut bytes = 0x67u32.to_le_bytes().to_vec();
    bytes.extend((year as u16).to_le_bytes());
    bytes.extend([
        time.tm_mon as u8 + 1,
        time.tm_mday as u8,
        time.tm_hour as u8,
        time.tm_min as u8,
        time.tm_sec as u8,
        0,
    ]);
    bytes.extend([0; 8]); // Nanoseconds, timezone, daylight, padding.
    bytes.extend(24u32.to_le_bytes());
    bytes.extend(0x0200u16.to_le_bytes());
    bytes.extend(0x0ef1u16.to_le_bytes());
    bytes.extend(PKCS7);
    bytes.extend(esl);
    Ok(bytes)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (gmtime_r, time).")]
fn now() -> Result<libc::tm> {
    let time = unsafe { libc::time(std::ptr::null_mut()) };
    let mut utc = unsafe { std::mem::zeroed() };
    require(
        time >= 0 && !unsafe { libc::gmtime_r(&time, &mut utc) }.is_null(),
        "EFI timestamp unavailable",
    )?;
    Ok(utc)
}
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(flags >= 0, "EFI description flags unavailable")?;
    Ok(flags)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn inode_flags(file: &File) -> Result<libc::c_long> {
    let mut value: libc::c_long = 0;
    require(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x80086601u64 as libc::c_ulong, &mut value) } == 0,
        "EFI inode flags unavailable",
    )?;
    Ok(value)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn set_inode_flags(file: &File, before: libc::c_long, after: libc::c_long) -> Result<()> {
    require(inode_flags(file)? == before, "EFI inode flags changed")?;
    require(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x40086602u64 as libc::c_ulong, &after) } == 0,
        "EFI inode flag update refused",
    )?;
    require(
        inode_flags(file)? == after,
        "EFI inode flag update uncertain",
    )
}
struct Member {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
}
impl Member {
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn open(parent: &File, name: &str, mount: u64) -> Result<Self> {
        let leaf = CString::new(name).map_err(|_| Error("EFI member basename".into()))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "original EFI member unavailable")?;
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o022 == 0
                && m.nlink() == 1
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original protected EFI member required",
        )?;
        let epoch = files::identity(&m);
        let flags = flags(&file)?;
        Ok(Self { file, epoch, flags })
    }
    fn recheck(&self, parent: &File, name: &str, mount: u64) -> Result<()> {
        let named = Self::open(parent, name, mount)?;
        require(
            named.epoch == self.epoch
                && files::identity(&self.file.metadata()?) == self.epoch
                && flags(&self.file)? == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == mount,
            "original EFI namespace member changed",
        )
    }
}
fn names() -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(secure_boot::EFI)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error("EFI member encoding".into()))?;
        require(
            names.len() < 4096 && !name.contains('/') && !name.is_empty(),
            "EFI namespace bound",
        )?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}
fn options(text: &str) -> Vec<&str> {
    let mut values = text.split(',').collect::<Vec<_>>();
    values.sort();
    values
}
fn change_access(row: &mountinfo::Row, read_only: bool) -> mountinfo::Row {
    let toggle = |s: &str| {
        let mut v = s
            .split(',')
            .filter(|v| !matches!(*v, "ro" | "rw"))
            .collect::<Vec<_>>();
        v.push(if read_only { "ro" } else { "rw" });
        v.sort();
        v.join(",")
    };
    let mut next = row.clone();
    next.options = toggle(&row.options);
    next.filesystem_options = toggle(&row.filesystem_options);
    next
}
fn equivalent(a: &mountinfo::Row, b: &mountinfo::Row) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.options = options(&a.options).join(",");
    b.options = options(&b.options).join(",");
    a.filesystem_options = options(&a.filesystem_options).join(",");
    b.filesystem_options = options(&b.filesystem_options).join(",");
    a == b
}
struct Firmware {
    directory: File,
    shape: (u64, u64, u32),
    directory_flags: i32,
    mount: u64,
    row: mountinfo::Row,
    members: BTreeMap<String, Member>,
}
impl Firmware {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    fn observe() -> Result<Self> {
        let directory = files::directory(Path::new(secure_boot::EFI), Some(0))?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } == 0
                && fs.f_type == 0xde5e81e4,
            "actual efivarfs required",
        )?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let normal = mount_identity::id(directory.as_fd(), false)?;
        let rows = storage_runtime::rows()?;
        let candidates = rows
            .iter()
            .filter(|r| r.target == secure_boot::EFI)
            .collect::<Vec<_>>();
        require(
            candidates.len() == 1
                && candidates[0].id == normal
                && candidates[0].filesystem == "efivarfs"
                && candidates[0].root == "/"
                && !rows
                    .iter()
                    .any(|r| r.target.starts_with(&format!("{}/", secure_boot::EFI))),
            "original EFI mount missing, shadowed or nested",
        )?;
        let row = candidates[0].clone();
        let m = directory.metadata()?;
        let shape = (m.dev(), m.ino(), m.mode());
        let directory_flags = flags(&directory)?;
        let mut members = BTreeMap::new();
        for name in names()? {
            members.insert(name.clone(), Member::open(&directory, &name, mount)?);
        }
        let this = Self {
            directory,
            shape,
            directory_flags,
            mount,
            row,
            members,
        };
        this.recheck(None)?;
        Ok(this)
    }
    fn recheck_mount(&self) -> Result<()> {
        crate::namespaces::initial()?;
        let named = files::directory(Path::new(secure_boot::EFI), Some(0))?;
        for directory in [&self.directory, &named] {
            let m = directory.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode()) == self.shape
                    && mount_identity::id(directory.as_fd(), true)? == self.mount,
                "original EFI directory replaced or covered",
            )?;
        }
        require(
            flags(&self.directory)? == self.directory_flags,
            "EFI directory status changed",
        )?;
        let rows = storage_runtime::rows()?;
        let candidates = rows
            .iter()
            .filter(|r| r.target == secure_boot::EFI)
            .collect::<Vec<_>>();
        require(
            candidates.len() == 1
                && equivalent(candidates[0], &self.row)
                && !rows
                    .iter()
                    .any(|r| r.target.starts_with(&format!("{}/", secure_boot::EFI))),
            "EFI mount changed outside owned remount",
        )?;
        Ok(())
    }
    fn recheck(&self, db: Option<&Member>) -> Result<()> {
        self.recheck_mount()?;
        let mut expected = self.members.keys().cloned().collect::<Vec<_>>();
        if db.is_some() && !self.members.contains_key(secure_boot::DB) {
            expected.push(secure_boot::DB.into());
            expected.sort();
        }
        require(
            names()? == expected,
            "EFI namespace changed outside owned db operation",
        )?;
        for (name, member) in &self.members {
            if name == secure_boot::DB
                && let Some(db) = db
            {
                db.recheck(&self.directory, name, self.mount)?;
                continue;
            }
            member.recheck(&self.directory, name, self.mount)?;
        }
        if let Some(db) = db {
            db.recheck(&self.directory, secure_boot::DB, self.mount)?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn remount(&mut self, read_only: bool, db: Option<&Member>) -> Result<()> {
        if read_only {
            self.recheck_mount()?;
        } else {
            self.recheck(db)?;
        }
        let mut mask = libc::MS_REMOUNT;
        for (option, flag) in [
            ("nosuid", libc::MS_NOSUID),
            ("nodev", libc::MS_NODEV),
            ("noexec", libc::MS_NOEXEC),
            ("noatime", libc::MS_NOATIME),
            ("nodiratime", libc::MS_NODIRATIME),
            ("relatime", libc::MS_RELATIME),
            ("strictatime", libc::MS_STRICTATIME),
            ("sync", libc::MS_SYNCHRONOUS),
            ("dirsync", libc::MS_DIRSYNC),
            ("lazytime", libc::MS_LAZYTIME),
        ] {
            if self.row.options.split(',').any(|s| s == option) {
                mask |= flag;
            }
        }
        if read_only {
            mask |= libc::MS_RDONLY;
        }
        let target = CString::new(format!("/proc/self/fd/{}", self.directory.as_raw_fd())).unwrap();
        require(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    target.as_ptr(),
                    std::ptr::null(),
                    mask,
                    std::ptr::null(),
                )
            } == 0,
            "owned EFI remount refused",
        )?;
        self.row = change_access(&self.row, read_only);
        self.recheck_mount()
    }
}

/// No arbitrary variable selector and no cold receipt replay. Only this live
/// producer can advance its original prepared record after a known append.
#[allow(unsafe_code, reason = "Linux syscall ABI (openat, write).")]
pub fn enroll_locked(lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    let idle = transition_idle::Snapshot::online()?;
    let owner = Owner::credentials()?;
    let state = secure_boot::firmware()?;
    require(
        state["uefi"] == true && state["setup_mode"] == true && state["enabled"] == false,
        "Setup Mode required for owner certificate append",
    )?;
    let der = &owner
        .material()
        .ok_or_else(|| Error("owner certificate absent".into()))?
        .der;
    let esl = signature_list(der)?;
    let packet = append_packet(&esl, &now()?)?;
    let mut firmware = Firmware::observe()?;
    require(
        files::optional_relative(
            &owner.directory.as_ref().unwrap().0,
            Path::new("enrollment-attempt.json"),
        )?
        .is_none(),
        "existing enrollment attempt requires review; no replay",
    )?;
    let original = files::optional_relative(&firmware.directory, Path::new(secure_boot::DB))?;
    let reader_flags = original.as_ref().map(flags).transpose()?;
    if let Some(file) = &original {
        require(
            reader_flags.unwrap() & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY,
            "original EFI db reader role",
        )?;
        require_reader(
            file,
            reader_flags.unwrap(),
            &firmware.members[secure_boot::DB],
            firmware.mount,
        )?;
    }
    let before = original
        .as_ref()
        .map(|file| files::read_file(file, 1024 * 1024, Some(0), false))
        .transpose()?;
    if let Some(bytes) = &before {
        require(
            bytes.len() >= 4
                && matches!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), 7 | 0x27),
            "unsupported original EFI db attributes",
        )?;
        if secure_boot::db_contains(bytes, der)? {
            owner.recheck()?;
            firmware.recheck(None)?;
            idle.recheck()?;
            lock.recheck()?;
            return Ok(result());
        }
    }
    let authorize = &mut || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        idle.recheck()?;
        owner.recheck_credentials()
    };
    authorize()?;
    owner.recheck()?;
    firmware.recheck(None)?;
    let path = Path::new(secure_boot::DIRECTORY).join("enrollment-attempt.json");
    let mut record = value!({"schema":1,"phase":"prepared","certificate_sha256":json::sha256(der),"original_db_sha256":before.as_ref().map(|b|json::sha256(b)),"append_only":true});
    let committed =
        publication::Prepared::write_authorized(&path, &json::canonical(&record)?, 0, authorize)?
            .commit_retained_authorized(false, authorize)?;
    let mut receipt = publication::Chain::new(committed)?;
    let read_only = firmware.row.options.split(',').any(|s| s == "ro");
    let original_flags = original.as_ref().map(inode_flags).transpose()?;
    if read_only {
        firmware.remount(false, None)?;
    }
    let mut changed = false;
    let mut after: Option<Member> = None;
    let attempt = (|| -> Result<()> {
        authorize()?;
        receipt.recheck()?;
        firmware.recheck(None)?;
        if let (Some(file), Some(flags)) = (&original, original_flags)
            && flags & IMMUTABLE != 0
        {
            set_inode_flags(file, flags, flags & !IMMUTABLE)?;
            changed = true;
            let new = Member::open(&firmware.directory, secure_boot::DB, firmware.mount)?;
            require(
                flag_transition(firmware.members[secure_boot::DB].epoch, new.epoch),
                "EFI db replaced while clearing immutable",
            )?;
            firmware.members.insert(secure_boot::DB.into(), new);
        }
        firmware.recheck(None)?;
        if let Some(file) = &original {
            require_reader(
                file,
                reader_flags.unwrap(),
                &firmware.members[secure_boot::DB],
                firmware.mount,
            )?;
        }
        authorize()?;
        receipt.recheck()?;
        let leaf = CString::new(secure_boot::DB).unwrap();
        let open_flags = libc::O_WRONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if original.is_none() {
                libc::O_CREAT | libc::O_EXCL
            } else {
                0
            };
        let fd = unsafe {
            libc::openat(
                firmware.directory.as_raw_fd(),
                leaf.as_ptr(),
                open_flags,
                0o644,
            )
        };
        require(fd >= 0, "original EFI db append descriptor unavailable")?;
        let writer = unsafe { File::from_raw_fd(fd) };
        if let Some(original) = &original {
            require(
                files::identity(&writer.metadata()?) == files::identity(&original.metadata()?),
                "EFI db append target replaced",
            )?;
        }
        require(
            mount_identity::id(writer.as_fd(), true)? == firmware.mount,
            "EFI append crosses mount",
        )?;
        after = Some(Member::open(
            &firmware.directory,
            secure_boot::DB,
            firmware.mount,
        )?);
        firmware.recheck(after.as_ref())?;
        if let Some(file) = &original {
            require_reader(
                file,
                reader_flags.unwrap(),
                after.as_ref().unwrap(),
                firmware.mount,
            )?;
        }
        require(
            flags(&writer)? & (libc::O_ACCMODE | libc::O_NONBLOCK | libc::O_APPEND)
                == libc::O_WRONLY,
            "EFI append writer role changed",
        )?;
        authorize()?;
        receipt.recheck()?;
        // A single kernel write; EINTR, partial or failed writes are uncertain.
        let written =
            unsafe { libc::write(writer.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        drop(writer);
        after = Some(Member::open(
            &firmware.directory,
            secure_boot::DB,
            firmware.mount,
        )?);
        require(
            written == packet.len() as isize,
            "EFI append outcome uncertain; do not replay",
        )?;
        if let Some(original) = &original {
            let m = original.metadata()?;
            require(
                (m.dev(), m.ino())
                    == (
                        after.as_ref().unwrap().epoch.0,
                        after.as_ref().unwrap().epoch.1,
                    ),
                "EFI db replaced across append",
            )?;
        }
        let file = files::open_relative(&firmware.directory, Path::new(secure_boot::DB))?;
        let body = files::read_file(&file, 1024 * 1024, Some(0), false)?;
        let mut expected = 0x27u32.to_le_bytes().to_vec();
        if let Some(before) = &before {
            expected.extend(&before[4..]);
        }
        expected.extend(&esl);
        require(
            body == expected && secure_boot::db_contains(&body, der)?,
            "EFI db append readback differs; review required",
        )?;
        firmware.recheck(after.as_ref())?;
        authorize()
    })();
    // Restore the owned immutable bit and readonly mount on every body outcome.
    // Cleanup uses retained object identity, never a fresh path as authority.
    let restore_inode = (|| -> Result<()> {
        if changed {
            let file = original.as_ref().unwrap();
            let named = Member::open(&firmware.directory, secure_boot::DB, firmware.mount)?;
            let m = file.metadata()?;
            require(
                (m.dev(), m.ino()) == (named.epoch.0, named.epoch.1),
                "EFI cleanup target replaced",
            )?;
            set_inode_flags(
                file,
                original_flags.unwrap() & !IMMUTABLE,
                original_flags.unwrap(),
            )?;
            let restored = Member::open(&firmware.directory, secure_boot::DB, firmware.mount)?;
            if after.is_some() {
                after = Some(restored);
            } else {
                firmware.members.insert(secure_boot::DB.into(), restored);
            }
        }
        Ok(())
    })();
    let restore_mount = if read_only {
        firmware.remount(true, after.as_ref())
    } else {
        firmware.recheck_mount()
    };
    restore_mount?;
    restore_inode?;
    firmware.recheck(after.as_ref())?;
    attempt?;

    authorize()?;
    firmware.recheck(after.as_ref())?;
    if let Some(file) = &original {
        require_reader(
            file,
            reader_flags.unwrap(),
            after.as_ref().unwrap(),
            firmware.mount,
        )?;
    }
    record["phase"] = value!("complete");
    receipt.replace(&json::canonical(&record)?, authorize)?;
    receipt.recheck()?;
    firmware.recheck(after.as_ref())?;
    authorize()?;
    Ok(result())
}
fn flag_transition(mut before: files::FileIdentity, mut after: files::FileIdentity) -> bool {
    // FS_IOC_SETFLAGS may update ctime; size/content/protection identities cannot change.
    before.5 = 0;
    before.6 = 0;
    after.5 = 0;
    after.6 = 0;
    before == after
}
fn require_reader(file: &File, expected_flags: i32, member: &Member, mount: u64) -> Result<()> {
    require(
        flags(file)? == expected_flags
            && files::identity(&file.metadata()?) == member.epoch
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original EFI db reader changed or replaced",
    )
}
fn result() -> Value {
    value!({"status":"owner-certificate-appended","platform_key_changed":false,"key_exchange_keys_changed":false})
}
/// Whether a prepared enrollment provably never reached firmware: the db still
/// holds exactly the bytes observed before the append (or is still absent).
/// Anything else may be the append itself and is past the point of no return.
fn never_appended(record: &Value, current: Option<&[u8]>) -> bool {
    record["phase"] == "prepared"
        && record["append_only"] == true
        && record["original_db_sha256"] == value!(current.map(json::sha256))
}
/// Abandon an unfinished enrollment only when firmware is provably unchanged;
/// a later `enroll-db` may then run again. Returns the enrollment outcome.
pub(crate) fn abandon_unchanged(authorize: &mut dyn FnMut() -> Result<()>) -> Result<&'static str> {
    let Some(owner) = files::optional_directory_relative(
        &files::directory(Path::new(crate::operation::CONTROL), Some(0))?,
        Path::new("secure-boot"),
        Some(0),
    )?
    else {
        return Ok("none");
    };
    let Some(attempt) = files::optional_relative(&owner, Path::new("enrollment-attempt.json"))?
    else {
        return Ok("none");
    };
    let record = json::decode(&files::read_file(&attempt, 4096, Some(0), true)?, 4096)?;
    if record["phase"] == "complete" {
        return Ok("complete");
    }
    let current = files::read_optional(
        &Path::new(secure_boot::EFI).join(secure_boot::DB),
        1024 * 1024,
        Some(0),
        false,
    )?;
    if !never_appended(&record, current.as_deref()) {
        return Ok("kept-firmware-may-have-changed");
    }
    secure_boot::abandon_record(
        &owner,
        &attempt,
        "enrollment-attempt.json",
        "enrollment-abandoned.json",
        &record,
        "explicit",
        authorize,
    )?;
    Ok("abandoned")
}
