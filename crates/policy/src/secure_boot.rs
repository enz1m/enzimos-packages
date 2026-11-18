// SPDX-License-Identifier: MIT
//! Explicit owner authority. No automatic firmware enrollment or key replacement.
use crate::operation;
use enzimos_platform::{Error, Result, files, json, require};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509, X509NameBuilder},
};
use serde_json::{Value, json as value};
use std::{
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub const EFI: &str = "/sys/firmware/efi/efivars";
pub const DIRECTORY: &str = "/var/lib/enzimos-control/secure-boot";
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
pub const DB: &str = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
fn crypto<T>(v: std::result::Result<T, openssl::error::ErrorStack>) -> Result<T> {
    // Never attach parsed key bytes or crypto-library diagnostics to API errors.
    v.map_err(|_| Error("owner certificate or key operation refused".into()))
}
pub fn flag(body: &[u8]) -> Result<bool> {
    require(body.len() == 5 && body[4] <= 1, "invalid EFI firmware flag")?;
    Ok(body[4] == 1)
}
pub fn firmware_at(directory: &Path, owner: u32) -> Result<Value> {
    match std::fs::symlink_metadata(directory) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(value!({"uefi":false,"capable":false,"enabled":false,"setup_mode":false}));
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let held = files::directory(directory, Some(owner))?;
    let read = |name: &str| {
        files::read_optional(
            &directory.join(format!("{name}-{GUID}")),
            5,
            Some(owner),
            false,
        )
    };
    let enabled = read("SecureBoot")?;
    let setup = read("SetupMode")?;
    if enabled.is_none() && setup.is_none() {
        return Ok(value!({"uefi":true,"capable":false,"enabled":false,"setup_mode":false}));
    }
    let enabled = flag(&enabled.ok_or_else(|| Error("missing EFI SecureBoot flag".into()))?)?;
    let setup = flag(&setup.ok_or_else(|| Error("missing EFI SetupMode flag".into()))?)?;
    let current = files::directory(directory, Some(owner))?.metadata()?;
    let before = held.metadata()?;
    require(
        (before.dev(), before.ino()) == (current.dev(), current.ino()),
        "firmware directory changed",
    )?;
    Ok(value!({"uefi":true,"capable":true,"enabled":enabled,"setup_mode":setup}))
}
pub fn firmware() -> Result<Value> {
    firmware_at(Path::new(EFI), 0)
}
pub fn db_contains(body: &[u8], certificate: &[u8]) -> Result<bool> {
    require(
        (4..=1024 * 1024).contains(&body.len())
            && !certificate.is_empty()
            && certificate.len() <= 16384,
        "firmware db byte bound",
    )?;
    let wanted = [
        0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0,
        0x72,
    ];
    let mut position = 4usize;
    let mut count = 0;
    let mut found = false;
    while position < body.len() {
        count += 1;
        require(
            count <= 128 && position + 28 <= body.len(),
            "firmware db list bound",
        )?;
        let word = |p| u32::from_le_bytes(body[p..p + 4].try_into().unwrap()) as usize;
        let size = word(position + 16);
        let header = word(position + 20);
        let entry = word(position + 24);
        require(
            size >= 28 + header
                && position.checked_add(size).is_some_and(|p| p <= body.len())
                && entry >= 16
                && (size - 28 - header) % entry == 0,
            "invalid firmware signature list",
        )?;
        if body[position..position + 16] == wanted {
            for p in (position + 28 + header..position + size).step_by(entry) {
                if &body[p + 16..p + entry] == certificate {
                    found = true;
                }
            }
        }
        position += size;
    }
    Ok(found)
}
pub struct Material {
    key: Zeroizing<Vec<u8>>,
    pub pem: Vec<u8>,
    pub der: Vec<u8>,
}
impl Material {
    pub(crate) fn key_file(&self) -> Result<std::fs::File> {
        enzimos_platform::memfile::sealed("enzimos-owner-signing", &self.key)
    }
    pub fn validate(key: Vec<u8>, pem: Vec<u8>, der: Vec<u8>) -> Result<Self> {
        let key = Zeroizing::new(key);
        require(
            !key.is_empty()
                && key.len() <= 16384
                && !pem.is_empty()
                && pem.len() <= 16384
                && !der.is_empty()
                && der.len() <= 16384,
            "owner credential byte bounds",
        )?;
        let certificate = crypto(X509::from_pem(&pem))?;
        let private = crypto(PKey::private_key_from_pem(&key))?;
        let public = crypto(certificate.public_key())?;
        require(
            crypto(certificate.to_der())? == der && public.public_eq(&private),
            "owner key/certificate mismatch",
        )?;
        Ok(Self { key, pem, der })
    }
    pub fn generate() -> Result<Self> {
        let key = crypto(PKey::from_rsa(crypto(Rsa::generate(3072))?))?;
        let mut name = crypto(X509NameBuilder::new())?;
        crypto(name.append_entry_by_text("CN", "enzimOS local owner Secure Boot"))?;
        let name = name.build();
        let mut serial = [0u8; 20];
        crypto(openssl::rand::rand_bytes(&mut serial))?;
        serial[0] &= 0x7f;
        // X.509 serials must be positive and at most 159 bits.
        if serial.iter().all(|b| *b == 0) {
            serial[19] = 1;
        }
        let serial = crypto(crypto(BigNum::from_slice(&serial))?.to_asn1_integer())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error("owner key clock".into()))?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| Error("owner key clock bound".into()))?;
        let start = crypto(Asn1Time::from_unix(now - 300))?;
        let end = crypto(Asn1Time::from_unix(
            now.checked_add(3650 * 86400)
                .ok_or_else(|| Error("certificate expiry overflow".into()))?,
        ))?;
        let mut certificate = crypto(X509::builder())?;
        crypto(certificate.set_version(2))?;
        crypto(certificate.set_serial_number(&serial))?;
        crypto(certificate.set_subject_name(&name))?;
        crypto(certificate.set_issuer_name(&name))?;
        crypto(certificate.set_pubkey(&key))?;
        crypto(certificate.set_not_before(&start))?;
        crypto(certificate.set_not_after(&end))?;
        crypto(certificate.sign(&key, MessageDigest::sha256()))?;
        let certificate = certificate.build();
        let mut private = Zeroizing::new(crypto(key.private_key_to_pem_pkcs8())?);
        let pem = crypto(certificate.to_pem())?;
        let der = crypto(certificate.to_der())?;
        Self::validate(std::mem::take(&mut *private), pem, der)
    }
    pub fn load(directory: &Path, owner: u32) -> Result<Self> {
        let held = files::directory(directory, Some(owner))?;
        let before = held.metadata()?;
        require(
            before.mode() & 0o777 == 0o700,
            "private owner key directory required",
        )?;
        let mut key = read_material(&held, "owner.key", owner, true)?;
        let pem = read_material(&held, "owner.crt", owner, false)?.to_vec();
        let der = read_material(&held, "owner.cer", owner, false)?.to_vec();
        let after = files::directory(directory, Some(owner))?.metadata()?;
        require(
            (before.dev(), before.ino()) == (after.dev(), after.ino()),
            "owner key directory changed",
        )?;
        Self::validate(std::mem::take(&mut *key), pem, der)
    }
    pub fn write_new(&self, directory: &Path, owner: u32) -> Result<()> {
        let held = files::create_directory(directory, 0o700, owner)?;
        // A partial directory is deliberately retained. No second key is created
        // automatically after a crash or interrupted transfer.
        for (name, body, mode) in [
            ("owner.key", self.key.as_slice(), 0o600),
            ("owner.crt", self.pem.as_slice(), 0o644),
            ("owner.cer", self.der.as_slice(), 0o644),
        ] {
            files::atomic(&directory.join(name), body, mode, Some(owner), false)?;
        }
        held.sync_all()?;
        files::directory(
            directory
                .parent()
                .ok_or_else(|| Error("owner key parent".into()))?,
            Some(owner),
        )?
        .sync_all()?;
        Ok(())
    }
}
fn read_material(
    directory: &std::fs::File,
    name: &str,
    owner: u32,
    private: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = files::open_relative(directory, Path::new(name))?;
    let before = file.metadata()?;
    require(
        before.uid() == owner
            && before.nlink() == 1
            && before.len() <= 16384
            && before.mode() & if private { 0o077 } else { 0o022 } == 0,
        "unsafe owner credential file",
    )?;
    let mut body = Zeroizing::new(Vec::new());
    (&mut file).take(16385).read_to_end(&mut body)?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    require(
        body.len() <= 16384
            && body.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?),
        "owner credential changed during read",
    )?;
    Ok(body)
}
pub fn credentials_at(directory: &Path) -> Result<Material> {
    let material = Material::load(directory, 0)?;
    if firmware()?["enabled"] == true {
        let db = files::read(&Path::new(EFI).join(DB), 1024 * 1024, Some(0), false)?;
        require(
            db_contains(&db, &material.der)?,
            "owner certificate is not enrolled in firmware db",
        )?;
    }
    Ok(material)
}
pub fn configured() -> Result<bool> {
    configured_at(
        &files::directory(Path::new(operation::CONTROL), Some(0))?,
        0,
    )
}
/// Absence is resolved beneath the retained control directory; unsafe containers
/// and incomplete policies remain errors rather than being reported disabled.
pub fn configured_at(control: &std::fs::File, owner: u32) -> Result<bool> {
    use std::os::fd::AsFd;
    let mount = enzimos_platform::mount_identity::id(control.as_fd(), true)?;
    require(
        control.metadata()?.uid() == owner && control.metadata()?.mode() & 0o7777 == 0o700,
        "private owner control directory required",
    )?;
    let Some(container) =
        files::optional_directory_relative(control, Path::new("secure-boot"), Some(owner))?
    else {
        return Ok(false);
    };
    require(
        container.metadata()?.is_dir()
            && container.metadata()?.uid() == owner
            && container.metadata()?.mode() & 0o7777 == 0o700
            && enzimos_platform::mount_identity::id(container.as_fd(), true)? == mount,
        "unsafe or independently mounted owner policy directory",
    )?;
    let original = files::identity(&container.metadata()?);
    let configured = match files::optional_relative(&container, Path::new("config.json"))? {
        None => false,
        Some(file) => {
            require(
                enzimos_platform::mount_identity::id(file.as_fd(), true)? == mount,
                "owner policy file crosses another mount",
            )?;
            let before = files::identity(&file.metadata()?);
            require(
                json::decode(&files::read_file(&file, 4096, Some(owner), true)?, 4096)?
                    == value!({"schema":1,"mode":"owner-uki"}),
                "unsupported Secure Boot policy",
            )?;
            require(
                files::identity(
                    &files::open_relative(&container, Path::new("config.json"))?.metadata()?,
                ) == before,
                "owner policy replaced during observation",
            )?;
            true
        }
    };
    require(
        files::identity(&container.metadata()?) == original
            && files::identity(
                &files::directory_relative(control, Path::new("secure-boot"), Some(owner))?
                    .metadata()?,
            ) == original,
        "original owner policy directory replaced during observation",
    )?;
    Ok(configured)
}
pub fn create_key() -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    require(firmware()?["uefi"] == true, "UEFI required")?;
    let _lock = operation::lock()?;
    require(
        std::fs::symlink_metadata(DIRECTORY)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "owner key already exists or cannot be observed",
    )?;
    Material::generate()?.write_new(Path::new(DIRECTORY), 0)?;
    Ok(
        value!({"status":"owner-key-created","firmware_changed":false,"certificate":format!("{DIRECTORY}/owner.cer")}),
    )
}
pub fn installer_preflight(encrypted: bool) -> Result<bool> {
    operation::root_only()?;
    if firmware()?["enabled"] != true {
        return Ok(false);
    }
    require(
        encrypted,
        "Secure Boot signing credentials require encrypted installation",
    )?;
    credentials_at(Path::new("/run/enzimos-owner-key"))?;
    Ok(true)
}
pub fn install_owner_credentials(target: &Path) -> Result<()> {
    operation::root_only()?;
    require(
        target == Path::new("/mnt/enzimos"),
        "fixed installer target required",
    )?;
    let material = credentials_at(Path::new("/run/enzimos-owner-key"))?;
    material.write_new(&target.join("var/lib/enzimos-control/secure-boot"), 0)
}
pub fn source_path(value: &str) -> Result<PathBuf> {
    require(
        value.starts_with('/')
            && !value.contains("..")
            && value.len() <= 4096
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"/_.+-".contains(&c)),
        "invalid UKI source path",
    )?;
    Ok(Path::new("/boot").join(value.trim_start_matches('/')))
}
/// End one unfinished owner attempt record (`name` in the owner directory) as
/// abandoned: publish the terminal `abandoned` record first, then unlink the
/// attempt only while its name still holds the inode that was read. An
/// interruption leaves the attempt in place, so abandoning again completes it.
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
pub(crate) fn abandon_record(
    owner: &std::fs::File,
    attempt: &std::fs::File,
    name: &str,
    abandoned: &str,
    original: &Value,
    reason: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let epoch = files::identity(&attempt.metadata()?);
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error("abandonment clock".into()))?
        .as_secs();
    let body = json::canonical(
        &value!({"schema":1,"phase":"abandoned","reason":reason,"abandoned_unix":at,"attempt":original}),
    )?;
    enzimos_platform::publication::Prepared::write_authorized(
        &Path::new(DIRECTORY).join(abandoned),
        &body,
        0,
        authorize,
    )?
    .commit_retained_authorized(true, authorize)?;
    authorize()?;
    let named = files::open_relative(owner, Path::new(name))?;
    require(
        files::identity(&named.metadata()?) == epoch
            && files::identity(&attempt.metadata()?) == epoch,
        "owner attempt changed during abandonment",
    )?;
    let leaf = std::ffi::CString::new(name).map_err(|_| Error("owner attempt name".into()))?;
    require(
        unsafe { libc::unlinkat(std::os::fd::AsRawFd::as_raw_fd(owner), leaf.as_ptr(), 0) } == 0,
        "owner attempt retirement failed",
    )?;
    owner.sync_all()?;
    Ok(())
}
