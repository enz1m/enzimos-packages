// SPDX-License-Identifier: MIT
//! Recovery password export to its approved owner, and that owner's separate
//! statement that a copy was saved elsewhere (never proof of possession).
//!
//! Export writes a `prepared` record with a fresh ticket, authenticates the
//! stored Root credential against the mounted repository (its current key ID,
//! never the password), hands the caller a sealed private RAM copy and only
//! then completes the record with `descriptor_scope_closed`. Confirmation is a
//! later, separately approved call naming that ticket. A new export supersedes
//! the previous ticket, so a later copy must be confirmed again before
//! automatic backups admit it ([`crate::backup_recovery_confirmation`]).
use super::{Image, Runtime};
use crate::{
    backup_admission::{Document, Repository, StoredPin},
    backup_configuration::Configuration,
    backup_credential::Credential,
    backup_destination::Destination,
    backup_remote_context::Context as Remote,
    backup_repository_header::Header,
    operation,
    storage_runtime::Guard,
};
use enzimos_platform::{
    Error, Result, files, json,
    local_restic::{self, CredentialReview},
    require,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub(crate) const ASSERTION: &str = "saved-outside-this-computer";
const EXPORT: &str = "backup-recovery-export.json";
const CONFIRMATION: &str = "backup-recovery-confirmation.json";
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
fn owner(uid: u32) -> Result<()> {
    require(
        (1000..i32::MAX as u32).contains(&uid),
        "recovery copy owner must be an ordinary account",
    )
}
/// The public, non-secret binding both records name (same as status reads).
pub(crate) fn binding(
    configuration: &Configuration,
    pin: &StoredPin<'_>,
    credential: &Credential,
    guard: &Guard,
) -> Result<Value> {
    Ok(
        value!({"destination_uuid":configuration.value()["destination_uuid"],
        "configuration_sha256":json::sha256(configuration.public_bytes()?),
        "destination_pin_sha256":json::sha256(pin.public_bytes()?),
        "credential_identity":credential.binding(guard)?}),
    )
}
fn prepared(uid: u32, ticket: &str, binding: &Value) -> Result<Value> {
    owner(uid)?;
    crate::identity::sha(ticket)?;
    Ok(
        value!({"schema":1,"phase":"prepared","owner_uid":uid,"ticket":ticket,"binding":binding,
        "repository_key_id":null,"descriptor_scope_closed":false}),
    )
}
/// The completed export: only after the caller's sealed copy exists and every
/// owned mount and credential handle closed.
fn completed(prepared: &Value, key: &str) -> Result<Value> {
    require(
        prepared["phase"] == "prepared",
        "recovery export not prepared",
    )?;
    crate::identity::sha(key)?;
    let mut value = prepared.clone();
    value["phase"] = value!("complete");
    value["repository_key_id"] = value!(key);
    value["descriptor_scope_closed"] = value!(true);
    Ok(value)
}
/// The owner's statement for exactly the completed export it names.
fn confirmed(
    exported: &Value,
    uid: u32,
    ticket: &str,
    assertion: &str,
    binding: &Value,
) -> Result<Value> {
    owner(uid)?;
    crate::identity::sha(ticket)?;
    require(assertion == ASSERTION, "recovery copy assertion required")?;
    require(
        exported["schema"] == 1
            && exported["phase"] == "complete"
            && exported["descriptor_scope_closed"] == true
            && exported["owner_uid"] == uid
            && exported["ticket"] == ticket
            && exported["binding"] == *binding,
        "recovery copy needs a fresh export; no automatic replay",
    )?;
    crate::identity::sha(exported["repository_key_id"].as_str().unwrap_or(""))?;
    Ok(
        value!({"schema":1,"phase":"complete","owner_uid":uid,"ticket":ticket,"binding":binding,
        "repository_key_id":exported["repository_key_id"],"user_attested_independent_copy":true,
        "physical_copy_verified":false}),
    )
}
fn read(name: &str) -> Result<Option<Value>> {
    Document::optional(&Path::new(operation::CONTROL).join(name), 0)?
        .map(|document| json::decode(document.bytes()?, crate::backup_configuration::LIMIT))
        .transpose()
}
fn write(name: &str, value: &Value) -> Result<()> {
    files::atomic_bounded(
        &Path::new(operation::CONTROL).join(name),
        &json::canonical(value)?,
        0o600,
        Some(0),
        true,
        crate::backup_configuration::LIMIT,
    )
}
/// A sealed, unlinked private RAM copy of `source` owned by `uid`, the exact
/// shape the `backup-recovery save|print` helpers accept. Copied by the
/// kernel; the source offset is not moved.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, fchown, fcntl, lseek and others)."
)]
pub(crate) fn sealed_copy(source: BorrowedFd<'_>, uid: u32) -> Result<File> {
    let length = File::from(source.try_clone_to_owned()?).metadata()?.len();
    require((1..=4096).contains(&length), "recovery credential bound")?;
    // SAFETY: The name is a NUL-terminated literal.
    let fd = unsafe {
        libc::memfd_create(
            c"enzimos-backup-recovery".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    require(fd >= 0, "recovery copy creation failed")?;
    // SAFETY: `fd` was just returned by memfd_create and is owned by nothing else.
    let output = unsafe { File::from_raw_fd(fd) };
    require(
        // SAFETY: fchmod takes no pointers and `fd` is the open memfd.
        unsafe { libc::fchmod(fd, 0o600) } == 0,
        "recovery copy permissions",
    )?;
    let mut offset: libc::off_t = 0;
    let mut interrupted = 0;
    while (offset as u64) < length {
        // SAFETY: `offset` is a writable off_t and both descriptors stay open.
        let count = unsafe {
            libc::sendfile(
                fd,
                source.as_raw_fd(),
                &mut offset,
                (length - offset as u64) as usize,
            )
        };
        if count < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            && interrupted < 16
        {
            interrupted += 1;
            continue;
        }
        require(
            count > 0 && offset as u64 <= length,
            "recovery copy incomplete",
        )?;
    }
    require(
        // SAFETY: fchown takes no pointers and `fd` is the open memfd.
        unsafe { libc::fchown(fd, uid, u32::MAX) } == 0
            // SAFETY: F_ADD_SEALS takes no pointers and `fd` is the open memfd.
            && unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } == 0
            // SAFETY: lseek takes no pointers and `fd` is the open memfd.
            && unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == 0,
        "recovery copy ownership/sealing failed",
    )?;
    let m = output.metadata()?;
    require(
        m.uid() == uid
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 0
            && m.len() == length
            // SAFETY: F_GET_SEALS takes no pointers and `fd` is the open memfd.
            && unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & SEALS == SEALS,
        "recovery copy shape",
    )?;
    Ok(output)
}
/// The current repository key the stored Root credential opens. The configured
/// destination must be mounted at its fixed path (borrowed or owned by the
/// caller); nothing in the repository changes.
fn current_key(guard: &Guard, authorize: &mut dyn FnMut() -> Result<()>) -> Result<String> {
    let config = Configuration::open()?;
    let destination = Destination::open(&config, guard)?;
    let pin = Repository::open(&destination)?;
    let credential = Credential::open()?;
    let image = Image::open()?;
    let repository = File::from(destination.repository_descriptor()?.try_clone_to_owned()?);
    let password = File::from(credential.descriptor()?.try_clone_to_owned()?);
    let header = Header::observe(&repository)?;
    let mut source = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        config.recheck()?;
        destination.recheck()?;
        pin.recheck()?;
        credential.recheck()?;
        header.recheck(&repository)?;
        image.evidence()?;
        Ok(())
    };
    let runtime = Runtime::create(&files::random_hex(16)?, &mut source)?;
    require(
        runtime.image_evidence()? == image.evidence()?,
        "recovery export vendor image changed",
    )?;
    runtime.empty()?;
    let output = local_restic::credential_review(
        CredentialReview::Keys,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || {
            source()?;
            runtime.recheck()
        },
    )?;
    source()?;
    runtime.empty()?;
    let keys = crate::backup_restic_result::keys(output.status.code(), &output.stdout)?;
    Ok(keys
        .into_iter()
        .find(|(_, current)| *current)
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
        .0)
}
/// Runs its body with the configured destination mounted at its fixed path.
pub(crate) type Mounted<'a> = dyn FnMut(&mut dyn FnMut() -> Result<String>) -> Result<String> + 'a;
/// Export under the held operation lock. Returns the public result and the
/// sealed copy for `uid`.
///
/// # Errors
///
/// Fails when the binding changed, `authorize` fails, or the export cannot be delivered.
pub fn export_locked(
    guard: &Guard,
    lock: &files::Lock,
    uid: u32,
    mounted: &mut Mounted<'_>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<(Value, File)> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    owner(uid)?;
    authorize()?;
    lock.recheck()?;
    if share_primary() {
        return export_share_locked(guard, lock, uid, authorize);
    }
    let configuration = Configuration::open()?;
    let pin = StoredPin::open(&configuration, guard)?;
    let credential = Credential::open()?;
    let check = || {
        authorize()?;
        lock.recheck()?;
        guard.recheck()?;
        pin.recheck()?;
        credential.recheck()
    };
    let bound = binding(&configuration, &pin, &credential, guard)?;
    let record = prepared(uid, &files::random_hex(32)?, &bound)?;
    check()?;
    write(EXPORT, &record)?;
    let key = mounted(&mut || current_key(guard, &mut || check()))?;
    check()?;
    let copy = sealed_copy(credential.descriptor()?, uid)?;
    require(
        binding(&configuration, &pin, &credential, guard)? == bound
            && read(EXPORT)?.as_ref() == Some(&record),
        "recovery export binding changed; no delivery",
    )?;
    let done = completed(&record, &key)?;
    check()?;
    write(EXPORT, &done)?;
    Ok((
        value!({"schema":1,"status":"backup-recovery-exported","ticket":done["ticket"],
        "destination_uuid":bound["destination_uuid"],"sealed_descriptor":true,
        "automatic_backup_enabled":false,"physical_copy_verified":false}),
        copy,
    ))
}
/// Record the owner's statement for the export it names, under the held lock.
/// Repeating the same confirmation returns it unchanged.
///
/// # Errors
///
/// Fails when the export is missing, the ticket or assertion is invalid, or the binding changed.
pub fn confirm_locked(
    guard: &Guard,
    lock: &files::Lock,
    uid: u32,
    ticket: &str,
    assertion: &str,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    lock.recheck()?;
    if share_primary() {
        let remote = Remote::observe(guard, lock, &mut || authorize())?;
        let bound = share_binding(&remote)?;
        let exported = read(EXPORT)?.ok_or_else(|| Error("recovery export missing".into()))?;
        let record = confirmed(&exported, uid, ticket, assertion, &bound)?;
        if read(CONFIRMATION)?.as_ref() != Some(&record) {
            authorize()?;
            lock.recheck()?;
            write(CONFIRMATION, &record)?;
        }
        require(
            share_binding(&remote)? == bound,
            "recovery copy binding changed",
        )?;
        return Ok(attested(ticket));
    }
    let configuration = Configuration::open()?;
    let pin = StoredPin::open(&configuration, guard)?;
    let credential = Credential::open()?;
    let bound = binding(&configuration, &pin, &credential, guard)?;
    let exported = read(EXPORT)?.ok_or_else(|| Error("recovery export missing".into()))?;
    let record = confirmed(&exported, uid, ticket, assertion, &bound)?;
    if read(CONFIRMATION)?.as_ref() != Some(&record) {
        authorize()?;
        lock.recheck()?;
        pin.recheck()?;
        credential.recheck()?;
        write(CONFIRMATION, &record)?;
    }
    require(
        binding(&configuration, &pin, &credential, guard)? == bound,
        "recovery copy binding changed",
    )?;
    Ok(attested(ticket))
}
fn attested(ticket: &str) -> Value {
    value!({"schema":1,"status":"backup-recovery-copy-attested","ticket":ticket,
        "user_attested_independent_copy":true,"physical_copy_verified":false,
        "automatic_backup_enabled":false})
}
fn share_primary() -> bool {
    crate::backup_share_destination::primary() == Some(crate::backup_share_destination::SHARE)
}
/// The binding of a setup without a backup drive, whose recovery password is
/// the NAS share repository password: the share configuration, the share pin
/// and that password file's metadata (never its bytes).
fn share_binding(remote: &Remote<'_>) -> Result<Value> {
    let evidence = remote.evidence(&mut || Ok(()))?;
    share_binding_of(&evidence["inputs"]["binding"], &evidence["pin"])
}
/// The same binding from the share inputs' public binding and the share pin.
pub(crate) fn share_binding_of(binding: &Value, pin: &Value) -> Result<Value> {
    let e = &binding["credentials"]["/etc/enzimos/backup-remote.password"];
    Ok(
        value!({"destination":"share","configuration_sha256":binding["configuration_sha256"],
        "destination_pin_sha256":json::fingerprint(pin)?,
        "credential_identity":{"dev":e[0],"ino":e[1],"size":e[2],"mtime_ns":e[3],"ctime_ns":e[4]}}),
    )
}
/// The current key of the pinned share repository that the share repository
/// password opens, from an authenticated `key list` over the share.
fn share_key(remote: &Remote<'_>, authorize: &mut dyn FnMut() -> Result<()>) -> Result<String> {
    use enzimos_platform::remote_restic::{self, Task};
    let descriptors = remote.descriptors(authorize)?;
    let share_password = File::from(descriptors["remote-share-password"].try_clone_to_owned()?);
    let credential = File::from(descriptors["remote-password"].try_clone_to_owned()?);
    let image = File::from(descriptors["restic"].try_clone_to_owned()?);
    let runtime = Runtime::create(&files::random_hex(16)?, &mut || remote.recheck(authorize))?;
    require(
        runtime.image_evidence()? == remote.evidence(authorize)?["restic"],
        "recovery export vendor image changed",
    )?;
    let (attachment, endpoint) =
        super::remote_share(remote.configuration(authorize)?, &share_password)?;
    let read = |task: Task, authorize: &mut dyn FnMut() -> Result<()>| {
        let output = remote_restic::rotation_read(
            &attachment,
            &endpoint,
            task,
            &"0".repeat(64),
            &image,
            &credential,
            &runtime.scratch,
            &mut || {
                remote.recheck(authorize)?;
                runtime.recheck()?;
                attachment.recheck()
            },
        )?;
        runtime.empty()?;
        Ok::<_, Error>(output)
    };
    let identity = read(Task::RemoteIdentity, authorize)?;
    remote.compare_identity_data(
        &crate::backup_remote_observation::identity_data(
            identity.status.code(),
            &identity.stdout,
            &remote.evidence(authorize)?["pin"],
        )?,
        authorize,
    )?;
    let output = read(Task::RemoteKeys, authorize)?;
    let keys = crate::backup_restic_result::keys(output.status.code(), &output.stdout)?;
    keys.into_iter()
        .find(|(_, current)| *current)
        .map(|(key, _)| key)
        .ok_or_else(|| Error("current share repository key unavailable".into()))
}
/// Export the share repository password of a setup without a backup drive;
/// the share must answer, since the password is checked against it.
fn export_share_locked(
    guard: &Guard,
    lock: &files::Lock,
    uid: u32,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<(Value, File)> {
    let remote = Remote::observe(guard, lock, &mut || authorize())?;
    let bound = share_binding(&remote)?;
    let record = prepared(uid, &files::random_hex(32)?, &bound)?;
    authorize()?;
    write(EXPORT, &record)?;
    let key = share_key(&remote, &mut || authorize())?;
    let copy = sealed_copy(
        remote.descriptors(&mut || authorize())?["remote-password"],
        uid,
    )?;
    require(
        share_binding(&remote)? == bound && read(EXPORT)?.as_ref() == Some(&record),
        "recovery export binding changed; no delivery",
    )?;
    let done = completed(&record, &key)?;
    authorize()?;
    lock.recheck()?;
    write(EXPORT, &done)?;
    Ok((
        value!({"schema":1,"status":"backup-recovery-exported","ticket":done["ticket"],
        "destination_uuid":null,"destination":"share","sealed_descriptor":true,
        "automatic_backup_enabled":false,"physical_copy_verified":false}),
        copy,
    ))
}
