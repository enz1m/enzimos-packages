// SPDX-License-Identifier: MIT
//! Freshly approved delivery enters its original durable grant before creating a child.
use crate::{
    control_record::Retained, delivery_account::Recipient, delivery_export::Export,
    delivery_worker_group::Group, identity, operation, storage_runtime::Guard,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, process_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "restore-delivery-grants";
fn text<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    body[name]
        .as_str()
        .ok_or_else(|| Error("delivery text required".into()))
}
fn selection(body: &Value) -> Result<(&str, &str)> {
    json::fields(body, "id grant_sha256")?;
    Ok((
        identity::safe_id(text(body, "id")?)?,
        identity::sha(text(body, "grant_sha256")?)?,
    ))
}
fn unused(record: &Value, id: &str, digest: &str, boot: &str) -> Result<()> {
    crate::delivery_cancel::validate(record, id)?;
    require(
        record["schema"] == 1
            && record["phase"] == "granted"
            && record["grant_sha256"] == digest
            && record["boot_id"] == boot,
        "delivery grant expired, stale, attempted or unsupported; no replay",
    )
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private delivery grant registry required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
#[expect(
    clippy::large_enum_variant,
    reason = "Built once per operation and rarely moved; boxing would only add an allocation."
)]
enum Storage<'g> {
    Original(Guard),
    Borrowed(&'g Guard),
}
impl std::ops::Deref for Storage<'_> {
    type Target = Guard;
    fn deref(&self) -> &Guard {
        match self {
            Self::Original(guard) => guard,
            Self::Borrowed(guard) => guard,
        }
    }
}
struct Scope<'g> {
    guard: Storage<'g>,
    own: bool,
    filename: String,
    directory: File,
    shape: (u64, u64, u32, u32, u32),
    record: Retained,
    image: crate::delivery_child::Image,
    recipient: Recipient,
    export: Export,
    boot: String,
    id: String,
}
impl Scope<'_> {
    fn open(body: &Value) -> Result<Self> {
        crate::namespaces::initial()?;
        let (id, digest) = selection(body)?;
        let guard = Guard::observe()?;
        let directory = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        let shape = shape(&directory)?;
        let record = Retained::open(
            &directory,
            Path::new(&format!("{id}.json")),
            32768,
            guard.control_mount_id(),
        )?;
        let boot = operation::boot_id()?;
        unused(record.value()?, id, digest, &boot)?;
        let uid = record.value()?["account"]["uid"]
            .as_u64()
            .filter(|n| (1000..i32::MAX as u64).contains(n))
            .ok_or_else(|| Error("ordinary grant recipient required".into()))?
            as u32;
        let recipient = Recipient::open(uid, &guard)?;
        let export = Export::open(&guard, text(&record.value()?["export"], "export")?)?;
        let image = crate::delivery_child::Image::open()?;
        let filename = enzimos_platform::json::string(&record.value()?["filename"])?.to_owned();
        let this = Self {
            guard: Storage::Original(guard),
            own: false,
            filename,
            directory,
            shape,
            record,
            image,
            recipient,
            export,
            boot,
            id: id.into(),
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.image.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.directory)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.directory.as_fd(), true)?
                    == self.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == self.guard.control_mount_id(),
            "original delivery registry replaced or covered",
        )?;
        self.record.recheck()?;
        crate::delivery_cancel::validate(self.record.value()?, &self.id)?;
        require(
            self.record.value()?["schema"] == if self.own { 2 } else { 1 }
                && self.record.value()?["filename"] == self.filename,
            "original delivery role/name changed",
        )?;
        require(
            self.boot == operation::boot_id()?
                && self.record.value()?["boot_id"] == self.boot
                && self.recipient.account(&self.guard)? == self.record.value()?["account"]
                && self.export.binding(&self.guard)? == self.record.value()?["export"],
            "original delivery grant account, export or boot changed",
        )?;
        self.guard.recheck()
    }
    fn view(&self) -> Result<Value> {
        self.recheck()?;
        let view = value!({"grant":self.record.value()?,"record_epoch":self.record.evidence()?,
            "directory":self.shape,"mount":self.guard.control_mount_id(),"boot_id":self.boot,
            "recipient":self.recipient.evidence(&self.guard)?,"export":self.export.evidence(&self.guard)?,
            "worker_image":self.image.evidence()?,"storage":self.guard.configuration});
        self.recheck()?;
        Ok(view)
    }
    fn request(&self, group: &Group) -> Result<Vec<u8>> {
        self.recheck()?;
        let account = self.recipient.account(&self.guard)?;
        let source = self.export.source(&self.guard)?;
        let home = self.recipient.home(&self.guard)?;
        let m = home.metadata()?;
        let pid = std::process::id();
        let stat = files::read_kernel(
            &Path::new("/proc")
                .join(std::process::id().to_string())
                .join("stat"),
            8192,
        )?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&stat)
                .map_err(|_| Error("delivery parent stat encoding".into()))?,
            pid,
        )?;
        let binding = self.export.binding(&self.guard)?;
        let mut request = value!({"schema":if self.own {3} else {2},"role":"exclusive-delivery-copy",
            "id":self.id,"group_nonce":group.nonce()?,"grant_sha256":self.record.value()?["grant_sha256"],
            "recipient":{"uid":account["uid"],"gid":account["gid"]},
            "supervisor":{"pid":pid,"start_ticks":stat.start_ticks,"uid":0},"boot_id":self.boot,
            "home":[m.dev(),m.ino(),m.uid(),m.gid(),m.mode()],"home_mount":mount_identity::id(home.as_fd(),true)?,
            "source":files::identity(&source.metadata()?),"source_mount":mount_identity::id(source.as_fd(),true)?,
            "bytes":binding["bytes"],"sha256":binding["sha256"]});
        if self.own {
            request["filename"] = value!(self.filename);
        }
        let body = json::canonical(&request)?;
        crate::delivery_copy_request::Request::decode(&body)?;
        self.recheck()?;
        Ok(body)
    }
}
/// Original newly published own-file grant and actual recipient/export descriptions.
/// No constructor accepts a receipt value, UID, filename or digest alone.
pub struct Owned<'g> {
    original: Scope<'g>,
}
impl<'g> Owned<'g> {
    pub(crate) fn from_original(
        guard: &'g Guard,
        recipient: Recipient,
        export: Export,
        directory: File,
        record: Retained,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let id = record.value()?["id"]
            .as_str()
            .ok_or_else(|| Error("original own grant ID required".into()))?
            .to_owned();
        let filename = record.value()?["filename"]
            .as_str()
            .ok_or_else(|| Error("original own grant name required".into()))?
            .to_owned();
        let boot = operation::boot_id()?;
        require(
            record.value()?["schema"] == 2
                && record.value()?["phase"] == "granted"
                && record.value()?["boot_id"] == boot,
            "new original own-file grant required",
        )?;
        let original = Scope {
            guard: Storage::Borrowed(guard),
            own: true,
            filename,
            shape: shape(&directory)?,
            directory,
            record,
            recipient,
            export,
            boot,
            id,
            image: crate::delivery_child::Image::open()?,
        };
        original.recheck()?;
        Ok(Self { original })
    }
    /// Run the approved delivery while `lock` is held.
    ///
    /// # Errors
    ///
    /// Fails when the grant changed, `authorize` fails, or the delivery fails.
    pub fn deliver(
        self,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        let expected = self.original.view()?;
        deliver_scope(self.original, &expected, lock, &mut || authorize())
    }
}
/// The delivery observation for request `body`.
///
/// # Errors
///
/// Fails when the request is invalid or the grant cannot be read.
pub fn observation(body: &Value) -> Result<Value> {
    Scope::open(body)?.view()
}
/// Deliver the grant in request `body` if it still matches `expected`.
///
/// # Errors
///
/// Fails when the request or grant changed, `authorize` fails, or the delivery fails.
pub fn deliver<F: FnMut() -> Result<()>>(
    body: &Value,
    expected: &Value,
    authorize: &mut F,
) -> Result<Value> {
    let lock = operation::lock()?;
    deliver_scope(Scope::open(body)?, expected, &lock, authorize)
}
fn deliver_scope<F: FnMut() -> Result<()>>(
    mut scope: Scope<'_>,
    expected: &Value,
    lock: &files::Lock,
    authorize: &mut F,
) -> Result<Value> {
    require(scope.view()? == *expected, "delivery review changed")?;
    authorize()?;
    lock.recheck()?;
    require(
        scope.view()? == *expected,
        "delivery review changed before entry",
    )?;
    let mut entered = scope.record.value()?.clone();
    entered["phase"] = value!("delivering");
    // This original receipt is durable before any cgroup, process or output exists.
    scope.record.replace(&entered)?;
    scope.recheck()?;
    authorize()?;
    lock.recheck()?;
    scope.recheck()?;
    let group = Group::create()?;
    let request = scope.request(&group)?;
    let output = crate::delivery_handoff::copy(
        &scope.image,
        &request,
        scope.export.source(&scope.guard)?,
        scope.recipient.home(&scope.guard)?,
        group,
        &mut || {
            authorize()?;
            lock.recheck()?;
            scope.recheck()?;
            require(
                scope.record.value()? == &entered,
                "original entered delivery intent differs",
            )
        },
    )?;
    // The actual output remains retained through the final original receipt write.
    scope.recheck()?;
    authorize()?;
    lock.recheck()?;
    scope.recheck()?;
    let request = crate::delivery_copy_request::Request::decode(&request)?;
    crate::delivery_handoff::verify_output(&request, scope.recipient.home(&scope.guard)?, &output)?;
    let mut complete = entered;
    complete["phase"] = value!("complete");
    scope.record.replace(&complete)?;
    scope.recheck()?;
    lock.recheck()?;
    require(
        scope.record.value()? == &complete,
        "original delivery completion changed",
    )?;
    let mut result = completion(
        &scope.id,
        request.recipient_uid,
        request.bytes,
        &request.sha256,
    )?;
    result["filename"] = value!(request.filename);
    Ok(result)
}
/// Closed System1 result data; no grant or output authority is created here.
pub(crate) fn completion(id: &str, uid: u32, bytes: u64, digest: &str) -> Result<Value> {
    identity::safe_id(id)?;
    identity::sha(digest)?;
    require(
        (1000..i32::MAX as u32).contains(&uid) && bytes <= crate::delivery_export::MAX_FILE,
        "delivery result bound",
    )?;
    Ok(
        value!({"id":id,"status":"delivered-new-private-file","recipient_uid":uid,
        "filename":format!("enzimos-restored-{id}.bin"),"bytes":bytes,"sha256":digest,
        "overwritten":false,"metadata_restored":false}),
    )
}
