// SPDX-License-Identifier: MIT
//! Authenticated boot artifact publication, with no private keys on the ESP.
use crate::{
    operation, pe,
    secure_boot::{self, Material},
};
use enzimos_platform::{
    Error, Result, copy_publication::Copy, files, json, memfile, mount_identity, process,
    publication, require, stream_copy,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
const MAX: u64 = 256 * 1024 * 1024;
fn name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty() && s.len() <= 200)
        .ok_or_else(|| Error("signing artifact name".into()))
}
fn spelling(path: &Path) -> Result<&str> {
    require(
        path.is_absolute()
            && path.components().all(|c| {
                matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            }),
        "canonical absolute artifact path",
    )?;
    path.to_str()
        .filter(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or_else(|| Error("artifact path encoding".into()))
}
fn identity(m: &std::fs::Metadata) -> Value {
    value!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
struct Source {
    path: PathBuf,
    file: File,
    identity: Value,
    epoch: files::FileIdentity,
    bytes: u64,
    sha: String,
    mount: u64,
}
impl Source {
    fn open(path: &Path) -> Result<Self> {
        spelling(path)?;
        let parent = files::directory(
            path.parent()
                .ok_or_else(|| Error("artifact parent".into()))?,
            Some(0),
        )?;
        let mut file = stream_copy::open(&parent, name(path)?)?;
        let identity = identity(&file.metadata()?);
        let epoch = files::identity(&file.metadata()?);
        let mount = mount_identity::id(file.as_fd(), true)?;
        let (bytes, sha) = stream_copy::hash(&mut file, MAX, Some(0))?;
        Ok(Self {
            path: path.into(),
            file,
            identity,
            epoch,
            bytes,
            sha,
            mount,
        })
    }
    fn check(&self) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(0))?;
        let current = stream_copy::open(&parent, name(&self.path)?)?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&current.metadata()?) == self.epoch
                && identity(&current.metadata()?) == self.identity
                && identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(current.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "signing source changed",
        )
    }
    fn after_owned_output(&self, published: &Copy) -> Result<()> {
        if let Some(before) = published.original_epoch(&self.file)? {
            require(
                before == self.epoch && mount_identity::id(self.file.as_fd(), true)? == self.mount,
                "signing replacement differs from original input epoch",
            )
        } else {
            self.check()
        }
    }
    fn copy_authorized(
        &mut self,
        parent: &File,
        name: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Copy> {
        authorize()?;
        self.check()?;
        let copied = Copy::create(
            &mut self.file,
            parent,
            name,
            self.bytes,
            &self.sha,
            0,
            authorize,
        )?;
        authorize()?;
        self.check()?;
        copied.recheck(authorize)?;
        Ok(copied)
    }
}
struct Stage {
    path: PathBuf,
    directory: File,
    receipt: PathBuf,
    record: Value,
    destination: PathBuf,
    parent: File,
    parent_before: files::FileIdentity,
    existing: Option<Value>,
    existing_file: Option<File>,
    existing_epoch: Option<files::FileIdentity>,
    receipt_witness: publication::Committed,
    mount: u64,
}
impl Stage {
    fn new_authorized(
        destination: &Path,
        sources: &Value,
        replace: bool,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        let destination_text = spelling(destination)?;
        name(destination)?;
        let parent = files::directory(destination.parent().unwrap(), Some(0))?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let parent_before = files::identity(&parent.metadata()?);
        let existing_file = files::optional_relative(&parent, Path::new(name(destination)?))?;
        let existing_epoch = existing_file
            .as_ref()
            .map(|f| f.metadata().map(|m| files::identity(&m)))
            .transpose()?;
        let existing = if let Some(file) = &existing_file {
            let m = file.metadata()?;
            require(
                replace
                    && m.is_file()
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7022 == 0
                    && m.nlink() == 1
                    && mount_identity::id(file.as_fd(), true)? == mount,
                "original signed destination exists or unsafe",
            )?;
            Some(identity(&m))
        } else {
            None
        };
        let directory = Path::new(secure_boot::DIRECTORY).join("signing");
        authorize()?;
        let root = files::ensure_directory(&directory, 0o700, 0)?;
        require(
            root.metadata()?.mode() & 0o777 == 0o700,
            "private signing journal required",
        )?;
        require(
            std::fs::read_dir(&directory)?.take(257).count() < 256,
            "signing journal retention bound",
        )?;
        let digest = json::fingerprint(&value!(destination_text))?;
        let receipt = directory.join(format!("{digest}.json"));
        let previous_receipt =
            files::optional_relative(&root, Path::new(receipt.file_name().unwrap()))?;
        let previous_receipt_epoch = previous_receipt
            .as_ref()
            .map(|f| f.metadata().map(|m| files::identity(&m)))
            .transpose()?;
        if let Some(previous) = &previous_receipt {
            let old = json::decode(&files::read_file(previous, 16384, Some(0), true)?, 16384)?;
            json::fields(
                &old,
                "schema phase destination sources staging output_sha256",
            )?;
            require(
                old["schema"] == 1
                    && old["phase"] == "complete"
                    && old["destination"] == destination_text,
                "interrupted signing requires review; no automatic replay",
            )?;
            require(
                old["output_sha256"].as_str().is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                }),
                "invalid signing completion receipt",
            )?;
        }
        let token = files::random_hex(16)?;
        let path = directory.join(format!("stage-{token}"));
        let record = value!({"schema":1,"phase":"prepared","destination":destination_text,"sources":sources,"staging":token,"output_sha256":null});
        authorize()?;
        if let Some(previous) = &previous_receipt {
            require(
                Some(files::identity(&previous.metadata()?)) == previous_receipt_epoch,
                "original prior signing receipt changed",
            )?;
        }
        let prepared = publication::Prepared::write_authorized(
            &receipt,
            &json::canonical(&record)?,
            0,
            authorize,
        )?;
        if let Some(previous) = &previous_receipt {
            prepared.require_original(previous)?;
        }
        let receipt_witness = prepared.commit_retained_authorized(true, authorize)?;
        authorize()?;
        let held = files::create_directory(&path, 0o700, 0)?;
        Ok(Self {
            path,
            directory: held,
            receipt,
            record,
            destination: destination.into(),
            parent,
            parent_before,
            existing,
            existing_file,
            existing_epoch,
            receipt_witness,
            mount,
        })
    }
    fn path(&self, name: &str) -> Result<String> {
        Ok(spelling(&self.path.join(name))?.to_owned())
    }
    fn publish_retained(
        mut self,
        output: &str,
        replace: bool,
        before: &mut dyn FnMut() -> Result<()>,
        after: &mut dyn FnMut(&Copy) -> Result<()>,
    ) -> Result<Signed> {
        before()?;
        self.receipt_witness.recheck()?;
        require(
            files::read_file(self.receipt_witness.file()?, 16384, Some(0), true)?
                == json::canonical(&self.record)?,
            "original prepared signing receipt changed",
        )?;
        let mut file = stream_copy::open(&self.directory, output)?;
        let (bytes, sha) = stream_copy::hash(&mut file, MAX, Some(0))?;
        let temporary = format!("{}.signed-new", name(&self.destination)?);
        let copy = Copy::create(&mut file, &self.parent, &temporary, bytes, &sha, 0, before)?;
        before()?;
        let named_directory = files::directory(self.destination.parent().unwrap(), Some(0))?;
        let held = self.parent.metadata()?;
        let named = named_directory.metadata()?;
        require(
            (held.dev(), held.ino(), held.mode(), held.uid(), held.gid())
                == (
                    named.dev(),
                    named.ino(),
                    named.mode(),
                    named.uid(),
                    named.gid(),
                )
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(named_directory.as_fd(), true)? == self.mount,
            "original signed publication parent replaced/covered",
        )?;
        if let Some(original) = &self.existing_file {
            let named = files::open_relative(&self.parent, Path::new(name(&self.destination)?))?;
            require(
                replace
                    && Some(files::identity(&original.metadata()?)) == self.existing_epoch
                    && Some(files::identity(&named.metadata()?)) == self.existing_epoch
                    && identity(&original.metadata()?) == *self.existing.as_ref().unwrap(),
                "original signed destination description changed",
            )?;
        }
        self.receipt_witness.recheck()?;
        let copy = copy.replace(
            name(&self.destination)?,
            self.existing_file.as_ref(),
            before,
        )?;
        let mut permission = || after(&copy);
        copy.recheck(&mut permission)?;
        self.record["phase"] = value!("complete");
        self.record["output_sha256"] = value!(sha);
        permission()?;
        let original = self.receipt_witness.file()?.try_clone()?;
        let prepared = publication::Prepared::write_authorized(
            &self.receipt,
            &json::canonical(&self.record)?,
            0,
            &mut permission,
        )?;
        prepared.require_original(&original)?;
        self.receipt_witness = prepared.commit_retained_authorized(true, &mut permission)?;
        copy.recheck(&mut permission)?;
        self.receipt_witness.recheck()?;
        permission()?;
        Ok(Signed {
            path: self.destination,
            copy,
            receipt: self.receipt_witness,
            parent: self.parent,
            parent_before: self.parent_before,
            mount: self.mount,
        })
    }
}
/// Only actual copied output plus its original completed receipt creates this actor.
pub struct Signed {
    path: PathBuf,
    copy: Copy,
    receipt: publication::Committed,
    parent: File,
    parent_before: files::FileIdentity,
    mount: u64,
}
impl Signed {
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.copy.checkpoint(authorize)?;
        self.receipt.recheck()?;
        let named = files::directory(self.path.parent().unwrap(), Some(0))?;
        let a = self.parent.metadata()?;
        let b = named.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid())
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original signed parent path covered/replaced",
        )?;
        let current = files::open_relative(&named, Path::new(name(&self.path)?))?;
        require(
            files::identity(&current.metadata()?)
                == files::identity(&self.copy.descriptor(authorize)?.metadata()?)
                && mount_identity::id(current.as_fd(), true)? == self.mount,
            "original signed path differs from actual copy",
        )?;
        authorize()
    }
    pub(crate) fn require_replaced_input(
        &self,
        original: &File,
        epoch: files::FileIdentity,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            self.copy.original_epoch(original)? == Some(epoch),
            "signed output does not own independently retained predecessor",
        )
    }
    pub fn file(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&File> {
        self.recheck(authorize)?;
        self.copy.descriptor(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(value!({"path":self.path,"sha256":self.copy.sha256()}))
    }
}
fn sign_in(
    stage: &Stage,
    input: &str,
    output: &str,
    material: &Material,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Source> {
    authorize()?;
    let source = Source::open(&stage.path.join(input))?;
    let key = material.key_file()?;
    let cert = memfile::sealed("enzimos-owner-certificate", &material.pem)?;
    let output = stage.path(output)?;
    let sign =
        crate::settings_command::Command::open_boot(crate::settings_command::BootTool::Sign)?;
    let result = sign.run_fds_authorized(
        &[
            "--key", "@fd:0", "--cert", "@fd:1", "--output", &output, "@fd:2",
        ],
        Duration::from_secs(600),
        16384,
        &[key.as_fd(), cert.as_fd(), source.file.as_fd()],
        &mut || {
            authorize()?;
            source.check()
        },
    )?;
    require(
        result.status.success(),
        "owner signing tool refused; retain prepared receipt",
    )?;
    source.check()?;
    let signed = Source::open(Path::new(&output))?;
    let verify =
        crate::settings_command::Command::open_boot(crate::settings_command::BootTool::Verify)?;
    let result = verify.run_fds_authorized(
        &["--cert", "@fd:0", "@fd:1"],
        Duration::from_secs(600),
        16384,
        &[cert.as_fd(), signed.file.as_fd()],
        &mut || {
            authorize()?;
            source.check()?;
            signed.check()
        },
    )?;
    require(
        result.status.success(),
        "signed artifact verification refused",
    )?;
    source.check()?;
    signed.check()?;
    authorize()?;
    Ok(signed)
}
pub fn sign(path: &Path, output: Option<&Path>) -> Result<Value> {
    operation::root_only()?;
    let _lock = operation::lock()?;
    sign_locked(path, output, &_lock)
}
pub fn sign_locked(path: &Path, output: Option<&Path>, _operation: &files::Lock) -> Result<Value> {
    sign_authorized(path, output, _operation, &mut || _operation.recheck())
}
pub fn sign_authorized(
    path: &Path,
    output: Option<&Path>,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    sign_retained_authorized(path, output, lock, authorize)?.evidence(authorize)
}
pub fn sign_retained_authorized(
    path: &Path,
    output: Option<&Path>,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Signed> {
    authorize()?;
    lock.recheck()?;
    operation::root_only()?;
    let owner = crate::secure_owner_source::Owner::credentials()?;
    let material = owner
        .material()
        .ok_or_else(|| Error("explicit owner signing material missing".into()))?;
    let mut source = Source::open(path)?;
    let destination = output.unwrap_or(path);
    let stage = Stage::new_authorized(
        destination,
        &value!({"input":{"path":path,"identity":source.identity,"sha256":source.sha},"owner":owner.identity()?}),
        true,
        authorize,
    )?;
    let copied = source.copy_authorized(&stage.directory, "source.efi", authorize)?;
    owner.recheck()?;
    let signed_source = sign_in(&stage, "source.efi", "signed.efi", material, &mut || {
        authorize()?;
        lock.recheck()?;
        owner.recheck()?;
        copied.checkpoint(&mut || Ok(()))?;
        source.check()
    })?;
    source.check()?;
    owner.recheck()?;
    let permission = std::cell::RefCell::new(authorize);
    let fresh = || -> Result<()> {
        let mut callback = permission
            .try_borrow_mut()
            .map_err(|_| Error("signing authorization reentered".into()))?;
        callback()?;
        lock.recheck()?;
        signed_source.check()?;
        owner.recheck()
    };
    let result = stage.publish_retained(
        "signed.efi",
        true,
        &mut || {
            fresh()?;
            copied.checkpoint(&mut || Ok(()))?;
            source.check()
        },
        &mut |published| {
            fresh()?;
            copied.checkpoint_after_source_replacement(published, &mut || Ok(()))?;
            source.after_owned_output(published)
        },
    )?;
    owner.recheck()?;
    Ok(result)
}
pub fn build_uki(kernel: &Path, initrd: &Path, options: &str, destination: &Path) -> Result<Value> {
    let lock = operation::lock()?;
    build_uki_locked(kernel, initrd, options, destination, &lock)
}
pub fn build_uki_locked(
    kernel: &Path,
    initrd: &Path,
    options: &str,
    destination: &Path,
    _operation: &files::Lock,
) -> Result<Value> {
    build_uki_retained_locked(kernel, initrd, options, destination, _operation)?
        .evidence(&mut || _operation.recheck())
}
/// Actual UKI output and original inputs remain retained beyond publication.
pub struct Uki {
    signed: Signed,
    kernel: Source,
    initrd: Source,
    options_sha: String,
}
impl Uki {
    pub(crate) fn require_original_parent(
        &self,
        parent: &File,
        before: files::FileIdentity,
        leaf: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        let signed = &self.signed;
        require(
            signed.parent_before == before
                && name(&signed.path)? == leaf
                && files::identity(&signed.parent.metadata()?)
                    == files::identity(&parent.metadata()?)
                && mount_identity::id(parent.as_fd(), true)? == signed.mount,
            "actual owned UKI publication differs from original prepared namespace",
        )?;
        let named = files::open_relative(parent, Path::new(leaf))?;
        require(
            files::identity(&named.metadata()?)
                == files::identity(&self.file(authorize)?.metadata()?)
                && mount_identity::id(named.as_fd(), true)? == signed.mount,
            "owned UKI namespace member differs from actual publication",
        )?;
        self.recheck(authorize)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        self.kernel.check()?;
        self.initrd.check()?;
        self.signed.recheck(authorize)
    }
    pub fn file(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&File> {
        self.recheck(authorize)?;
        self.signed.file(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let mut result = self.signed.evidence(authorize)?;
        result["kernel_sha256"] = value!(self.kernel.sha);
        result["initrd_sha256"] = value!(self.initrd.sha);
        result["options_sha256"] = value!(self.options_sha);
        Ok(result)
    }
}
pub fn build_uki_retained_locked(
    kernel: &Path,
    initrd: &Path,
    options: &str,
    destination: &Path,
    operation: &files::Lock,
) -> Result<Uki> {
    build_uki_retained_authorized(kernel, initrd, options, destination, operation, &mut || {
        operation.recheck()
    })
}
/// Fresh caller authorization accompanies preparation, original source copying,
/// assembly, signing and the retained no-replace publication. Revocation after
/// assembly preserves prepared evidence and prevents final publication.
pub fn build_uki_retained_authorized(
    kernel: &Path,
    initrd: &Path,
    options: &str,
    destination: &Path,
    _operation: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Uki> {
    operation::root_only()?;
    let authorization = std::cell::RefCell::new(authorize);
    let permission = || {
        _operation.recheck()?;
        (authorization.borrow_mut())()
    };
    permission()?;
    require(
        !options.is_empty()
            && options.len() <= 4096
            && options.bytes().all(|b| (32..127).contains(&b)),
        "invalid embedded command line",
    )?;
    let owner = crate::secure_owner_source::Owner::credentials()?;
    let material = owner
        .material()
        .ok_or_else(|| Error("explicit owner UKI material missing".into()))?;
    let mut kernel = Source::open(kernel)?;
    let mut initrd = Source::open(initrd)?;
    let options_sha = json::sha256(options.as_bytes());
    let stage = Stage::new_authorized(
        destination,
        &value!({"kernel":{"path":kernel.path,"identity":kernel.identity,"sha256":kernel.sha},"initrd":{"path":initrd.path,"identity":initrd.identity,"sha256":initrd.sha},"options_sha256":options_sha,"owner":owner.identity()?}),
        false,
        &mut || permission(),
    )?;
    let kernel_copy = kernel.copy_authorized(&stage.directory, "kernel", &mut || {
        permission()?;
        owner.recheck()
    })?;
    let initrd_copy = initrd.copy_authorized(&stage.directory, "initrd.img", &mut || {
        permission()?;
        owner.recheck()
    })?;
    permission()?;
    files::atomic(
        &stage.path.join("cmdline"),
        format!("{options}\n").as_bytes(),
        0o600,
        Some(0),
        false,
    )?;
    kernel_copy.recheck(&mut || permission())?;
    initrd_copy.recheck(&mut || permission())?;
    let command = format!("@{}", stage.path("cmdline")?);
    let unsigned = stage.path("unsigned.efi")?;
    files::read(Path::new("/etc/os-release"), 16384, Some(0), false)?;
    permission()?;
    let result = process::run_with_fds(
        "/usr/lib/systemd/ukify",
        &[
            "build",
            "--linux",
            "@fd:0",
            "--initrd",
            "@fd:1",
            "--cmdline",
            &command,
            "--os-release",
            "@/etc/os-release",
            "--output",
            &unsigned,
        ],
        &[],
        Duration::from_secs(600),
        16384,
        &[
            kernel_copy.file(&mut || permission())?.as_fd(),
            initrd_copy.file(&mut || permission())?.as_fd(),
        ],
    )?;
    permission()?;
    require(
        result.status.success(),
        "UKI assembly refused; retain prepared receipt",
    )?;
    owner.recheck()?;
    let signed_source = sign_in(&stage, "unsigned.efi", "signed.efi", material, &mut || {
        permission()?;
        owner.recheck()?;
        kernel.check()?;
        initrd.check()?;
        kernel_copy.checkpoint(&mut || Ok(()))?;
        initrd_copy.checkpoint(&mut || Ok(()))
    })?;
    signed_source.check()?;
    let body = files::read_file(&signed_source.file, MAX as usize, Some(0), true)?;
    verify_payload(&body, &kernel.sha, &initrd.sha, options)?;
    kernel.check()?;
    initrd.check()?;
    owner.recheck()?;
    let fresh = || {
        permission()?;
        owner.recheck()?;
        kernel.check()?;
        initrd.check()?;
        kernel_copy.checkpoint(&mut || Ok(()))?;
        initrd_copy.checkpoint(&mut || Ok(()))?;
        signed_source.check()
    };
    let signed = stage.publish_retained("signed.efi", false, &mut || fresh(), &mut |_| fresh())?;
    fresh()?;
    let result = Uki {
        signed,
        kernel,
        initrd,
        options_sha,
    };
    result.recheck(&mut || permission())?;
    Ok(result)
}

/// This content binding complements signature verification; a signature alone
/// does not prove this UKI contains the selected kernel, initrd and command line.
pub fn verify_payload(body: &[u8], kernel: &str, initrd: &str, options: &str) -> Result<()> {
    let sections = pe::sections(body)?;
    let command = sections
        .get(".cmdline")
        .ok_or_else(|| Error("UKI command line missing".into()))?;
    let end = command
        .iter()
        .rposition(|b| !matches!(*b, 0 | b'\n'))
        .map_or(0, |n| n + 1);
    require(
        sections
            .get(".linux")
            .is_some_and(|b| json::sha256(b) == kernel)
            && sections
                .get(".initrd")
                .is_some_and(|b| json::sha256(b) == initrd)
            && &command[..end] == options.as_bytes(),
        "UKI payload binding differs from reviewed artifacts",
    )
}
