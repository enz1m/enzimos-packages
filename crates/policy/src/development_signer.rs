// SPDX-License-Identifier: MIT
//! One ephemeral, machine-local development signer. It cannot grant release authority.
use crate::{authority, authority_build, package_signature};
use enzimos_platform::{Error, Result, files, mount_identity, process, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const UID: &str = "enzimOS development install (this machine only)";
pub struct Signer {
    home: PathBuf,
    directory: File,
    inode: (u64, u64, u32, u32),
    mount: u64,
    owner: u32,
    agent: crate::development_agent_owner::Owner,
    pub fingerprint: String,
    retired: bool,
}
fn directory_identity(file: &File) -> Result<(u64, u64, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.mode()))
}
fn generate(home: &Path) -> Result<()> {
    let output = process::run(
        "/usr/bin/gpg",
        &[
            "--no-options",
            "--homedir",
            home.to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            UID,
            "ed25519",
            "sign",
            "1d",
        ],
        &[],
        Duration::from_secs(60),
        65536,
    )?;
    require(
        output.status.success(),
        "ephemeral development signer generation failed",
    )
}
fn handshake(
    home: &Path,
    owner: u32,
    original: &mut crate::development_agent_owner::Owner,
) -> Result<()> {
    let query = process::run(
        "/usr/bin/gpgconf",
        &[
            "--homedir",
            home.to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            "--list-dirs",
            "agent-socket",
        ],
        &[],
        Duration::from_secs(5),
        4096,
    )?;
    require(
        query.status.success(),
        "ephemeral agent socket query failed",
    )?;
    let text = std::str::from_utf8(&query.stdout)
        .map_err(|_| Error("ephemeral socket path encoding".into()))?;
    require(
        text.ends_with('\n')
            && text.lines().count() == 1
            && !text.contains('%')
            && !text.contains('\0'),
        "ephemeral socket path query shape",
    )?;
    let socket = PathBuf::from(text.trim_end_matches('\n'));
    let runtime = PathBuf::from(format!("/run/user/{owner}/gnupg"));
    let hashed = socket.strip_prefix(&runtime).ok().is_some_and(|relative| {
        let parts = relative.components().collect::<Vec<_>>();
        parts.len() == 2
            && parts[1].as_os_str() == "S.gpg-agent"
            && parts[0].as_os_str().to_str().is_some_and(|name| {
                name.strip_prefix("d.").is_some_and(|hash| {
                    (16..=64).contains(&hash.len())
                        && hash.bytes().all(|b| b.is_ascii_alphanumeric())
                })
            })
    });
    require(
        socket == home.join("S.gpg-agent") || hashed,
        "ephemeral socket left its owned GnuPG runtime",
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::symlink_metadata(&socket).is_err() && Instant::now() < deadline {
        original.recheck()?;
        std::thread::sleep(Duration::from_millis(10));
    }
    let parent = files::directory(
        socket
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(owner),
    )?;
    require(
        parent.metadata()?.mode() & 0o7777 == 0o700,
        "ephemeral socket parent protection",
    )?;
    let metadata = std::fs::symlink_metadata(&socket)
        .map_err(|e| Error(format!("ephemeral agent socket metadata: {e}")))?;
    use std::os::unix::fs::FileTypeExt;
    require(
        metadata.file_type().is_socket() && metadata.uid() == owner && metadata.nlink() == 1,
        "ephemeral signer agent socket authority",
    )?;
    let pid = crate::development_agent::sender(&socket, owner)?;
    original.bind(pid)
}

impl Signer {
    /// A fresh directory only. The installer supplies its retained live/target
    /// guard around each call; unprivileged fixtures can use their own directory.
    pub fn create(home: &Path, owner: u32) -> Result<Self> {
        require(
            enzimos_platform::process_identity::effective_uid() == owner
                && home.is_absolute()
                && home.as_os_str().as_encoded_bytes().len() + 16 < 108,
            "ephemeral signer owner or local socket path bound",
        )?;
        let directory = files::create_directory(home, 0o700, owner)?;
        let mut agent = crate::development_agent_owner::Owner::start(home, owner)?;
        handshake(home, owner, &mut agent)?;
        generate(home)?;
        let listing = authority_build::gpg(
            home,
            &["--with-colons", "--fingerprint", "--list-keys"],
            &[],
        )?;
        let fingerprints = authority::fingerprints(
            std::str::from_utf8(&listing)
                .map_err(|_| Error("ephemeral signer listing encoding".into()))?,
        )?;
        require(
            fingerprints.len() == 1,
            "ephemeral signer must contain exactly one public key",
        )?;
        let fingerprint = fingerprints
            .into_iter()
            .next()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        let result = Self {
            home: home.into(),
            inode: directory_identity(&directory)?,
            mount: mount_identity::id(directory.as_fd(), true)?,
            directory,
            owner,
            agent,
            fingerprint,
            retired: false,
        };
        result
            .recheck()
            .map_err(|e| Error(format!("signer initial recheck: {e}")))?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        require(!self.retired, "retired development key cannot sign again")?;
        let named = files::directory(&self.home, Some(self.owner))?;
        require(
            directory_identity(&named)? == self.inode
                && directory_identity(&self.directory)? == self.inode
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount,
            "ephemeral signer directory changed",
        )?;
        self.agent.recheck()
    }
    pub fn public(&self) -> Result<Vec<u8>> {
        self.recheck()?;
        let bytes = authority_build::gpg(&self.home, &["--export", &self.fingerprint], &[])?;
        require(
            !bytes.is_empty() && bytes.len() <= 1024 * 1024,
            "ephemeral public key export bound",
        )?;
        self.recheck()?;
        Ok(bytes)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub fn sign(&self, archive: &File, destination: &Path) -> Result<()> {
        self.recheck()?;
        let before = archive.metadata()?;
        require(
            before.is_file()
                && before.uid() == self.owner
                && before.nlink() == 1
                && before.mode() & 0o022 == 0
                && (1..=enzimos_platform::stream_copy::STREAM_BOUND).contains(&before.len())
                && enzimos_platform::files::status_flags(&archive) & libc::O_ACCMODE
                    == libc::O_RDONLY,
            "development signing requires a retained protected read-only archive",
        )?;
        // Creation is exclusive; an old detached signature is never reused.
        let parent = files::directory(
            destination
                .parent()
                .ok_or_else(|| Error("signature parent missing".into()))?,
            Some(self.owner),
        )?;
        let name = std::ffi::CString::new(
            destination
                .file_name()
                .ok_or_else(|| Error("signature filename missing".into()))?
                .as_encoded_bytes(),
        )
        .map_err(|_| Error("signature filename encoding".into()))?;
        // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0, "exclusive local signature creation failed")?;
        // SAFETY: `fd` was just returned by openat and is owned by nothing else.
        let output = unsafe { File::from_raw_fd(fd) };
        let result = process::run_with_fds(
            "/usr/bin/gpg",
            &[
                "--no-options",
                "--homedir",
                self.home
                    .to_str()
                    .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
                "--batch",
                "--no-tty",
                "--no-autostart",
                "--no-auto-key-retrieve",
                "--auto-key-locate",
                "clear",
                "--yes",
                "--local-user",
                &self.fingerprint,
                "--digest-algo",
                "SHA256",
                "--output",
                "@fd:1",
                "--detach-sign",
                "@fd:0",
            ],
            &[],
            Duration::from_secs(60),
            65536,
            &[archive.as_fd(), output.as_fd()],
        )?;
        require(
            result.status.success()
                && files::identity(&archive.metadata()?) == files::identity(&before)
                && (1..=65536).contains(&output.metadata()?.len()),
            "ephemeral development package signing failed",
        )?;
        output.sync_all()?;
        self.recheck()
    }
    /// Confirm the exact agent's kernel exit before removing only files in this
    /// newly created private-key directory. No installed authority is touched.
    pub fn retire(&mut self) -> Result<()> {
        self.recheck()?;
        self.agent.terminate()?;
        let end = Instant::now() + Duration::from_secs(10);
        while !self.agent.exited()? && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        require(
            self.agent.exited()?,
            "ephemeral signer agent exit unconfirmed; key retained",
        )?;
        let keys = self.home.join("private-keys-v1.d");
        let directory = files::directory(&keys, Some(self.owner))?;
        let mut count = 0;
        for entry in std::fs::read_dir(&keys)? {
            count += 1;
            require(count <= 8, "ephemeral private-key file count bound")?;
            let entry = entry?;
            let name = entry.file_name();
            let text = name
                .to_str()
                .ok_or_else(|| Error("private key filename encoding".into()))?;
            require(
                text.strip_suffix(".key")
                    .is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())),
                "unexpected ephemeral private key member",
            )?;
            let held = files::open_relative(&directory, Path::new(&name))?;
            let before = held.metadata()?;
            require(
                before.is_file()
                    && before.uid() == self.owner
                    && before.nlink() == 1
                    && before.mode() & 0o7777 == 0o600
                    && (1..=1024 * 1024).contains(&before.len()),
                "ephemeral private key file authority",
            )?;
            let named = std::fs::symlink_metadata(entry.path())?;
            require(
                files::identity(&before) == files::identity(&named),
                "ephemeral key identity changed before retirement",
            )?;
            std::fs::remove_file(entry.path())?;
        }
        require(
            count == 1 && std::fs::read_dir(&keys)?.next().is_none(),
            "ephemeral signing key retirement count",
        )?;
        directory.sync_all()?;
        std::fs::remove_dir(&keys)?;
        self.directory.sync_all()?;
        require(
            authority_build::gpg(&self.home, &["--list-secret-keys"], &[])?.is_empty(),
            "retired development signer still contains secret material",
        )?;
        self.retired = true;
        Ok(())
    }
}
pub fn verify_local(
    archive: &File,
    signature: &File,
    home: &Path,
    fingerprint: &str,
) -> Result<()> {
    require(
        package_signature::verify(archive, signature, home)? == fingerprint,
        "locally signed development package signer differs",
    )
}
