use super::*;
use std::fmt::Write as _;

pub fn publish_locked(lock: &files::Lock, stage_uuid: &str) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::uuid(stage_uuid)?;
    lock.recheck()?;
    let ram = backup_ram_source::Source::observe()?;
    let guard = Source::Ram(&ram);
    let quiet = backup_ram_quiet::Quiet::observe(&ram)?;
    let config = backup_configuration::Configuration::open()?;
    let destination = backup_destination::ram::Destination::open(&config, &ram)?;
    let pin = backup_admission::ram::Repository::open(&destination)?;
    let parent =
        files::directory_relative(ram.control(), Path::new("backup-complete-stages"), Some(0))?;
    require(
        parent.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(parent.as_fd(), true)? == ram.control_mount_id(),
        "private complete boot receipt registry required",
    )?;
    let parent_shape = shape(&parent)?;
    let mut members = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut selected = None;
    for name in files::directory_names(&parent, 16)? {
        let name = name
            .into_string()
            .map_err(|_| Error("complete boot receipt encoding".into()))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| Error("unknown/interrupted complete receipt member".into()))?;
        crate::identity::uuid(id)?;
        let original = Observation::open(
            &parent,
            Path::new(&name),
            256 * 1024,
            ram.control_mount_id(),
        )?;
        super::super::validate_complete(original.value()?, id)?;
        require(
            matches!(
                original.value()?["phase"].as_str(),
                Some("staged" | "data-prepared-not-bootable" | "uefi-boot-prepared")
            ),
            "uncertain complete receipt requires review",
        )?;
        if id == stage_uuid {
            require(
                original.value()?["phase"] == "data-prepared-not-bootable",
                "complete data unavailable/already attempted; no replay",
            )?;
            selected = Some(original);
        } else {
            members.insert(name.clone(), original);
        }
        names.insert(name);
    }
    let mut receipt =
        selected.ok_or_else(|| Error("original complete data receipt missing".into()))?;
    let mut record = receipt.value()?.clone();
    let replacement = record["replacement"].clone();
    let layout = replacement["layout"].clone();
    let uuid = boot_uuid(&layout)?;
    let crypttab = layout["crypttab"]
        .as_str()
        .ok_or_else(|| Error("fresh crypttab required".into()))?;
    let luks = if crypttab.is_empty() {
        None
    } else {
        Some(
            crypttab
                .strip_prefix("enzimos-crypt UUID=")
                .and_then(|v| v.strip_suffix(" none luks,discard,x-initrd.attach\n"))
                .ok_or_else(|| Error("closed fresh encryption configuration required".into()))?,
        )
    };
    require(
        layout
            == crate::backup_restore_layout::layout(
                enzimos_platform::json::string(&ram.configuration()["filesystem_uuid"])?,
                &uuid,
                luks,
                false,
            )?,
        "complete layout differs from closed fresh configuration",
    )?;

    require(
        layout["storage"]
            .as_object()
            .is_some_and(|fields| fields.iter().all(|(key, v)| ram.configuration()[key] == *v)),
        "complete fresh storage configuration differs",
    )?;
    let stage =
        Target::observe_at_state(&guard, stage_uuid, super::super::TARGET, None, false, true)?;
    require(
        stage.evidence(&guard)? == record["target"],
        "actual frozen complete stage differs from original data receipt",
    )?;
    let root = Target::observe_at(
        &guard,
        crate::recovery_records::text(&replacement["root"]["object"], "uuid")?,
        "/restore-system",
        Some("enzimos-root"),
        false,
    )?;
    let home = Target::observe_at(
        &guard,
        crate::recovery_records::text(&replacement["home"]["object"], "uuid")?,
        "/restore-home",
        Some("enzimos-home"),
        false,
    )?;
    require(
        root.object == replacement["root"]["object"]
            && home.object == replacement["home"]["object"]
            && root.row.optional.is_empty()
            && home.row.optional.is_empty(),
        "prepared replacements differ or have mount propagation",
    )?;
    let esp = Esp::observe(&uuid)?;
    let keys = Keys::observe()?;
    let chroot = Input::open(&root.directory, "usr/bin/chroot", 32 * 1024 * 1024)?;
    let mut placeholders = Vec::new();
    for name in [
        "boot",
        "home",
        "etc/pacman.d/gnupg",
        "var/lib/enzimos-control",
        "dev",
        "proc",
        "sys",
        "run",
        "tmp",
        "var/tmp",
    ] {
        let directory = files::directory_relative(&root.directory, Path::new(name), Some(0))?;
        require(
            mount_identity::id(directory.as_fd(), true)? == root.mount
                && files::directory_names(&directory, 1)?.is_empty(),
            "unsafe/nonempty prepared mount placeholder",
        )?;
        placeholders.push((name, directory));
    }
    let source_system =
        files::directory_relative(&stage.directory, Path::new("backup-source/system"), Some(0))?;
    let before = || -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        ram.recheck()?;
        quiet.recheck(&ram)?;
        config.recheck()?;
        destination.recheck()?;
        pin.recheck()?;
        stage.recheck(&guard)?;
        root.recheck(&guard)?;
        home.recheck(&guard)?;
        esp.recheck()?;
        keys.recheck()?;
        chroot.recheck(&root.directory, "usr/bin/chroot")?;
        let named =
            files::directory_relative(ram.control(), Path::new("backup-complete-stages"), Some(0))?;
        require(
            shape(&parent)? == parent_shape
                && shape(&named)? == parent_shape
                && mount_identity::id(named.as_fd(), true)? == ram.control_mount_id(),
            "original complete boot registry replaced",
        )?;
        let current = files::directory_names(&parent, 16)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("complete registry filename encoding".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            current == names,
            "complete boot registry member set changed",
        )?;
        for member in members.values() {
            member.recheck()?;
        }
        for (name, directory) in &placeholders {
            let named = files::directory_relative(&root.directory, Path::new(name), Some(0))?;
            require(
                files::identity(&named.metadata()?) == files::identity(&directory.metadata()?)
                    && mount_identity::id(named.as_fd(), true)? == root.mount
                    && files::directory_names(directory, 1)?.is_empty(),
                "original prepared placeholder changed/replaced",
            )?;
        }
        Ok(())
    };
    before()?;
    receipt.recheck()?;
    let runtime_parent =
        files::ensure_directory(Path::new("/run/enzimos/complete-boot/jobs"), 0o700, 0)?;
    require(
        runtime_parent.metadata()?.mode() & 0o7777 == 0o700,
        "private complete boot runtime required",
    )?;
    let job = Path::new("/run/enzimos/complete-boot/jobs").join(files::random_hex(16)?);
    let runtime = files::create_directory(&job, 0o700, 0)?;
    let runtime_epoch = files::identity(&runtime.metadata()?);
    let runtime_shape = shape(&runtime)?;
    record["phase"] = value!("boot-preparing");
    record["boot_mount"] = esp.evidence()?;
    super::super::validate_complete(&record, stage_uuid)?;
    receipt.replace_original(&record)?;
    let entered = || -> Result<()> {
        before()?;
        receipt.recheck()?;
        let named = files::directory(&job, Some(0))?;
        require(
            shape(&runtime)? == runtime_shape
                && shape(&named)? == runtime_shape
                && (named.metadata()?.dev(), named.metadata()?.ino())
                    == (runtime_epoch.0, runtime_epoch.1)
                && mount_identity::id(named.as_fd(), true)?
                    == mount_identity::id(runtime.as_fd(), true)?,
            "original complete boot runtime replaced/covered",
        )
    };
    set_root_readonly(&root, &guard, true, &mut || entered())?;
    super::super::complete_tree::compare(&source_system, &root.directory, &mut || entered())?;
    // Fresh configuration and cleared state are the only skipped source trees.
    let etc = files::directory_relative(&root.directory, Path::new("etc"), Some(0))?;
    for (path, bytes) in [
        (
            "fstab",
            layout["fstab"]
                .as_str()
                .ok_or_else(|| Error("fresh fstab required".into()))?
                .as_bytes(),
        ),
        (
            "crypttab",
            layout["crypttab"]
                .as_str()
                .ok_or_else(|| Error("fresh crypttab required".into()))?
                .as_bytes(),
        ),
    ] {
        let input = Input::open(&etc, path, 2 * 1024 * 1024)?;
        require(input.bytes == bytes, "prepared fresh configuration differs")?;
    }
    let restored_storage =
        Input::open(&root.directory, "etc/enzimos/storage.json", 2 * 1024 * 1024)?;
    require(
        json::decode(&restored_storage.bytes, 2 * 1024 * 1024)? == layout["storage"],
        "prepared storage configuration differs",
    )?;
    let state = files::directory_relative(&root.directory, Path::new("var/lib/enzimos"), Some(0))?;
    require(
        state.metadata()?.mode() & 0o7777 == 0o700 && files::directory_names(&state, 1)?.is_empty(),
        "prepared service state not empty/private",
    )?;
    let timers = files::optional_directory_relative(
        &root.directory,
        Path::new("etc/systemd/system/timers.target.wants"),
        Some(0),
    )?;
    if let Some(timers) = timers {
        require(
            files::optional_relative(&timers, Path::new("enzimos-backup.timer"))?.is_none(),
            "prepared automatic backup timer present",
        )?;
    }
    let mut histories = Vec::new();
    for target in [&root, &home] {
        let dir = files::directory_relative(&target.directory, Path::new(".snapshots"), Some(0))?;
        require(
            dir.metadata()?.ino() == 256
                && dir.metadata()?.mode() & 0o7777 == 0o750
                && files::directory_names(&dir, 1)?.is_empty()
                && subvolume::observe(dir.as_fd(), ".snapshots")?.0["parent_uuid"].is_null(),
            "prepared new history differs",
        )?;
        histories.push(dir);
    }
    let review = files::create_directory_relative(&runtime, Path::new("key-review"), 0o700, 0)?;
    for (name, input) in &keys.inputs {
        files::atomic_relative(
            &review,
            Path::new(name),
            &input.bytes,
            if name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(0),
            false,
            16 * 1024 * 1024,
        )?;
    }
    let gpg = Command::open_boot(BootTool::PublicAuthority)?;
    let checked = gpg.run_fds_authorized(
        &[
            "--no-options",
            "--homedir",
            "@fd:0",
            "--batch",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--with-colons",
            "--list-secret-keys",
        ],
        Duration::from_secs(120),
        32768,
        &[review.as_fd()],
        &mut || entered(),
    )?;
    require(
        checked.status.success() && checked.stdout.is_empty(),
        "recovery authority must be public-only",
    )?;
    let mut authority = Authority::mount(job.join("authority"), &ram)?;
    let authority_file = authority.file()?.try_clone()?;
    let mut published_keys = Vec::new();
    for (name, input) in &keys.inputs {
        entered()?;
        keys.recheck()?;
        published_keys.push((
            name.clone(),
            files::atomic_relative_retained(
                &authority_file,
                Path::new(name),
                &input.bytes,
                if name == "gpg.conf" { 0o644 } else { 0o600 },
                Some(0),
                false,
                16 * 1024 * 1024,
            )?,
        ));
    }
    let ongoing = || -> Result<()> {
        entered()?;
        authority.recheck()?;
        for (name, file) in &published_keys {
            let named = files::open_relative(&authority_file, Path::new(name))?;
            require(
                files::identity(&named.metadata()?) == files::identity(&file.metadata()?),
                "published fresh authority member replaced",
            )?;
        }
        for history in &histories {
            require(
                files::directory_names(history, 1)?.is_empty(),
                "prepared history gained runtime contents",
            )?;
        }
        Ok(())
    };
    let modules =
        files::directory_relative(&root.directory, Path::new("usr/lib/modules"), Some(0))?;
    let mut kernels = BTreeMap::new();
    for name in files::directory_names(&modules, 128)? {
        let name = name
            .into_string()
            .map_err(|_| Error("restored kernel directory encoding".into()))?;
        crate::identity::safe_id(&name)?;
        let directory = files::directory_relative(&modules, Path::new(&name), Some(0))?;
        let pkgbase = Input::open(&directory, "pkgbase", 128)?;
        let flavor = std::str::from_utf8(&pkgbase.bytes)
            .map_err(|_| Error("restored kernel flavor encoding".into()))?
            .trim();
        require(
            matches!(flavor, "linux" | "linux-lts") && !kernels.contains_key(flavor),
            "exact restored kernel flavors required",
        )?;
        let image = copy_file(
            &directory,
            "vmlinuz",
            &esp.directory,
            &format!("vmlinuz-{flavor}"),
            &mut || ongoing(),
        )?;
        kernels.insert(flavor.to_owned(), image);
    }
    require(
        kernels.len() == 2,
        "one restored kernel per flavor required",
    )?;
    for tool in [Tool::Initramfs, Tool::Loader] {
        ongoing()?;
        let mut group = Group::create()?;
        let context = Context::prepare(
            &root.directory,
            &home.directory,
            &esp.directory,
            ram.control(),
            &authority_file,
            &group,
        )?;
        let result =
            process::recovery_boot_tool(&chroot.file, tool, context, &group, &mut || ongoing());
        group.close()?;
        let result = result?;
        require(
            result.status.success(),
            "restored boot tool failed; preparing receipt retained",
        )?;
        ongoing()?;
    }
    let loader = files::directory_relative(&esp.directory, Path::new("loader"), Some(0))?;
    let entries = files::ensure_directory_relative(&loader, Path::new("entries"), 0o700, 0)?;
    let mut outputs = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        let initrd = Input::open(
            &esp.directory,
            &format!("initramfs-{flavor}.img"),
            1024 * 1024 * 1024,
        )?;
        require(!initrd.bytes.is_empty(), "rebuilt initramfs missing/empty")?;
        let name = format!("{flavor}.conf");
        let bytes = format!(
            "title enzimOS ({flavor})\nlinux /vmlinuz-{flavor}\ninitrd /initramfs-{flavor}.img\noptions {}\n",
            layout["boot_options"]
                .as_str()
                .ok_or_else(|| Error("fresh boot options required".into()))?
        );
        let file = match files::optional_relative(&entries, Path::new(&name))? {
            Some(old) => {
                super::super::complete_fat::write(&entries, &name, bytes.as_bytes(), Some(&old))?
            }
            None => output(&entries, &name, bytes.as_bytes())?,
        };
        outputs.push((entries.try_clone()?, name, file));
    }
    let loader_conf = match files::optional_relative(&loader, Path::new("loader.conf"))? {
        Some(old) => super::super::complete_fat::write(
            &loader,
            "loader.conf",
            b"default linux.conf\ntimeout menu-hidden\neditor no\n",
            Some(&old),
        )?,
        None => output(
            &loader,
            "loader.conf",
            b"default linux.conf\ntimeout menu-hidden\neditor no\n",
        )?,
    };
    outputs.push((loader.try_clone()?, "loader.conf".into(), loader_conf));
    let limine = files::create_directory_relative(&esp.directory, Path::new("limine"), 0o700, 0)?;
    let source_limine =
        files::directory_relative(&root.directory, Path::new("usr/share/limine"), Some(0))?;
    let bios = copy_file(
        &source_limine,
        "limine-bios.sys",
        &limine,
        "limine-bios.sys",
        &mut || ongoing(),
    )?;
    outputs.push((limine.try_clone()?, "limine-bios.sys".into(), bios));
    let mut menu =
        String::from("timeout: 1\nquiet: yes\ndefault_entry: 1\ninterface_branding: enzimOS\n");
    for flavor in ["linux", "linux-lts"] {
        let _ = write!(
            menu,
            "/enzimOS {flavor}\n    protocol: linux\n    path: boot():/vmlinuz-{flavor}\n    module_path: boot():/initramfs-{flavor}.img\n    cmdline: {}\n",
            enzimos_platform::json::string(&layout["boot_options"])?
        );
    }
    let bios_menu = output(&limine, "limine.conf", menu.as_bytes())?;
    outputs.push((limine.try_clone()?, "limine.conf".into(), bios_menu));
    let efi = files::directory_relative(&esp.directory, Path::new("EFI"), Some(0))?;
    let frontend = files::create_directory_relative(&efi, Path::new("enzimos"), 0o700, 0)?;
    let icons = files::create_directory_relative(&frontend, Path::new("icons"), 0o700, 0)?;
    let refind =
        files::directory_relative(&root.directory, Path::new("usr/share/refind"), Some(0))?;
    let refind_image = copy_file(
        &refind,
        "refind_x64.efi",
        &frontend,
        "refind_x64.efi",
        &mut || ongoing(),
    )?;
    outputs.push((frontend.try_clone()?, "refind_x64.efi".into(), refind_image));
    let source_icons = files::directory_relative(&refind, Path::new("icons"), Some(0))?;
    for name in files::directory_names(&source_icons, 4096)? {
        let name = name
            .into_string()
            .map_err(|_| Error("restored icon encoding".into()))?;

        let file = copy_file(&source_icons, &name, &icons, &name, &mut || ongoing())?;
        outputs.push((icons.try_clone()?, name, file));
    }
    let art = files::directory_relative(
        &root.directory,
        Path::new("usr/share/enzimos-boot"),
        Some(0),
    )?;
    for name in ["background.png", "select-entry.efi"] {
        let file = copy_file(&art, name, &frontend, name, &mut || ongoing())?;
        outputs.push((frontend.try_clone()?, name.into(), file));
    }
    for name in files::directory_names(&art, 4096)? {
        let name = name
            .into_string()
            .map_err(|_| Error("restored boot art encoding".into()))?;
        if name.ends_with(".png") {
            let input = Input::open(&art, &name, 32 * 1024 * 1024)?;
            let file = match files::optional_relative(&icons, Path::new(&name))? {
                Some(old) => {
                    super::super::complete_fat::write(&icons, &name, &input.bytes, Some(&old))?
                }
                None => output(&icons, &name, &input.bytes)?,
            };
            let icons_inode = icons.metadata().map(|m| (m.dev(), m.ino()))?;
            let mut kept = Vec::with_capacity(outputs.len());
            for output in outputs.drain(..) {
                let parent_inode = output.0.metadata().map(|m| (m.dev(), m.ino()))?;
                if output.1 != name || parent_inode != icons_inode {
                    kept.push(output);
                }
            }
            outputs = kept;
            outputs.push((icons.try_clone()?, name, file));
        }
    }
    // Native menu rendering replaces the captured Python boot-menu invocation.
    ongoing()?;
    let mut material = crate::boot_menu::material(Path::new(ESP), false)?;
    for name in ["recovery.conf", "power.conf", "refind.conf"] {
        let bytes = material
            .remove(name)
            .ok_or_else(|| Error("complete native boot menu material missing".into()))?;
        let file = output(&frontend, name, &bytes)?;
        outputs.push((frontend.try_clone()?, name.into(), file));
    }
    ongoing()?;
    for (parent, name, file) in &outputs {
        let named = files::open_relative(parent, Path::new(name))?;
        require(
            files::identity(&named.metadata()?) == files::identity(&file.metadata()?),
            "owned boot output replaced/changed",
        )?;
    }
    for (flavor, file) in &kernels {
        let named = files::open_relative(&esp.directory, Path::new(&format!("vmlinuz-{flavor}")))?;
        require(
            files::identity(&named.metadata()?) == files::identity(&file.metadata()?),
            "owned copied kernel replaced",
        )?;
    }
    subvolume::sync(root.directory.as_fd())?;
    esp.directory.sync_all()?;
    drop(published_keys);
    drop(authority_file);
    authority.close()?;
    entered()?;
    set_root_readonly(&root, &guard, false, &mut || entered())?;
    // No vendor or restored tool runs beyond this point. Publish the pending
    // recovery-image marker, retire the exact original active pin, then finish
    // the original receipt. Each transition retains its actual descriptions.
    let original_pin = pin.original_for_retirement()?;
    entered()?;
    let marker = files::atomic_relative_retained(
        ram.control(),
        Path::new("recovery-image-pending"),
        b"",
        0o600,
        Some(0),
        false,
        1,
    )?;
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    ram.recheck()?;
    root.recheck(&guard)?;
    home.recheck(&guard)?;
    stage.recheck(&guard)?;
    esp.recheck()?;
    keys.recheck()?;
    original_pin.recheck()?;
    receipt.recheck()?;
    let retired_pin = original_pin.retire_repository(&files::random_hex(16)?)?;
    retired_pin.recheck()?;
    let marker_named = files::open_relative(ram.control(), Path::new("recovery-image-pending"))?;
    require(
        files::identity(&marker_named.metadata()?) == files::identity(&marker.metadata()?),
        "owned pending recovery marker replaced",
    )?;
    record["phase"] = value!("uefi-boot-prepared");
    super::super::validate_complete(&record, stage_uuid)?;
    receipt.replace_original(&record)?;
    receipt.recheck()?;
    retired_pin.recheck()?;
    root.recheck(&guard)?;
    home.recheck(&guard)?;
    stage.recheck(&guard)?;
    esp.recheck()?;
    lock.recheck()?;
    Ok(
        value!({"status":"complete-uefi-boot-prepared","snapshot":record["snapshot"],"boot_verified":false,"authority_replayed":false,"automatic_backup_enabled":false}),
    )
}
