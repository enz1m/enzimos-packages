// SPDX-License-Identifier: MIT
//! Original durable worker intent. Interrupted entry is never replayed or adopted.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const LIMIT: usize = 128 * 1024;
const CAPACITY: usize = 128;
fn identifier(s: &str) -> bool {
    crate::backup_worker_request::id(s).is_ok()
}
pub(crate) fn worker(v: &Value, id: &str) -> Result<()> {
    json::fields(v, "schema id unit group worker cgroup")?;
    let unit = enzimos_platform::backup_worker_scope::unit(id)?;
    crate::update_worker_record::process(&v["worker"])?;
    json::fields(&v["cgroup"], "device inode mode uid gid mount")?;
    require(
        v["schema"] == 1
            && v["id"] == id
            && v["unit"] == unit
            && v["group"] == format!("/system.slice/{unit}")
            && ["device", "inode", "mount"]
                .iter()
                .all(|key| v["cgroup"][*key].as_u64().is_some_and(|n| n > 0))
            && v["cgroup"]["mode"].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFDIR
                    && n & 0o022 == 0
            })
            && v["cgroup"]["uid"] == 0
            && v["cgroup"]["gid"] == 0,
        "worker receipt binding shape differs from native backup role",
    )
}
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase request_sha256 request worker_scope_closed worker result",
    )?;
    crate::backup_worker_request::id(id)?;
    crate::backup_worker_request::request(&v["request"])?;
    require(
        v["schema"] == 2
            && v["id"] == id
            && v["request"]["id"] == id
            && v["request_sha256"] == json::fingerprint(&v["request"])?
            && matches!(
                v["phase"].as_str(),
                Some("prepared" | "starting" | "uncertain" | "complete")
            ),
        "original worker receipt schema/request/phase differs",
    )?;
    if !v["worker"].is_null() {
        worker(&v["worker"], id)?;
    }
    if v["phase"] == "starting" || v["phase"] == "complete" {
        crate::backup_worker_request::executable(&v["request"])?;
    }
    if v["phase"] == "complete" {
        require(
            v["worker_scope_closed"] == true && !v["worker"].is_null() && !v["result"].is_null(),
            "complete worker receipt lacks original observed closure/result",
        )?;
        crate::backup_worker_result::for_request(&v["result"], &v["request"])
    } else {
        require(
            v["worker_scope_closed"] == false
                && v["result"].is_null()
                && (v["phase"] != "prepared" || v["worker"].is_null()),
            "unfinished worker receipt cannot manufacture closure/result",
        )
    }
}

type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "private native backup worker directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
struct Record {
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    value: Value,
}
struct Store<'g> {
    path: PathBuf,
    directory: File,
    shape: Shape,
    mount: u64,
    owner: u32,
    records: BTreeMap<String, Record>,
    guard: Box<dyn Fn() -> Result<()> + 'g>,
}
impl<'g> Store<'g> {
    fn names(&self) -> Result<Vec<String>> {
        let mut result = Vec::new();
        for entry in files::directory_names(&self.directory, CAPACITY)? {
            require(
                result.len() < CAPACITY,
                "native backup worker capacity or interrupted files require review",
            )?;
            let name = entry.into_string().map_err(|_| {
                enzimos_platform::Error("native backup worker filename encoding".into())
            })?;
            require(
                name.strip_suffix(".json").is_some_and(identifier),
                "unknown/interrupted native backup worker file requires review",
            )?;
            result.push(name);
        }
        result.sort();
        Ok(result)
    }
    fn read(&self, name: &str) -> Result<Record> {
        let file = files::open_relative(&self.directory, Path::new(name))?;
        let m = file.metadata()?;
        require(
            m.uid() == self.owner
                && m.gid() == self.directory.metadata()?.gid()
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "protected native backup worker inode required",
        )?;
        let bytes = files::read_file(&file, LIMIT, Some(self.owner), true)?;
        let value = json::decode(&bytes, LIMIT)?;
        validate(&value, name.strip_suffix(".json").unwrap())?;
        let identity = files::identity(&m);
        require(
            files::identity(&file.metadata()?) == identity,
            "native backup worker changed during read",
        )?;
        Ok(Record {
            file,
            identity,
            bytes,
            value,
        })
    }
    fn retained(
        path: &Path,
        owner: u32,
        mount: u64,
        guard: Box<dyn Fn() -> Result<()> + 'g>,
    ) -> Result<Self> {
        guard()?;
        let directory = files::directory(path, Some(owner))?;
        require(
            mount_identity::id(directory.as_fd(), true)? == mount,
            "native backup worker directory outside original control mount",
        )?;
        let mut this = Self {
            path: path.into(),
            shape: shape(&directory, owner)?,
            directory,
            mount,
            owner,
            records: BTreeMap::new(),
            guard,
        };
        for name in this.names()? {
            this.records.insert(name.clone(), this.read(&name)?);
        }
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        self.recheck_originals(true)
    }
    // Read-only completed witnesses cannot start/change records. They retain
    // every original inode while a later fresh attempt adds its own record.
    fn recheck_originals(&self, membership: bool) -> Result<()> {
        (self.guard)()?;
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.directory, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && (!membership
                    || self.names()? == self.records.keys().cloned().collect::<Vec<_>>()),
            "original native backup worker directory/membership changed",
        )?;
        for (name, row) in &self.records {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&row.file.metadata()?) == row.identity
                    && files::identity(&named.metadata()?) == row.identity
                    && mount_identity::id(row.file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && files::read_file(&row.file, LIMIT, Some(self.owner), true)? == row.bytes,
                "original native backup worker epoch changed or replaced",
            )?;
        }
        (self.guard)()
    }
    fn prepare(&mut self, request: &Value) -> Result<()> {
        self.recheck()?;
        crate::backup_worker_request::request(request)?;
        require(
            request["consumer_input"].is_null(),
            "consumer publication must follow original durable prepared intent",
        )?;
        require(
            self.records.len() < CAPACITY
                && self
                    .records
                    .values()
                    .all(|r| r.value["phase"] == "complete"),
            "unfinished native worker/capacity requires inspection; no replay",
        )?;
        let id = request["id"].as_str().unwrap();
        let name = format!("{id}.json");
        require(
            !self.records.contains_key(&name),
            "native worker ID already exists; no replay",
        )?;
        let v = value!({"schema":2,"id":id,"phase":"prepared","request_sha256":json::fingerprint(request)?,"request":request,"worker_scope_closed":false,"worker":null,"result":null});
        validate(&v, id)?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_relative_retained(
            &self.directory,
            Path::new(&name),
            &bytes,
            0o600,
            Some(self.owner),
            false,
            LIMIT,
        )?;
        self.records.insert(
            name,
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v,
            },
        );
        self.recheck()
    }
    fn attach_input(&mut self, id: &str, evidence: &Value) -> Result<()> {
        self.recheck()?;
        let name = format!("{id}.json");
        let row = self.records.get(&name).ok_or_else(|| {
            enzimos_platform::Error("original prepared input intent missing".into())
        })?;
        require(
            row.value["phase"] == "prepared"
                && row.value["request"]["task"] == "authenticate-input"
                && row.value["request"]["consumer_input"].is_null(),
            "input may be attached once to original prepared intent only",
        )?;
        let mut v = row.value.clone();
        v["request"]["consumer_input"] = evidence.clone();
        v["request_sha256"] = value!(json::fingerprint(&v["request"])?);
        validate(&v, id)?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_replace_original(
            &self.directory,
            Path::new(&name),
            &bytes,
            0o600,
            Some(self.owner),
            LIMIT,
            &row.file,
        )?;
        self.records.insert(
            name,
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v,
            },
        );
        self.recheck()
    }
    fn attach_worker(&mut self, id: &str, binding: &Value) -> Result<()> {
        self.recheck()?;
        worker(binding, id)?;
        let name = format!("{id}.json");
        let row = self.records.get(&name).ok_or_else(|| {
            enzimos_platform::Error("original starting worker intent missing".into())
        })?;
        require(
            row.value["phase"] == "starting" && row.value["worker"].is_null(),
            "measured original worker may attach once only",
        )?;
        let mut v = row.value.clone();
        v["worker"] = binding.clone();
        self.publish_original(&name, v)?;
        Ok(())
    }
    fn complete(&mut self, id: &str, binding: &Value, result: &Value) -> Result<Value> {
        self.recheck()?;
        let name = format!("{id}.json");
        let row = self.records.get(&name).ok_or_else(|| {
            enzimos_platform::Error("original started worker intent missing".into())
        })?;
        require(
            row.value["phase"] == "starting"
                && row.value["worker"] == *binding
                && !binding.is_null(),
            "completion differs from original measured worker",
        )?;
        let mut v = row.value.clone();
        v["phase"] = value!("complete");
        v["worker_scope_closed"] = value!(true);
        v["result"] = result.clone();
        self.publish_original(&name, v)
    }
    fn publish_original(&mut self, name: &str, v: Value) -> Result<Value> {
        self.recheck()?;
        validate(&v, name.strip_suffix(".json").unwrap())?;
        let row = self
            .records
            .get(name)
            .ok_or_else(|| enzimos_platform::Error("original worker record missing".into()))?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_replace_original(
            &self.directory,
            Path::new(name),
            &bytes,
            0o600,
            Some(self.owner),
            LIMIT,
            &row.file,
        )?;
        self.records.insert(
            name.into(),
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v.clone(),
            },
        );
        self.recheck()?;
        Ok(v)
    }
    fn change(&mut self, id: &str, phase: &str) -> Result<Value> {
        self.recheck()?;
        let name = format!("{id}.json");
        let row = self.records.get(&name).ok_or_else(|| {
            enzimos_platform::Error("original native worker intent missing".into())
        })?;
        require(
            matches!(
                (row.value["phase"].as_str(), phase),
                (Some("prepared"), "starting" | "uncertain") | (Some("starting"), "uncertain")
            ),
            "native worker cannot restart or manufacture completion",
        )?;
        let mut v = row.value.clone();
        v["phase"] = value!(phase);
        validate(&v, id)?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_replace_original(
            &self.directory,
            Path::new(&name),
            &bytes,
            0o600,
            Some(self.owner),
            LIMIT,
            &row.file,
        )?;
        self.records.insert(
            name,
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v.clone(),
            },
        );
        self.recheck()?;
        Ok(v)
    }
}
pub struct Intent<'g> {
    store: Store<'g>,
    id: String,
    image: crate::backup_setup_image::Image,
    lock: &'g files::Lock,
    source: &'g crate::storage_runtime::Guard,
    additional: Box<dyn Fn() -> Result<()> + 'g>,
}
/// Consumed completed intent. It has no start, attach, change or completion API.
pub struct Completed<'g> {
    intent: Intent<'g>,
}
impl Completed<'_> {
    pub fn recheck(&self) -> Result<()> {
        (self.intent.additional)()?;
        self.intent.image.recheck()?;
        self.intent.store.recheck_originals(false)?;
        let row = &self.intent.store.records[&format!("{}.json", self.intent.id)];
        require(
            row.value["phase"] == "complete" && row.value["worker_scope_closed"] == true,
            "original completed worker witness required",
        )
    }
    pub fn value(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            self.intent.store.records[&format!("{}.json", self.intent.id)]
                .value
                .clone(),
        )
    }
}
impl<'g> Intent<'g> {
    pub fn into_completed(self) -> Result<Completed<'g>> {
        self.recheck()?;
        let this = Completed { intent: self };
        this.recheck()?;
        Ok(this)
    }
    pub fn prepare(
        request: &Value,
        guard: &'g crate::storage_runtime::Guard,
        lock: &'g files::Lock,
        authorize: &'g dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        Self::prepare_checked(request, guard, lock, authorize, Box::new(|| Ok(())))
    }
    /// Additional original typed coordinator guards may restrict every boundary;
    /// they never replace source, caller, lock or fresh authorization checks.
    pub fn prepare_checked(
        request: &Value,
        guard: &'g crate::storage_runtime::Guard,
        lock: &'g files::Lock,
        authorize: &'g dyn Fn() -> Result<()>,
        additional: Box<dyn Fn() -> Result<()> + 'g>,
    ) -> Result<Self> {
        crate::namespaces::initial()?;
        additional()?;
        crate::backup_worker_request::request(request)?;
        guard.recheck()?;
        lock.recheck()?;
        authorize()?;
        let image = crate::backup_setup_image::Image::open()?;
        require(
            image.actor()? == request["caller"]
                && guard.backup_root_binding()? == request["plan"]["source"],
            "native worker intent differs from actual original caller/source",
        )?;
        let directory = files::ensure_directory_relative(
            guard.control(),
            Path::new("backup-native-workers"),
            0o700,
            0,
        )?;
        require(
            mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
            "native worker journal outside original control mount",
        )?;
        let path = Path::new(crate::operation::CONTROL).join("backup-native-workers");
        let mut store = Store::retained(
            &path,
            0,
            guard.control_mount_id(),
            Box::new(|| {
                guard.recheck()?;
                lock.recheck()?;
                authorize()
            }),
        )?;
        store.prepare(request)?;
        let this = Self {
            store,
            id: request["id"].as_str().unwrap().into(),
            image,
            lock,
            source: guard,
            additional,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        (self.additional)()?;
        self.image.recheck()?;
        self.store.recheck()
    }
    pub fn source(&self) -> Result<&crate::storage_runtime::Guard> {
        self.recheck()?;
        Ok(self.source)
    }
    pub fn caller_descriptors(&self) -> Result<(&File, std::os::fd::BorrowedFd<'_>, &File)> {
        self.recheck()?;
        let (image, pidfd) = self.image.descriptors()?;
        Ok((image, pidfd, self.lock.as_file()))
    }
    /// The caller creates the original temporary only after prepare(), using
    /// recheck() at every copy boundary. Only this typed original can update the
    /// prepared request; JSON cannot attach a replacement credential authority.
    pub fn attach_input(&mut self, input: &crate::backup_auth_input::Temporary<'_>) -> Result<()> {
        self.recheck()?;
        let request = &self.store.records[&format!("{}.json", self.id)].value["request"];
        let (original, reader) = input.input_binding()?;
        require(
            request["credential"]["identity"] == original && request["reader"] == reader,
            "temporary differs from original prepared sealed input/validator",
        )?;
        self.store.attach_input(&self.id, &input.evidence()?)?;
        input.recheck()?;
        self.recheck()
    }
    pub fn attach_worker(
        &mut self,
        scope: &enzimos_platform::backup_worker_scope::Scope,
    ) -> Result<()> {
        self.recheck()?;
        self.store.attach_worker(&self.id, scope.binding()?)?;
        scope.binding()?;
        self.recheck()
    }
    /// Every proof is an original live-captured object. No JSON or callback can
    /// manufacture worker, temporary-input or normal mount completion.
    pub fn complete<T>(
        &mut self,
        observation: &crate::backup_worker_observation::Observation,
        closed: &enzimos_platform::backup_worker_scope::Closed,
        mount: &crate::backup_setup_mount::Closed<'_, '_, '_, T>,
        input: Option<&crate::backup_auth_input::Retired<'_>>,
    ) -> Result<Value> {
        self.recheck()?;
        let request = &self.store.records[&format!("{}.json", self.id)].value["request"];
        require(
            mount.binding()? == &request["mount"],
            "worker completion differs from original normally closed mount",
        )?;
        if request["consumer_input"].is_null() {
            require(
                input.is_none(),
                "stored credential cannot substitute temporary retirement",
            )?;
        } else {
            let input = input.ok_or_else(|| {
                enzimos_platform::Error("original temporary retirement proof required".into())
            })?;
            require(
                input.evidence()? == &request["consumer_input"],
                "temporary retirement differs from original consumer input",
            )?;
        }
        let result = observation.completed(request, closed)?;
        let binding = closed.binding()?.clone();
        self.recheck()?;
        let value = self.store.complete(&self.id, &binding, &result)?;
        closed.recheck()?;
        mount.recheck()?;
        if let Some(input) = input {
            input.recheck()?;
        }
        self.recheck()?;
        Ok(value)
    }
    /// Must precede scratch creation/PID1 start; a repeated call is refused.
    pub fn starting(&mut self) -> Result<Value> {
        self.recheck()?;
        let value = self.store.change(&self.id, "starting")?;
        self.recheck()?;
        Ok(value)
    }
    pub fn uncertain(&mut self) -> Result<Value> {
        self.recheck()?;
        self.store.change(&self.id, "uncertain")
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.store.records[&format!("{}.json", self.id)].file)
    }
    pub fn value(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.store.records[&format!("{}.json", self.id)]
            .value
            .clone())
    }
}
