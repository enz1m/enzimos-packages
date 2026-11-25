// SPDX-License-Identifier: MIT
//! Retained actual offline retirement record. Data cannot grant deletion/replay.
use crate::{
    control_record::{Predecessor, Retained},
    root_retirement_offline_control::Control,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    cell::RefCell,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "root-retirements";
const LIMIT: usize = 2 * 1024 * 1024;
pub struct Journal<'a, 's> {
    control: &'a Control<'a, 's>,
    folder: File,
    folder_flags: i32,
    mount: u64,
    id: String,
    prepared: Value,
    state: RefCell<State>,
}
struct State {
    first_delete_attempted: bool,
    cursor_attempt: Option<usize>,
    folder_epoch: files::FileIdentity,
    current: Retained,
    current_flags: i32,
    predecessors: Vec<Predecessor>,
    uncertain: bool,
}
pub struct Entered<'j, 'a, 's> {
    original: &'j Journal<'a, 's>,
    sealed: &'j crate::root_retirement_seal::Installed<'a, 's>,
}
pub struct StepEntered<'j, 'a, 's> {
    original: Entered<'j, 'a, 's>,
}
fn entered_data(prepared: &Value) -> Result<Value> {
    require(
        prepared["phase"] == "prepared"
            && prepared["next_step"] == 0
            && prepared["inflight"].is_null()
            && prepared["targets"]
                .as_array()
                .is_some_and(|v| (1..=64).contains(&v.len())),
        "one original unstarted prepared receipt required",
    )?;
    let mut result = prepared.clone();
    result["phase"] = value!("executing");
    Ok(result)
}
fn first_step_data(prepared: &Value) -> Result<Value> {
    let mut result = entered_data(prepared)?;
    result["inflight"] = value!(0);
    Ok(result)
}
fn first_advanced_data(prepared: &Value) -> Result<Value> {
    let mut result = entered_data(prepared)?;
    result["next_step"] = value!(1);
    result["phase"] = value!(
        if enzimos_platform::json::array(&prepared["targets"])?.len() == 1 {
            "deleted"
        } else {
            "executing"
        }
    );
    Ok(result)
}
fn second_step_data(prepared: &Value) -> Result<Value> {
    let mut result = first_advanced_data(prepared)?;
    require(
        result["phase"] == "executing",
        "all original targets already deleted",
    )?;
    result["inflight"] = value!(1);
    Ok(result)
}
fn cursor_data(prepared: &Value, index: usize, inflight: bool) -> Result<Value> {
    let mut result = entered_data(prepared)?;
    let count = enzimos_platform::json::array(&prepared["targets"])?.len();
    require(
        index >= 1 && index <= count && (!inflight || index < count),
        "original remaining progress bound",
    )?;
    result["next_step"] = value!(index);
    result["inflight"] = if inflight { value!(index) } else { Value::Null };
    result["phase"] = value!(if index == count {
        "deleted"
    } else {
        "executing"
    });
    Ok(result)
}
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline journal folder flags",
    )?;
    Ok(flags)
}
fn private(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let m = file.metadata()?;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && mount_identity::id(file.as_fd(), true)? == mount,
        "actual Root-private offline journal folder required",
    )?;
    Ok(files::identity(&m))
}
impl<'a, 's> Journal<'a, 's> {
    pub(crate) fn identifier(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.id)
    }
    pub(crate) fn require_original_folder(&self, folder: &File) -> Result<files::FileIdentity> {
        self.recheck()?;
        let state = self
            .state
            .try_borrow()
            .map_err(|_| Error("original offline receipt publication is active".into()))?;
        require(
            private(folder, self.mount)? == state.folder_epoch,
            "offline reference folder differs from original owned receipt lineage",
        )?;
        Ok(state.folder_epoch)
    }
    pub(crate) fn require_original_control(&self, control: &Control<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.control, control),
            "actual original offline journal/control pair differs",
        )?;
        self.recheck()
    }
    pub fn observe(control: &'a Control<'a, 's>, id: &str) -> Result<Self> {
        control.recheck()?;
        crate::identity::safe_id(id)?;
        let mount = control.mount_id()?;
        let folder = files::directory_relative(control.descriptor()?, Path::new(FOLDER), Some(0))?;
        let folder_epoch = private(&folder, mount)?;
        let original = Retained::open(&folder, Path::new(&format!("{id}.json")), LIMIT, mount)?;
        crate::root_retirement_record::validate(original.value()?, id)?;
        require(
            original.value()?["filesystem_uuid"]
                == crate::filesystem::observe(control.descriptor()?.as_fd())?["filesystem_uuid"],
            "offline retirement record belongs to another actual filesystem",
        )?;
        let this = Self {
            control,
            folder_flags: flags(&folder)?,
            folder,
            mount,
            id: id.into(),
            prepared: original.value()?.clone(),
            state: RefCell::new(State {
                first_delete_attempted: false,
                cursor_attempt: None,
                folder_epoch,
                current_flags: flags(original.descriptor()?)?,
                current: original,
                predecessors: Vec::new(),
                uncertain: false,
            }),
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.control.recheck()?;
        let state = self
            .state
            .try_borrow()
            .map_err(|_| Error("original offline receipt publication is active".into()))?;
        require(
            !state.uncertain,
            "original offline receipt publication uncertain; review required",
        )?;
        state.current.recheck()?;
        for predecessor in &state.predecessors {
            predecessor.recheck()?;
        }
        let named =
            files::directory_relative(self.control.descriptor()?, Path::new(FOLDER), Some(0))?;
        require(
            private(&self.folder, self.mount)? == state.folder_epoch
                && private(&named, self.mount)? == state.folder_epoch
                && flags(&self.folder)? == self.folder_flags,
            "original offline journal parent replaced/changed/covered",
        )?;
        let record = files::open_relative(&self.folder, Path::new(&format!("{}.json", self.id)))?;
        require(
            files::identity(&record.metadata()?)
                == files::identity(&state.current.descriptor()?.metadata()?)
                && mount_identity::id(record.as_fd(), true)? == self.mount
                && flags(state.current.descriptor()?)? == state.current_flags,
            "original offline record is not the exact held folder member or flags changed",
        )?;
        crate::root_retirement_record::validate(state.current.value()?, &self.id)?;
        require(
            state.current.value()?["filesystem_uuid"]
                == crate::filesystem::observe(self.control.descriptor()?.as_fd())?["filesystem_uuid"],
            "original offline record/source filesystem changed",
        )?;
        self.control.recheck()
    }
    /// Read-only diagnostic data; no cold in-flight row authorizes a delete.
    pub fn record(&self) -> Result<Value> {
        self.recheck()?;
        let state = self
            .state
            .try_borrow()
            .map_err(|_| Error("original offline receipt publication is active".into()))?;
        Ok(state.current.value()?.clone())
    }
    pub(crate) fn prepared_record(&self) -> Result<Value> {
        self.recheck()?;
        require(
            self.prepared["phase"] == "prepared"
                && self.prepared["next_step"] == 0
                && self.prepared["inflight"].is_null(),
            "cold in-flight record cannot supply original prepared lineage",
        )?;
        Ok(self.prepared.clone())
    }
    /// Only the still-live original sealed actor can durably enter once. This
    /// receipt does not perform or grant a delete, and cannot be cold replayed.
    pub fn enter<'j>(
        &'j self,
        sealed: &'j crate::root_retirement_seal::Installed<'a, 's>,
    ) -> Result<Entered<'j, 'a, 's>> {
        sealed.require_original_journal(self)?;
        self.prepared_record()?;
        let next = entered_data(&self.prepared)?;
        self.publish_owned(&self.prepared, &next, 0)?;
        self.recheck()?;
        sealed.require_original_journal(self)?;
        let result = Entered {
            original: self,
            sealed,
        };
        result.recheck()?;
        Ok(result)
    }
    fn publish_owned(&self, previous: &Value, next: &Value, predecessors: usize) -> Result<()> {
        self.recheck()?;
        crate::root_retirement_record::validate(next, &self.id)?;
        {
            let mut state = self
                .state
                .try_borrow_mut()
                .map_err(|_| Error("original offline receipt publication is active".into()))?;
            require(
                state.predecessors.len() == predecessors && state.current.value()? == previous,
                "original offline receipt already attempted; no replay",
            )?;
            state.uncertain = true;
            let predecessor = state.current.replace_with_predecessor(next)?;
            let epoch = private(&self.folder, self.mount)?;
            let before = state.folder_epoch;
            require(
                (before.0, before.1, before.7, before.8, before.9)
                    == (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9),
                "actual receipt publication changed original parent identity",
            )?;
            state.folder_epoch = epoch;
            state.current_flags = flags(state.current.descriptor()?)?;
            state.predecessors.push(predecessor);
            state.uncertain = false;
        }
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let state = self
            .state
            .try_borrow()
            .map_err(|_| Error("original offline receipt publication is active".into()))?;
        let result = value!({"id":self.id,"record":state.current.evidence()?,
            "folder_epoch":state.folder_epoch,"owned_predecessors_retained":state.predecessors.len(),"mount":self.mount,"execution_authorized":false,
            "cold_replay_available":false});
        drop(state);
        self.recheck()?;
        Ok(result)
    }
}
impl<'j, 'a, 's> Entered<'j, 'a, 's> {
    /// Consume this actual entry and persist the first original in-flight step.
    /// There is no decoded-row constructor or cold continuation.
    pub fn begin_first(self) -> Result<StepEntered<'j, 'a, 's>> {
        self.recheck()?;
        let previous = entered_data(&self.original.prepared)?;
        let next = first_step_data(&self.original.prepared)?;
        self.original.publish_owned(&previous, &next, 1)?;
        let result = StepEntered { original: self };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.sealed.require_original_journal(self.original)?;
        self.original.recheck()?;
        let state = self
            .original
            .state
            .try_borrow()
            .map_err(|_| Error("original offline receipt publication is active".into()))?;
        let expected = entered_data(&self.original.prepared)?;
        require(
            state.predecessors.len() == 1 && state.current.value()? == &expected,
            "actual entered receipt no longer has its original owned lineage",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"actual_durable_execution_entry":true,"original_predecessor_retained":true,
            "execution_authorized":false,"cold_replay_available":false}),
        )
    }
}
impl<'j, 'a, 's> StepEntered<'j, 'a, 's> {
    pub(crate) fn cursor_lineage(
        &self,
        index: usize,
        inflight: bool,
        attempted: Option<usize>,
    ) -> Result<()> {
        let journal = self.original.original;
        journal.recheck()?;
        let state = journal
            .state
            .try_borrow()
            .map_err(|_| Error("original remaining publication is active".into()))?;
        let predecessors = 2 * index + if inflight { 2 } else { 1 };
        require(
            state.first_delete_attempted
                && state.cursor_attempt == attempted
                && state.predecessors.len() == predecessors
                && state.current.value()? == &cursor_data(&journal.prepared, index, inflight)?,
            "remaining actor differs from actual owned receipt and attempt lineage",
        )
    }
    pub(crate) fn mark_cursor_attempt(
        &self,
        proof: &crate::root_retirement_cursor::Executing<'j, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_step(self)?;
        proof.recheck()?;
        let mut state = self
            .original
            .original
            .state
            .try_borrow_mut()
            .map_err(|_| Error("original remaining attempt is active".into()))?;
        state.cursor_attempt = Some(proof.index());
        Ok(())
    }
    pub(crate) fn advance_cursor(
        &self,
        proof: &crate::root_retirement_cursor::Succeeded<'j, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_step(self)?;
        proof.recheck()?;
        let index = proof.index();
        let journal = self.original.original;
        journal.publish_owned(
            &cursor_data(&journal.prepared, index, true)?,
            &cursor_data(&journal.prepared, index + 1, false)?,
            2 * index + 2,
        )
    }
    pub(crate) fn begin_cursor(
        &self,
        proof: &crate::root_retirement_cursor::Progress<'j, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_step(self)?;
        proof.recheck()?;
        let index = proof.next_index();
        let journal = self.original.original;
        journal.publish_owned(
            &cursor_data(&journal.prepared, index, false)?,
            &cursor_data(&journal.prepared, index, true)?,
            2 * index + 1,
        )
    }
    pub(crate) fn begin_second(
        &self,
        proof: &crate::root_retirement_first_delete::Advanced<'j, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_step(self)?;
        proof.recheck()?;
        let journal = self.original.original;
        journal.publish_owned(
            &first_advanced_data(&journal.prepared)?,
            &second_step_data(&journal.prepared)?,
            3,
        )?;
        self.require_second_inflight()
    }
    pub(crate) fn require_second_inflight(&self) -> Result<()> {
        let journal = self.original.original;
        journal.recheck()?;
        let state = journal
            .state
            .try_borrow()
            .map_err(|_| Error("original next in-flight publication is active".into()))?;
        require(
            state.first_delete_attempted
                && state.predecessors.len() == 4
                && state.current.value()? == &second_step_data(&journal.prepared)?,
            "actual next in-flight differs from original owned progress lineage",
        )
    }
    pub(crate) fn advance_first(
        &self,
        proof: &crate::root_retirement_first_delete::After<'j, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_step(self)?;
        proof.recheck()?;
        let journal = self.original.original;
        journal.publish_owned(
            &first_step_data(&journal.prepared)?,
            &first_advanced_data(&journal.prepared)?,
            2,
        )?;
        self.require_first_advanced()
    }
    pub(crate) fn require_first_advanced(&self) -> Result<()> {
        let journal = self.original.original;
        journal.recheck()?;
        let state = journal
            .state
            .try_borrow()
            .map_err(|_| Error("original progress publication is active".into()))?;
        require(
            state.first_delete_attempted
                && state.predecessors.len() == 3
                && state.current.value()? == &first_advanced_data(&journal.prepared)?,
            "actual first progress differs from original owned successful lineage",
        )
    }
    pub(crate) fn original_seal(&self) -> &'j crate::root_retirement_seal::Installed<'a, 's> {
        self.original.sealed
    }
    pub(crate) fn mark_first_attempt(&self) -> Result<()> {
        self.recheck()?;
        let mut state = self
            .original
            .original
            .state
            .try_borrow_mut()
            .map_err(|_| Error("original delete attempt is active".into()))?;
        require(
            !state.first_delete_attempted,
            "original first delete already attempted; no retry",
        )?;
        state.first_delete_attempted = true;
        Ok(())
    }
    pub(crate) fn require_actual_first_attempt(&self) -> Result<()> {
        self.original.original.recheck()?;
        let state = self
            .original
            .original
            .state
            .try_borrow()
            .map_err(|_| Error("original delete attempt is active".into()))?;
        require(
            state.first_delete_attempted
                && state.predecessors.len() == 2
                && state.current.value()? == &first_step_data(&self.original.original.prepared)?,
            "actual first syscall attempt differs from original durable in-flight lineage",
        )
    }
    pub fn prepare_first_delete(
        self,
    ) -> Result<crate::root_retirement_first_delete::First<'j, 'a, 's>> {
        crate::root_retirement_first_delete::First::prepare(self)
    }
    pub(crate) fn first_descriptions(
        &self,
    ) -> Result<crate::root_retirement_first_delete::Descriptions<'_>> {
        self.recheck()?;
        self.original.sealed.first_descriptions()
    }
    pub fn recheck(&self) -> Result<()> {
        let original = &self.original;
        original
            .sealed
            .require_original_journal(original.original)?;
        original.original.recheck()?;
        let state = original
            .original
            .state
            .try_borrow()
            .map_err(|_| Error("original offline receipt publication is active".into()))?;
        require(
            !state.first_delete_attempted
                && state.predecessors.len() == 2
                && state.current.value()? == &first_step_data(&original.original.prepared)?,
            "actual original first in-flight receipt no longer has its owned lineage",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"actual_durable_original_inflight_step":0,"owned_predecessors_retained":2,
            "execution_authorized":false,"cold_replay_available":false}),
        )
    }
}
