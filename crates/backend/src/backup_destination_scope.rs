// SPDX-License-Identifier: MIT
//! One actual destination close before terminal backup publication. The state
//! cannot be deserialized or constructed from a mount/receipt JSON observation.
use enzimos_platform::{Error, Result, require};
use enzimos_policy::{
    backup_destination::Destination,
    backup_setup_mount::{Active, Closed},
};
use std::cell::{Cell, RefCell};
pub(crate) trait Closure {
    fn require_destination(&self, destination: &Destination<'_>) -> Result<()>;
    fn recheck(&self) -> Result<()>;
    fn close(&self) -> Result<()>;
}
pub(crate) struct Owned<'a, 'r, 'd> {
    active: RefCell<Option<Active<'a, 'r, 'd>>>,
    closed: RefCell<Option<Closed<'a, 'r, 'd, ()>>>,
    entered_close: Cell<bool>,
}
impl<'a, 'r, 'd> Owned<'a, 'r, 'd> {
    /// Infallible so the owned mount is never dropped unclosed: every later
    /// use rechecks it, and `failed`/`close` settle it exactly once.
    pub(crate) fn new(active: Active<'a, 'r, 'd>) -> Self {
        Self {
            active: RefCell::new(Some(active)),
            closed: RefCell::new(None),
            entered_close: Cell::new(false),
        }
    }
    pub(crate) fn finish(self) -> Result<Closed<'a, 'r, 'd, ()>> {
        self.recheck()?;
        require(
            self.active.borrow().is_none() && self.entered_close.get(),
            "backup destination has not actually closed",
        )?;
        let closed = self
            .closed
            .into_inner()
            .ok_or_else(|| Error("original destination close proof unavailable".into()))?;
        closed.recheck()?;
        Ok(closed)
    }
    /// On an entered body failure close once without beginning a new authorized
    /// operation. Do not publish a successful journal/receipt for failed bodies.
    pub(crate) fn failed(&self, error: Error) -> Error {
        if self.entered_close.replace(true) {
            return error;
        }
        let active = { self.active.borrow_mut().take() };
        match active {
            Some(active) => match active.close_result::<()>(Err(error)) {
                Err(error) => error,
                Ok(_) => Error("failed backup cannot become a closed success".into()),
            },
            None => error,
        }
    }
}
impl Closure for Owned<'_, '_, '_> {
    fn require_destination(&self, destination: &Destination<'_>) -> Result<()> {
        self.recheck()?;
        let active = self.active.borrow();
        active
            .as_ref()
            .ok_or_else(|| Error("original destination already closing/closed".into()))?
            .require_destination(destination)
    }
    fn recheck(&self) -> Result<()> {
        if let Some(active) = self.active.borrow().as_ref() {
            require(
                !self.entered_close.get() && self.closed.borrow().is_none(),
                "original destination state conflict",
            )?;
            active.recheck()
        } else {
            require(
                self.entered_close.get(),
                "destination has no original active/closed owner",
            )?;
            self.closed
                .borrow()
                .as_ref()
                .ok_or_else(|| Error("destination closure failed or uncertain; no replay".into()))?
                .recheck()
        }
    }
    fn close(&self) -> Result<()> {
        self.recheck()?;
        require(
            !self.entered_close.replace(true),
            "destination closure already entered; no replay",
        )?;
        let active = { self.active.borrow_mut().take() }
            .ok_or_else(|| Error("actual destination owner unavailable".into()))?;
        // Nothing retains a RefCell borrow while the actual closure invokes
        // independent Source/authorization barriers.
        let closed = active.close()?;
        closed.recheck()?;
        *self.closed.borrow_mut() = Some(closed);
        self.recheck()
    }
}
