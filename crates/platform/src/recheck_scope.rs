// SPDX-License-Identifier: MIT
//! One composite check observes each retained actor once.
//!
//! The backup pipeline's composite checks recheck the same retained actors
//! (storage guard, sources, capture) from many nested callers. Within one
//! [`evaluation`] each actor's fresh observation is made once and then reused;
//! the next evaluation observes everything again, so no result outlives the
//! check that produced it. Only actors whose expected state cannot change
//! while they are borrowed may use [`once`]; authorization is never cached.
use crate::Result;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
    static DONE: RefCell<BTreeSet<(usize, &'static str)>> = const { RefCell::new(BTreeSet::new()) };
}
struct Entered;
impl Entered {
    fn new() -> Self {
        DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}
impl Drop for Entered {
    fn drop(&mut self) {
        let outermost = DEPTH.with(|depth| {
            depth.set(depth.get() - 1);
            depth.get() == 0
        });
        if outermost {
            DONE.with(|done| done.borrow_mut().clear());
        }
    }
}
/// Run one composite check; nested [`once`] observations inside it are shared.
pub fn evaluation<T>(check: impl FnOnce() -> T) -> T {
    let _entered = Entered::new();
    check()
}
/// Observe `actor` in `role` with `check` unless the current evaluation
/// already observed it successfully. Outside an evaluation this starts one.
///
/// # Errors
/// The error of `check`; a failed observation is not remembered.
pub fn once<T: ?Sized>(
    actor: &T,
    role: &'static str,
    check: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let key = (std::ptr::from_ref(actor).cast::<()>() as usize, role);
    evaluation(|| {
        if DONE.with(|done| done.borrow().contains(&key)) {
            return Ok(());
        }
        check()?;
        DONE.with(|done| done.borrow_mut().insert(key));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_actor_is_observed_once_per_evaluation_and_again_in_the_next() {
        let actor = 1u8;
        let count = Cell::new(0);
        let observe = || {
            once(&actor, "role", || {
                count.set(count.get() + 1);
                Ok(())
            })
        };
        evaluation(|| {
            observe().unwrap();
            observe().unwrap();
            evaluation(|| observe().unwrap());
        });
        assert_eq!(count.get(), 1);
        observe().unwrap();
        observe().unwrap();
        assert_eq!(count.get(), 3);
        evaluation(|| observe().unwrap());
        assert_eq!(count.get(), 4);
    }
    #[test]
    fn a_failed_observation_is_repeated_and_roles_and_actors_stay_apart() {
        let (one, two) = (1u8, 2u8);
        let count = Cell::new(0);
        evaluation(|| {
            assert!(once(&one, "role", || Err(crate::Error("changed".into()))).is_err());
            for (actor, role) in [
                (&one, "role"),
                (&one, "role"),
                (&one, "other"),
                (&two, "role"),
            ] {
                once(actor, role, || {
                    count.set(count.get() + 1);
                    Ok(())
                })
                .unwrap();
            }
        });
        assert_eq!(count.get(), 3);
    }
}
