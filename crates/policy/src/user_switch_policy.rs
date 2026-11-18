// SPDX-License-Identifier: MIT
//! Typed local-session decisions. Data alone never grants D-Bus caller authority.
use enzimos_platform::{Error, Result, require};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub path: String,
    pub uid: u32,
    pub seat: String,
    pub kind: String,
    pub session_type: String,
    pub service: String,
    pub vt: u32,
    pub active: bool,
    pub remote: bool,
    pub locked: bool,
}
pub const POOL: [u32; 4] = [3, 4, 5, 6];
pub fn local(
    s: &Session,
    uid: u32,
    kind: &str,
    active: Option<bool>,
    locked: Option<bool>,
) -> Result<()> {
    require(
        uid < u32::MAX && s.uid == uid && s.seat == "seat0" && !s.remote && s.kind == kind,
        "Not authorized",
    )?;
    require(
        matches!(s.session_type.as_str(), "wayland" | "x11")
            || kind == "greeter" && s.session_type == "tty",
        "Not authorized",
    )?;
    require(
        !s.id.is_empty() && s.vt > 0 && (kind != "greeter" || s.service == "greetd"),
        "Not authorized",
    )?;
    require(active.is_none_or(|v| s.active == v), "Not authorized")?;
    require(
        locked.is_none_or(|v| s.locked == v),
        "Session must be locked",
    )
}
#[derive(Debug, PartialEq, Eq)]
pub enum Choice {
    Activate(usize),
    Start(u32),
}
pub fn choose(
    sessions: &[Session],
    states: &std::collections::BTreeMap<u32, String>,
    greeter: u32,
) -> Result<Choice> {
    require(sessions.len() <= 128, "Unavailable")?;
    for (i, row) in sessions.iter().enumerate() {
        if row.uid == greeter && row.kind == "greeter" && POOL.contains(&row.vt) {
            local(row, greeter, "greeter", None, None)?;
            if !sessions.iter().any(|s| s.vt == row.vt && s.kind == "user") {
                return Ok(Choice::Activate(i));
            }
        }
    }
    for vt in POOL {
        if !sessions.iter().any(|s| s.vt == vt)
            && states
                .get(&vt)
                .is_some_and(|s| matches!(s.as_str(), "inactive" | "failed"))
        {
            return Ok(Choice::Start(vt));
        }
    }
    Err(Error("No more sessions can be opened".into()))
}
pub fn existing(caller: &Session, target: &Session, greeter: u32) -> Result<()> {
    local(caller, greeter, "greeter", Some(true), None)?;
    require(
        target.uid != greeter && target.id != caller.id,
        "Not authorized",
    )?;
    local(target, target.uid, "user", None, Some(true))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row() -> Session {
        Session {
            id: "1".into(),
            path: "/session/1".into(),
            uid: 1000,
            seat: "seat0".into(),
            kind: "user".into(),
            session_type: "wayland".into(),
            service: "greetd".into(),
            vt: 3,
            active: true,
            remote: false,
            locked: true,
        }
    }
    #[test]
    fn refuse_remote_unlocked_wrong_seat_and_identity() {
        let mut s = row();
        assert!(local(&s, 1000, "user", Some(true), Some(true)).is_ok());
        s.remote = true;
        assert!(local(&s, 1000, "user", None, None).is_err());
        s.remote = false;
        s.locked = false;
        assert!(local(&s, 1000, "user", None, Some(true)).is_err());
        s.locked = true;
        s.seat = "seat1".into();
        assert!(local(&s, 1000, "user", None, None).is_err());
    }
}
