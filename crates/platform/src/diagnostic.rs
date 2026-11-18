// SPDX-License-Identifier: MIT
//! Bounded single-line diagnostic text for the journal.
//!
//! Error strings in this workspace are fixed messages plus kernel/IO text; they
//! never carry credential contents. This still bounds length and strips control
//! characters so a hostile filename or label cannot forge journal lines.
const LIMIT: usize = 400;
pub fn bounded(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(LIMIT + 3));
    for (count, c) in text.chars().enumerate() {
        if count == LIMIT {
            out.push_str("...");
            break;
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}
