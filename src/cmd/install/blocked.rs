//! blocked.rs — Dependency names that must never resolve to a separate
//! userland package because Zainium's own syshub/core already provides
//! equivalent functionality under a different name (or built directly
//! into the base) — no file-level overlap for `backend::is_in_syshub` to
//! catch automatically, so this is an explicit, hand-maintained list.
//!
//! To block a new dependency name: add a `("dependency-name", "what
//! provides it")` pair below and rebuild. No other code changes needed —
//! `depends.rs` checks this alongside `is_in_syshub` for every dependency
//! token, so a blocked name is skipped before it's ever resolved/downloaded.

const BLOCKED: &[(&str, &str)] = &[
    ("coreutils", "userutils"),
];

/// Returns what provides `name`, if `name` is on the blocked list.
/// `name` should already be constraint-stripped and lowercased.
pub fn provided_by(name: &str) -> Option<&'static str> {
    BLOCKED
        .iter()
        .find(|(dep, _)| *dep == name)
        .map(|(_, provider)| *provider)
}
