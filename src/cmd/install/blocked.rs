//! blocked.rs — package names Zainium's base (syshub) already provides, so they
//! are never installed into userland. As a dependency a blocked name counts as
//! satisfied and is never downloaded; installing one directly is refused.
//!
//! This is the hand-kept fallback for names `backend::is_in_syshub` can't detect
//! from files (e.g. `coreutils`, which Zainium's own `userutils` replaces). To
//! block a name, add a `| "name"` line to the list in `provided_by`.

/// What in the base provides `name`, if `name` is blocked in userland.
/// `name` should already be constraint-stripped and lowercased.
pub fn provided_by(name: &str) -> Option<&'static str> {
    match name {
        "coreutils" => Some("userutils"),

        "musl" => Some("syshub"),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_names_are_blocked() {
        assert_eq!(provided_by("coreutils"), Some("userutils"));
        assert_eq!(provided_by("musl"), Some("syshub"));
        assert_eq!(provided_by("wget"), None);
    }
}
