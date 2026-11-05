//! vercmp.rs: Version comparison for upgrade decisions.

use std::cmp::Ordering;

/// A parsed, comparable version.
#[derive(Debug, Eq, PartialEq)]
pub struct Version {
    parts: Vec<u64>,
    suffix: String,
    release: u64,
}

impl Version {
    pub fn parse(s: &str) -> Self {
        let (s, release) = split_release(s);
        let (numeric, suffix) = split_suffix(s);
        let parts = numeric
            .split('.')
            .filter_map(|p| p.parse::<u64>().ok())
            .collect();
        Self {
            parts,
            suffix: suffix.to_string(),
            release,
        }
    }
}

/// Splits a trailing `-rN` package release off; no release counts as 0.
fn split_release(s: &str) -> (&str, u64) {
    if let Some(i) = s.rfind("-r") {
        if let Ok(n) = s[i + 2..].parse::<u64>() {
            return (&s[..i], n);
        }
    }
    (s, 0)
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let max = self.parts.len().max(other.parts.len());
        for i in 0..max {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        self.suffix
            .cmp(&other.suffix)
            .then(self.release.cmp(&other.release))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Returns `true` when `remote` is strictly newer than `local`.
pub fn is_upgrade(local: &str, remote: &str) -> bool {
    Version::parse(remote) > Version::parse(local)
}

fn split_suffix(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() || c == '.' {
            i += 1;
        } else {
            break;
        }
    }
    (&s[..i], &s[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_minor() {
        assert!(is_upgrade("26.0.0", "26.1.0"));
    }
    #[test]
    fn newer_patch() {
        assert!(is_upgrade("1.2.5", "1.2.6"));
    }
    #[test]
    fn same_not_upgrade() {
        assert!(!is_upgrade("5.2", "5.2"));
    }
    #[test]
    fn older_not_upgrade() {
        assert!(!is_upgrade("26.1.0", "26.0.0"));
    }
    #[test]
    fn apk_revision() {
        assert!(is_upgrade("9.1.0-r0", "9.1.0-r1"));
    }
    #[test]
    fn git_snapshot() {
        assert!(is_upgrade("1.0", "1.0.g20260627"));
    }
    #[test]
    fn pkgrel_rebuild() {
        assert!(is_upgrade("3.18.3", "3.18.3-r1"));
    }
    #[test]
    fn pkgrel_numeric() {
        assert!(is_upgrade("3.18.3-r9", "3.18.3-r10"));
    }
    #[test]
    fn pkgrel_r0_same() {
        assert!(!is_upgrade("3.18.3", "3.18.3-r0"));
    }
    #[test]
    fn new_version_beats_release() {
        assert!(is_upgrade("3.18.3-r5", "3.18.4"));
    }
    #[test]
    fn empty_suffix_lt_any() {
        assert!(is_upgrade("1.0", "1.0-r1"));
    }
}
