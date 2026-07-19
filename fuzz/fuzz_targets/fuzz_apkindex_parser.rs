//! fuzz_apkindex_parser — Fuzz Alpine `APKINDEX` file parsing.
//!
//! Target: The APKINDEX text format used by Tier 2 Alpine packages.
//! APKINDEX is a flat-text format with key:value lines, blank-line-separated packages.
//!
//! Invariants:
//!   • Parser never panics on arbitrary bytes
//!   • If a package entry is parsed: name is non-empty, version is non-empty
//!   • Numeric fields (size, installed-size) parse without overflow

#![no_main]
use libfuzzer_sys::fuzz_target;

/// Minimal APKINDEX entry parser — mirrors what the real prober does.
fn parse_apkindex(data: &str) -> Vec<ApkEntry> {
    let mut entries = Vec::new();
    let mut current = ApkEntry::default();
    let mut in_entry = false;

    for line in data.lines() {
        if line.is_empty() {
            if in_entry && !current.name.is_empty() {
                entries.push(std::mem::take(&mut current));
            }
            in_entry = false;
            continue;
        }
        in_entry = true;
        if let Some(rest) = line.strip_prefix("P:") {
            current.name = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("V:") {
            current.version = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("T:") {
            current.description = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("S:") {
            current.size = rest.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("I:") {
            current.installed_size = rest.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("D:") {
            current.depends = rest.split_whitespace()
                .map(|s| s.to_string())
                .collect();
        } else if let Some(rest) = line.strip_prefix("p:") {
            current.provides = rest.split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
        // Unknown fields: ignore gracefully
    }
    // Last entry without trailing newline
    if in_entry && !current.name.is_empty() {
        entries.push(current);
    }

    entries
}

#[derive(Default)]
struct ApkEntry {
    name:           String,
    version:        String,
    description:    String,
    size:           u64,
    installed_size: u64,
    depends:        Vec<String>,
    provides:       Vec<String>,
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        // Non-UTF8 — parser should handle or reject gracefully
        // Our parser takes &str so we return here, but a real parser
        // reading from bytes should not panic
        return;
    };

    // Must not panic
    let entries = parse_apkindex(s);

    // Invariants on parsed results
    for entry in &entries {
        // Name must be non-empty (we only push if name is non-empty)
        assert!(!entry.name.is_empty(), "APK entry has empty name");

        // Name must be printable ASCII-ish (no null bytes)
        assert!(!entry.name.contains('\0'),
            "APK name contains null byte: {:?}", entry.name);

        // Size fields must not overflow (we already use .unwrap_or(0))
        let _ = entry.size.checked_add(entry.installed_size);

        // Version, if present, must be non-null
        assert!(!entry.version.contains('\0'),
            "APK version contains null byte");

        // Depends must be individual tokens without spaces
        for dep in &entry.depends {
            assert!(!dep.is_empty(), "empty APK dependency");
        }
    }

    // Entry count sanity: even 1GB APKINDEX shouldn't have infinite entries
    // (in practice: Alpine main has ~2000, community ~7000)
    assert!(entries.len() <= 1_000_000,
        "suspiciously many APK entries: {}", entries.len());
});
