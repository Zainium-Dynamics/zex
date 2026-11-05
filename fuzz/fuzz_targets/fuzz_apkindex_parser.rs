//! fuzz_apkindex_parser: Fuzz Alpine `APKINDEX` file parsing.

#![no_main]
use libfuzzer_sys::fuzz_target;

/// Minimal APKINDEX entry parser: mirrors what the real prober does.
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
    }
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
        return;
    };

    let entries = parse_apkindex(s);

    for entry in &entries {
        assert!(!entry.name.is_empty(), "APK entry has empty name");

        assert!(!entry.name.contains('\0'),
            "APK name contains null byte: {:?}", entry.name);

        let _ = entry.size.checked_add(entry.installed_size);

        assert!(!entry.version.contains('\0'),
            "APK version contains null byte");

        for dep in &entry.depends {
            assert!(!dep.is_empty(), "empty APK dependency");
        }
    }

    assert!(entries.len() <= 1_000_000,
        "suspiciously many APK entries: {}", entries.len());
});
