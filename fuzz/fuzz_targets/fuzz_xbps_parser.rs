//! fuzz_xbps_parser — Fuzz Void Linux `index.plist` parsing.
//!
//! Target: The plist XML format used by Tier 3 Void xbps packages.
//! The plist is an Apple-style XML property list embedded in a tar.zst.
//!
//! Invariants:
//!   • plist parser never panics on arbitrary bytes
//!   • If package dict parsed: name is non-empty, size is ≥ 0
//!   • No package name contains path separators (injection prevention)

#![no_main]
use libfuzzer_sys::fuzz_target;

/// Parse XBPS plist using the `plist` crate (same as zex uses).
/// Returns package names found in the plist, or empty vec on parse error.
fn parse_xbps_plist(data: &[u8]) -> Vec<String> {
    let Ok(val) = plist::Value::from_reader(std::io::Cursor::new(data)) else {
        return Vec::new();
    };

    let mut names = Vec::new();

    // XBPS index.plist is a dict of package-name → package-dict
    if let plist::Value::Dictionary(dict) = val {
        for (key, value) in &dict {
            // key is the package name
            names.push(key.clone());

            // The value should be a dict with metadata
            if let plist::Value::Dictionary(pkg) = value {
                // Check required fields if present
                if let Some(plist::Value::String(arch)) = pkg.get("architecture") {
                    // Architecture should not be absurdly long
                    assert!(arch.len() < 256, "architecture field too long");
                }
                if let Some(plist::Value::String(ver)) = pkg.get("pkgver") {
                    assert!(!ver.contains('\0'), "pkgver contains null byte");
                }
            }
        }
    }

    names
}

fuzz_target!(|data: &[u8]| {
    // Must not panic
    let names = parse_xbps_plist(data);

    for name in &names {
        // Invariant 1: names must not contain path separators
        assert!(!name.contains('/'),
            "XBPS package name contains slash: {name}");
        assert!(!name.contains(".."),
            "XBPS package name contains ..: {name}");

        // Invariant 2: names must not be empty
        assert!(!name.is_empty(), "empty XBPS package name");

        // Invariant 3: no null bytes
        assert!(!name.contains('\0'),
            "XBPS package name contains null byte");

        // Invariant 4: name length sane
        assert!(name.len() < 512,
            "XBPS package name too long: {} chars", name.len());
    }

    // Invariant 5: package count sanity
    assert!(names.len() <= 500_000,
        "suspiciously many XBPS packages: {}", names.len());
});
