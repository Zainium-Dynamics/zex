//! fuzz_xbps_parser: Fuzz Void Linux `index.plist` parsing.

#![no_main]
use libfuzzer_sys::fuzz_target;

/// Parse XBPS plist using the `plist` crate (same as zex uses).
/// Returns package names found in the plist, or empty vec on parse error.
fn parse_xbps_plist(data: &[u8]) -> Vec<String> {
    let Ok(val) = plist::Value::from_reader(std::io::Cursor::new(data)) else {
        return Vec::new();
    };

    let mut names = Vec::new();

    if let plist::Value::Dictionary(dict) = val {
        for (key, value) in &dict {
            names.push(key.clone());

            if let plist::Value::Dictionary(pkg) = value {
                if let Some(plist::Value::String(arch)) = pkg.get("architecture") {
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
    let names = parse_xbps_plist(data);

    for name in &names {
        assert!(!name.contains('/'),
            "XBPS package name contains slash: {name}");
        assert!(!name.contains(".."),
            "XBPS package name contains ..: {name}");

        assert!(!name.is_empty(), "empty XBPS package name");

        assert!(!name.contains('\0'),
            "XBPS package name contains null byte");

        assert!(name.len() < 512,
            "XBPS package name too long: {} chars", name.len());
    }

    assert!(names.len() <= 500_000,
        "suspiciously many XBPS packages: {}", names.len());
});
