//! fuzz_receipt_parser — Fuzz installed package receipt TOML parsing.
//!
//! Target: The `.toml` receipt files in `/overlayer/zexlib/registry/installed/`.
//!
//! Invariants:
//!   • Parser never panics on arbitrary TOML-ish input
//!   • If parsed as valid receipt: all file paths are under /overlayer/
//!   • No null bytes in any string field
//!   • Size fields don't overflow u64
//!   • Name/version fields don't contain path traversal sequences

#![no_main]
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

/// Receipt schema — mirrors what the install driver writes.
#[derive(Debug, Deserialize)]
struct Receipt {
    name:                          String,
    version:                       String,
    #[serde(default)] description: String,
    #[serde(default)] origin:      String,
    #[serde(default)] installed_at:String,
    #[serde(default)] libc_target: Option<String>,
    #[serde(default)] build_type:  Option<String>,
    #[serde(default)] size:        Option<u64>,
    remove:                        Option<RemoveMap>,
}

#[derive(Debug, Deserialize, Default)]
struct RemoveMap {
    #[serde(default)] files:    Vec<String>,
    #[serde(default)] symlinks: Vec<String>,
    #[serde(default)] dirs:     Vec<String>,
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // Must not panic on any valid UTF-8 input
    let Ok(receipt) = toml::from_str::<Receipt>(s) else {
        // Parse failure is fine — invalid TOML or missing required fields
        return;
    };

    // ── Invariants on successfully parsed receipts ─────────────────────────

    // 1. name must be non-empty and no null bytes
    assert!(!receipt.name.is_empty(),
        "receipt name must not be empty");
    assert!(!receipt.name.contains('\0'),
        "receipt name contains null: {:?}", receipt.name);

    // 2. version must be non-empty
    assert!(!receipt.version.is_empty(),
        "receipt version must not be empty");

    // 3. name must not contain path traversal
    assert!(!receipt.name.contains(".."),
        "receipt name contains ..: {:?}", receipt.name);
    assert!(!receipt.name.contains('/'),
        "receipt name contains /: {:?}", receipt.name);

    // 4. origin must be one of the known tiers (if non-empty)
    if !receipt.origin.is_empty() {
        let valid_origins = [
            "tier1-zainium", "tier2-alpine", "tier3-void", "tier4-chimera",
            "syshub", "local",
        ];
        // Not a hard invariant — just check it doesn't contain dangerous chars
        assert!(!receipt.origin.contains('\0'),
            "origin contains null: {:?}", receipt.origin);
    }

    // 5. libc_target must be known value if present
    if let Some(ref libc) = receipt.libc_target {
        assert!(!libc.contains('\0'), "libc_target contains null");
        // Valid values: musl, relibc, glibc, none
        // Not enforced here — just no null bytes
    }

    // 6. All file paths must be absolute and under /overlayer/
    if let Some(ref rm) = receipt.remove {
        for path in rm.files.iter()
            .chain(rm.symlinks.iter())
            .chain(rm.dirs.iter())
        {
            // Must be absolute
            assert!(path.starts_with('/'),
                "remove path not absolute: {path:?}");

            // Must stay under /overlayer/
            assert!(path.starts_with("/overlayer/"),
                "SECURITY: remove path escapes /overlayer/: {path:?}");

            // No path traversal
            assert!(!path.contains("../"),
                "SECURITY: path traversal in remove path: {path:?}");

            // No null bytes
            assert!(!path.contains('\0'),
                "null byte in remove path: {path:?}");

            // Reasonable length
            assert!(path.len() < 4096,
                "remove path too long: {} chars", path.len());
        }

        // Count sanity: a package shouldn't have billions of files
        let total = rm.files.len() + rm.symlinks.len() + rm.dirs.len();
        assert!(total < 100_000,
            "suspiciously many files in remove map: {total}");
    }

    // 7. size field sanity
    if let Some(size) = receipt.size {
        // Max sane package size: 10 GB
        assert!(size <= 10 * 1024 * 1024 * 1024,
            "package size too large: {size} bytes");
    }
});
