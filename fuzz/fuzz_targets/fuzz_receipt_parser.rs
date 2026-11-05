//! fuzz_receipt_parser: Fuzz installed package receipt TOML parsing.

#![no_main]
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

/// Receipt schema: mirrors what the install driver writes.
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

    let Ok(receipt) = toml::from_str::<Receipt>(s) else {
        return;
    };

    assert!(!receipt.name.is_empty(),
        "receipt name must not be empty");
    assert!(!receipt.name.contains('\0'),
        "receipt name contains null: {:?}", receipt.name);

    assert!(!receipt.version.is_empty(),
        "receipt version must not be empty");

    assert!(!receipt.name.contains(".."),
        "receipt name contains ..: {:?}", receipt.name);
    assert!(!receipt.name.contains('/'),
        "receipt name contains /: {:?}", receipt.name);

    if !receipt.origin.is_empty() {
        let valid_origins = [
            "tier1-zainium", "tier2-alpine", "tier3-void", "tier4-chimera",
            "syshub", "local",
        ];
        assert!(!receipt.origin.contains('\0'),
            "origin contains null: {:?}", receipt.origin);
    }

    if let Some(ref libc) = receipt.libc_target {
        assert!(!libc.contains('\0'), "libc_target contains null");
    }

    if let Some(ref rm) = receipt.remove {
        for path in rm.files.iter()
            .chain(rm.symlinks.iter())
            .chain(rm.dirs.iter())
        {
            assert!(path.starts_with('/'),
                "remove path not absolute: {path:?}");

            assert!(path.starts_with("/overlayer/"),
                "SECURITY: remove path escapes /overlayer/: {path:?}");

            assert!(!path.contains("../"),
                "SECURITY: path traversal in remove path: {path:?}");

            assert!(!path.contains('\0'),
                "null byte in remove path: {path:?}");

            assert!(path.len() < 4096,
                "remove path too long: {} chars", path.len());
        }

        let total = rm.files.len() + rm.symlinks.len() + rm.dirs.len();
        assert!(total < 100_000,
            "suspiciously many files in remove map: {total}");
    }

    if let Some(size) = receipt.size {
        assert!(size <= 10 * 1024 * 1024 * 1024,
            "package size too large: {size} bytes");
    }
});
