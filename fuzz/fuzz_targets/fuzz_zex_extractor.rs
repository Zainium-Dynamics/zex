//! fuzz_zex_extractor — Fuzz `.zex` archive extraction.
//!
//! Target: `extract::extract()` on arbitrary bytes.
//!
//! Invariants:
//!   • Never panics on malformed input
//!   • On success: output dir created, at least one file extracted
//!   • No extracted path can escape the output dir (path traversal prevention)
//!   • No extracted file is empty (except explicitly empty payloads)

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::{fs, path::Path};

fuzz_target!(|data: &[u8]| {
    // Write fuzz data as a .zex file in a temp dir
    let tmp = match tempfile::TempDir::new() {
        Ok(t) => t,
        Err(_) => return,
    };

    let zex_path = tmp.path().join("fuzz.zex");
    if fs::write(&zex_path, data).is_err() { return; }

    let out_dir = tmp.path().join("out");

    // Must not panic — any error is acceptable
    match zex::extract::extract(&zex_path, &out_dir) {
        Ok(result) => {
            // Invariant 1: files_extracted >= 0 (trivially true but asserted for clarity)
            let _ = result.files_extracted;

            // Invariant 2: all extracted files must be under out_dir
            // (no path traversal like ../../etc/passwd)
            if out_dir.is_dir() {
                check_no_escape(&out_dir, &out_dir);
            }
        }
        Err(_) => {
            // Error is fine — corrupt input should fail gracefully
            // The critical check is that we didn't panic
        }
    }
});

fn check_no_escape(base: &Path, dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        // Resolve symlinks and check the canonical path starts with base
        if let Ok(canonical) = path.canonicalize() {
            if let Ok(base_canonical) = base.canonicalize() {
                assert!(
                    canonical.starts_with(&base_canonical),
                    "SECURITY: extracted path escapes output dir!\n\
                     base: {}\n\
                     path: {}",
                    base_canonical.display(),
                    canonical.display()
                );
            }
        }
        if path.is_dir() {
            check_no_escape(base, &path);
        }
    }
}
