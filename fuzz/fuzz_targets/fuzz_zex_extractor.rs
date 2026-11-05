//! fuzz_zex_extractor: Fuzz `.zex` archive extraction.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::{fs, path::Path};

fuzz_target!(|data: &[u8]| {
    let tmp = match tempfile::TempDir::new() {
        Ok(t) => t,
        Err(_) => return,
    };

    let zex_path = tmp.path().join("fuzz.zex");
    if fs::write(&zex_path, data).is_err() { return; }

    let out_dir = tmp.path().join("out");

    match zex::extract::extract(&zex_path, &out_dir) {
        Ok(result) => {
            let _ = result.files_extracted;

            if out_dir.is_dir() {
                check_no_escape(&out_dir, &out_dir);
            }
        }
        Err(_) => {
        }
    }
});

fn check_no_escape(base: &Path, dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
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
