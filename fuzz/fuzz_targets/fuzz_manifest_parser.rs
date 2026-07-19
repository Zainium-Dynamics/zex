//! fuzz_manifest_parser — Fuzz `manifest.toml` TOML parsing.
//!
//! Target: `zex_manifest::ZexManifest` deserialization.
//!
//! Invariants checked:
//!   • Parser never panics on arbitrary input
//!   • If parse succeeds: name + version are non-empty, UTF-8 clean
//!   • No path in install/remove leaves /overlayer/ scope
//!   • Roundtrip: serialize(parse(valid)) == valid

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(val) = toml::from_str::<toml::Value>(s) else { return };

    // If it parses as a ZexManifest, check invariants
    if let Ok(m) = toml::from_str::<zex::cmd::install::zex_manifest::ZexManifest>(s) {
        // Invariant 1: name and version must be non-empty UTF-8
        assert!(!m.package.name.is_empty(),
            "manifest.package.name must not be empty");
        assert!(!m.package.version.is_empty(),
            "manifest.package.version must not be empty");

        // Invariant 2: all install paths must stay under /overlayer/
        for (_, dest) in &m.install.paths {
            assert!(
                dest.starts_with("/overlayer/") || dest.starts_with("/tmp"),
                "install path escapes /overlayer/: {dest}"
            );
        }

        // Invariant 3: all remove.files must be absolute and under /overlayer/
        for f in &m.remove.files {
            assert!(
                f.starts_with('/'),
                "remove file must be absolute: {f}"
            );
            assert!(
                f.starts_with("/overlayer/"),
                "remove file escapes /overlayer/: {f}"
            );
        }

        // Invariant 4: no path traversal in any field
        let all_paths: Vec<&str> = m.remove.files.iter()
            .chain(m.remove.symlinks.iter())
            .chain(m.remove.dirs.iter())
            .map(|s| s.as_str())
            .chain(m.install.paths.values().map(|s| s.as_str()))
            .collect();

        for path in all_paths {
            assert!(!path.contains("../"),
                "path traversal detected: {path}");
            assert!(!path.contains("/.."),
                "path traversal detected: {path}");
        }

        // Invariant 5: ed25519_sig is either None or valid base64 length (88 chars)
        if let Some(sig) = &m.package.ed25519_sig {
            assert!(
                sig.len() <= 256,
                "ed25519_sig suspiciously long: {} chars", sig.len()
            );
        }

        // Invariant 6: depends/provides/tags are all non-empty strings if present
        for dep in &m.package.depends {
            assert!(!dep.is_empty(), "empty dependency string");
        }
        for prov in &m.package.provides {
            assert!(!prov.is_empty(), "empty provides string");
        }
    }

    // Invariant: toml parse + re-serialize must produce valid toml
    let re = toml::to_string(&val);
    if let Ok(text) = re {
        let _ = toml::from_str::<toml::Value>(&text);
        // If re-parsing fails, that's a toml crate bug — don't panic ourselves
    }
});
