//! fuzz_manifest_parser: Fuzz `manifest.toml` TOML parsing.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(val) = toml::from_str::<toml::Value>(s) else { return };

    if let Ok(m) = toml::from_str::<zex::cmd::install::zex_manifest::ZexManifest>(s) {
        assert!(!m.package.name.is_empty(),
            "manifest.package.name must not be empty");
        assert!(!m.package.version.is_empty(),
            "manifest.package.version must not be empty");

        for (_, dest) in &m.install.paths {
            assert!(
                dest.starts_with("/overlayer/") || dest.starts_with("/tmp"),
                "install path escapes /overlayer/: {dest}"
            );
        }

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

        if let Some(sig) = &m.package.ed25519_sig {
            assert!(
                sig.len() <= 256,
                "ed25519_sig suspiciously long: {} chars", sig.len()
            );
        }

        for dep in &m.package.depends {
            assert!(!dep.is_empty(), "empty dependency string");
        }
        for prov in &m.package.provides {
            assert!(!prov.is_empty(), "empty provides string");
        }
    }

    let re = toml::to_string(&val);
    if let Ok(text) = re {
        let _ = toml::from_str::<toml::Value>(&text);
    }
});
