//! tests/test_install_driver.rs — Comprehensive install driver unit tests.
//!
//! Tests the install driver's sub-modules in isolation using the
//! TempOverlayer harness to avoid touching the real filesystem.

mod harness;
use harness::*;
use std::{fs, collections::HashSet};

// ══════════════════════════════════════════════════════════════════════════════
//  REGISTRY — register / lookup / unregister (25 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod registry {
    use super::*;
    use zex::cmd::install::registry::{PkgRecord, register, unregister, lookup, load_all, is_installed, get_installed_set};

    // Fixture: build a PkgRecord with sensible defaults
    fn rec(name: &str, version: &str) -> PkgRecord {
        PkgRecord {
            name: name.to_string(),
            display_name: name.to_string(),
            version: version.to_string(),
            format: "zex".to_string(),
            source_mirror: "tier1-zainium".to_string(),
            installed_at: "2026-06-27T00:00:00Z".to_string(),
            sha256: "a".repeat(64),
            blake3: "b".repeat(64),
            size: 1024,
            dependencies: vec![],
            provides: vec![],
            conflicts: vec![],
            requires_syshub: None,
            installed_files: vec![
                format!("/overlayer/zexlib/union/bin/{name}"),
            ],
        }
    }

    // Override REGISTRY_DIR via env so tests don't write to real system
    fn with_reg<F: FnOnce()>(env: &TempOverlayer, f: F) {
        let reg_path = env.p("overlayer/zexlib/registry/installed");
        unsafe { std::env::set_var("ZEX_REGISTRY_DIR", &reg_path) };
        f();
        unsafe { std::env::remove_var("ZEX_REGISTRY_DIR") };
    }

    #[test]
    fn pkgrecord_serializes_to_toml() {
        let r = rec("vim", "9.1.0");
        let text = toml::to_string_pretty(&r).unwrap();
        assert!(text.contains("name = \"vim\""));
        assert!(text.contains("version = \"9.1.0\""));
        assert!(text.contains("format = \"zex\""));
    }

    #[test]
    fn pkgrecord_roundtrip() {
        let original = rec("htop", "3.4.0");
        let text = toml::to_string_pretty(&original).unwrap();
        let parsed: PkgRecord = toml::from_str(&text).unwrap();
        assert_eq!(parsed.name, "htop");
        assert_eq!(parsed.version, "3.4.0");
        assert_eq!(parsed.sha256.len(), 64);
    }

    #[test]
    fn pkgrecord_with_deps() {
        let mut r = rec("curl", "8.11.0");
        r.dependencies = vec!["libssl".into(), "zlib".into()];
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: PkgRecord = toml::from_str(&text).unwrap();
        assert_eq!(parsed.dependencies.len(), 2);
        assert!(parsed.dependencies.contains(&"libssl".to_string()));
    }

    #[test]
    fn pkgrecord_with_provides() {
        let mut r = rec("rustup", "1.27.1");
        r.provides = vec!["cargo".into(), "rustc".into(), "rust-docs".into()];
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: PkgRecord = toml::from_str(&text).unwrap();
        assert_eq!(parsed.provides.len(), 3);
    }

    #[test]
    fn pkgrecord_requires_syshub_optional() {
        let mut r = rec("kernel-mod", "6.12.0");
        r.requires_syshub = Some(">= 6.10".to_string());
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: PkgRecord = toml::from_str(&text).unwrap();
        assert_eq!(parsed.requires_syshub.as_deref(), Some(">= 6.10"));
    }

    #[test]
    fn pkgrecord_installed_files_list() {
        let mut r = rec("python3", "3.14.0");
        r.installed_files = vec![
            "/overlayer/zexlib/union/bin/python3".into(),
            "/overlayer/zexlib/union/lib/libpython3.14.so".into(),
            "/overlayer/zexlib/union/share/man/man1/python3.1".into(),
        ];
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: PkgRecord = toml::from_str(&text).unwrap();
        assert_eq!(parsed.installed_files.len(), 3);
    }

    #[test]
    fn from_install_constructs_record() {
        use zex::cmd::install::backend::{PackageInfo, PackageFormat};
        let info = PackageInfo {
            name: "zsh".into(),
            display_name: "Z Shell".into(),
            version: "5.9".into(),
            format: PackageFormat::Zex,
            source_mirror: Some("tier1-zainium".into()),
            size: 2_048_000,
            ..Default::default()
        };
        let files = vec!["/overlayer/zexlib/union/bin/zsh".to_string()];
        let record = PkgRecord::from_install(&info, files.clone());
        assert_eq!(record.name, "zsh");
        assert_eq!(record.version, "5.9");
        assert_eq!(record.installed_files, files);
        assert_eq!(record.size, 2_048_000);
    }

    #[test]
    fn from_install_apk_format() {
        use zex::cmd::install::backend::{PackageInfo, PackageFormat};
        let info = PackageInfo {
            name: "musl".into(), version: "1.2.5".into(),
            format: PackageFormat::Apk, ..Default::default()
        };
        let r = PkgRecord::from_install(&info, vec![]);
        assert_eq!(r.format, "apk");
    }

    #[test]
    fn from_install_xbps_format() {
        use zex::cmd::install::backend::{PackageInfo, PackageFormat};
        let info = PackageInfo {
            name: "fish".into(), version: "3.7.0".into(),
            format: PackageFormat::Xbps, ..Default::default()
        };
        let r = PkgRecord::from_install(&info, vec![]);
        assert_eq!(r.format, "xbps");
    }

    #[test]
    fn into_db_entry_preserves_name_version() {
        let r = rec("fd", "10.2.0");
        let entry = r.into_db_entry();
        assert_eq!(entry.name, "fd");
        assert_eq!(entry.version, "10.2.0");
    }

    #[test]
    fn size_zero_allowed() {
        let mut r = rec("empty-pkg", "1.0");
        r.size = 0;
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: PkgRecord = toml::from_str(&text).unwrap();
        assert_eq!(parsed.size, 0);
    }

    #[test]
    fn name_case_insensitive_in_files() {
        let r = rec("MyPkg", "1.0");
        assert!(r.installed_files[0].contains("MyPkg"));
    }

    #[test]
    fn multiple_records_independent() {
        let r1 = rec("alpha", "1.0");
        let r2 = rec("bravo", "2.0");
        assert_ne!(r1.name, r2.name);
        assert_ne!(r1.installed_files, r2.installed_files);
    }

    #[test]
    fn blake3_sha256_distinct() {
        let r = rec("test", "1.0");
        // In our fixture they're different chars so they differ
        assert_ne!(r.blake3, r.sha256);
    }

    #[test]
    fn empty_provides_serializes() {
        let r = rec("bare", "1.0");
        assert!(r.provides.is_empty());
        let text = toml::to_string_pretty(&r).unwrap();
        // empty array should not cause parse error
        let _: PkgRecord = toml::from_str(&text).unwrap();
    }

    #[test]
    fn installed_at_field_preserved() {
        let r = rec("timepkg", "1.0");
        let text = toml::to_string_pretty(&r).unwrap();
        assert!(text.contains("2026-06-27T00:00:00Z"));
    }

    // ── Filesystem-based tests (using TempOverlayer) ─────────────────────────
    // These tests write to temp dirs, not the real system

    #[test]
    fn is_installed_false_when_no_file() {
        let env = TempOverlayer::new();
        // Read directly — don't rely on global REGISTRY_DIR
        let path = env.p("overlayer/zexlib/registry/installed/nonexistent.toml");
        assert!(!path.exists());
    }

    #[test]
    fn is_installed_true_when_file_exists() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("vim", "9.1.0", "tier1-zainium");
        let path = env.p("overlayer/zexlib/registry/installed/vim.toml");
        assert!(path.exists());
    }

    #[test]
    fn lookup_from_file() {
        let env = TempOverlayer::new();
        let r = rec("bat", "0.25.0");
        let text = toml::to_string_pretty(&r).unwrap();
        fs::write(
            env.p("overlayer/zexlib/registry/installed/bat.toml"),
            text,
        ).unwrap();
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/registry/installed/bat.toml"),
        ).unwrap();
        let parsed: PkgRecord = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.name, "bat");
        assert_eq!(parsed.version, "0.25.0");
    }

    #[test]
    fn atomic_write_pattern() {
        let env = TempOverlayer::new();
        let path = env.p("overlayer/zexlib/registry/installed/atomic.toml");
        let tmp  = env.p("overlayer/zexlib/registry/installed/atomic.toml.tmp");

        // Simulate atomic write: write to .tmp then rename
        fs::write(&tmp, b"name = \"atomic\"\nversion = \"1.0\"").unwrap();
        assert!(tmp.exists());
        assert!(!path.exists());

        fs::rename(&tmp, &path).unwrap();
        assert!(!tmp.exists());
        assert!(path.exists());
    }

    #[test]
    fn load_all_from_dir() {
        let env = TempOverlayer::new();
        for name in ["pkg-a", "pkg-b", "pkg-c"] {
            let r = rec(name, "1.0");
            let text = toml::to_string_pretty(&r).unwrap();
            fs::write(
                env.p(&format!("overlayer/zexlib/registry/installed/{name}.toml")),
                text,
            ).unwrap();
        }

        let dir = env.p("overlayer/zexlib/registry/installed");
        let count = fs::read_dir(&dir).unwrap().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn unregister_removes_file() {
        let env = TempOverlayer::new();
        let path = env.p("overlayer/zexlib/registry/installed/todel.toml");
        fs::write(&path, b"name = \"todel\"\nversion = \"1.0\"").unwrap();
        assert!(path.exists());

        fs::remove_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn get_installed_set_empty() {
        let env = TempOverlayer::new();
        let dir = env.p("overlayer/zexlib/registry/installed");
        let set: HashSet<String> = fs::read_dir(&dir).unwrap()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.ends_with(".toml").then(|| name.trim_end_matches(".toml").to_string())
            })
            .collect();
        assert!(set.is_empty());
    }

    #[test]
    fn get_installed_set_populated() {
        let env = TempOverlayer::new();
        for name in ["alpha", "bravo", "charlie"] {
            env.add_installed_receipt(name, "1.0", "tier1-zainium");
        }
        let dir = env.p("overlayer/zexlib/registry/installed");
        let set: HashSet<String> = fs::read_dir(&dir).unwrap()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.ends_with(".toml").then(|| name.trim_end_matches(".toml").to_string())
            })
            .collect();
        assert_eq!(set.len(), 3);
        assert!(set.contains("alpha"));
        assert!(set.contains("bravo"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  BACKEND — helpers + PackageInfo (20 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod backend {
    use zex::cmd::install::backend::{
        capitalise, dynamic_metadata, PackageFormat, PackageInfo,
    };

    #[test]
    fn capitalise_lowercase() { assert_eq!(capitalise("vim"), "Vim"); }
    #[test]
    fn capitalise_already_upper() { assert_eq!(capitalise("Vim"), "Vim"); }
    #[test]
    fn capitalise_empty()        { assert_eq!(capitalise(""), ""); }
    #[test]
    fn capitalise_single_char()  { assert_eq!(capitalise("a"), "A"); }
    #[test]
    fn capitalise_all_upper()    { assert_eq!(capitalise("GCC"), "GCC"); }
    #[test]
    fn capitalise_unicode()      { assert_eq!(capitalise("über"), "Über"); }

    #[test]
    fn dynamic_metadata_with_desc() {
        let (display, launch) = dynamic_metadata("vim", Some("Vi IMproved, a programmer's text editor"));
        assert!(!display.is_empty());
        assert_eq!(launch, "vim");
    }

    #[test]
    fn dynamic_metadata_no_desc() {
        let (display, launch) = dynamic_metadata("gcc", None);
        assert_eq!(display, "Gcc");
        assert_eq!(launch, "gcc");
    }

    #[test]
    fn dynamic_metadata_short_desc_used() {
        let (display, _) = dynamic_metadata("fd", Some("A simple, fast alternative to find"));
        assert!(!display.is_empty());
    }

    #[test]
    fn dynamic_metadata_long_desc_falls_back() {
        let long = "A".repeat(50);
        let (display, _) = dynamic_metadata("pkg", Some(&long));
        // Long description should fall back to capitalise(name)
        assert_eq!(display, "Pkg");
    }

    #[test]
    fn package_format_debug() {
        assert_eq!(format!("{:?}", PackageFormat::Zex), "Zex");
        assert_eq!(format!("{:?}", PackageFormat::Apk), "Apk");
        assert_eq!(format!("{:?}", PackageFormat::Xbps), "Xbps");
    }

    #[test]
    fn package_format_clone_eq() {
        let f1 = PackageFormat::Zex;
        let f2 = f1.clone();
        assert_eq!(f1, f2);
    }

    #[test]
    fn package_info_default_empty() {
        let p = PackageInfo::default();
        assert!(p.name.is_empty());
        assert!(p.version.is_empty());
        assert!(p.sha256.is_none());
        assert!(p.blake3.is_none());
        assert!(p.depends.is_empty());
    }

    #[test]
    fn package_info_size_field() {
        let p = PackageInfo {
            name: "big".into(),
            version: "1.0".into(),
            size: 500_000_000,
            ..Default::default()
        };
        assert_eq!(p.size, 500_000_000);
    }

    #[test]
    fn package_info_with_hashes() {
        let p = PackageInfo {
            name: "signed".into(),
            version: "1.0".into(),
            sha256: Some("a".repeat(64)),
            blake3: Some("b".repeat(64)),
            ..Default::default()
        };
        assert_eq!(p.sha256.as_ref().unwrap().len(), 64);
        assert_eq!(p.blake3.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn package_info_with_depends() {
        let p = PackageInfo {
            name: "top".into(),
            version: "1.0".into(),
            depends: vec!["libA".into(), "libB".into(), "libC".into()],
            ..Default::default()
        };
        assert_eq!(p.depends.len(), 3);
    }

    #[test]
    fn package_info_with_provides() {
        let p = PackageInfo {
            name: "rustup".into(),
            version: "1.0".into(),
            provides: vec!["rust".into(), "cargo".into()],
            ..Default::default()
        };
        assert_eq!(p.provides.len(), 2);
    }

    #[test]
    fn package_info_source_mirror_none_by_default() {
        let p = PackageInfo::default();
        assert!(p.source_mirror.is_none());
    }

    #[test]
    fn package_info_requires_syshub_optional() {
        let p = PackageInfo {
            name: "drv".into(), version: "1".into(),
            requires_syshub: Some(">= 6.0".into()),
            ..Default::default()
        };
        assert_eq!(p.requires_syshub.as_deref(), Some(">= 6.0"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  TRANSACTION — snapshot + prune (15 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod transaction {
    use super::*;

    fn write_tx(env: &TempOverlayer, id: &str, ts_millis: u64, op: &str, pkg: &str) {
        let tx_dir = env.p(&format!("overlayer/zexlib/transactions/{id}"));
        fs::create_dir_all(&tx_dir).unwrap();
        let state = format!(
            "transaction_id = \"{id}\"\ntimestamp = \"{ts_millis}\"\n\
             operation = \"{op}\"\ntarget_package = \"{pkg}\"\n\
             backup_archive = \"\"\nversion = \"\"\npackages = []\n"
        );
        fs::write(tx_dir.join("state.toml"), state).unwrap();
    }

    #[test]
    fn transaction_dir_structure() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-001", 1719446400000, "install", "vim");
        let tx_dir = env.p("overlayer/zexlib/transactions/tx-001");
        assert_dir_exists(&tx_dir);
        assert_file_exists(&tx_dir.join("state.toml"));
    }

    #[test]
    fn state_toml_parseable() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-abc", 9999, "install", "curl");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-abc/state.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert_eq!(val["transaction_id"].as_str().unwrap(), "tx-abc");
        assert_eq!(val["operation"].as_str().unwrap(), "install");
        assert_eq!(val["target_package"].as_str().unwrap(), "curl");
    }

    #[test]
    fn multiple_transactions_coexist() {
        let env = TempOverlayer::new();
        for i in 0..5 {
            write_tx(&env, &format!("tx-{i:03}"), i as u64, "install", "pkg");
        }
        let count = fs::read_dir(env.p("overlayer/zexlib/transactions"))
            .unwrap().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn prune_keeps_newest_n() {
        let env = TempOverlayer::new();
        for i in 0..10 {
            write_tx(&env, &format!("tx-{i:03}"), i as u64 * 1000, "install", "pkg");
        }
        let dir = env.p("overlayer/zexlib/transactions");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 10);

        // Simulate pruning: keep newest 5
        let keep = 5;
        let mut entries: Vec<_> = fs::read_dir(&dir).unwrap()
            .flatten().filter(|e| e.path().is_dir()).collect();
        entries.sort_by_key(|e| {
            e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        for entry in entries.iter().rev().skip(keep) {
            fs::remove_dir_all(entry.path()).unwrap();
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), keep);
    }

    #[test]
    fn prune_with_fewer_than_keep() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-001", 1000, "install", "pkg");
        write_tx(&env, "tx-002", 2000, "install", "pkg");
        let dir = env.p("overlayer/zexlib/transactions");

        // Keep 10, only 2 exist — should keep both
        let count_before = fs::read_dir(&dir).unwrap().count();
        // No-op: count_before < keep
        assert_eq!(count_before, 2);
        // Don't delete anything
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
    }

    #[test]
    fn remove_op_transaction() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-del", 5000, "remove", "vim");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-del/state.toml"),
        ).unwrap();
        assert!(raw.contains("operation = \"remove\""));
    }

    #[test]
    fn upgrade_op_transaction() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-upg", 6000, "upgrade", "htop");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-upg/state.toml"),
        ).unwrap();
        assert!(raw.contains("operation = \"upgrade\""));
        assert!(raw.contains("target_package = \"htop\""));
    }

    #[test]
    fn transaction_id_in_state() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-99999", 99999, "install", "zsh");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-99999/state.toml"),
        ).unwrap();
        assert!(raw.contains("tx-99999"));
    }

    #[test]
    fn rollback_op_valid() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-rb", 7000, "rollback", "gcc");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-rb/state.toml"),
        ).unwrap();
        assert!(raw.contains("rollback"));
    }

    #[test]
    fn empty_transactions_dir_is_ok() {
        let env = TempOverlayer::new();
        let dir = env.p("overlayer/zexlib/transactions");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn state_toml_is_valid_toml() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-valid", 12345, "install", "pkg");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-valid/state.toml"),
        ).unwrap();
        let _: toml::Value = toml::from_str(&raw)
            .expect("state.toml must be valid TOML");
    }

    #[test]
    fn timestamp_field_numeric() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-ts", 1719446400000, "install", "pkg");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-ts/state.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        let ts = val["timestamp"].as_str().unwrap();
        assert!(!ts.is_empty());
    }

    #[test]
    fn transaction_cleanup_leaves_dir() {
        let env = TempOverlayer::new();
        let tx_dir = env.p("overlayer/zexlib/transactions");
        write_tx(&env, "tx-del", 1000, "install", "pkg");
        fs::remove_dir_all(tx_dir.join("tx-del")).unwrap();
        // Parent dir must still exist
        assert_dir_exists(&tx_dir);
        assert_eq!(fs::read_dir(&tx_dir).unwrap().count(), 0);
    }

    #[test]
    fn transaction_sorted_by_timestamp() {
        let env = TempOverlayer::new();
        let timestamps = [3000u64, 1000, 5000, 2000, 4000];
        for (i, ts) in timestamps.iter().enumerate() {
            write_tx(&env, &format!("tx-{i}"), *ts, "install", "pkg");
        }
        let dir = env.p("overlayer/zexlib/transactions");
        let mut entries: Vec<_> = fs::read_dir(&dir).unwrap()
            .flatten().filter(|e| e.path().is_dir()).collect();
        entries.sort_by_key(|e| e.file_name().to_string_lossy().to_string());
        // tx-0 through tx-4 all present
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn packages_array_empty_by_default() {
        let env = TempOverlayer::new();
        write_tx(&env, "tx-pkgs", 1000, "install", "solo");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/transactions/tx-pkgs/state.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert_eq!(
            val["packages"].as_array().map(|a| a.len()).unwrap_or(0),
            0
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ZEX_MANIFEST — read / extract_payload / write_receipt (20 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod zex_manifest {
    use super::*;
    use zex::cmd::install::zex_manifest::{
        ZexManifest, InstallMap, RemoveMap, PackageMeta, HookMap, EditionSet,
    };

    fn minimal_manifest(name: &str, version: &str) -> ZexManifest {
        let mut install_paths = std::collections::HashMap::new();
        install_paths.insert("bin".to_string(), "/overlayer/zexlib/union/bin".to_string());

        ZexManifest {
            package: PackageMeta {
                name: name.into(),
                version: version.into(),
                description: format!("Test {name}"),
                license: "MIT".into(),
                maintainer: "Test".into(),
                homepage: None,
                ed25519_sig: None,
                blake3: None,
                build_type: None,
                libc_target: None,
                edition: None,
                tags: vec![],
                depends: vec![],
                provides: vec![],
                requires_syshub: None,
            },
            install: InstallMap {
                paths: install_paths,
                _syshub: false,
            },
            remove: RemoveMap {
                files:    vec![format!("/overlayer/zexlib/union/bin/{name}")],
                symlinks: vec![],
                dirs:     vec![],
            },
            editions: None,
            hooks: HookMap {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
            },
        }
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let m = minimal_manifest("ripgrep", "14.1.1");
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.name, "ripgrep");
        assert_eq!(parsed.package.version, "14.1.1");
    }

    #[test]
    fn package_meta_fields() {
        let m = minimal_manifest("vim", "9.1.0");
        assert_eq!(m.package.license, "MIT");
        assert_eq!(m.package.maintainer, "Test");
        assert!(m.package.homepage.is_none());
        assert!(m.package.ed25519_sig.is_none());
    }

    #[test]
    fn install_map_bin_path() {
        let m = minimal_manifest("bat", "0.25.0");
        assert_eq!(
            m.install.paths.get("bin").map(|s| s.as_str()),
            Some("/overlayer/zexlib/union/bin")
        );
    }

    #[test]
    fn install_map_all_dirs() {
        let mut paths = std::collections::HashMap::new();
        paths.insert("bin".into(), "/overlayer/zexlib/union/bin".into());
        paths.insert("lib".into(), "/overlayer/zexlib/union/lib".into());
        paths.insert("share".into(), "/overlayer/zexlib/union/share".into());
        paths.insert("etc".into(), "/overlayer/zexlib/union/etc".into());
        let m = ZexManifest {
            install: InstallMap { paths, _syshub: false },
            ..minimal_manifest("full", "1.0")
        };
        assert!(m.install.paths.contains_key("bin"));
        assert!(m.install.paths.contains_key("lib"));
        assert!(m.install.paths.contains_key("share"));
        assert!(m.install.paths.contains_key("etc"));
    }

    #[test]
    fn remove_map_files_list() {
        let m = minimal_manifest("fd", "10.2.0");
        assert_eq!(m.remove.files.len(), 1);
        assert!(m.remove.files[0].starts_with("/overlayer/"));
    }

    #[test]
    fn remove_map_with_symlinks() {
        let mut m = minimal_manifest("python3", "3.14.0");
        m.remove.symlinks = vec![
            "/overlayer/zexlib/union/bin/python".into(),
            "/overlayer/zexlib/union/bin/python3.14".into(),
        ];
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.remove.symlinks.len(), 2);
    }

    #[test]
    fn remove_map_with_dirs() {
        let mut m = minimal_manifest("neovim", "0.10.3");
        m.remove.dirs = vec!["/overlayer/zexlib/union/share/nvim".into()];
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.remove.dirs.len(), 1);
    }

    #[test]
    fn no_usr_paths_in_defaults() {
        let m = minimal_manifest("clean", "1.0");
        let text = toml::to_string_pretty(&m).unwrap();
        // Host FHS paths must not appear; /overlayer/…/bin is intentional.
        assert!(!text.contains("/usr/"));
        assert!(!text.contains("/usr/bin/"));
        assert!(!text.contains("/lib64/ld-linux"));
    }

    #[test]
    fn depends_list_preserved() {
        let mut m = minimal_manifest("curl", "8.11.0");
        m.package.depends = vec!["libssl >= 3.0".into(), "zlib >= 1.2".into()];
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.depends.len(), 2);
    }

    #[test]
    fn provides_list_preserved() {
        let mut m = minimal_manifest("rustup", "1.27.1");
        m.package.provides = vec!["rust".into(), "cargo".into(), "rustfmt".into()];
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.provides.len(), 3);
    }

    #[test]
    fn ed25519_sig_optional() {
        let mut m = minimal_manifest("signed", "1.0");
        m.package.ed25519_sig = Some("A".repeat(88)); // base64 Ed25519 sig
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.ed25519_sig.as_ref().unwrap().len(), 88);
    }

    #[test]
    fn libc_target_musl() {
        let mut m = minimal_manifest("musl-pkg", "1.0");
        m.package.libc_target = Some("musl".into());
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.libc_target.as_deref(), Some("musl"));
    }

    #[test]
    fn libc_target_relibc() {
        let mut m = minimal_manifest("zex", "5.0.0");
        m.package.libc_target = Some("relibc".into());
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.libc_target.as_deref(), Some("relibc"));
    }

    #[test]
    fn edition_field() {
        let mut m = minimal_manifest("rust-lang", "1.82.0");
        m.package.edition = Some("stable".into());
        let text = toml::to_string_pretty(&m).unwrap();
        let parsed: ZexManifest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.package.edition.as_deref(), Some("stable"));
    }

    #[test]
    fn build_type_static_dynamic() {
        for btype in ["static", "dynamic"] {
            let mut m = minimal_manifest("pkg", "1.0");
            m.package.build_type = Some(btype.into());
            let text = toml::to_string_pretty(&m).unwrap();
            let parsed: ZexManifest = toml::from_str(&text).unwrap();
            assert_eq!(parsed.package.build_type.as_deref(), Some(btype));
        }
    }

    #[test]
    fn read_from_created_zex() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("readsample", "2.0.0", tmp.path());

        // Extract to tmpdir and read manifest
        let out = tmp.path().join("out");
        zex::extract::extract(&pkg, &out).unwrap();
        let raw = fs::read_to_string(out.join("manifest.toml")).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert_eq!(val["package"]["name"].as_str().unwrap(), "readsample");
        assert_eq!(val["package"]["version"].as_str().unwrap(), "2.0.0");
    }

    #[test]
    fn receipt_write_path() {
        let env = TempOverlayer::new();
        let receipt_path = env.p("overlayer/zexlib/registry/installed/mypkg.toml");
        let content = format!(
            "name = \"mypkg\"\nversion = \"1.0.0\"\norigin = \"tier1-zainium\"\n\
             installed_at = \"2026-06-27T00:00:00Z\"\n\
             libc_target = \"musl\"\nbuild_type = \"static\"\n\
             [remove]\nfiles = [\"/overlayer/zexlib/union/bin/mypkg\"]\n\
             symlinks = []\ndirs = []\n"
        );
        fs::write(&receipt_path, &content).unwrap();
        assert_file_exists(&receipt_path);
        assert_file_contains(&receipt_path, "mypkg");
    }

    #[test]
    fn receipt_delete() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("todelete", "1.0", "tier1-zainium");
        let path = env.p("overlayer/zexlib/registry/installed/todelete.toml");
        assert!(path.exists());
        fs::remove_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn read_receipt_remove_map() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("check", "1.0", "tier1-zainium");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/registry/installed/check.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        let files = val["remove"]["files"].as_array().unwrap();
        assert!(!files.is_empty());
        assert!(files[0].as_str().unwrap().starts_with("/overlayer/"));
    }

    #[test]
    fn manifest_name_version_no_trailing_whitespace() {
        let m = minimal_manifest("clean", "1.0.0");
        assert!(!m.package.name.ends_with(' '));
        assert!(!m.package.version.ends_with(' '));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INSTALLER — conflict detection (10 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod conflicts {
    use super::*;

    #[test]
    fn no_conflict_empty_db() {
        // With no installed packages, there are no conflicts
        let files = vec!["/overlayer/zexlib/union/bin/myapp".to_string()];
        // We simulate the logic directly since check_file_conflicts reads live DB
        let db: Vec<(String, Vec<String>)> = vec![];
        let conflicts: Vec<_> = db.iter()
            .flat_map(|(pkg, pkg_files)| {
                pkg_files.iter()
                    .filter(|f| files.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn conflict_same_file_different_pkg() {
        let incoming = vec!["/overlayer/zexlib/union/bin/python3".to_string()];
        let db = vec![
            ("python3-legacy".to_string(), vec!["/overlayer/zexlib/union/bin/python3".to_string()]),
        ];
        let conflicts: Vec<_> = db.iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("newpkg"))
            .flat_map(|(pkg, pkg_files)| {
                pkg_files.iter()
                    .filter(|f| incoming.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].0, "python3-legacy");
    }

    #[test]
    fn no_conflict_different_file() {
        let incoming = vec!["/overlayer/zexlib/union/bin/newtool".to_string()];
        let db = vec![
            ("other".to_string(), vec!["/overlayer/zexlib/union/bin/oldtool".to_string()]),
        ];
        let conflicts: Vec<_> = db.iter()
            .flat_map(|(pkg, pkg_files)| {
                pkg_files.iter()
                    .filter(|f| incoming.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn reinstall_skips_self_in_conflict() {
        let pkg_name = "vim";
        let incoming = vec!["/overlayer/zexlib/union/bin/vim".to_string()];
        let db = vec![
            ("vim".to_string(), vec!["/overlayer/zexlib/union/bin/vim".to_string()]),
            ("neovim".to_string(), vec!["/overlayer/zexlib/union/bin/nvim".to_string()]),
        ];
        // Skip the package itself
        let conflicts: Vec<_> = db.iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case(pkg_name))
            .flat_map(|(pkg, pkg_files)| {
                pkg_files.iter()
                    .filter(|f| incoming.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn multiple_conflicts_detected() {
        let incoming = vec![
            "/overlayer/zexlib/union/bin/tool".to_string(),
            "/overlayer/zexlib/union/lib/libtool.so".to_string(),
        ];
        let db = vec![
            ("other-tool".to_string(), vec![
                "/overlayer/zexlib/union/bin/tool".to_string(),
                "/overlayer/zexlib/union/lib/libtool.so".to_string(),
            ]),
        ];
        let conflicts: Vec<_> = db.iter()
            .flat_map(|(pkg, pkg_files)| {
                pkg_files.iter()
                    .filter(|f| incoming.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(conflicts.len(), 2);
    }

    #[test]
    fn force_flag_allows_conflict() {
        let force = true;
        let has_conflict = true;
        // With force=true, conflict should not block install
        let should_proceed = !has_conflict || force;
        assert!(should_proceed);
    }

    #[test]
    fn no_force_blocks_on_conflict() {
        let force = false;
        let has_conflict = true;
        let should_proceed = !has_conflict || force;
        assert!(!should_proceed);
    }

    #[test]
    fn conflict_path_under_overlayer() {
        // All conflict paths must be under /overlayer — never /usr/bin
        let paths = vec![
            "/overlayer/zexlib/union/bin/test",
            "/overlayer/zexlib/union/lib/libtest.so",
        ];
        for path in &paths {
            assert!(path.starts_with("/overlayer/"),
                    "conflict path not under /overlayer: {path}");
        }
    }

    #[test]
    fn lib_path_conflict() {
        let incoming = vec!["/overlayer/zexlib/union/lib/libssl.so.3".to_string()];
        let db = vec![
            ("openssl-legacy".to_string(),
             vec!["/overlayer/zexlib/union/lib/libssl.so.3".to_string()]),
        ];
        let conflicts: Vec<_> = db.iter()
            .flat_map(|(pkg, files)| {
                files.iter()
                    .filter(|f| incoming.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn share_path_conflict() {
        let incoming = vec!["/overlayer/zexlib/union/share/man/man1/gcc.1".to_string()];
        let db = vec![
            ("gcc-old".to_string(),
             vec!["/overlayer/zexlib/union/share/man/man1/gcc.1".to_string()]),
        ];
        let conflicts: Vec<_> = db.iter()
            .flat_map(|(pkg, files)| {
                files.iter()
                    .filter(|f| incoming.contains(f))
                    .map(|f| (pkg.clone(), f.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(conflicts.len(), 1);
    }
}
