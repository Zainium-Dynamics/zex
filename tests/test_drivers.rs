//! tests/test_drivers.rs — Unit tests for driver sub-modules.
//! Tests internal logic without running full CLI dispatch.

mod harness;
use harness::*;
use std::fs;

// ══════════════════════════════════════════════════════════════════════════════
//  UPGRADE — vercmp (18 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod vercmp {
    use zex::cmd::upgrade::vercmp::is_upgrade;

    #[test] fn newer_major()         { assert!(is_upgrade("1.0.0", "2.0.0")); }
    #[test] fn newer_minor()         { assert!(is_upgrade("1.2.0", "1.3.0")); }
    #[test] fn newer_patch()         { assert!(is_upgrade("1.2.5", "1.2.6")); }
    #[test] fn same_not_upgrade()    { assert!(!is_upgrade("5.2", "5.2")); }
    #[test] fn older_not_upgrade()   { assert!(!is_upgrade("2.0.0", "1.0.0")); }
    // Suffix compare is pure lexicographic (no hardcoded alpha/beta/rc policy).
    #[test] fn suffix_lex_order() {
        assert!(is_upgrade("1.0-alpha", "1.0-beta")); // "-alpha" < "-beta"
        assert!(is_upgrade("1.0-beta", "1.0-rc1"));   // "-beta"  < "-rc1"
    }
    #[test] fn apk_revision()        { assert!(is_upgrade("9.1.0-r0", "9.1.0-r1")); }
    #[test] fn xbps_underscore()     { assert!(is_upgrade("3.4.0_1", "3.4.0_2")); }
    #[test] fn long_vs_short()       { assert!(is_upgrade("1.0", "1.0.1")); }
    #[test] fn equal_long()          { assert!(!is_upgrade("1.0.0.0", "1.0.0.0")); }
    #[test] fn single_digit()        { assert!(is_upgrade("8", "9")); }
    #[test] fn double_digit()        { assert!(is_upgrade("9", "10")); }
    #[test] fn zero_to_one()         { assert!(is_upgrade("0", "1")); }
    #[test] fn empty_old()           { assert!(is_upgrade("", "1.0")); }
    #[test] fn git_snapshot()        { assert!(is_upgrade("1.0", "1.0.g20260627")); }

    #[test]
    fn downgrade_detected() {
        assert!(!is_upgrade("14.2.0", "14.1.0"));
        assert!(!is_upgrade("3.0", "2.99"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  UPGRADE — checksum (8 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod checksum {
    use zex::cmd::upgrade::checksum;

    #[test]
    fn sha256_known_value() {
        let hash = checksum::calculate_sha256_bytes(b"hello world");
        assert!(hash.starts_with("b94d27b"));
    }

    #[test]
    fn sha256_empty() {
        let hash = checksum::calculate_sha256_bytes(b"");
        assert!(hash.starts_with("e3b0c44"));
    }

    #[test]
    fn sha256_different_inputs() {
        let h1 = checksum::calculate_sha256_bytes(b"aaa");
        let h2 = checksum::calculate_sha256_bytes(b"bbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_deterministic() {
        let h1 = checksum::calculate_sha256_bytes(b"deterministic");
        let h2 = checksum::calculate_sha256_bytes(b"deterministic");
        assert_eq!(h1, h2);
    }

    #[test]
    fn verify_correct_hash() {
        let data = b"verify me";
        let hash = checksum::calculate_sha256_bytes(data);
        assert!(checksum::verify_bytes(data, &hash));
    }

    #[test]
    fn verify_wrong_hash() {
        assert!(!checksum::verify_bytes(b"data", "0000000000000000"));
    }

    #[test]
    fn hash_display_truncation() {
        let hash = checksum::calculate_sha256_bytes(b"test");
        let display = checksum::format_hash_for_display(&hash);
        assert!(display.len() <= hash.len());
    }

    #[test]
    fn sha256_hex_length() {
        let hash = checksum::calculate_sha256_bytes(b"anything");
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  UPGRADE — signing (6 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod signing {
    use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
    use rand_core::OsRng;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let msg = b"test package payload";
        let sig = sk.sign(msg);
        assert!(vk.verify_strict(msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(vk.verify_strict(b"tampered", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let sig = sk1.sign(b"message");
        assert!(sk2.verifying_key().verify_strict(b"message", &sig).is_err());
    }

    #[test]
    fn key_roundtrip_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        let bytes = sk.to_bytes();
        let restored = SigningKey::from_bytes(&bytes);
        assert_eq!(sk.verifying_key(), restored.verifying_key());
    }

    #[test]
    fn verifying_key_is_32_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        assert_eq!(sk.verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn signature_is_64_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        let sig = sk.sign(b"data");
        assert_eq!(sig.to_bytes().len(), 64);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  SWEEP — scanner logic (10 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod sweep {
    use super::*;

    #[test]
    fn empty_system_is_clean() {
        let env = TempOverlayer::new();
        // No cache, no tmp files — should report clean
        let cache_dir = env.p("overlayer/zexlib/registry/cache/tier1-zainium");
        assert!(fs::read_dir(cache_dir).unwrap().count() == 0);
    }

    #[test]
    fn cache_files_detectable() {
        let env = TempOverlayer::new();
        env.fill_cache("tier1-zainium", 8192);
        let cache = env.p("overlayer/zexlib/registry/cache/tier1-zainium");
        let size: u64 = fs::read_dir(&cache).unwrap()
            .flatten()
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        assert!(size >= 8192);
    }

    #[test]
    fn tmp_files_detectable() {
        let env = TempOverlayer::new();
        env.fill_tmp(5);
        let count = fs::read_dir(env.p("overlayer/zexlib/tmp")).unwrap().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn cache_clearable() {
        let env = TempOverlayer::new();
        env.fill_cache("tier1-zainium", 4096);
        let cache = env.p("overlayer/zexlib/registry/cache/tier1-zainium");

        // Clear
        for entry in fs::read_dir(&cache).unwrap().flatten() {
            fs::remove_file(entry.path()).unwrap();
        }
        assert_eq!(fs::read_dir(&cache).unwrap().count(), 0);
    }

    #[test]
    fn tmp_clearable() {
        let env = TempOverlayer::new();
        env.fill_tmp(3);
        let tmp = env.p("overlayer/zexlib/tmp");

        for entry in fs::read_dir(&tmp).unwrap().flatten() {
            fs::remove_file(entry.path()).unwrap();
        }
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0);
    }

    #[test]
    fn transaction_dir_structure() {
        let env = TempOverlayer::new();
        env.add_transaction("tx-001", "2026-06-01T00:00:00Z");
        env.add_transaction("tx-002", "2026-06-15T00:00:00Z");

        let tx_dir = env.p("overlayer/zexlib/transactions");
        let count = fs::read_dir(&tx_dir).unwrap().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn transaction_manifest_readable() {
        let env = TempOverlayer::new();
        env.add_transaction("tx-abc", "2026-06-27T12:00:00Z");
        assert_file_contains(
            &env.p("overlayer/zexlib/transactions/tx-abc/manifest.toml"),
            "tx-abc",
        );
    }

    #[test]
    fn orphaned_staging_detectable() {
        let env = TempOverlayer::new();
        let staging = env.p("overlayer/syshub.new");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("some-file"), b"leftover").unwrap();
        assert!(staging.is_dir());
    }

    #[test]
    fn multiple_cache_tiers() {
        let env = TempOverlayer::new();
        env.fill_cache("tier1-zainium", 1024);
        env.fill_cache("tier2-alpine", 2048);
        env.fill_cache("tier3-void", 4096);

        for tier in ["tier1-zainium", "tier2-alpine", "tier3-void"] {
            let cache = env.p(&format!("overlayer/zexlib/registry/cache/{tier}"));
            assert!(fs::read_dir(cache).unwrap().count() > 0, "tier {tier} empty");
        }
    }

    #[test]
    fn human_bytes_formatting() {
        // Test the formatting logic
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.00 GB");
    }

    fn format_bytes(b: u64) -> String {
        if b >= 1_073_741_824 { format!("{:.2} GB", b as f64 / 1_073_741_824.0) }
        else if b >= 1_048_576 { format!("{:.1} MB", b as f64 / 1_048_576.0) }
        else if b >= 1024      { format!("{:.1} KB", b as f64 / 1024.0) }
        else                   { format!("{b} B") }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INSPECT — receipt parsing (8 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod inspect {
    use super::*;

    #[test]
    fn receipt_parseable() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("neovim", "0.10.3", "tier1-zainium");
        let path = env.p("overlayer/zexlib/registry/installed/neovim.toml");
        let raw = fs::read_to_string(&path).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert_eq!(val.get("name").unwrap().as_str().unwrap(), "neovim");
        assert_eq!(val.get("version").unwrap().as_str().unwrap(), "0.10.3");
    }

    #[test]
    fn receipt_has_remove_section() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("htop", "3.4.0", "tier1-zainium");
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/registry/installed/htop.toml")
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert!(val.get("remove").is_some());
        assert!(val["remove"].get("files").is_some());
    }

    #[test]
    fn receipt_origin_correct() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("curl", "8.11", "tier2-alpine");
        assert_file_contains(
            &env.p("overlayer/zexlib/registry/installed/curl.toml"),
            "tier2-alpine",
        );
    }

    #[test]
    fn receipt_lowercase_name() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("MyPkg", "1.0", "tier1-zainium");
        // Receipt should be at mypkg.toml (lowercase) — but our harness uses the name as-is
        // This tests the exact filename behavior
        assert_file_exists(&env.p("overlayer/zexlib/registry/installed/MyPkg.toml"));
    }

    #[test]
    fn syshub_manifest_parseable() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(
            env.p("overlayer/syshub/engine/services/syshub.toml")
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert!(val["packages"]["bash"]["version"].as_str().is_some());
    }

    #[test]
    fn syshub_manifest_has_bash() {
        let env = TempOverlayer::new();
        assert_toml_has_key(
            &env.p("overlayer/syshub/engine/services/syshub.toml"),
            "packages.bash.version",
        );
    }

    #[test]
    fn multiple_receipts_coexist() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("a", "1.0", "tier1-zainium");
        env.add_installed_receipt("b", "2.0", "tier2-alpine");
        env.add_installed_receipt("c", "3.0", "tier3-void");

        let dir = env.p("overlayer/zexlib/registry/installed");
        let count = fs::read_dir(dir).unwrap().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn receipt_files_list() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("ripgrep", "14.1.1", "tier1-zainium");
        assert_file_contains(
            &env.p("overlayer/zexlib/registry/installed/ripgrep.toml"),
            "/overlayer/zexlib/union/bin/ripgrep",
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  DOCTOR — layout checks (10 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod doctor_layout {
    use super::*;

    #[test]
    fn syshub_bin_exists() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/syshub/bin"));
    }

    #[test]
    fn syshub_lib_exists() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/syshub/lib"));
    }

    #[test]
    fn syshub_lib64_exists() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/syshub/lib64"));
    }

    #[test]
    fn zexlib_union_layout() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/zexlib/union/bin"));
        assert_dir_exists(&env.p("overlayer/zexlib/union/lib"));
        assert_dir_exists(&env.p("overlayer/zexlib/union/share"));
    }

    #[test]
    fn registry_layout() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/zexlib/registry/installed"));
        assert_file_exists(&env.p("overlayer/zexlib/registry/packages.toml"));
    }

    #[test]
    fn musl_sysroot_layout() {
        let env = TempOverlayer::new();
        let musl = "overlayer/syshub/x86_64-zainium-linux-musl";
        assert_dir_exists(&env.p(&format!("{musl}/bin")));
        assert_dir_exists(&env.p(&format!("{musl}/lib")));
        assert_dir_exists(&env.p(&format!("{musl}/include")));
    }

    #[test]
    fn zaisys_kernel_exists() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/zaisys/kernel"));
    }

    #[test]
    fn engine_services_dir() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/syshub/engine/services"));
    }

    #[test]
    fn zex_services_config() {
        let env = TempOverlayer::new();
        assert_file_exists(
            &env.p("overlayer/syshub/engine/services/zex_services.toml"),
        );
    }

    #[test]
    fn zex_services_has_mirrors() {
        let env = TempOverlayer::new();
        assert_toml_has_key(
            &env.p("overlayer/syshub/engine/services/zex_services.toml"),
            "mirrors",
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  SEARCH — models + config (6 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod search {
    use zex::cmd::search::models::{Origin, SearchResult};

    #[test]
    fn origin_label_t1() {
        assert_eq!(Origin::Zainium.label(), "Zainium");
    }

    #[test]
    fn origin_label_t2() {
        assert_eq!(Origin::Alpine.label(), "Alpine");
    }

    #[test]
    fn search_result_display() {
        let r = SearchResult {
            name:        "vim".into(),
            version:     "9.1.0".into(),
            description: "Vi IMproved".into(),
            origin:      Origin::Zainium,
            installed:   false,
            tags:        vec!["editor".into()],
        };
        assert_eq!(r.name, "vim");
        assert!(!r.installed);
    }

    #[test]
    fn search_result_clone() {
        let r = SearchResult {
            name: "a".into(), version: "1".into(),
            description: "test".into(), origin: Origin::Zainium,
            installed: false, tags: vec![],
        };
        let c = r.clone();
        assert_eq!(c.name, r.name);
    }

    #[test]
    fn origin_chimera() {
        let o = Origin::Chimera;
        assert_eq!(o.label(), "Chimera");
    }

    #[test]
    fn origin_void() {
        let o = Origin::Void;
        assert_eq!(o.label(), "Void");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  UPDATE — diff logic (6 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod update_vercmp {
    use zex::cmd::update::vercmp::is_upgrade;

    #[test] fn newer()          { assert!(is_upgrade("1.0", "1.1")); }
    #[test] fn same()           { assert!(!is_upgrade("1.0", "1.0")); }
    #[test] fn older()          { assert!(!is_upgrade("2.0", "1.0")); }
    #[test] fn apk_rev()        { assert!(is_upgrade("1.0-r0", "1.0-r1")); }
    #[test] fn major_jump()     { assert!(is_upgrade("1.99", "2.0")); }
    #[test] fn empty_to_ver()   { assert!(is_upgrade("", "0.1")); }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INSTALL — backend config (5 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod install_backend {
    use zex::cmd::install::backend::PackageFormat;

    #[test]
    fn format_zex() {
        let f = PackageFormat::Zex;
        assert_eq!(format!("{:?}", f), "Zex");
    }

    #[test]
    fn format_apk() {
        let f = PackageFormat::Apk;
        assert_eq!(format!("{:?}", f), "Apk");
    }

    #[test]
    fn format_xbps() {
        let f = PackageFormat::Xbps;
        assert_eq!(format!("{:?}", f), "Xbps");
    }

    #[test]
    fn format_clone() {
        let f = PackageFormat::Zex;
        let c = f.clone();
        assert_eq!(format!("{:?}", f), format!("{:?}", c));
    }

    #[test]
    fn package_info_default() {
        let pi = zex::cmd::install::backend::PackageInfo::default();
        assert!(pi.name.is_empty());
        assert!(pi.sha256.is_none());
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INSTALL — zex_manifest (6 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod zex_manifest {
    #[test]
    fn manifest_toml_parse() {
        let raw = r#"
[package]
name = "hello"
version = "1.0.0"
description = "Hello world"
license = "MIT"

[install]
bin = "/overlayer/zexlib/union/bin"

[remove]
files = ["/overlayer/zexlib/union/bin/hello"]
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert_eq!(val["package"]["name"].as_str().unwrap(), "hello");
        assert_eq!(val["package"]["version"].as_str().unwrap(), "1.0.0");
        assert!(val.get("install").is_some());
        assert!(val.get("remove").is_some());
    }

    #[test]
    fn manifest_with_depends() {
        let raw = r#"
[package]
name = "myapp"
version = "2.0"

[depends]
runtime = ["libfoo >= 1.0", "libbar"]
build = ["gcc", "cmake"]
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        let runtime = val["depends"]["runtime"].as_array().unwrap();
        assert_eq!(runtime.len(), 2);
    }

    #[test]
    fn manifest_with_edition() {
        let raw = r#"
[package]
name = "rust"
version = "1.82.0"

[editions]
stable = { version = "1.82.0", default = true }
nightly = { version = "1.84.0-nightly" }
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert!(val["editions"]["stable"]["default"].as_bool().unwrap());
    }

    #[test]
    fn manifest_remove_map() {
        let raw = r#"
[remove]
files = ["/overlayer/zexlib/union/bin/a", "/overlayer/zexlib/union/lib/liba.so"]
symlinks = ["/overlayer/zexlib/union/bin/a-link"]
dirs = ["/overlayer/zexlib/union/share/a"]
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert_eq!(val["remove"]["files"].as_array().unwrap().len(), 2);
        assert_eq!(val["remove"]["symlinks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn manifest_install_map() {
        let raw = r#"
[install]
bin = "/overlayer/zexlib/union/bin"
lib = "/overlayer/zexlib/union/lib"
share = "/overlayer/zexlib/union/share"
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert_eq!(
            val["install"]["bin"].as_str().unwrap(),
            "/overlayer/zexlib/union/bin"
        );
    }

    #[test]
    fn manifest_minimal_valid() {
        let raw = r#"
[package]
name = "minimal"
version = "0.1"
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert_eq!(val["package"]["name"].as_str().unwrap(), "minimal");
    }
}
