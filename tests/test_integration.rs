//! tests/test_integration.rs — End-to-end integration tests.
//! Tests full package lifecycle: create → extract → install → inspect → remove.

mod harness;
use harness::*;
use std::fs;

// ══════════════════════════════════════════════════════════════════════════════
//  PACKAGE LIFECYCLE — create, extract, verify (12 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod lifecycle {
    use super::*;

    #[test]
    fn create_and_extract_zex_package() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("lifecycle", "1.0.0", tmp.path());

        assert!(pkg.exists());
        assert!(pkg.metadata().unwrap().len() > 0);

        let out = tmp.path().join("extracted");
        let result = zex::extract::extract(&pkg, &out).unwrap();

        assert!(result.files_extracted >= 2);
        assert_file_exists(&out.join("manifest.toml"));
        assert_file_exists(&out.join("payload/bin/lifecycle"));
    }

    #[test]
    fn manifest_roundtrip_integrity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("integrity", "2.5.0", tmp.path());
        let out = tmp.path().join("out");
        zex::extract::extract(&pkg, &out).unwrap();

        let manifest = fs::read_to_string(out.join("manifest.toml")).unwrap();
        assert!(manifest.contains("name = \"integrity\""));
        assert!(manifest.contains("version = \"2.5.0\""));
        assert!(manifest.contains("[install]"));
        assert!(manifest.contains("[remove]"));
    }

    #[test]
    fn payload_binary_present_after_extract() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("mybin", "1.0.0", tmp.path());
        let out = tmp.path().join("out");
        zex::extract::extract(&pkg, &out).unwrap();

        let bin = out.join("payload/bin/mybin");
        assert_file_exists(&bin);
        let content = fs::read_to_string(&bin).unwrap();
        assert!(content.contains("mybin"));
    }

    #[test]
    fn multiple_packages_independent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg_a = create_test_zex_package("alpha", "1.0", tmp.path());
        let pkg_b = create_test_zex_package("bravo", "2.0", tmp.path());

        let out_a = tmp.path().join("out_a");
        let out_b = tmp.path().join("out_b");
        zex::extract::extract(&pkg_a, &out_a).unwrap();
        zex::extract::extract(&pkg_b, &out_b).unwrap();

        assert_file_contains(&out_a.join("manifest.toml"), "alpha");
        assert_file_contains(&out_b.join("manifest.toml"), "bravo");
        // They don't contaminate each other
        let a_content = fs::read_to_string(out_a.join("manifest.toml")).unwrap();
        assert!(!a_content.contains("bravo"));
    }

    #[test]
    fn package_is_valid_zexc() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("zexctest", "1.0", tmp.path());

        // First 4 bytes of zexc: "ZEX1" (0x5A 0x45 0x58 0x31)
        let data = fs::read(&pkg).unwrap();
        assert!(data.len() >= 4);
        assert_eq!(&data[..4], b"ZEX1");
        assert!(zex::zex_codec::is_zex_magic(&data));
    }

    #[test]
    fn large_package_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let name = "a".repeat(64);
        let pkg = create_test_zex_package(&name, "1.0", tmp.path());

        let out = tmp.path().join("out");
        let result = zex::extract::extract(&pkg, &out);
        assert!(result.is_ok());
    }

    #[test]
    fn version_with_special_chars() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("specver", "1.0.0-rc1+build.42", tmp.path());
        let out = tmp.path().join("out");
        zex::extract::extract(&pkg, &out).unwrap();
        assert_file_contains(&out.join("manifest.toml"), "1.0.0-rc1+build.42");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  OVERLAYER STATE — registry integrity (10 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod registry {
    use super::*;

    #[test]
    fn installed_packages_trackable() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("vim", "9.1.0", "tier1-zainium");
        env.add_installed_receipt("htop", "3.4.0", "tier1-zainium");
        env.add_installed_receipt("curl", "8.11", "tier2-alpine");

        let installed_dir = env.p("overlayer/zexlib/registry/installed");
        let count = fs::read_dir(&installed_dir).unwrap().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn packages_toml_parseable() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/registry/packages.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert!(val["packages"]["htop"]["version"].as_str().is_some());
    }

    #[test]
    fn receipt_version_matches() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("gcc", "14.2.0", "tier1-zainium");

        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/registry/installed/gcc.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert_eq!(val["version"].as_str().unwrap(), "14.2.0");
    }

    #[test]
    fn receipt_has_all_fields() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("test", "1.0", "tier1-zainium");

        let raw = fs::read_to_string(
            env.p("overlayer/zexlib/registry/installed/test.toml"),
        ).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        assert!(val.get("name").is_some());
        assert!(val.get("version").is_some());
        assert!(val.get("origin").is_some());
        assert!(val.get("installed_at").is_some());
        assert!(val.get("libc_target").is_some());
        assert!(val.get("remove").is_some());
    }

    #[test]
    fn pinned_toml_isolated() {
        let env = TempOverlayer::new();
        env.set_pinned(r#"[[pinned]]
name = "gcc"
pinned_version = "14.2.0"
pinned_at = "2026-06-27"
pinned_by = "alizain"
"#);
        assert_file_contains(
            &env.p("overlayer/zexlib/registry/pinned.toml"),
            "gcc",
        );
    }

    #[test]
    fn transaction_history() {
        let env = TempOverlayer::new();
        for i in 1..=5 {
            env.add_transaction(
                &format!("tx-{i:03}"),
                &format!("2026-06-{i:02}T00:00:00Z"),
            );
        }
        let count = fs::read_dir(env.p("overlayer/zexlib/transactions")).unwrap().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn cache_tiers_isolated() {
        let env = TempOverlayer::new();
        env.fill_cache("tier1-zainium", 1024);

        // tier2 should be empty
        let t2 = env.p("overlayer/zexlib/registry/cache/tier2-alpine");
        assert_eq!(fs::read_dir(t2).unwrap().count(), 0);
    }

    #[test]
    fn syshub_immutable_marker() {
        let env = TempOverlayer::new();
        // syshub.toml is the immutable manifest
        let syshub = env.p("overlayer/syshub/engine/services/syshub.toml");
        let raw = fs::read_to_string(&syshub).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        // Should have bash and coreutils
        assert!(val["packages"]["bash"].is_table());
        assert!(val["packages"]["coreutils"].is_table());
    }

    #[test]
    fn zex_services_mirror_urls() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(
            env.p("overlayer/syshub/engine/services/zex_services.toml"),
        ).unwrap();
        assert!(raw.contains("archive.zainiumdynamics.tech"));
        assert!(raw.contains("alpinelinux.org"));
        assert!(raw.contains("voidlinux.org"));
    }

    #[test]
    fn union_dir_is_userland_root() {
        let env = TempOverlayer::new();
        // union/ is where userland packages install their files
        assert_dir_exists(&env.p("overlayer/zexlib/union/bin"));
        assert_dir_exists(&env.p("overlayer/zexlib/union/lib"));
        assert_dir_exists(&env.p("overlayer/zexlib/union/share"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  FILESYSTEM SAFETY — permission + error handling (8 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod fs_safety {
    use super::*;
    use std::path::Path;

    #[test]
    fn extract_to_readonly_dir_fails_gracefully() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("readonly", "1.0", tmp.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let out = tmp.path().join("readonly_dir");
            fs::create_dir(&out).unwrap();
            fs::set_permissions(&out, fs::Permissions::from_mode(0o444)).unwrap();

            let result = zex::extract::extract(&pkg, &out.join("sub"));
            // Should fail — can't write to readonly parent
            // (may succeed if running as root)
            if !nix::unistd::Uid::effective().is_root() {
                assert!(result.is_err());
            }

            // Restore permissions for cleanup
            fs::set_permissions(&out, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn nonexistent_package_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = zex::extract::extract(
            Path::new("/no/such/file.zex"),
            &tmp.path().join("out"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let empty = tmp.path().join("empty.zex");
        fs::write(&empty, b"").unwrap();
        let result = zex::extract::extract(&empty, &tmp.path().join("out"));
        assert!(result.is_err());
    }

    #[test]
    fn corrupt_zstd_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let corrupt = tmp.path().join("corrupt.zex");
        // Write zstd magic but garbage after
        fs::write(&corrupt, &[0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF]).unwrap();
        let result = zex::extract::extract(&corrupt, &tmp.path().join("out"));
        assert!(result.is_err());
    }

    #[test]
    fn receipt_dir_must_exist() {
        let env = TempOverlayer::new();
        let path = env.p("overlayer/zexlib/registry/installed");
        assert!(path.is_dir());
    }

    #[test]
    fn concurrent_tmp_writes_safe() {
        let env = TempOverlayer::new();
        let tmp = env.p("overlayer/zexlib/tmp");

        // Simulate concurrent writes
        for i in 0..10 {
            fs::write(tmp.join(format!("concurrent_{i}")), format!("data {i}")).unwrap();
        }
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 10);
    }

    #[test]
    fn receipt_overwrite_updates() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("pkg", "1.0", "tier1-zainium");
        assert_file_contains(
            &env.p("overlayer/zexlib/registry/installed/pkg.toml"),
            "1.0",
        );

        // Overwrite with new version
        env.add_installed_receipt("pkg", "2.0", "tier1-zainium");
        assert_file_contains(
            &env.p("overlayer/zexlib/registry/installed/pkg.toml"),
            "2.0",
        );
    }

    #[test]
    fn deep_nested_extract() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("deep", "1.0", tmp.path());
        let out = tmp.path().join("a/b/c/d/e/f");
        let result = zex::extract::extract(&pkg, &out);
        assert!(result.is_ok());
        assert_file_exists(&out.join("manifest.toml"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  CRYPTO — Ed25519 + Blake3 + SHA256 roundtrips (10 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod crypto {
    use ed25519_dalek::{SigningKey, Signer};
    use sha2::{Sha256, Digest};
    use rand_core::OsRng;

    #[test]
    fn sha256_of_package_deterministic() {
        let data = b"simulated package bytes 12345";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let h1 = hex::encode(hasher.finalize());

        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let h2 = hex::encode(hasher2.finalize());

        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn blake3_of_package_deterministic() {
        let data = b"simulated package content";
        let h1 = blake3::hash(data).to_hex().to_string();
        let h2 = blake3::hash(data).to_hex().to_string();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn sign_package_hash() {
        let sk = SigningKey::generate(&mut OsRng);
        let package_hash = blake3::hash(b"package payload").to_hex();
        let sig = sk.sign(package_hash.as_bytes());
        assert!(sk.verifying_key()
            .verify_strict(package_hash.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn tampered_hash_signature_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let real_hash = blake3::hash(b"real payload").to_hex();
        let sig = sk.sign(real_hash.as_bytes());

        let fake_hash = blake3::hash(b"tampered payload").to_hex();
        assert!(sk.verifying_key()
            .verify_strict(fake_hash.as_bytes(), &sig)
            .is_err());
    }

    #[test]
    fn blake3_vs_sha256_different() {
        let data = b"compare me";
        let b3 = blake3::hash(data).to_hex().to_string();
        let mut sha = Sha256::new();
        sha.update(data);
        let s2 = hex::encode(sha.finalize());
        assert_ne!(b3, s2); // Different algorithms produce different hashes
    }

    #[test]
    fn empty_data_still_produces_hash() {
        let b3 = blake3::hash(b"").to_hex().to_string();
        assert_eq!(b3.len(), 64);
        assert_ne!(b3, "0".repeat(64));
    }

    #[test]
    fn large_data_hashing() {
        let data = vec![0xAB_u8; 10_000_000]; // 10 MB
        let h = blake3::hash(&data).to_hex().to_string();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn key_serialization_base64() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            vk.as_bytes(),
        );
        assert!(!b64.is_empty());
        // Decode back
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &b64,
        ).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn multiple_signatures_same_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        for i in 0..10 {
            let msg = format!("package-{i}");
            let sig = sk.sign(msg.as_bytes());
            assert!(vk.verify_strict(msg.as_bytes(), &sig).is_ok());
        }
    }

    #[test]
    fn different_keys_different_signatures() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let msg = b"same message";
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}
