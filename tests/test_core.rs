//! tests/test_core.rs: Tests for core zex modules:

mod harness;
use harness::*;
use std::fs;

mod aliases {
    use zex::aliases;

    #[test]
    fn resolve_install() {
        let r = aliases::resolve("install").unwrap();
        assert!(r.binary_candidates.iter().any(|b| b.contains("install")));
    }

    #[test]
    fn resolve_remove() {
        let r = aliases::resolve("remove").unwrap();
        assert!(r.binary_candidates.iter().any(|b| b.contains("remove")));
    }

    #[test]
    fn resolve_search() {
        let r = aliases::resolve("search").unwrap();
        assert!(r.binary_candidates.iter().any(|b| b.contains("search")));
    }

    #[test]
    fn resolve_doctor() {
        let r = aliases::resolve("doctor").unwrap();
        assert!(r.binary_candidates.iter().any(|b| b.contains("doctor")));
    }

    #[test]
    fn resolve_upgrade_not_a_command() {
        assert!(aliases::resolve("upgrade").is_none());
    }

    #[test]
    fn resolve_syshub_alias() {
        let r = aliases::resolve("syshub").unwrap();
        assert!(r.binary_candidates.iter().any(|b| b.contains("upgrade")));
        assert!(r.internal_args.iter().any(|a| a == "syshub"));
        assert!(r.internal_args.iter().any(|a| a == "--u"));
    }

    #[test]
    fn resolve_uland_alias() {
        let r = aliases::resolve("uland").unwrap();
        assert!(r.internal_args.iter().any(|a| a == "uland"));
        assert!(r.internal_args.iter().any(|a| a == "--u"));
    }

    #[test]
    fn resolve_sweep() {
        assert!(aliases::resolve("sweep").is_some());
    }

    #[test]
    fn resolve_inspect() {
        assert!(aliases::resolve("inspect").is_some());
    }

    #[test]
    fn resolve_rollback() {
        assert!(aliases::resolve("rollback").is_some());
    }

    #[test]
    fn resolve_depends() {
        assert!(aliases::resolve("depends").is_some());
    }

    #[test]
    fn resolve_why() {
        assert!(aliases::resolve("why").is_some());
    }

    #[test]
    fn resolve_update() {
        assert!(aliases::resolve("update").is_some());
    }

    #[test]
    fn unknown_returns_none() {
        assert!(aliases::resolve("nonexistent-cmd-xyz").is_none());
    }

    #[test]
    fn all_routes_have_candidates() {
        for cmd in [
            "install", "remove", "search", "doctor", "syshub", "uland", "sweep", "inspect",
            "rollback", "depends", "why", "update",
        ] {
            let r =
                aliases::resolve(cmd).unwrap_or_else(|| panic!("command '{cmd}' should resolve"));
            assert!(
                !r.binary_candidates.is_empty(),
                "command '{cmd}' has no binary candidates"
            );
        }
    }
}

mod extract {
    use super::*;
    use std::path::Path;
    use zex::extract;

    #[test]
    fn detect_zex_format() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("hello", "1.0.0", tmp.path());
        let fmt = extract::detect_format(&pkg).unwrap();
        assert_eq!(fmt, extract::PackageFormat::Zex);
    }

    #[test]
    fn extract_zex_package() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("myapp", "2.0.0", tmp.path());

        let out_dir = tmp.path().join("extracted");
        let result = extract::extract(&pkg, &out_dir).unwrap();

        assert!(result.files_extracted > 0);
        assert!(out_dir.join("manifest.toml").exists());
        assert!(out_dir.join("payload/bin/myapp").exists());
    }

    #[test]
    fn extract_preserves_manifest_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("checkme", "3.0.0", tmp.path());

        let out = tmp.path().join("out");
        extract::extract(&pkg, &out).unwrap();

        let manifest = fs::read_to_string(out.join("manifest.toml")).unwrap();
        assert!(manifest.contains("checkme"));
        assert!(manifest.contains("3.0.0"));
    }

    #[test]
    fn detect_tar_gz_format_by_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("test.tar.gz");
        fs::write(&path, &[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        let fmt = extract::detect_format(&path).unwrap();
        assert_eq!(fmt, extract::PackageFormat::TarGz);
    }

    #[test]
    fn detect_tar_xz_format_by_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("test.tar.xz");
        fs::write(&path, &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x00]).unwrap();
        let fmt = extract::detect_format(&path).unwrap();
        assert_eq!(fmt, extract::PackageFormat::TarXz);
    }

    #[test]
    fn extract_nonexistent_file_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = extract::extract(Path::new("/nonexistent/file.zex"), &tmp.path().join("out"));
        assert!(result.is_err());
    }

    #[test]
    fn run_with_no_args_errors() {
        let result = extract::run(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn run_with_valid_zex() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("runtest", "1.0.0", tmp.path());
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let args = vec![
            pkg.to_string_lossy().to_string(),
            "-o".to_string(),
            out_dir.to_string_lossy().to_string(),
        ];
        let result = extract::run(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn extracted_file_count_matches() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("counter", "1.0.0", tmp.path());
        let out = tmp.path().join("out");
        let result = extract::extract(&pkg, &out).unwrap();
        assert!(
            result.files_extracted >= 2,
            "expected >= 2 files, got {}",
            result.files_extracted
        );
    }

    #[test]
    fn extract_creates_output_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("autocreate", "1.0.0", tmp.path());
        let out = tmp.path().join("deeply/nested/output");
        assert!(!out.exists());
        extract::extract(&pkg, &out).unwrap();
        assert!(out.exists());
    }

    #[test]
    fn format_display_names() {
        assert_eq!(format!("{:?}", extract::PackageFormat::Zex), "Zex");
        assert_eq!(format!("{:?}", extract::PackageFormat::TarZst), "TarZst");
        assert_eq!(format!("{:?}", extract::PackageFormat::TarGz), "TarGz");
        assert_eq!(format!("{:?}", extract::PackageFormat::TarXz), "TarXz");
    }

    #[test]
    fn multiple_extract_same_dir_overwrites() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("overwrite", "1.0.0", tmp.path());
        let out = tmp.path().join("out");

        extract::extract(&pkg, &out).unwrap();
        let r2 = extract::extract(&pkg, &out);
        assert!(r2.is_ok());
    }
}

mod pinning {
    use super::*;
    use zex::pinning;

    #[test]
    fn pinned_file_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("pinned.toml");

        let pkg = pinning::PinnedPackage {
            name: "vim".into(),
            pinned_version: "9.1.0".into(),
            pinned_at: "2026-06-27T00:00:00Z".into(),
            pinned_by: "alizain".into(),
            reason: Some("kernel build".into()),
        };

        #[derive(serde::Serialize, serde::Deserialize)]
        struct PF {
            pinned: Vec<pinning::PinnedPackage>,
        }

        let pf = PF {
            pinned: vec![pkg.clone()],
        };
        let text = toml::to_string_pretty(&pf).unwrap();
        fs::write(&path, &text).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let parsed: PF = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.pinned.len(), 1);
        assert_eq!(parsed.pinned[0].name, "vim");
        assert_eq!(parsed.pinned[0].pinned_version, "9.1.0");
        assert_eq!(parsed.pinned[0].reason, Some("kernel build".into()));
    }

    #[test]
    fn pinned_package_serializes_all_fields() {
        let pkg = pinning::PinnedPackage {
            name: "test".into(),
            pinned_version: "1.0".into(),
            pinned_at: "2026-01-01".into(),
            pinned_by: "user".into(),
            reason: None,
        };
        let json = serde_json::to_string(&pkg).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"pinned_version\":\"1.0\""));
    }

    #[test]
    fn pinned_package_without_reason() {
        let pkg = pinning::PinnedPackage {
            name: "pkg".into(),
            pinned_version: "2.0".into(),
            pinned_at: "now".into(),
            pinned_by: "root".into(),
            reason: None,
        };
        let text = toml::to_string(&pkg).unwrap();
        assert!(!text.contains("reason ="));
    }

    #[test]
    fn empty_pinned_list() {
        let pins: Vec<pinning::PinnedPackage> = Vec::new();
        assert!(pins.is_empty());
        pinning::print_pins(&pins);
    }

    #[test]
    fn print_pins_does_not_panic_with_data() {
        let pins = vec![
            pinning::PinnedPackage {
                name: "vim".into(),
                pinned_version: "9.1".into(),
                pinned_at: "2026-01-01".into(),
                pinned_by: "alizain".into(),
                reason: Some("stable".into()),
            },
            pinning::PinnedPackage {
                name: "gcc".into(),
                pinned_version: "14.2".into(),
                pinned_at: "2026-01-01".into(),
                pinned_by: "root".into(),
                reason: None,
            },
        ];
        pinning::print_pins(&pins);
    }

    #[test]
    fn pinned_package_clone() {
        let pkg = pinning::PinnedPackage {
            name: "a".into(),
            pinned_version: "1".into(),
            pinned_at: "t".into(),
            pinned_by: "u".into(),
            reason: None,
        };
        let cloned = pkg.clone();
        assert_eq!(cloned.name, "a");
    }

    #[test]
    fn pinned_toml_multiple_entries() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct PF {
            pinned: Vec<pinning::PinnedPackage>,
        }

        let pf = PF {
            pinned: vec![
                pinning::PinnedPackage {
                    name: "a".into(),
                    pinned_version: "1".into(),
                    pinned_at: "t".into(),
                    pinned_by: "u".into(),
                    reason: None,
                },
                pinning::PinnedPackage {
                    name: "b".into(),
                    pinned_version: "2".into(),
                    pinned_at: "t".into(),
                    pinned_by: "u".into(),
                    reason: Some("critical".into()),
                },
                pinning::PinnedPackage {
                    name: "c".into(),
                    pinned_version: "3".into(),
                    pinned_at: "t".into(),
                    pinned_by: "u".into(),
                    reason: None,
                },
            ],
        };
        let text = toml::to_string_pretty(&pf).unwrap();
        let parsed: PF = toml::from_str(&text).unwrap();
        assert_eq!(parsed.pinned.len(), 3);
        assert_eq!(parsed.pinned[1].reason, Some("critical".into()));
    }
}

mod overlayer {
    use super::*;

    #[test]
    fn creates_syshub_dirs() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/syshub/bin"));
        assert_dir_exists(&env.p("overlayer/syshub/lib"));
        assert_dir_exists(&env.p("overlayer/syshub/drivers/system"));
    }

    #[test]
    fn creates_zexlib_dirs() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/zexlib/registry/installed"));
        assert_dir_exists(&env.p("overlayer/zexlib/registry/cache/tier1-zainium"));
        assert_dir_exists(&env.p("overlayer/zexlib/union/bin"));
        assert_dir_exists(&env.p("overlayer/zexlib/transactions"));
        assert_dir_exists(&env.p("overlayer/zexlib/tmp"));
    }

    #[test]
    fn creates_musl_sysroot() {
        let env = TempOverlayer::new();
        assert_dir_exists(&env.p("overlayer/syshub/x86_64-zainium-linux-musl/bin"));
        assert_dir_exists(&env.p("overlayer/syshub/x86_64-zainium-linux-musl/lib"));
        assert_dir_exists(&env.p("overlayer/syshub/x86_64-zainium-linux-musl/include"));
    }

    #[test]
    fn syshub_toml_exists() {
        let env = TempOverlayer::new();
        assert_file_exists(&env.p("overlayer/syshub/engine/services/syshub.toml"));
    }

    #[test]
    fn syshub_toml_has_packages() {
        let env = TempOverlayer::new();
        assert_toml_has_key(
            &env.p("overlayer/syshub/engine/services/syshub.toml"),
            "packages",
        );
    }

    #[test]
    fn add_receipt_creates_file() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("vim", "9.1.0", "tier1-zainium");
        assert_file_exists(&env.p("overlayer/zexlib/registry/installed/vim.toml"));
    }

    #[test]
    fn add_receipt_content_correct() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("gcc", "14.2.0", "tier1-zainium");
        assert_file_contains(
            &env.p("overlayer/zexlib/registry/installed/gcc.toml"),
            "version = \"14.2.0\"",
        );
    }

    #[test]
    fn fill_cache_creates_files() {
        let env = TempOverlayer::new();
        env.fill_cache("tier1-zainium", 4096);
        let cache = env.p("overlayer/zexlib/registry/cache/tier1-zainium");
        assert!(fs::read_dir(cache).unwrap().count() > 0);
    }
}
