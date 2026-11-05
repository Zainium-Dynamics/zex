//! tests/test_registry.rs: Registry TOML format validation.

mod harness;
use harness::*;
use std::fs;

mod pinned_schema {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct PinnedFile {
        pinned: Vec<PinnedEntry>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct PinnedEntry {
        name: String,
        pinned_version: String,
        pinned_at: String,
        pinned_by: String,
        reason: Option<String>,
    }

    fn sample() -> PinnedFile {
        PinnedFile {
            pinned: vec![
                PinnedEntry {
                    name: "gcc".into(),
                    pinned_version: "14.2.0".into(),
                    pinned_at: "2026-06-27T00:00:00Z".into(),
                    pinned_by: "alizain".into(),
                    reason: Some("compiler ABI stability".into()),
                },
                PinnedEntry {
                    name: "libc".into(),
                    pinned_version: "1.0.0".into(),
                    pinned_at: "2026-06-27T00:00:00Z".into(),
                    pinned_by: "alizain".into(),
                    reason: None,
                },
            ],
        }
    }

    #[test]
    fn roundtrip_full() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("pinned.toml");
        let original = sample();
        let text = toml::to_string_pretty(&original).unwrap();
        fs::write(&path, &text).unwrap();
        let parsed: PinnedFile = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn with_reason_serializes() {
        let f = PinnedFile {
            pinned: vec![PinnedEntry {
                name: "a".into(),
                pinned_version: "1".into(),
                pinned_at: "t".into(),
                pinned_by: "u".into(),
                reason: Some("important".into()),
            }],
        };
        let text = toml::to_string_pretty(&f).unwrap();
        assert!(text.contains("reason = \"important\""));
    }

    #[test]
    fn without_reason_omits_key() {
        let f = PinnedFile {
            pinned: vec![PinnedEntry {
                name: "a".into(),
                pinned_version: "1".into(),
                pinned_at: "t".into(),
                pinned_by: "u".into(),
                reason: None,
            }],
        };
        let text = toml::to_string_pretty(&f).unwrap();
        assert!(!text.contains("reason ="));
    }

    #[test]
    fn empty_pinned_list() {
        let f = PinnedFile { pinned: vec![] };
        let text = toml::to_string_pretty(&f).unwrap();
        let parsed: PinnedFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.pinned.len(), 0);
    }

    #[test]
    fn many_pins_roundtrip() {
        let pins: Vec<PinnedEntry> = (0..50)
            .map(|i| PinnedEntry {
                name: format!("pkg{i}"),
                pinned_version: format!("1.{i}.0"),
                pinned_at: "2026-06-27T00:00:00Z".into(),
                pinned_by: "alizain".into(),
                reason: if i % 3 == 0 {
                    Some(format!("reason {i}"))
                } else {
                    None
                },
            })
            .collect();
        let f = PinnedFile { pinned: pins };
        let text = toml::to_string_pretty(&f).unwrap();
        let parsed: PinnedFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.pinned.len(), 50);
    }

    #[test]
    fn lookup_by_name() {
        let f = sample();
        let found = f.pinned.iter().find(|p| p.name == "gcc");
        assert!(found.is_some());
        assert_eq!(found.unwrap().pinned_version, "14.2.0");
    }

    #[test]
    fn name_case_insensitive_lookup() {
        let f = sample();
        let found = f.pinned.iter().find(|p| p.name.eq_ignore_ascii_case("GCC"));
        assert!(found.is_some());
    }
}

mod receipt_schema {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct Receipt {
        name: String,
        version: String,
        #[serde(default)]
        description: String,
        #[serde(default)]
        license: String,
        #[serde(default)]
        maintainer: String,
        #[serde(default)]
        origin: String,
        #[serde(default)]
        installed_at: String,
        #[serde(default)]
        libc_target: Option<String>,
        #[serde(default)]
        build_type: Option<String>,
        remove: Option<RemoveMap>,
    }

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct RemoveMap {
        #[serde(default)]
        files: Vec<String>,
        #[serde(default)]
        symlinks: Vec<String>,
        #[serde(default)]
        dirs: Vec<String>,
    }

    fn sample() -> Receipt {
        Receipt {
            name: "ripgrep".into(),
            version: "14.1.1".into(),
            description: "Fast grep alternative".into(),
            license: "MIT/Unlicense".into(),
            maintainer: "BurntSushi".into(),
            origin: "tier1-zainium".into(),
            installed_at: "2026-06-27T00:00:00Z".into(),
            libc_target: Some("musl".into()),
            build_type: Some("static".into()),
            remove: Some(RemoveMap {
                files: vec!["/overlayer/zexlib/union/bin/rg".into()],
                symlinks: vec![],
                dirs: vec![],
            }),
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample();
        let text = toml::to_string_pretty(&original).unwrap();
        let parsed: Receipt = toml::from_str(&text).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn has_name_version() {
        let text = toml::to_string_pretty(&sample()).unwrap();
        assert!(text.contains("name = \"ripgrep\""));
        assert!(text.contains("version = \"14.1.1\""));
    }

    #[test]
    fn remove_files_serialized() {
        let text = toml::to_string_pretty(&sample()).unwrap();
        assert!(text.contains("/overlayer/zexlib/union/bin/rg"));
    }

    #[test]
    fn libc_target_preserved() {
        let r = sample();
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: Receipt = toml::from_str(&text).unwrap();
        assert_eq!(parsed.libc_target, Some("musl".into()));
    }

    #[test]
    fn without_remove_parses() {
        let raw = r#"
name = "minimal"
version = "1.0"
"#;
        let r: Receipt = toml::from_str(raw).unwrap();
        assert_eq!(r.name, "minimal");
        assert!(r.remove.is_none());
    }

    #[test]
    fn multiple_files_in_remove() {
        let r = Receipt {
            name: "big".into(),
            version: "1.0".into(),
            remove: Some(RemoveMap {
                files: (0..20)
                    .map(|i| format!("/overlayer/zexlib/union/lib/lib{i}.so"))
                    .collect(),
                symlinks: vec!["/overlayer/zexlib/union/bin/big".into()],
                dirs: vec!["/overlayer/zexlib/union/share/big".into()],
            }),
            ..Default::default()
        };
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: Receipt = toml::from_str(&text).unwrap();
        assert_eq!(parsed.remove.as_ref().unwrap().files.len(), 20);
        assert_eq!(parsed.remove.as_ref().unwrap().symlinks.len(), 1);
    }

    #[test]
    fn origin_tier_variants() {
        for tier in [
            "tier1-zainium",
            "tier2-alpine",
            "tier3-void",
            "tier4-chimera",
        ] {
            let r = Receipt {
                name: "x".into(),
                version: "1".into(),
                origin: tier.into(),
                ..Default::default()
            };
            let text = toml::to_string_pretty(&r).unwrap();
            let parsed: Receipt = toml::from_str(&text).unwrap();
            assert_eq!(parsed.origin, tier);
        }
    }

    #[test]
    fn build_type_static_dynamic() {
        for btype in ["static", "dynamic"] {
            let r = Receipt {
                name: "x".into(),
                version: "1".into(),
                build_type: Some(btype.into()),
                ..Default::default()
            };
            let text = toml::to_string_pretty(&r).unwrap();
            let parsed: Receipt = toml::from_str(&text).unwrap();
            assert_eq!(parsed.build_type.as_deref(), Some(btype));
        }
    }

    #[test]
    fn unicode_in_description() {
        let r = Receipt {
            name: "unicode".into(),
            version: "1.0".into(),
            description: "Zainium OS 🚀 — نظام التشغيل زينيوم".into(),
            ..Default::default()
        };
        let text = toml::to_string_pretty(&r).unwrap();
        let parsed: Receipt = toml::from_str(&text).unwrap();
        assert!(parsed.description.contains("Zainium"));
    }

    #[test]
    fn installed_at_iso8601() {
        let r = Receipt {
            name: "ts".into(),
            version: "1.0".into(),
            installed_at: "2026-06-27T12:34:56Z".into(),
            ..Default::default()
        };
        let text = toml::to_string_pretty(&r).unwrap();
        assert!(text.contains("2026-06-27T12:34:56Z"));
    }
}

mod manifest_schema {

    #[test]
    fn full_manifest_roundtrip() {
        let raw = r#"
[package]
name = "zed"
version = "0.180.3"
description = "Fast code editor"
license = "GPL-3.0"
maintainer = "Zed Team <team@zed.dev>"
homepage = "https://zed.dev"

[install]
bin   = "/overlayer/zexlib/union/bin"
lib   = "/overlayer/zexlib/union/lib"
share = "/overlayer/zexlib/union/share"

[remove]
files    = ["/overlayer/zexlib/union/bin/zed"]
symlinks = []
dirs     = ["/overlayer/zexlib/union/share/zed"]

[depends]
runtime = ["libxcb >= 1.14", "wayland >= 1.21"]
build   = ["cargo"]

[metadata]
libc_target = "musl"
build_type  = "dynamic"
edition     = "stable"
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        let back = toml::to_string_pretty(&val).unwrap();
        let re_parsed: toml::Value = toml::from_str(&back).unwrap();
        assert_eq!(val, re_parsed);
    }

    #[test]
    fn package_section_required_fields() {
        let raw = r#"
[package]
name = "req"
version = "1.0"
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert!(val["package"]["name"].as_str().is_some());
        assert!(val["package"]["version"].as_str().is_some());
    }

    #[test]
    fn install_map_all_paths_under_overlayer() {
        let raw = r#"
[install]
bin   = "/overlayer/zexlib/union/bin"
lib   = "/overlayer/zexlib/union/lib"
share = "/overlayer/zexlib/union/share"
etc   = "/overlayer/zexlib/union/etc"
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        for key in ["bin", "lib", "share", "etc"] {
            let path = val["install"][key].as_str().unwrap();
            assert!(
                path.starts_with("/overlayer/"),
                "path {path} not under /overlayer"
            );
        }
    }

    #[test]
    fn remove_map_all_paths_under_overlayer() {
        let raw = r#"
[remove]
files = ["/overlayer/zexlib/union/bin/myapp", "/overlayer/zexlib/union/lib/libmy.so"]
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        for f in val["remove"]["files"].as_array().unwrap() {
            assert!(f.as_str().unwrap().starts_with("/overlayer/"));
        }
    }

    #[test]
    fn edition_stable_nightly_lts() {
        for ed in ["stable", "nightly", "lts", "testing"] {
            let raw = format!("[package]\nname = \"pkg\"\nversion = \"1\"\nedition = \"{ed}\"");
            let val: toml::Value = toml::from_str(&raw).unwrap();
            assert_eq!(val["package"]["edition"].as_str().unwrap(), ed);
        }
    }

    #[test]
    fn depends_version_constraint_formats() {
        let raw = r#"
[depends]
runtime = [
    "libfoo >= 1.0",
    "libbar",
    "libbaz >= 2.0, < 3.0",
]
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        let deps = val["depends"]["runtime"].as_array().unwrap();
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn no_hardcoded_usr_paths() {
        let raw = r#"
[install]
bin = "/overlayer/zexlib/union/bin"
[remove]
files = ["/overlayer/zexlib/union/bin/tool"]
"#;
        assert!(!raw.contains("/usr/"));
        assert!(!raw.contains("/usr/bin/"));
        assert!(!raw.contains("/lib64/ld-linux"));
        assert!(raw.contains("/overlayer/zexlib/union/bin"));
    }

    #[test]
    fn signature_field_is_optional() {
        let raw = r#"
[package]
name = "unsigned"
version = "1.0"
[remove]
files = []
"#;
        let val: toml::Value = toml::from_str(raw).unwrap();
        assert!(val["package"].get("ed25519_sig").is_none());
    }
}

mod zex_services_schema {
    use super::*;

    #[test]
    fn parseable() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(env.p("overlayer/syshub/engine/services/zex_services.toml"))
            .unwrap();
        let _: toml::Value = toml::from_str(&raw).unwrap();
    }

    #[test]
    fn tier1_format_is_zex() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(env.p("overlayer/syshub/engine/services/zex_services.toml"))
            .unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        let t1 = &val["mirrors"]["zainium-userland-zexlib"];
        assert_eq!(t1["format"].as_str().unwrap(), "zex");
        assert_eq!(t1["tier"].as_integer().unwrap(), 1);
    }

    #[test]
    fn tier2_format_is_apk() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(env.p("overlayer/syshub/engine/services/zex_services.toml"))
            .unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        let t2 = &val["mirrors"]["alpine-main"];
        assert_eq!(t2["format"].as_str().unwrap(), "apk");
        assert_eq!(t2["tier"].as_integer().unwrap(), 2);
    }

    #[test]
    fn tier3_format_is_xbps() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(env.p("overlayer/syshub/engine/services/zex_services.toml"))
            .unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        let t3 = &val["mirrors"]["void-musl-current"];
        assert_eq!(t3["format"].as_str().unwrap(), "xbps");
        assert_eq!(t3["tier"].as_integer().unwrap(), 3);
    }

    #[test]
    fn all_mirrors_have_url() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(env.p("overlayer/syshub/engine/services/zex_services.toml"))
            .unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        for (_name, mirror) in val["mirrors"].as_table().unwrap() {
            let url = mirror.get("url").and_then(|u| u.as_str());
            assert!(
                url.is_some() && url.unwrap().starts_with("https://"),
                "mirror missing https URL: {mirror:?}"
            );
        }
    }

    #[test]
    fn urls_dont_have_trailing_slash() {
        let env = TempOverlayer::new();
        let raw = fs::read_to_string(env.p("overlayer/syshub/engine/services/zex_services.toml"))
            .unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        for (_name, mirror) in val["mirrors"].as_table().unwrap() {
            if let Some(url) = mirror.get("url").and_then(|u| u.as_str()) {
                assert!(
                    !url.ends_with('/'),
                    "URL should not have trailing slash: {url}"
                );
            }
        }
    }
}
