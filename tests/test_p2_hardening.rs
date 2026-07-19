//! P2 hardening integration tests — trust, archive safety, union sync, executable.

mod harness;

use harness::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// ══════════════════════════════════════════════════════════════════════════════
//  Archive safety — path traversal + O_NOFOLLOW confinement
// ══════════════════════════════════════════════════════════════════════════════

mod archive_safety {
    use super::*;

    #[test]
    fn extract_rejects_path_traversal_entries() {
        let err = zex::archive_safety::sanitize_archive_path(Path::new("../escape.txt"));
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("traversal"));
    }

    #[test]
    fn extract_writes_files_under_output_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pkg = create_test_zex_package("confined", "1.0.0", tmp.path());
        let out = tmp.path().join("extracted");
        zex::extract::extract(&pkg, &out).unwrap();

        assert_file_exists(&out.join("payload/bin/confined"));
        assert!(out.join("payload/bin/confined").starts_with(&out));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Executable policy — no silent chmod
// ══════════════════════════════════════════════════════════════════════════════

mod executable {
    use super::*;

    #[test]
    fn fails_on_non_executable_binary() {
        let dir = tempfile::TempDir::new().unwrap();
        let bin = dir.path().join("zex-install");
        fs::write(&bin, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o644)).unwrap();

        let err = zex::executable::ensure_executable(bin.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("not executable"));
    }

    #[test]
    fn first_available_picks_executable_candidate() {
        let dir = tempfile::TempDir::new().unwrap();
        let bad = dir.path().join("missing");
        let good = dir.path().join("zex-install");
        fs::write(&good, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o755)).unwrap();

        let paths = vec![
            bad.to_string_lossy().into_owned(),
            good.to_string_lossy().into_owned(),
        ];
        let chosen = zex::executable::first_available_executable(&paths).unwrap();
        assert_eq!(chosen, good.to_string_lossy());
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Union sync event — JSON stamp format for Quantra hook
// ══════════════════════════════════════════════════════════════════════════════

mod union_sync {
    #[test]
    fn sync_event_serializes_for_quantra_watchers() {
        let event = zex::cmd::install::union::build_sync_event();
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("zex-upperlayer-sync"));
        assert!(json.contains("/overlayer/zexlib/union"));
        assert!(json.contains("/run/quantra-system/zex-upperlayer-stamp"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  TempOverlayer fixture — registry + syshub layout smoke
// ══════════════════════════════════════════════════════════════════════════════

mod overlayer_fixture {
    use super::*;

    #[test]
    fn temp_overlayer_has_zainium_layout() {
        let ovl = TempOverlayer::new();
        assert_dir_exists(&ovl.p("overlayer/syshub/bin"));
        assert_dir_exists(&ovl.p("overlayer/zexlib/union/bin"));
        assert_dir_exists(&ovl.p("overlayer/zexlib/registry/installed"));
        assert_file_exists(&ovl.p("overlayer/syshub/engine/services/zex_services.toml"));
    }

    #[test]
    fn temp_overlayer_installed_receipt_roundtrip() {
        let ovl = TempOverlayer::new();
        ovl.add_installed_receipt("htop", "3.4.0", "tier1-zainium");

        let receipt = ovl.p("overlayer/zexlib/registry/installed/htop.toml");
        assert_file_exists(&receipt);
        assert_file_contains(&receipt, "version = \"3.4.0\"");
        assert_file_exists(&ovl.p("overlayer/zexlib/union/bin/htop"));
    }

    #[test]
    fn safe_join_under_confines_to_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();

        let dest = zex::archive_safety::safe_join_under(&root, Path::new("bin/vim")).unwrap();
        assert!(dest.starts_with(&root));
        assert!(zex::archive_safety::safe_join_under(&root, Path::new("../etc/passwd")).is_err());
    }
}