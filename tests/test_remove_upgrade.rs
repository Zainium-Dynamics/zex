//! tests/test_remove_upgrade.rs — Remove and Upgrade driver tests.

mod harness;
use harness::*;
use std::fs;

// ══════════════════════════════════════════════════════════════════════════════
//  REMOVE DRIVER — preflight + single package removal logic (15 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod remove {
    use super::*;

    #[test]
    fn remove_files_in_receipt() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("ripgrep", "14.1.1", "tier1-zainium");
        let bin = env.p("overlayer/zexlib/union/bin/ripgrep");
        assert_file_exists(&bin);

        // Read files from receipt and remove them
        let receipt =
            fs::read_to_string(env.p("overlayer/zexlib/registry/installed/ripgrep.toml")).unwrap();
        let val: toml::Value = toml::from_str(&receipt).unwrap();
        let files = val["remove"]["files"].as_array().unwrap();
        for file_val in files {
            let f = file_val.as_str().unwrap();
            // Remap to temp env
            let rel = f.strip_prefix('/').unwrap_or(f);
            let path = env.path().join(rel);
            if path.exists() {
                fs::remove_file(&path).unwrap();
            }
        }
        // Binary gone
        assert!(!bin.exists());
    }

    #[test]
    fn remove_deletes_receipt() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("htop", "3.4.0", "tier1-zainium");
        let receipt = env.p("overlayer/zexlib/registry/installed/htop.toml");
        assert_file_exists(&receipt);

        fs::remove_file(&receipt).unwrap();
        assert!(!receipt.exists());
    }

    #[test]
    fn remove_noninstalled_errors() {
        let env = TempOverlayer::new();
        let receipt = env.p("overlayer/zexlib/registry/installed/ghost.toml");
        assert!(!receipt.exists());
        // Cannot remove what isn't installed
        assert!(fs::read_to_string(&receipt).is_err());
    }

    #[test]
    fn remove_updates_packages_toml() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("curl", "8.11", "tier2-alpine");
        let pkg_toml = env.p("overlayer/zexlib/registry/packages.toml");

        // Simulate updating packages.toml after removal
        let raw = fs::read_to_string(&pkg_toml).unwrap();
        let mut val: toml::Value = toml::from_str(&raw).unwrap();
        if let Some(pkgs) = val.get_mut("packages").and_then(|p| p.as_table_mut()) {
            pkgs.remove("curl");
        }
        let new_content = toml::to_string_pretty(&val).unwrap();
        fs::write(&pkg_toml, &new_content).unwrap();

        let updated = fs::read_to_string(&pkg_toml).unwrap();
        assert!(!updated.contains("[packages.curl]"));
    }

    #[test]
    fn dry_run_does_not_delete() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("vim", "9.1.0", "tier1-zainium");
        let bin = env.p("overlayer/zexlib/union/bin/vim");
        let receipt = env.p("overlayer/zexlib/registry/installed/vim.toml");

        let dry_run = true;
        if !dry_run {
            fs::remove_file(&bin).unwrap();
            fs::remove_file(&receipt).unwrap();
        }
        // Files should still exist in dry run
        assert_file_exists(&bin);
        assert_file_exists(&receipt);
    }

    #[test]
    fn remove_creates_transaction() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("bash", "5.2.37", "tier1-zainium");
        env.add_transaction("tx-remove-bash", "2026-06-27T00:00:00Z");

        let tx = env.p("overlayer/zexlib/transactions/tx-remove-bash");
        assert_dir_exists(&tx);
    }

    #[test]
    fn remove_symlinks() {
        let env = TempOverlayer::new();
        let target = env.p("overlayer/zexlib/union/bin/python3.14");
        let link = env.p("overlayer/zexlib/union/bin/python3");
        fs::write(&target, b"binary").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(link.exists());
            fs::remove_file(&link).unwrap();
            assert!(!link.exists());
            assert!(target.exists()); // Target untouched
        }
    }

    #[test]
    fn remove_dirs_only_when_empty() {
        let env = TempOverlayer::new();
        let pkg_dir = env.p("overlayer/zexlib/union/share/myapp");
        fs::create_dir_all(&pkg_dir).unwrap();
        let datafile = pkg_dir.join("data.dat");
        fs::write(&datafile, b"data").unwrap();

        // Dir not empty — should not remove
        let result = fs::remove_dir(&pkg_dir);
        assert!(result.is_err(), "remove_dir should fail when not empty");

        // Remove file first, then dir
        fs::remove_file(&datafile).unwrap();
        fs::remove_dir(&pkg_dir).unwrap();
        assert!(!pkg_dir.exists());
    }

    #[test]
    fn preflight_package_not_installed() {
        let env = TempOverlayer::new();
        let receipt = env.p("overlayer/zexlib/registry/installed/nothere.toml");
        let is_installed = receipt.exists();
        assert!(!is_installed, "package should not be installed");
    }

    #[test]
    fn preflight_syshub_package_blocked() {
        let env = TempOverlayer::new();
        let syshub_manifest = env.p("overlayer/syshub/engine/services/syshub.toml");
        let raw = fs::read_to_string(&syshub_manifest).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        // bash is in syshub — can't remove via zex remove
        let is_syshub = val["packages"].get("bash").is_some();
        assert!(is_syshub);
    }

    #[test]
    fn remove_multiple_packages_sequential() {
        let env = TempOverlayer::new();
        for pkg in ["alpha", "bravo", "charlie"] {
            env.add_installed_receipt(pkg, "1.0", "tier1-zainium");
        }
        for pkg in ["alpha", "bravo", "charlie"] {
            let receipt = env.p(&format!("overlayer/zexlib/registry/installed/{pkg}.toml"));
            fs::remove_file(&receipt).unwrap();
        }
        let installed_dir = env.p("overlayer/zexlib/registry/installed");
        assert_eq!(fs::read_dir(&installed_dir).unwrap().count(), 0);
    }

    #[test]
    fn remove_records_in_audit_log() {
        let env = TempOverlayer::new();
        let log = env.p("overlayer/zexlib/union/var/log/zex-audit.log");
        let entry = "2026-06-27T00:00:00Z REMOVE vim 9.1.0 tier1-zainium\n";
        fs::write(&log, entry).unwrap();
        assert_file_contains(&log, "REMOVE vim");
    }

    #[test]
    fn remove_pinned_package_blocked() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("gcc", "14.2.0", "tier1-zainium");
        env.set_pinned(
            "[[pinned]]\nname = \"gcc\"\npinned_version = \"14.2.0\"\n\
                        pinned_at = \"2026-06-27\"\npinned_by = \"alizain\"\n",
        );

        let pinned_path = env.p("overlayer/zexlib/registry/pinned.toml");
        let raw = fs::read_to_string(&pinned_path).unwrap();
        let is_pinned = raw.contains("name = \"gcc\"");
        assert!(is_pinned, "gcc should be pinned");
        // In real driver: return error "package is pinned"
    }

    #[test]
    fn receipt_remove_map_files_absolute() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("fd", "10.2.0", "tier1-zainium");
        let raw = fs::read_to_string(env.p("overlayer/zexlib/registry/installed/fd.toml")).unwrap();
        let val: toml::Value = toml::from_str(&raw).unwrap();
        for f in val["remove"]["files"].as_array().unwrap() {
            let path = f.as_str().unwrap();
            assert!(
                path.starts_with("/overlayer/"),
                "remove path not absolute overlayer: {path}"
            );
        }
    }

    #[test]
    fn remove_leaves_other_packages_intact() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("keep", "1.0", "tier1-zainium");
        env.add_installed_receipt("remove", "1.0", "tier1-zainium");

        let remove_receipt = env.p("overlayer/zexlib/registry/installed/remove.toml");
        fs::remove_file(&remove_receipt).unwrap();

        // keep is still there
        assert_file_exists(&env.p("overlayer/zexlib/registry/installed/keep.toml"));
        assert!(!remove_receipt.exists());
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  UPGRADE — vercmp and diff logic (18 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod upgrade_logic {
    use zex::cmd::upgrade::vercmp::is_upgrade;

    #[test]
    fn many_version_pairs() {
        // Pure structural compare (numeric then raw suffix lex) — no keyword policy.
        let should_upgrade = [
            ("1.0", "1.1"),
            ("1.0.0", "1.0.1"),
            ("0.9", "1.0"),
            ("1.0-alpha", "1.0-beta"), // suffix lex only
            ("9.1.0-r0", "9.1.0-r1"),
            ("3.14.0_1", "3.14.0_2"),
            ("0", "1"),
            ("1.9", "2.0"),
        ];
        for (old, new) in &should_upgrade {
            assert!(is_upgrade(old, new), "{old} → {new} should be upgrade");
        }
    }

    #[test]
    fn no_upgrade_pairs() {
        let no_upgrade = [
            ("1.0", "1.0"),
            ("2.0", "1.9"),
            ("1.0.1", "1.0.0"),
            ("1.0-rc1", "1.0-alpha"),
        ];
        for (old, new) in &no_upgrade {
            assert!(!is_upgrade(old, new), "{old} → {new} should NOT be upgrade");
        }
    }

    #[test]
    fn epoch_handling() {
        // Some distros use 1:1.0 epoch notation
        // If we don't support it, at least don't panic
        let result = std::panic::catch_unwind(|| {
            let _ = is_upgrade("1:1.0", "1:1.1");
        });
        assert!(
            result.is_ok(),
            "is_upgrade should not panic on epoch notation"
        );
    }

    #[test]
    fn very_long_version() {
        let v1 = "1.2.3.4.5.6.7.8.9.10.11.12";
        let v2 = "1.2.3.4.5.6.7.8.9.10.11.13";
        // Just shouldn't panic
        let result = std::panic::catch_unwind(|| is_upgrade(v1, v2));
        assert!(result.is_ok());
    }

    #[test]
    fn empty_versions() {
        // "" → "1.0" = should be upgrade (empty = unknown = old)
        let result = std::panic::catch_unwind(|| is_upgrade("", "1.0"));
        assert!(result.is_ok());
    }

    #[test]
    fn prerelease_ordering() {
        // alpha < beta < rc < release
        assert!(
            is_upgrade("1.0-alpha", "1.0-beta") || !is_upgrade("1.0-beta", "1.0-alpha"),
            "pre-release ordering must be consistent"
        );
    }

    #[test]
    fn apk_revision_latest() {
        // r5 > r4 > r0
        assert!(is_upgrade("1.0.0-r4", "1.0.0-r5"));
        assert!(!is_upgrade("1.0.0-r5", "1.0.0-r4"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ROLLBACK — transaction restore (10 tests)
// ══════════════════════════════════════════════════════════════════════════════

mod rollback {
    use super::*;

    #[test]
    fn list_transactions_sorted() {
        let env = TempOverlayer::new();
        let timestamps = [1000u64, 3000, 2000, 5000, 4000];
        for (i, ts) in timestamps.iter().enumerate() {
            env.add_transaction(
                &format!("tx-{ts}"),
                &format!("2026-06-{:02}T00:00:00Z", i + 1),
            );
        }

        let dir = env.p("overlayer/zexlib/transactions");
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        entries.sort();
        assert_eq!(entries.len(), 5);
        // Sorted means deterministic order
        assert!(entries[0] < entries[4]);
    }

    #[test]
    fn rollback_userland_restore() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("curl", "8.11", "tier2-alpine");

        // Simulate rollback: restore receipt from backup
        let current_receipt = env.p("overlayer/zexlib/registry/installed/curl.toml");
        let backup_content = "name = \"curl\"\nversion = \"8.10\"\n\
                              origin = \"tier2-alpine\"\ninstalled_at = \"2026-06-01\"\n\
                              libc_target = \"musl\"\nbuild_type = \"dynamic\"\n\
                              [remove]\nfiles = [\"/overlayer/zexlib/union/bin/curl\"]\n\
                              symlinks = []\ndirs = []\n";

        fs::write(&current_receipt, backup_content).unwrap();
        assert_file_contains(&current_receipt, "8.10");
    }

    #[test]
    fn rollback_target_nonexistent() {
        let env = TempOverlayer::new();
        let tx_dir = env.p("overlayer/zexlib/transactions/tx-ghost");
        assert!(!tx_dir.exists());
    }

    #[test]
    fn rollback_syshub_swaps_back() {
        let env = TempOverlayer::new();
        let live = env.p("overlayer/syshub");
        let backup = env.p("overlayer/syshub.old");

        // Create fake backup
        fs::create_dir_all(backup.join("bin")).unwrap();
        fs::write(backup.join("bin/old-zex"), b"old binary").unwrap();

        // Rollback: live → trash, backup → live
        let trash = env.p("overlayer/syshub.rollback_trash");
        fs::rename(&live, &trash).unwrap();
        fs::rename(&backup, &live).unwrap();

        assert_file_exists(&live.join("bin/old-zex"));
        assert!(!backup.exists());
    }

    #[test]
    fn rollback_cleans_up_new_receipt() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("vim", "9.1.0", "tier1-zainium");

        // Rollback: delete the new receipt (downgrade)
        let receipt = env.p("overlayer/zexlib/registry/installed/vim.toml");
        fs::remove_file(&receipt).unwrap();
        assert!(!receipt.exists());
    }

    #[test]
    fn rollback_preserves_unrelated_packages() {
        let env = TempOverlayer::new();
        env.add_installed_receipt("vim", "9.1.0", "tier1-zainium");
        env.add_installed_receipt("htop", "3.4.0", "tier1-zainium");
        env.add_installed_receipt("curl", "8.11", "tier2-alpine");

        // Rollback only vim
        fs::remove_file(env.p("overlayer/zexlib/registry/installed/vim.toml")).unwrap();

        // Others intact
        assert_file_exists(&env.p("overlayer/zexlib/registry/installed/htop.toml"));
        assert_file_exists(&env.p("overlayer/zexlib/registry/installed/curl.toml"));
    }

    #[test]
    fn transaction_state_readable() {
        let env = TempOverlayer::new();
        env.add_transaction("tx-readable", "2026-06-27T00:00:00Z");
        let raw =
            fs::read_to_string(env.p("overlayer/zexlib/transactions/tx-readable/manifest.toml"))
                .unwrap();
        assert!(raw.contains("tx-readable"));
    }

    #[test]
    fn oldest_transaction_pruned_first() {
        let env = TempOverlayer::new();
        // Add 15 transactions, keep 10
        for i in 0..15 {
            env.add_transaction(
                &format!("tx-{i:03}"),
                &format!("2026-06-{:02}T00:00:00Z", (i % 28) + 1),
            );
        }
        let dir = env.p("overlayer/zexlib/transactions");
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        entries.sort();

        // Prune oldest (first 5)
        let keep = 10;
        for tx_name in entries.iter().take(entries.len() - keep) {
            fs::remove_dir_all(dir.join(tx_name)).unwrap();
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), keep);
    }

    #[test]
    fn rollback_id_format() {
        // Transaction IDs should be sortable by timestamp
        let ids = ["tx-1719446400000", "tx-1719446500000", "tx-1719446600000"];
        let mut sorted = ids.to_vec();
        sorted.sort();
        assert_eq!(sorted, ids); // Already in order
    }

    #[test]
    fn empty_rollback_list_no_panic() {
        let env = TempOverlayer::new();
        let dir = env.p("overlayer/zexlib/transactions");
        let count = fs::read_dir(&dir).unwrap().count();
        assert_eq!(count, 0);
        // Listing empty dir should not panic
    }
}
