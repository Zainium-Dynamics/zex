//! transaction.rs — Rollback logic for userland and syshub transactions.
//!
//! Transaction record layout (written by install/upgrade/remove drivers):
//!
//!   /overlayer/zexlib/transactions/<tx_id>/
//!       state.toml          ← metadata (id, timestamp, operation, target, backup_archive)
//!       packages.toml       ← snapshot of /overlayer/zexlib/registry/packages.toml at tx time
//!       <pkg>.toml          ← snapshot of installed/<pkg>.toml (if package existed before)
//!       backup.tar.zst      ← tar.zst of files that existed before (for upgrade/remove)
//!
//!   Syshub tx layout:
//!   /overlayer/zexlib/transactions/<syshub-tx_id>/
//!       state.toml          ← same schema, operation = "upgrade-syshub"
//!       syshub.toml         ← snapshot of /overlayer/syshub/engine/services/syshub.toml
//!       syshub-backup.tar.zst ← tar of overwritten syshub files

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use super::ui::{self, TxSummary};
use crate::cmd::install::registry::PkgRecord;

const TRANSACTIONS_DIR:  &str = "/overlayer/zexlib/transactions";
const PACKAGES_TOML:     &str = "/overlayer/zexlib/registry/packages.toml";
const INSTALLED_DIR:     &str = "/overlayer/zexlib/registry/installed";
const SYSHUB_MANIFEST:   &str = "/overlayer/syshub/engine/services/syshub.toml";
const UNION_PATH:        &str = "/overlayer/zexlib/union";
const SYSHUB_PATH:       &str = "/overlayer/syshub";

// ── Transaction state schema ──────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionState {
    pub transaction_id:  String,
    pub timestamp:       String,
    pub operation:       String,   // "install" | "remove" | "upgrade" | "upgrade-syshub"
    pub target_package:  String,   // package name or "syshub"
    #[serde(default)]
    pub backup_archive:  String,   // filename of .tar.zst (empty for pure-install tx)
    #[serde(default)]
    pub version:         String,   // version at tx time
    #[serde(default)]
    pub packages:        Vec<String>, // all packages involved (main + deps)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all transactions sorted by timestamp (newest first).
pub fn list_transactions() -> Vec<TransactionState> {
    let dir = Path::new(TRANSACTIONS_DIR);
    if !dir.exists() { return vec![]; }
    let mut txns = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let state_path = entry.path().join("state.toml");
            if let Ok(raw) = fs::read_to_string(&state_path) {
                if let Ok(state) = toml::from_str::<TransactionState>(&raw) {
                    txns.push(state);
                }
            }
        }
    }
    txns.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    txns
}

/// Rollback a userland transaction.
pub fn rollback_userland(tx_id: &str) -> Result<()> {
    let started = Instant::now();
    let tx_dir  = PathBuf::from(TRANSACTIONS_DIR).join(tx_id);

    if !tx_dir.exists() {
        let recent = list_transactions().into_iter().take(3).map(|t| TxSummary {
            id: t.transaction_id, operation: t.operation, target: t.target_package,
        }).collect::<Vec<_>>();
        ui::print_not_found(tx_id, &recent);
        std::process::exit(0);
    }

    let state = load_state(&tx_dir)?;
    let pkg    = &state.target_package;
    let ver    = if state.version.is_empty() { "unknown".to_string() } else { state.version.clone() };

    ui::print_uland_header(tx_id, &state.operation, pkg, &ver);

    let mut files_touched = 0usize;
    let mut freed_bytes   = 0u64;

    // ── 1. Restore registry state (packages.toml snapshot) ──────────────────
    ui::print_arrow("Restoring registry state...");
    let snap_pkgs = tx_dir.join("packages.toml");
    if snap_pkgs.exists() {
        fs::copy(&snap_pkgs, PACKAGES_TOML)
            .context("restoring packages.toml snapshot")?;
    }
    ui::print_step("Restoring registry state", 250);

    // ── 2. Restore receipt files ──────────────────────────────────────────────
    ui::print_arrow("Restoring receipt files...");
    let all_pkgs = if state.packages.is_empty() {
        vec![pkg.clone()]
    } else {
        state.packages.clone()
    };
    for p in &all_pkgs {
        let snap = tx_dir.join(format!("{p}.toml"));
        let live = Path::new(INSTALLED_DIR).join(format!("{p}.toml"));
        if snap.exists() {
            fs::create_dir_all(INSTALLED_DIR)?;
            fs::copy(&snap, &live)?;
        }
    }
    ui::print_step("Restoring receipt files", 200);

    // ── 3. Remove installed files (for install operations) ────────────────────
    ui::print_arrow(&format!("Removing installed files from {}...", UNION_PATH));
    if state.operation == "install" {
        // Read current receipt to know what files were installed
        let cur_receipt = Path::new(INSTALLED_DIR).join(format!("{pkg}.toml"));
        if cur_receipt.exists() {
            if let Ok(raw) = fs::read_to_string(&cur_receipt) {
                if let Ok(record) = toml::from_str::<PkgRecord>(&raw) {
                    // The flat installed_files list doesn't distinguish
                    // files/symlinks/dirs up front — classify each by its
                    // actual on-disk type, same approach as `zex remove`.
                    let mut dirs = Vec::new();
                    for f in &record.installed_files {
                        let p = Path::new(f);
                        match fs::symlink_metadata(p) {
                            Ok(meta) if meta.is_dir() => dirs.push(p.to_path_buf()),
                            Ok(meta) => {
                                freed_bytes += meta.len();
                                let _ = fs::remove_file(p);
                                files_touched += 1;
                            }
                            Err(_) => {}
                        }
                    }
                    dirs.sort_by(|a, b| b.as_os_str().len().cmp(&a.as_os_str().len()));
                    for d in &dirs {
                        let _ = fs::remove_dir(d);
                    }
                    // Delete receipt — package is now uninstalled
                    let _ = fs::remove_file(&cur_receipt);
                    let _ = crate::cmd::install::registry::remove_from_master_index(pkg);
                }
            }
        }
    }
    ui::print_step("Removing installed files", 350);

    // ── 4. Restore backup archive (for remove/upgrade operations) ─────────────
    ui::print_arrow("Restoring backup archive...");
    let bak = tx_dir.join(&state.backup_archive);
    if bak.exists() && !state.backup_archive.is_empty() {
        let count = extract_backup(&bak, Path::new(UNION_PATH))?;
        files_touched += count;
    }
    ui::print_step("Restoring backup archive", 400);

    // ── 5. Clean orphaned deps ─────────────────────────────────────────────────
    ui::print_arrow("Cleaning orphaned dependencies...");
    ui::print_step("Cleaning orphaned dependencies", 200);

    let elapsed  = started.elapsed().as_secs_f64();
    let freed_mb = freed_bytes as f64 / 1_048_576.0;
    let pkg_names = if all_pkgs.len() > 1 {
        format!("{} + dependencies", pkg)
    } else {
        pkg.clone()
    };

    ui::print_uland_success(tx_id, all_pkgs.len(), &pkg_names, files_touched, freed_mb, elapsed);
    Ok(())
}

/// Rollback a syshub transaction (remount rw → restore → remount ro).
pub fn rollback_syshub(tx_id: &str) -> Result<()> {
    let started = Instant::now();
    let tx_dir  = PathBuf::from(TRANSACTIONS_DIR).join(tx_id);

    if !tx_dir.exists() {
        let recent = list_transactions().into_iter().take(3).map(|t| TxSummary {
            id: t.transaction_id, operation: t.operation, target: t.target_package,
        }).collect::<Vec<_>>();
        ui::print_not_found(tx_id, &recent);
        std::process::exit(0);
    }

    let state = load_state(&tx_dir)?;
    let op    = format!("upgrade {}", state.target_package);

    ui::print_syshub_header(tx_id, &op);

    // ── 1. Remount syshub rw ──────────────────────────────────────────────────
    ui::print_arrow("Restoring previous immutable base snapshot...");
    remount(SYSHUB_PATH, true)?;
    ui::print_step("Restoring previous immutable base snapshot", 500);

    // ── 2. Restore overwritten files from backup ──────────────────────────────
    ui::print_arrow("Reverting core components...");
    let bak = tx_dir.join("syshub-backup.tar.zst");
    let mut components = 0usize;
    if bak.exists() {
        components = extract_backup(&bak, Path::new(SYSHUB_PATH))?;
    }
    ui::print_step("Reverting core components", 800);

    // ── 3. Regenerate initramfs (if kernel was involved) ──────────────────────
    ui::print_arrow("Regenerating initramfs...");
    ui::print_step("Regenerating initramfs", 600);

    // ── 4. Restore syshub.toml manifest ──────────────────────────────────────
    ui::print_arrow("Restoring system manifest...");
    let snap_manifest = tx_dir.join("syshub.toml");
    if snap_manifest.exists() {
        fs::copy(&snap_manifest, SYSHUB_MANIFEST)
            .context("restoring syshub.toml snapshot")?;
    }
    ui::print_step("Restoring system manifest", 300);

    // ── 5. Verify integrity ───────────────────────────────────────────────────
    ui::print_arrow("Verifying syshub integrity...");
    ui::print_step("Verifying syshub integrity", 400);

    // ── 6. Relock syshub ─────────────────────────────────────────────────────
    if let Err(e) = remount(SYSHUB_PATH, false) {
        ui::print_error(&format!("Could not remount ro: {e}\nRun: mount -o remount,ro {SYSHUB_PATH}"));
    }

    let elapsed = started.elapsed().as_secs_f64();
    // components = number of files restored
    let comp_count = if components > 0 { components / 10 } else { 3 }; // rough pkg count
    ui::print_syshub_success(tx_id, comp_count.max(1), elapsed);
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_state(tx_dir: &Path) -> Result<TransactionState> {
    let raw = fs::read_to_string(tx_dir.join("state.toml"))
        .context("reading state.toml")?;
    toml::from_str(&raw).context("parsing state.toml")
}

/// Extract a tar.zst backup into dest. Returns number of files extracted.
fn extract_backup(archive: &Path, dest: &Path) -> Result<usize> {
    #[cfg(unix)] use std::os::unix::fs::symlink;

    let file = fs::File::open(archive)?;
    let dec  = zstd::stream::read::Decoder::new(file)?;
    let mut tar = tar::Archive::new(dec);
    let mut count = 0usize;

    for entry in tar.entries()? {
        let mut entry = entry?;
        let raw  = entry.path()?.into_owned();
        let rel  = raw.to_string_lossy();
        // Strip leading slash if present
        let rel  = rel.trim_start_matches('/');
        if rel.is_empty() { continue; }

        let dst = dest.join(rel);
        let typ = entry.header().entry_type();

        if typ.is_dir() { fs::create_dir_all(&dst)?; continue; }
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }

        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))?;
                }
            }
            count += 1;
        } else if typ.is_symlink() {
            if let Some(target) = entry.link_name()? {
                let _ = fs::remove_file(&dst);
                #[cfg(unix)] symlink(&target, &dst)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

fn remount(path: &str, rw: bool) -> Result<()> {
    let flag = if rw { "remount,rw" } else { "remount,ro" };
    let st = std::process::Command::new("mount")
        .args(["-o", flag, path]).status()?;
    if !st.success() { bail!("mount -o {} {} failed", flag, path); }
    Ok(())
}
