//! scanner.rs — Scans Zainium-specific locations and cleans them.
//!
//! All paths are real Zainium overlayer layout — no /usr, no /var/cache/apt,
//! no flatpak, no snap. Only what actually exists in Zainium OS.

use anyhow::Result;
use std::{fs, path::Path};
use walkdir::WalkDir;
use std::time::{SystemTime, Duration};

// ── Zainium paths ─────────────────────────────────────────────────────────────
const CACHE_DIR:        &str = "/overlayer/zexlib/registry/cache";
const TMP_DIR:          &str = "/overlayer/zexlib/tmp";
const TRANSACTIONS_DIR: &str = "/overlayer/zexlib/transactions";
const LOG_DIR:          &str = "/overlayer/zexlib/union/var/log";
const STAGING_NEW:      &str = "/overlayer/syshub.new";
const DL_PREFIXES: &[&str]   = &[
    "/overlayer/zexlib/tmp/update-dl",
    "/overlayer/zexlib/tmp/uland-dl",
    "/overlayer/zexlib/tmp/syshub-dl",
    "/overlayer/zexlib/tmp/syshub-rollback",
];

/// A single cleanable target with its size.
#[derive(Debug, Clone)]
pub struct SweepTarget {
    pub label:      String,
    pub path:       String,
    pub size_bytes: u64,
    pub kind:       TargetKind,
}

#[derive(Debug, Clone)]
pub enum TargetKind {
    /// Delete everything under this directory (but keep the dir itself)
    ClearDir,
    /// Delete the directory entirely
    RemoveDir,
    /// Keep only the newest N entries in this directory
    KeepNewest(usize),
    /// Delete files older than N days
    OlderThan(u64),
}

/// Scan all targets and return their sizes.
pub async fn scan_all(aggressive: bool) -> Vec<SweepTarget> {
    let mut targets = Vec::new();

    // 1. Package download cache
    let cache_size = dir_size(CACHE_DIR);
    targets.push(SweepTarget {
        label:      "Package cache".into(),
        path:       CACHE_DIR.into(),
        size_bytes: cache_size,
        kind:       TargetKind::ClearDir,
    });

    // 2. Temp files
    let tmp_size = dir_size(TMP_DIR);
    targets.push(SweepTarget {
        label:      "Temp files".into(),
        path:       TMP_DIR.into(),
        size_bytes: tmp_size,
        kind:       TargetKind::ClearDir,
    });

    // 3. Orphaned staging (syshub.new from interrupted upgrade)
    let staging_size = dir_size(STAGING_NEW);
    if staging_size > 0 {
        targets.push(SweepTarget {
            label:      "Orphaned upgrade staging".into(),
            path:       STAGING_NEW.into(),
            size_bytes: staging_size,
            kind:       TargetKind::RemoveDir,
        });
    }

    // 4. Failed download artifacts
    let mut dl_size = 0u64;
    for prefix in DL_PREFIXES {
        dl_size += dir_size(prefix);
    }
    if dl_size > 0 {
        targets.push(SweepTarget {
            label:      "Orphaned downloads".into(),
            path:       "/overlayer/zexlib/tmp/[dl dirs]".into(),
            size_bytes: dl_size,
            kind:       TargetKind::ClearDir, // handled specially in clean_all
        });
    }

    // 5. Old transaction records (keep newest 10)
    let tx_size = old_transaction_size(TRANSACTIONS_DIR, 10);
    if tx_size > 0 {
        targets.push(SweepTarget {
            label:      "Old transaction history".into(),
            path:       TRANSACTIONS_DIR.into(),
            size_bytes: tx_size,
            kind:       TargetKind::KeepNewest(10),
        });
    }

    // 6. Old logs (aggressive only — files > 30 days)
    if aggressive {
        let log_size = old_files_size(LOG_DIR, 30);
        if log_size > 0 {
            targets.push(SweepTarget {
                label:      "Old logs (>30 days)".into(),
                path:       LOG_DIR.into(),
                size_bytes: log_size,
                kind:       TargetKind::OlderThan(30),
            });
        }
    }

    targets
}

/// Execute cleanup on all targets. Returns (files_removed, bytes_freed).
pub async fn clean_all(targets: &[SweepTarget]) -> (usize, u64) {
    use super::ui;

    let mut removed = 0usize;
    let mut freed   = 0u64;

    for target in targets {
        if target.size_bytes == 0 { continue; }

        ui::print_step(&format!("Cleaning {}", target.label), 400);

        match &target.kind {
            TargetKind::ClearDir => {
                // Special case for orphaned downloads (multiple dirs)
                if target.label == "Orphaned downloads" {
                    for prefix in DL_PREFIXES {
                        let (r, b) = clear_dir(Path::new(prefix));
                        removed += r; freed += b;
                    }
                } else {
                    let (r, b) = clear_dir(Path::new(&target.path));
                    removed += r; freed += b;
                }
            }
            TargetKind::RemoveDir => {
                freed += dir_size(&target.path);
                if fs::remove_dir_all(&target.path).is_ok() {
                    removed += 1;
                }
            }
            TargetKind::KeepNewest(n) => {
                let (r, b) = keep_newest(Path::new(&target.path), *n);
                removed += r; freed += b;
            }
            TargetKind::OlderThan(days) => {
                let (r, b) = remove_older_than(Path::new(&target.path), *days);
                removed += r; freed += b;
            }
        }
    }

    (removed, freed)
}

// ── Size calculators ──────────────────────────────────────────────────────────

fn dir_size(path: &str) -> u64 {
    let p = Path::new(path);
    if !p.exists() { return 0; }
    WalkDir::new(p).into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

fn old_transaction_size(dir: &str, keep: usize) -> u64 {
    let p = Path::new(dir);
    if !p.exists() { return 0; }
    let mut entries: Vec<_> = fs::read_dir(p).into_iter().flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| {
        e.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH)
    });
    entries.iter().rev().skip(keep)
        .map(|e| dir_size(&e.path().to_string_lossy()))
        .sum()
}

fn old_files_size(dir: &str, days: u64) -> u64 {
    let p = Path::new(dir);
    if !p.exists() { return 0; }
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(days * 86400))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    WalkDir::new(p).into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            let modified = meta.modified().ok()?;
            if modified < cutoff { Some(meta.len()) } else { None }
        })
        .sum()
}

// ── Cleaners ──────────────────────────────────────────────────────────────────

/// Delete all contents of dir, keep the dir itself.
fn clear_dir(p: &Path) -> (usize, u64) {
    if !p.exists() { return (0, 0); }
    let mut removed = 0usize;
    let mut freed   = 0u64;
    if let Ok(entries) = fs::read_dir(p) {
        for entry in entries.flatten() {
            let path = entry.path();
            let size = if path.is_dir() {
                dir_size(&path.to_string_lossy())
            } else {
                fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
            };
            let ok = if path.is_dir() {
                fs::remove_dir_all(&path).is_ok()
            } else {
                fs::remove_file(&path).is_ok()
            };
            if ok { removed += 1; freed += size; }
        }
    }
    (removed, freed)
}

/// Keep the newest N subdirectories, delete the rest.
fn keep_newest(p: &Path, keep: usize) -> (usize, u64) {
    if !p.exists() { return (0, 0); }
    let mut entries: Vec<_> = fs::read_dir(p).into_iter().flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| {
        e.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH)
    });

    let mut removed = 0usize;
    let mut freed   = 0u64;
    let to_delete = entries.len().saturating_sub(keep);
    for entry in entries.iter().take(to_delete) {
        let path = entry.path();
        let size = dir_size(&path.to_string_lossy());
        if fs::remove_dir_all(&path).is_ok() {
            removed += 1;
            freed   += size;
        }
    }
    (removed, freed)
}

/// Delete files older than `days` days inside `p`.
fn remove_older_than(p: &Path, days: u64) -> (usize, u64) {
    if !p.exists() { return (0, 0); }
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(days * 86400))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let mut removed = 0usize;
    let mut freed   = 0u64;

    for entry in WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let meta = match entry.metadata() { Ok(m) => m, Err(_) => continue };
        let modified = match meta.modified() { Ok(t) => t, Err(_) => continue };
        if modified < cutoff {
            let size = meta.len();
            if fs::remove_file(entry.path()).is_ok() {
                removed += 1;
                freed   += size;
            }
        }
    }
    (removed, freed)
}
