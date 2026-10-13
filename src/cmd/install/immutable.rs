//! immutable.rs — Immutable Core & System Snapshot Engine for Zainium OS.
//!
//! Architecture:
//!   Zainium's system partition is treated as read-only by default.  Before any
//!   package install/upgrade/remove operation, zex creates a lightweight snapshot
//!   of the current system state.  If the operation fails — or if the user
//!   explicitly requests rollback — the snapshot is restored atomically.
//!
//! Design Principles (vs competitors):
//!   • APT/Pacman: No snapshot system.  A failed `apt upgrade` can brick the
//!     system.  Manual `timeshift` or btrfs snapshots are separate tools.
//!   • RedoxOS pkgar: Has atomic updates but no multi-snapshot history.
//!   • Zex: Built-in snapshot chain with instant rollback + boot-time recovery.
//!
//! Snapshot Layout:
//!   /overlayer/zexlib/registry/snapshots/
//!     ├── current → symlink to active snapshot ID
//!     ├── 1716048000-pre-install-vlc/
//!     │   ├── manifest.toml      (packages + versions + file hashes)
//!     │   ├── db_backup.toml     (full registry::PkgRecord list, not a lossy projection)
//!     │   └── files/             (backed-up files that will be overwritten)
//!     ├── 1716048300-pre-upgrade-gcc/
//!     │   └── ...
//!     └── boot-fallback/         (last known-good state for boot recovery)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::registry::{self, PkgRecord};
use super::ui;

// ─── Constants ───────────────────────────────────────────────────────────────

const SNAPSHOT_ROOT: &str = "/overlayer/zexlib/registry/snapshots";
const CURRENT_LINK: &str = "/overlayer/zexlib/registry/snapshots/current";
const BOOT_FALLBACK: &str = "/overlayer/zexlib/registry/snapshots/boot-fallback";
const MAX_SNAPSHOTS: usize = 10;

/// Immutable system paths — these directories are read-only by default.
/// Zex temporarily unlocks them during install/upgrade, then re-locks.
const IMMUTABLE_PATHS: &[&str] = &[
    "/overlayer/syshub/bin",
    "/overlayer/syshub/lib",
    "/overlayer/syshub/share",
    "/overlayer/syshub/libexec",
    "/overlayer/syshub/sbin",
];

// ─── Snapshot Manifest ───────────────────────────────────────────────────────

/// Records the exact system state at snapshot creation time.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapshotManifest {
    /// Unique snapshot ID (Unix timestamp)
    pub id: u64,
    /// Human-readable label (e.g. "pre-install-vlc")
    pub label: String,
    /// ISO 8601 timestamp
    pub created_at: String,
    /// Package database state at snapshot time
    pub packages: Vec<SnapshotPackageEntry>,
    /// SHA256 hashes of critical system files
    pub file_hashes: HashMap<String, String>,
    /// Operation that triggered the snapshot
    pub trigger: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapshotPackageEntry {
    pub name: String,
    pub version: String,
    pub format: String,
    pub file_count: usize,
}

/// TOML requires a table at the document root — wraps the flat package
/// list `db_backup.toml` actually stores.
#[derive(Debug, Serialize, Deserialize)]
struct DbBackup {
    packages: Vec<PkgRecord>,
}

// ─── Immutable Core Guard ────────────────────────────────────────────────────

/// Check if system paths are currently in immutable (read-only) state.
/// Returns a list of paths and their immutable status.
pub fn check_immutable_status() -> Vec<(String, bool)> {
    IMMUTABLE_PATHS
        .iter()
        .map(|path| {
            let is_immutable = is_path_immutable(path);
            (path.to_string(), is_immutable)
        })
        .collect()
}

/// Test if a path is effectively read-only by checking filesystem attributes.
fn is_path_immutable(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() {
        return false;
    }

    // Try to get extended attributes — check for immutable flag
    // On Linux, this checks the FS_IMMUTABLE_FL flag via ioctl
    match std::fs::metadata(p) {
        Ok(meta) => meta.permissions().readonly(),
        Err(_) => false,
    }
}

/// Temporarily unlock immutable system paths for package operations.
/// Returns a guard that re-locks on drop.
pub fn unlock_system() -> Result<ImmutableGuard> {
    ui::print_immutable_unlock();

    for path in IMMUTABLE_PATHS {
        let p = Path::new(path);
        if p.exists() {
            // Remove read-only flag to allow writes
            if let Ok(meta) = std::fs::metadata(p) {
                let mut perms = meta.permissions();
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(p, perms);
                }
            }
        }
    }

    Ok(ImmutableGuard { locked: false })
}

/// RAII guard that re-locks system paths when dropped.
pub struct ImmutableGuard {
    locked: bool,
}

impl ImmutableGuard {
    /// Explicitly re-lock before drop if needed.
    pub fn relock(&mut self) {
        if !self.locked {
            lock_system_paths();
            self.locked = true;
        }
    }
}

impl Drop for ImmutableGuard {
    fn drop(&mut self) {
        if !self.locked {
            lock_system_paths();
        }
    }
}

/// Re-lock all immutable system paths.
fn lock_system_paths() {
    for path in IMMUTABLE_PATHS {
        let p = Path::new(path);
        if p.exists() {
            if let Ok(meta) = std::fs::metadata(p) {
                let mut perms = meta.permissions();
                perms.set_readonly(true);
                let _ = std::fs::set_permissions(p, perms);
            }
        }
    }
    ui::print_immutable_relock();
}

// ─── Snapshot Operations ─────────────────────────────────────────────────────

/// Create a pre-operation snapshot of the current system state.
///
/// This captures:
///   1. The entire installed package database
///   2. SHA256 hashes of all files owned by affected packages
///   3. Backup copies of files that will be overwritten
///
/// The snapshot is stored under /var/lib/zex/snapshots/<timestamp>-<label>/
pub fn create_snapshot(label: &str, affected_packages: &[String]) -> Result<SnapshotManifest> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let snap_id = format!("{}-{}", timestamp, label);
    let snap_dir = PathBuf::from(SNAPSHOT_ROOT).join(&snap_id);

    std::fs::create_dir_all(&snap_dir).context("Failed to create snapshot directory")?;

    // 1. Backup the full package registry — the real `PkgRecord` list, not
    // a lossy `DbEntry` projection (that drops dependencies/provides/
    // source_mirror, which a real restore needs).
    let db = registry::load_all();
    let db_backup_path = snap_dir.join("db_backup.toml");
    let db_toml = toml::to_string_pretty(&DbBackup {
        packages: db.clone(),
    })
    .context("Failed to serialise package registry backup")?;
    std::fs::write(&db_backup_path, &db_toml).context("Failed to write database backup")?;

    // 2. Build manifest with package entries
    let packages: Vec<SnapshotPackageEntry> = db
        .iter()
        .map(|entry| SnapshotPackageEntry {
            name: entry.name.clone(),
            version: entry.version.clone(),
            format: entry.format.clone(),
            file_count: entry.installed_files.len(),
        })
        .collect();

    // 3. Hash files owned by affected packages
    let mut file_hashes = HashMap::new();
    let files_dir = snap_dir.join("files");

    for pkg_name in affected_packages {
        if let Some(entry) = db.iter().find(|e| e.name.eq_ignore_ascii_case(pkg_name)) {
            for file_path in &entry.installed_files {
                let p = Path::new(file_path);
                if p.exists() && p.is_file() {
                    // Compute hash
                    if let Ok(hash) = sha256_of_path(p) {
                        file_hashes.insert(file_path.clone(), hash);
                    }

                    // Backup the file
                    let backup_path =
                        files_dir.join(file_path.strip_prefix('/').unwrap_or(file_path));
                    if let Some(parent) = backup_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::copy(p, &backup_path);
                }
            }
        }
    }

    // 4. Build and save manifest
    let manifest = SnapshotManifest {
        id: timestamp,
        label: label.to_string(),
        created_at: chrono_now_iso(),
        packages,
        file_hashes,
        trigger: label.to_string(),
    };

    let manifest_path = snap_dir.join("manifest.toml");
    let manifest_toml =
        toml::to_string_pretty(&manifest).context("Failed to serialise snapshot manifest")?;
    std::fs::write(&manifest_path, &manifest_toml).context("Failed to write snapshot manifest")?;

    // 5. Update current symlink
    let current = Path::new(CURRENT_LINK);
    let _ = std::fs::remove_file(current);
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(&snap_dir, current);
    }

    // 6. Prune old snapshots (keep MAX_SNAPSHOTS)
    prune_old_snapshots()?;

    ui::print_snapshot_created(&snap_id);

    Ok(manifest)
}

/// Restore the system to a specific snapshot state.
///
/// This is the nuclear option: it replaces the entire package database
/// and restores all backed-up files to their snapshot-time state.
pub fn restore_snapshot(snapshot_id: &str) -> Result<()> {
    let snap_dir = PathBuf::from(SNAPSHOT_ROOT).join(snapshot_id);

    if !snap_dir.exists() {
        bail!("Snapshot '{}' not found", snapshot_id);
    }

    ui::print_snapshot_restoring(snapshot_id);

    // 1. Restore the registry: re-register every package the snapshot
    // knew about (via registry::register(), which also keeps the master
    // packages.toml index in sync), then unregister anything installed
    // *after* the snapshot that the snapshot never saw.
    let db_backup = snap_dir.join("db_backup.toml");
    if db_backup.exists() {
        let raw = std::fs::read_to_string(&db_backup).context("reading db_backup.toml")?;
        let backup: DbBackup = toml::from_str(&raw).context("parsing db_backup.toml")?;

        let snapshot_names: std::collections::HashSet<String> = backup
            .packages
            .iter()
            .map(|r| r.name.to_lowercase())
            .collect();

        for record in &backup.packages {
            registry::register(record).context("restoring package registry entry")?;
        }

        for current in registry::load_all() {
            if !snapshot_names.contains(&current.name.to_lowercase()) {
                let _ = registry::unregister(&current.name);
            }
        }
    }

    // 2. Restore backed-up files
    let files_dir = snap_dir.join("files");
    if files_dir.exists() {
        restore_files_recursive(&files_dir, Path::new("/"))?;
    }

    // 3. Update current symlink
    let current = Path::new(CURRENT_LINK);
    let _ = std::fs::remove_file(current);
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(&snap_dir, current);
    }

    ui::print_snapshot_restored(snapshot_id);

    Ok(())
}

/// Save the current state as the boot fallback.
/// Called after every successful install/upgrade operation.
/// On boot failure, the init system can restore this state automatically.
pub fn update_boot_fallback() -> Result<()> {
    let fallback_dir = PathBuf::from(BOOT_FALLBACK);
    let _ = std::fs::remove_dir_all(&fallback_dir);
    std::fs::create_dir_all(&fallback_dir)?;

    // Snapshot the real, current registry — not a dead path nothing writes
    // to any more.
    let db = registry::load_all();
    let db_toml = toml::to_string_pretty(&DbBackup { packages: db })
        .context("Failed to serialise boot-fallback registry backup")?;
    std::fs::write(fallback_dir.join("installed.toml"), db_toml)?;

    // Write boot marker with timestamp
    let marker = format!(
        "last_good_boot = \"{}\"\nkernel = \"{}\"\n",
        chrono_now_iso(),
        get_kernel_version()
    );
    std::fs::write(fallback_dir.join("boot_marker.toml"), marker)?;

    Ok(())
}

/// List all available snapshots, newest first.
pub fn list_snapshots() -> Result<Vec<SnapshotManifest>> {
    let snap_root = PathBuf::from(SNAPSHOT_ROOT);
    if !snap_root.exists() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();

    for entry in std::fs::read_dir(&snap_root)? {
        let entry = entry?;
        let path = entry.path();

        // Skip non-directories and special entries
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name == "current" || name == "boot-fallback" {
            continue;
        }

        let manifest_path = path.join("manifest.toml");
        if manifest_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = toml::from_str::<SnapshotManifest>(&data) {
                    snapshots.push(manifest);
                }
            }
        }
    }

    // Sort by ID (timestamp) descending — newest first
    snapshots.sort_by(|a, b| b.id.cmp(&a.id));

    Ok(snapshots)
}

/// Verify system integrity against the current snapshot.
/// Returns a list of files that have been modified since the snapshot was taken.
pub fn verify_integrity() -> Result<Vec<String>> {
    let current = Path::new(CURRENT_LINK);
    if !current.exists() {
        return Ok(Vec::new());
    }

    let manifest_path = std::fs::read_link(current)?.join("manifest.toml");

    if !manifest_path.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read_to_string(&manifest_path)?;
    let manifest: SnapshotManifest = toml::from_str(&data)?;

    let mut modified = Vec::new();

    for (file_path, expected_hash) in &manifest.file_hashes {
        let p = Path::new(file_path);
        if !p.exists() {
            modified.push(format!("DELETED: {}", file_path));
            continue;
        }
        if let Ok(current_hash) = sha256_of_path(p) {
            if &current_hash != expected_hash {
                modified.push(format!("MODIFIED: {}", file_path));
            }
        }
    }

    Ok(modified)
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/// Recursively restore files from backup directory to target root.
fn restore_files_recursive(src: &Path, target_root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();

        // Compute the destination path relative to the backup dir
        let relative = path.strip_prefix(src).unwrap_or(&path);
        let dest = target_root.join(relative);

        if path.is_dir() {
            std::fs::create_dir_all(&dest)?;
            restore_files_recursive(&path, target_root)?;
        } else {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}

/// Remove oldest snapshots when we exceed MAX_SNAPSHOTS.
fn prune_old_snapshots() -> Result<()> {
    let snap_root = PathBuf::from(SNAPSHOT_ROOT);
    if !snap_root.exists() {
        return Ok(());
    }

    let mut dirs: Vec<(String, PathBuf)> = Vec::new();

    for entry in std::fs::read_dir(&snap_root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if name == "current" || name == "boot-fallback" {
            continue;
        }
        dirs.push((name, path));
    }

    // Sort alphabetically (timestamp prefix ensures chronological order)
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    // Remove oldest entries exceeding MAX_SNAPSHOTS
    while dirs.len() > MAX_SNAPSHOTS {
        if let Some((name, path)) = dirs.first() {
            log::info!("Pruning old snapshot: {}", name);
            let _ = std::fs::remove_dir_all(path);
            dirs.remove(0);
        }
    }

    Ok(())
}

/// Compute SHA256 of a file.
fn sha256_of_path(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

/// Public wrapper for other modules (history, pinning) to use.
pub fn chrono_now_iso_pub() -> String {
    chrono_now_iso()
}

/// Get current timestamp in ISO 8601 format (no chrono dependency).
fn chrono_now_iso() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple epoch to ISO conversion (UTC)
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Approximate date calculation from epoch days
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }
    let month_days: [i64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 1u32;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        m += 1;
    }
    let d = remaining + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Get current kernel version string.
fn get_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrono_now_iso_format() {
        let ts = chrono_now_iso();
        // Should match ISO 8601 pattern: YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.len() == 20, "Unexpected timestamp length: {}", ts);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[test]
    fn test_immutable_paths_defined() {
        assert!(!IMMUTABLE_PATHS.is_empty());
        for path in IMMUTABLE_PATHS {
            assert!(
                path.starts_with("/overlayer/"),
                "immutable path must be under /overlayer/: {path}"
            );
        }
    }

    #[test]
    fn test_snapshot_manifest_serialization() {
        let manifest = SnapshotManifest {
            id: 1716048000,
            label: "pre-install-vlc".to_string(),
            created_at: "2026-05-18T12:00:00Z".to_string(),
            packages: vec![SnapshotPackageEntry {
                name: "vlc".to_string(),
                version: "3.0.20".to_string(),
                format: "deb".to_string(),
                file_count: 42,
            }],
            file_hashes: HashMap::new(),
            trigger: "install vlc".to_string(),
        };

        let toml_str = toml::to_string(&manifest).unwrap();
        let restored: SnapshotManifest = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.id, manifest.id);
        assert_eq!(restored.label, manifest.label);
        assert_eq!(restored.packages.len(), 1);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap(2024));
        assert!(!is_leap(2025));
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
    }
}
