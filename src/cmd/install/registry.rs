//! registry.rs — TOML-per-package registry for Zex.
//!
//! Replaces SQLite (db.rs, store_index.rs) and JSON (/var/lib/zex/installed.json)
//! with a filesystem-based registry: one `.toml` file per installed package.
//!
//! Path: /overlayer/zexlib/registry/installed/<package_name>.toml
//!
//! Design:
//!   - `is_installed()` is O(1): just `Path::exists()`
//!   - Atomic writes: write to `.tmp` then `rename()`
//!   - No locking needed for different packages (file-per-package)
//!   - Human-readable: `cat /overlayer/zexlib/registry/installed/vlc.toml`
//!
//! ## Authoritative vs. derived state
//!
//! Exactly one thing in this whole module is authoritative: the set of
//! `PkgRecord` files under `installed/` (`load_all()` reads every one of
//! them). Everything else this module writes is a **derived** view built
//! from that source, kept only for other commands' convenience — none of
//! it is ever the thing that gets consulted to answer "is X installed,
//! and at what version":
//!
//!   - `packages.toml` (the "master index") — a flattened summary consumed
//!     by `uland --u`, `doctor`, `search`, and `rollback` so they don't
//!     each have to re-scan and re-parse every `installed/*.toml` file.
//!     Kept in sync incrementally on every `register()`/`unregister()`
//!     call via `sync_master_index`/`remove_from_master_index`. If it
//!     ever drifts from the authoritative source (deleted, corrupted,
//!     a bug skipped a sync call, or it predates that sync logic
//!     existing at all), [`rebuild_master_index`] regenerates it *from
//!     scratch* by replaying every real `PkgRecord` — this is the actual
//!     integrity/repair operation (`zex doctor --fix` calls it), not
//!     [`prune_master_index`], which only ever removes stale entries and
//!     can't fix the opposite kind of drift (a real package missing from
//!     the index).
//!   - Any other cache built from this data (search indices, dashboards,
//!     etc.) must follow the same rule: never treated as ground truth,
//!     always regeneratable from `load_all()` alone.
//!
//! The practical test for "is this authoritative or derived": if the
//! `installed/*.toml` files disappeared, would this file still tell the
//! truth? For everything except `installed/` itself, the answer is no —
//! which is exactly why every one of those views needs a from-scratch
//! rebuild path, not just incremental patching.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Base directory for the installed package registry.
pub const REGISTRY_DIR: &str = "/overlayer/zexlib/registry/installed";

/// Master summary index consumed by `uland --u`, `doctor`, and `rollback`.
/// The per-package files under `installed/` are the real source of truth;
/// this is a derived, best-effort aggregate kept in sync on every
/// register/unregister so those other commands (which only read this file)
/// don't see a permanently empty registry.
const MASTER_INDEX: &str = "/overlayer/zexlib/registry/packages.toml";

/// A single installed package record, serialised as TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgRecord {
    pub name: String,
    pub display_name: String,
    pub version: String,
    pub format: String,
    #[serde(default)]
    pub source_mirror: String,
    pub installed_at: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub blake3: String,
    pub size: u64,

    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    /// Packages this one genuinely cannot coexist with (Alpine's bare
    /// "!pkgname" negative-dependency convention). Checked bidirectionally
    /// at install time — see `check_conflicts` in depends.rs.
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub requires_syshub: Option<String>,
    #[serde(default)]
    pub installed_files: Vec<String>,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Check if a package is installed.  O(1) — just a filesystem path check.
pub fn is_installed(name: &str) -> bool {
    toml_path(name).exists()
}

/// Get the set of all installed package names.
/// Used by the dependency resolver to skip already-installed deps.
pub fn get_installed_set() -> HashSet<String> {
    let mut installed = HashSet::new();
    let dir = Path::new(REGISTRY_DIR);
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".toml") {
                    let pkg_name = name.trim_end_matches(".toml").to_lowercase();
                    installed.insert(pkg_name);
                }
            }
        }
    }
    installed
}

/// Get the set of all installed package names AND their provided virtual capabilities/libraries.
pub fn get_installed_capabilities() -> HashSet<String> {
    let mut caps = HashSet::new();
    let records = load_all();
    for record in records {
        caps.insert(record.name.to_lowercase());
        for p in record.provides {
            caps.insert(p.to_lowercase());
        }
    }
    caps
}

/// Look up a single installed package by name (case-insensitive).
pub fn lookup(name: &str) -> Option<PkgRecord> {
    let path = toml_path(&name.to_lowercase());
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    toml::from_str(&content).ok()
}

/// Register a package in the registry (atomic write).
pub fn register(record: &PkgRecord) -> Result<()> {
    let dir = Path::new(REGISTRY_DIR);
    fs::create_dir_all(dir)
        .with_context(|| format!("Cannot create registry dir: {}", dir.display()))?;

    let toml_str = toml::to_string_pretty(record)
        .context("Failed to serialise PkgRecord to TOML")?;

    // Atomic write: write to .tmp then rename
    let path = toml_path(&record.name.to_lowercase());
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, toml_str.as_bytes())
        .with_context(|| format!("Failed to write temp registry file: {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("Failed to atomically install registry file: {}", path.display()))?;

    let _ = sync_master_index(record);

    Ok(())
}

/// Bumps an already-installed package's version in place, for `uland --u`.
///
/// Loads the existing full `PkgRecord`, updates only `version` and
/// `installed_at`, and re-registers it — preserving every other field
/// (`installed_files`, `dependencies`, `provides`, `sha256`, …). Upgrade
/// code must use this instead of writing a fresh, mostly-empty receipt:
/// a receipt missing `installed_files` makes `zex remove` a no-op for
/// that package, and one missing `dependencies` breaks orphan detection.
pub fn update_version(name: &str, new_version: &str) -> Result<()> {
    let mut record = lookup(name)
        .with_context(|| format!("cannot bump version: '{name}' has no existing registry entry"))?;
    record.version = new_version.to_string();
    record.installed_at = chrono::Utc::now().to_rfc3339();
    register(&record)
}

/// Remove a package from the registry.
pub fn unregister(name: &str) -> Result<()> {
    let path = toml_path(&name.to_lowercase());
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove registry file: {}", path.display()))?;
    }
    let _ = remove_from_master_index(name);
    Ok(())
}

// ─── Master index (packages.toml) sync ──────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
struct MasterIndex {
    #[serde(default)]
    system: MasterSystemMeta,
    #[serde(default)]
    packages: std::collections::BTreeMap<String, MasterPkgEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MasterSystemMeta {
    #[serde(default)]
    last_update: String,
    #[serde(default)]
    total_packages: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MasterPkgEntry {
    version: String,
    origin: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    receipt: String,
    /// The *exact* mirror this package was resolved from (e.g.
    /// "alpine-community", not just "tier3-alpine"). Upgrade checking must
    /// use this, not a generic per-tier default — a tier can have several
    /// mirrors (alpine-main vs alpine-community, chimera-main vs
    /// chimera-user), and checking the wrong one either misses the
    /// package entirely or — worse — silently "upgrades" it from a
    /// different mirror/tier than it was actually installed from.
    #[serde(default)]
    source_mirror: String,
}

/// Maps (format, source_mirror) to the "tierN-vendor" label the master
/// index (and `uland --u`) expect in the `origin` field.
///
/// Tier numbers match `zex_services.toml`'s real mirror priorities: Void
/// is tier2 (power-user tier, tried first), Alpine is tier3 (embedded/
/// minimal tier), Chimera stays tier4 — updated when the priorities were
/// reordered. `upgrade/userland.rs::match_mirror` matches on the distro
/// name substring too (`contains("alpine")`, not just `contains("tier2")`),
/// so this rename doesn't change upgrade-routing behavior, only the label.
pub fn derive_origin(format: &str, source_mirror: &str) -> String {
    if format == "zex" {
        return "tier1-zainium".to_string();
    }
    let m = source_mirror.to_ascii_lowercase();
    if m.starts_with("void") { "tier2-void".to_string() }
    else if m.starts_with("alpine") { "tier3-alpine".to_string() }
    else if m.starts_with("chimera") { "tier4-chimera".to_string() }
    else { format!("tier?-{format}") }
}

fn load_master_index() -> MasterIndex {
    fs::read_to_string(MASTER_INDEX)
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_master_index(index: &MasterIndex) -> Result<()> {
    let path = Path::new(MASTER_INDEX);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).ok();
    }
    let toml_str = toml::to_string_pretty(index)
        .context("Failed to serialise master packages.toml")?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, toml_str.as_bytes())
        .with_context(|| format!("Failed to write temp master index: {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("Failed to atomically install master index: {}", path.display()))?;
    Ok(())
}

fn sync_master_index(record: &PkgRecord) -> Result<()> {
    let mut index = load_master_index();
    let key = record.name.to_lowercase();
    index.packages.insert(key.clone(), MasterPkgEntry {
        version: record.version.clone(),
        origin: derive_origin(&record.format, &record.source_mirror),
        description: record.display_name.clone(),
        dependencies: record.dependencies.clone(),
        receipt: format!("installed/{key}.toml"),
        source_mirror: record.source_mirror.clone(),
    });
    index.system.total_packages = index.packages.len();
    index.system.last_update = chrono::Utc::now().to_rfc3339();
    write_master_index(&index)
}

/// Removes a package's entry from the master index. Public so `zex remove`
/// can keep the same file in sync without duplicating the parsing logic.
pub fn remove_from_master_index(name: &str) -> Result<()> {
    let mut index = load_master_index();
    if index.packages.remove(&name.to_lowercase()).is_some() {
        index.system.total_packages = index.packages.len();
        index.system.last_update = chrono::Utc::now().to_rfc3339();
        write_master_index(&index)?;
    }
    Ok(())
}

/// Drops every master-index entry whose package no longer has a receipt
/// under `installed/` (used by `zex doctor --fix` to prune stale entries).
/// Returns the names that were removed. Safe struct-based read/write —
/// no raw TOML text surgery.
///
/// Only ever *removes* entries — it can't fix the opposite drift (a real,
/// currently-installed package that's simply *missing* from the index,
/// e.g. because `packages.toml` was deleted/corrupted, or predates
/// `sync_master_index` existing at all). For that, use
/// [`rebuild_master_index`], which reconstructs the whole file from the
/// authoritative source rather than patching around whatever's already
/// there.
pub fn prune_master_index(keep_names: &HashSet<String>) -> Result<Vec<String>> {
    let mut index = load_master_index();
    let stale: Vec<String> = index.packages.keys()
        .filter(|k| !keep_names.contains(k.as_str()))
        .cloned()
        .collect();
    if stale.is_empty() {
        return Ok(stale);
    }
    for name in &stale {
        index.packages.remove(name);
    }
    index.system.total_packages = index.packages.len();
    index.system.last_update = chrono::Utc::now().to_rfc3339();
    write_master_index(&index)?;
    Ok(stale)
}

/// Regenerates `packages.toml` **from scratch**, entirely from the
/// authoritative per-package files under `installed/` — the actual
/// integrity/repair operation for the derived index, as opposed to
/// [`prune_master_index`]'s narrower "remove entries that no longer have a
/// receipt" pass. Whatever the file currently contains (missing entries,
/// stale entries, or the file not existing / being corrupt at all) is
/// irrelevant: this always produces an index that exactly matches
/// `load_all()`'s output, because it's built by replaying every real
/// `PkgRecord` through the exact same `sync_master_index` logic
/// `register()` uses for a normal install. Returns the number of packages
/// the rebuilt index now contains.
pub fn rebuild_master_index() -> Result<usize> {
    let records = load_all();
    let mut index = MasterIndex::default();

    for record in &records {
        let key = record.name.to_lowercase();
        index.packages.insert(key.clone(), MasterPkgEntry {
            version: record.version.clone(),
            origin: derive_origin(&record.format, &record.source_mirror),
            description: record.display_name.clone(),
            dependencies: record.dependencies.clone(),
            receipt: format!("installed/{key}.toml"),
            source_mirror: record.source_mirror.clone(),
        });
    }

    index.system.total_packages = index.packages.len();
    index.system.last_update = chrono::Utc::now().to_rfc3339();
    write_master_index(&index)?;
    Ok(index.packages.len())
}

/// Load all installed package records.
pub fn load_all() -> Vec<PkgRecord> {
    let dir = Path::new(REGISTRY_DIR);
    let mut records = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".toml") {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if let Ok(record) = toml::from_str::<PkgRecord>(&content) {
                            records.push(record);
                        }
                    }
                }
            }
        }
    }
    records
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn toml_path(name: &str) -> PathBuf {
    Path::new(REGISTRY_DIR).join(format!("{}.toml", name))
}

// ─── Conversion helpers for compatibility with existing DbEntry API ──────────

impl PkgRecord {
    /// Create a PkgRecord from a resolved PackageInfo + installed file list.
    pub fn from_install(
        info: &super::backend::PackageInfo,
        installed_files: Vec<String>,
    ) -> Self {
        let format_str = match info.format {
            super::backend::PackageFormat::Zex => "zex",
            super::backend::PackageFormat::Apk => "apk",
            super::backend::PackageFormat::Xbps => "xbps",
            super::backend::PackageFormat::Adb => "adb",
        };

        PkgRecord {
            name: info.name.clone(),
            display_name: info.display_name.clone(),
            version: info.version.clone(),
            format: format_str.to_string(),
            source_mirror: info.source_mirror.clone().unwrap_or_default(),
            installed_at: chrono::Utc::now().to_rfc3339(),
            sha256: info.sha256.clone().unwrap_or_default(),
            blake3: info.blake3.clone().unwrap_or_default(),
            size: info.size,
            dependencies: info.depends.clone(),
            provides: info.provides.clone(),
            conflicts: info.conflicts.clone(),
            requires_syshub: info.requires_syshub.clone(),
            installed_files,
        }
    }

    /// Convert to a DbEntry for backward compatibility with code that still
    /// uses the old DbEntry interface.
    pub fn into_db_entry(self) -> super::backend::DbEntry {
        let format = match self.format.as_str() {
            "zex" => super::backend::PackageFormat::Zex,
            "apk" => super::backend::PackageFormat::Apk,
            "xbps" => super::backend::PackageFormat::Xbps,
            "adb" => super::backend::PackageFormat::Adb,
            _ => super::backend::PackageFormat::Apk,
        };

        super::backend::DbEntry {
            name: self.name,
            display_name: self.display_name,
            version: self.version,
            size: self.size,
            format,
            installed_at: self.installed_at,
            installed_files: self.installed_files,
            sha256: if self.sha256.is_empty() { None } else { Some(self.sha256) },
            blake3: if self.blake3.is_empty() { None } else { Some(self.blake3) },
        }
    }
}
