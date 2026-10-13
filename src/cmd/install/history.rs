//! history.rs — Transaction History Engine for Zex.
//!
//! Logs every install/remove/upgrade/pin operation with full metadata.
//! Stored at /overlayer/zexlib/history.toml (TOML, not JSON — kept
//! consistent with every other piece of zex-managed state: receipts,
//! packages.toml master index, transaction snapshots — all TOML, no
//! JSON, no SQL). Moved here from /var/lib/zex/history.json — that path
//! sat outside /overlayer entirely, which is inconsistent with every
//! other piece of zex state living under zexlib.
//!
//! Features:
//!   • Full audit trail of every package operation
//!   • Timestamps, package lists, operation types, success/failure
//!   • Query by date range or package name
//!   • Enables future `zex history undo <id>` functionality

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const HISTORY_PATH: &str = "/overlayer/zexlib/history.toml";
const MAX_HISTORY_ENTRIES: usize = 1000;

// ─── Data Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    Install,
    Remove,
    Upgrade,
    Pin,
    Unpin,
    Refresh,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Install => write!(f, "install"),
            Self::Remove => write!(f, "remove"),
            Self::Upgrade => write!(f, "upgrade"),
            Self::Pin => write!(f, "pin"),
            Self::Unpin => write!(f, "unpin"),
            Self::Refresh => write!(f, "refresh"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique monotonic ID
    pub id: u64,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// What operation was performed
    pub operation: OperationType,
    /// List of affected packages
    pub packages: Vec<PackageRecord>,
    /// Whether the operation succeeded
    pub success: bool,
    /// Optional error message on failure
    pub error: Option<String>,
    /// Duration of the operation in milliseconds
    pub duration_ms: u64,
    /// User who invoked the operation (from $SUDO_USER or $USER)
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRecord {
    pub name: String,
    pub version: String,
    pub format: String,
}

/// TOML requires a top-level table, not a bare array — this wraps the
/// entry list as `[[entry]]` array-of-tables.
#[derive(Debug, Default, Serialize, Deserialize)]
struct HistoryFile {
    #[serde(default, rename = "entry")]
    entries: Vec<HistoryEntry>,
}

// ─── Core API ────────────────────────────────────────────────────────────────

/// Load the history log from disk. Returns empty vec if file doesn't exist.
pub fn load_history() -> Vec<HistoryEntry> {
    let path = Path::new(HISTORY_PATH);
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(data) => toml::from_str::<HistoryFile>(&data)
            .map(|f| f.entries)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Save history log to disk atomically.
fn save_history(entries: &[HistoryEntry]) -> Result<()> {
    let dir = Path::new(HISTORY_PATH)
        .parent()
        .unwrap_or(Path::new("/overlayer/zexlib"));
    std::fs::create_dir_all(dir)?;

    let file = HistoryFile {
        entries: entries.to_vec(),
    };
    let toml_str = toml::to_string_pretty(&file).context("Failed to serialize history")?;

    // Atomic write: write to temp, then rename
    let tmp_path = format!("{}.tmp", HISTORY_PATH);
    std::fs::write(&tmp_path, &toml_str).context("Failed to write history temp file")?;
    std::fs::rename(&tmp_path, HISTORY_PATH).context("Failed to commit history file")?;

    Ok(())
}

/// Record a new operation in the history log.
pub fn record(
    operation: OperationType,
    packages: Vec<PackageRecord>,
    success: bool,
    error: Option<String>,
    duration_ms: u64,
) -> Result<()> {
    let mut history = load_history();

    // Compute next ID
    let next_id = history.iter().map(|e| e.id).max().unwrap_or(0) + 1;

    // Detect user
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());

    let entry = HistoryEntry {
        id: next_id,
        timestamp: super::immutable::chrono_now_iso_pub(),
        operation,
        packages,
        success,
        error,
        duration_ms,
        user,
    };

    history.push(entry);

    // Prune oldest entries if exceeding max
    while history.len() > MAX_HISTORY_ENTRIES {
        history.remove(0);
    }

    save_history(&history)?;
    Ok(())
}

/// Get the last N history entries.
pub fn last_n(n: usize) -> Vec<HistoryEntry> {
    let history = load_history();
    let start = history.len().saturating_sub(n);
    history[start..].to_vec()
}

/// Find all history entries for a specific package.
pub fn find_by_package(name: &str) -> Vec<HistoryEntry> {
    load_history()
        .into_iter()
        .filter(|e| e.packages.iter().any(|p| p.name.eq_ignore_ascii_case(name)))
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_type_display() {
        assert_eq!(OperationType::Install.to_string(), "install");
        assert_eq!(OperationType::Remove.to_string(), "remove");
        assert_eq!(OperationType::Upgrade.to_string(), "upgrade");
        assert_eq!(OperationType::Pin.to_string(), "pin");
        assert_eq!(OperationType::Unpin.to_string(), "unpin");
    }

    #[test]
    fn test_history_entry_serialization() {
        let entry = HistoryEntry {
            id: 1,
            timestamp: "2026-05-18T12:00:00Z".to_string(),
            operation: OperationType::Install,
            packages: vec![PackageRecord {
                name: "vlc".to_string(),
                version: "3.0.20".to_string(),
                format: "deb".to_string(),
            }],
            success: true,
            error: None,
            duration_ms: 5000,
            user: "ali-zain".to_string(),
        };

        let file = HistoryFile {
            entries: vec![entry],
        };
        let toml_str = toml::to_string(&file).unwrap();
        let restored: HistoryFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].id, 1);
        assert_eq!(restored.entries[0].packages.len(), 1);
        assert!(restored.entries[0].success);
    }
}
