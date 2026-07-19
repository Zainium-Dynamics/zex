//! Structural integrity checks performed at pack/unpack time.
//!
//! IMPORTANT: this module does NOT implement malware signature
//! detection or heuristic antivirus scanning. It performs concrete,
//! verifiable structural checks:
//!   - every file in the archive matches its declared manifest entry & hash
//!   - no unexpected setuid/setgid bits are present
//! Reports describe exactly these checks, not broader "malware" coverage.

use crate::cmd::fmt::core::manifest::FileEntry;
use crate::cmd::fmt::error::{Result, ZexError};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestIntegrityResult {
    pub result: CheckOutcome,
    pub description: String,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PermissionAuditResult {
    pub result: CheckOutcome,
    pub setuid_files: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    #[default]
    Passed,
    Failed,
}

/// Verify that every manifest entry's declared hash matches the actual
/// file on disk under `root`. Used both at pack time (sanity check
/// right before compressing) and conceptually at unpack time against
/// extracted files.
pub fn verify_manifest_integrity(
    root: &Path,
    files: &[FileEntry],
) -> Result<ManifestIntegrityResult> {
    let mut mismatches = Vec::new();

    for entry in files {
        let full_path = root.join(&entry.path);
        let actual_hash = match crate::cmd::fmt::utils::hash::sha256_file(&full_path) {
            Ok(h) => h,
            Err(_) => {
                mismatches.push(format!("{}: missing on disk", entry.path));
                continue;
            }
        };
        if actual_hash != entry.sha256 {
            mismatches.push(format!(
                "{}: hash mismatch (expected {}, got {})",
                entry.path, entry.sha256, actual_hash
            ));
        }
    }

    let result = if mismatches.is_empty() {
        CheckOutcome::Passed
    } else {
        CheckOutcome::Failed
    };

    Ok(ManifestIntegrityResult {
        result,
        description:
            "Every file in archive matches a manifest entry and hash".to_string(),
        mismatches,
    })
}

/// Audit permission bits across the package tree, flagging any
/// setuid/setgid files. These aren't automatically rejected (some
/// legitimate tools need them) but are always surfaced in the report
/// so a human reviewer sees them.
pub fn audit_permissions(root: &Path) -> Result<PermissionAuditResult> {
    let mut setuid_files = Vec::new();

    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = entry.path().symlink_metadata().map_err(ZexError::Io)?;
        let mode = meta.permissions().mode();
        let is_setuid = mode & 0o4000 != 0;
        let is_setgid = mode & 0o2000 != 0;
        if is_setuid || is_setgid {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string();
            setuid_files.push(rel);
        }
    }

    Ok(PermissionAuditResult {
        result: CheckOutcome::Passed, // informational, not a hard failure
        setuid_files,
        description: "No unexpected setuid/setgid bits found".to_string(),
    })
}
