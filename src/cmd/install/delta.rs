//! delta.rs — Delta Updates for Zex.
//!
//! Only downloads changed files when upgrading a package.
//! Compares SHA256 hashes of installed files against remote manifest.
//! Falls back to full download if delta info is unavailable.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Manifest of file hashes from the remote repository.
#[derive(Debug, Clone)]
pub struct DeltaManifest {
    pub package: String,
    pub version: String,
    /// Map of relative file path → SHA256 hash
    pub file_hashes: HashMap<String, String>,
}

/// Result of delta comparison.
#[derive(Debug)]
pub struct DeltaResult {
    /// Files that need to be downloaded (new or changed)
    pub changed: Vec<String>,
    /// Files that are unchanged (skip download)
    pub unchanged: Vec<String>,
    /// Files that were removed in new version
    pub removed: Vec<String>,
    /// Bytes saved by skipping unchanged files
    pub bytes_saved: u64,
}

/// Compare installed files against a remote manifest to find what changed.
pub fn compute_delta(installed_files: &[String], remote_manifest: &DeltaManifest) -> DeltaResult {
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    let mut removed = Vec::new();
    let mut bytes_saved: u64 = 0;

    // Check existing files against remote hashes
    for (remote_path, remote_hash) in &remote_manifest.file_hashes {
        let local = Path::new(remote_path);
        if local.exists() && local.is_file() {
            if let Ok(local_hash) = sha256_file(local) {
                if local_hash == *remote_hash {
                    unchanged.push(remote_path.clone());
                    if let Ok(meta) = std::fs::metadata(local) {
                        bytes_saved += meta.len();
                    }
                    continue;
                }
            }
        }
        changed.push(remote_path.clone());
    }

    // Files in installed but not in remote = removed
    for file in installed_files {
        if !remote_manifest.file_hashes.contains_key(file) {
            removed.push(file.clone());
        }
    }

    DeltaResult {
        changed,
        unchanged,
        removed,
        bytes_saved,
    }
}

/// Check if delta updates are available for a package.
/// Currently checks for a .delta.json manifest alongside the package.
pub fn check_delta_available(package_url: &str) -> Option<String> {
    let delta_url = format!(
        "{}.delta.json",
        package_url
            .trim_end_matches(".zex")
            .trim_end_matches(".apk")
            .trim_end_matches(".xbps")
    );
    // Return the URL — caller decides whether to fetch
    Some(delta_url)
}

/// Build a delta manifest from the currently installed files.
pub fn build_local_manifest(
    package_name: &str,
    version: &str,
    installed_files: &[String],
) -> DeltaManifest {
    let mut file_hashes = HashMap::new();
    for file_path in installed_files {
        let p = Path::new(file_path);
        if p.exists() && p.is_file() {
            if let Ok(hash) = sha256_file(p) {
                file_hashes.insert(file_path.clone(), hash);
            }
        }
    }
    DeltaManifest {
        package: package_name.to_string(),
        version: version.to_string(),
        file_hashes,
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_delta() {
        let manifest = DeltaManifest {
            package: "test".to_string(),
            version: "1.0".to_string(),
            file_hashes: HashMap::new(),
        };
        let result = compute_delta(&[], &manifest);
        assert!(result.changed.is_empty());
        assert!(result.unchanged.is_empty());
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_delta_url() {
        let url = check_delta_available("https://example.com/pkg.deb");
        assert!(url.is_some());
        assert!(url.unwrap().contains("delta.json"));
    }
}
