use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Verify that a driver/binary exists and is executable.
/// Never mutates permissions — callers must fix packaging if the bit is missing.
pub fn ensure_executable(binary_path: &str) -> Result<()> {
    let path = Path::new(binary_path);

    if !path.exists() {
        bail!("binary not found: {binary_path}");
    }

    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }

    let mode = metadata.permissions().mode();
    if mode & 0o100 == 0 {
        bail!(
            "binary is not executable: {} (mode {:o}) — fix package permissions, do not chmod at runtime",
            path.display(),
            mode & 0o777
        );
    }

    Ok(())
}

/// Returns the first executable candidate path that exists on disk.
pub fn first_available_executable(binary_paths: &[String]) -> Result<String> {
    let mut last_err = None;
    for path in binary_paths {
        match ensure_executable(path) {
            Ok(()) => return Ok(path.clone()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no driver candidates provided")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rejects_non_executable_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let bin = dir.path().join("zex-install");
        fs::write(&bin, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o644)).unwrap();

        let err = ensure_executable(bin.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("not executable"));
    }

    #[test]
    fn accepts_executable_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let bin = dir.path().join("zex-install");
        fs::write(&bin, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        ensure_executable(bin.to_str().unwrap()).unwrap();
    }
}