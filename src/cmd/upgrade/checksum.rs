//! Checksum utilities for verifying file integrity

use anyhow::anyhow;
use hex::encode;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Calculate SHA256 hash of a file
pub async fn calculate_sha256(path: &Path) -> anyhow::Result<String> {
    let mut file =
        File::open(path).map_err(|e| anyhow!("Failed to open file {}: {}", path.display(), e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(anyhow!("Error reading file: {}", e)),
        }
    }

    Ok(encode(hasher.finalize()))
}

/// Verify file against expected SHA256 hash
#[allow(dead_code)]
pub async fn verify_file(path: &Path, expected: &str) -> anyhow::Result<bool> {
    let actual = calculate_sha256(path).await?;
    Ok(actual.eq_ignore_ascii_case(expected))
}

/// Calculate SHA256 of bytes
#[allow(dead_code)]
pub fn calculate_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    encode(hasher.finalize())
}

/// Verify bytes against expected SHA256 hash
#[allow(dead_code)]
pub fn verify_bytes(data: &[u8], expected: &str) -> bool {
    calculate_sha256_bytes(data).eq_ignore_ascii_case(expected)
}

/// Format hash for display (first 16 chars and last 8 chars)
#[allow(dead_code)]
pub fn format_hash_for_display(hash: &str) -> String {
    if hash.len() <= 24 {
        hash.to_string()
    } else {
        format!("{}...{}", &hash[..16], &hash[hash.len() - 8..])
    }
}
