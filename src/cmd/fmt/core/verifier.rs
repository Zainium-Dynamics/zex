//! verifier.rs — Verify a canonical .zex package (tar + zexc).
//!
//! Reads: manifest.toml + signature.b3 + payload/ tree from a zexc frame.
//! Verifies: Blake3 integrity + Ed25519 signature.

use crate::cmd::fmt::core::manifest::ZexTomlManifest;
use crate::cmd::fmt::core::report::SecurityReport;
use crate::cmd::fmt::error::{Result, ZexError};
use crate::cmd::fmt::security::signer::SignatureBlock;
use crate::zex_codec;
use ed25519_dalek::VerifyingKey;
use std::io::Read;

/// Parsed and verified contents of a .zex package.
pub struct ParsedZex {
    pub manifest:      ZexTomlManifest,
    pub manifest_raw:  String,
    pub signature:     SignatureBlock,
    pub report:        SecurityReport,
    pub payload_files: Vec<(String, Vec<u8>)>,
}

/// Parse a .zex file from raw bytes without verifying signature.
/// Call [`verify_signature`] separately.
pub fn parse(data: Vec<u8>) -> Result<ParsedZex> {
    // Decompress zexc (ZEX1) → tar
    let dec = zex_codec::decompress(&data)
        .map_err(|e| ZexError::InvalidFormat(format!("zexc decompress failed: {e}")))?;

    let mut archive = tar::Archive::new(std::io::Cursor::new(&dec));

    let mut manifest_toml:    Option<String>         = None;
    let mut sig_b3_file:      Option<String>         = None;
    let mut payload_files:    Vec<(String, Vec<u8>)> = Vec::new();

    for entry in archive.entries()
        .map_err(|e| ZexError::InvalidFormat(format!("tar read failed: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| ZexError::InvalidFormat(format!("tar entry error: {e}")))?;

        let path = entry.path()
            .map_err(|e| ZexError::InvalidFormat(format!("tar path error: {e}")))?
            .to_string_lossy()
            .to_string();

        // Reject path traversal immediately
        if path.contains("../") || path.contains("/..") {
            return Err(ZexError::InvalidFormat(
                format!("SECURITY: path traversal in package: {path}")
            ));
        }

        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)
            .map_err(|e| ZexError::Io(e))?;

        match path.as_str() {
            "manifest.toml" => {
                manifest_toml = Some(String::from_utf8(bytes).map_err(|_| {
                    ZexError::InvalidFormat("manifest.toml is not valid UTF-8".into())
                })?);
            }
            "signature.b3" => {
                sig_b3_file = Some(String::from_utf8(bytes).map_err(|_| {
                    ZexError::InvalidFormat("signature.b3 is not valid UTF-8".into())
                })?);
            }
            p if p.starts_with("payload/") => {
                payload_files.push((path, bytes));
            }
            _ => {
                // Ignore unknown root-level files
            }
        }
    }

    let manifest_str = manifest_toml.ok_or_else(|| {
        ZexError::InvalidFormat("manifest.toml missing from .zex archive".into())
    })?;
    let sig_b3_str = sig_b3_file.ok_or_else(|| {
        ZexError::InvalidFormat("signature.b3 missing from .zex archive".into())
    })?;

    let manifest: ZexTomlManifest = toml::from_str(&manifest_str).map_err(|e| {
        ZexError::InvalidFormat(format!("manifest.toml parse error: {e}"))
    })?;

    // Sort payload files (deterministic hash order)
    payload_files.sort_by(|a, b| a.0.cmp(&b.0));

    // Build signature block from manifest fields
    let signed_by = manifest.package.maintainer.clone();
    let blake3_digest = manifest.package.blake3.clone().unwrap_or_default();
    let ed25519_sig   = manifest.package.ed25519_sig.clone();
    let signature = SignatureBlock {
        signed_by,
        blake3_digest,
        sha512_digest: String::new(), // reserved
        ed25519_signature: ed25519_sig,
        sig_b3: sig_b3_str.trim().to_string(),
    };

    // Default empty report (loaded from JSON sidecar if present)
    let report = SecurityReport::default();

    Ok(ParsedZex {
        manifest,
        manifest_raw: manifest_str,
        signature,
        report,
        payload_files,
    })
}

/// Verify cryptographic integrity of a parsed .zex.
///
/// Checks (in order):
///   1. Recompute Blake3 over payload tree — compare to manifest.package.blake3
///   2. Ed25519 verify(blake3, manifest.ed25519_sig, public_key)
///   3. Recompute signature.b3 — compare to embedded sig_b3
pub fn verify_signature(parsed: &ParsedZex, public_key: &VerifyingKey) -> Result<bool> {
    // 1. Recompute Blake3 over payload files (sorted)
    let mut payload_hasher = blake3::Hasher::new();
    for (path, bytes) in &parsed.payload_files {
        payload_hasher.update(path.as_bytes());
        payload_hasher.update(bytes);
    }
    let computed_blake3 = payload_hasher.finalize().to_hex().to_string();

    if computed_blake3 != parsed.signature.blake3_digest {
        return Ok(false); // payload tampered
    }

    // 2. Ed25519 verify
    if let Some(ref sig_hex) = parsed.signature.ed25519_signature {
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| ZexError::Other(e.to_string()))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| ZexError::Other(e.to_string()))?;
        if public_key
            .verify_strict(computed_blake3.as_bytes(), &sig)
            .is_err()
        {
            return Ok(false); // signature invalid
        }
    }

    // 3. signature.b3 check (raw manifest.toml bytes + payload blake3)
    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(parsed.manifest_raw.as_bytes());
    sig_hasher.update(computed_blake3.as_bytes());
    let computed_sig_b3 = sig_hasher.finalize().to_hex().to_string();

    if computed_sig_b3 != parsed.signature.sig_b3 {
        return Ok(false); // manifest tampered after signing
    }

    Ok(true)
}
