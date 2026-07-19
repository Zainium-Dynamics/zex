//! Zainium package trust anchor — Ed25519 verification for .zex archives.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use ed25519_dalek::VerifyingKey;

use crate::cmd::fmt::core::verifier;

pub const TRUST_KEY_PATH: &str = "/overlayer/syshub/engine/services/trust.pub";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerificationMode {
    Off,
    Audit,
    Strict,
}

impl SignatureVerificationMode {
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "audit" => Self::Audit,
            _ => Self::Strict,
        }
    }
}

/// Load the 32-byte Ed25519 public key from `trust.pub` (base64-encoded).
pub fn load_verifying_key() -> Result<VerifyingKey> {
    let key_b64 = fs::read_to_string(TRUST_KEY_PATH)
        .with_context(|| format!("reading trust anchor at {TRUST_KEY_PATH}"))?;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .context("decoding trust.pub as base64")?;
    if key_bytes.len() != 32 {
        bail!(
            "trust.pub must be exactly 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("trust.pub key length invalid"))?;
    VerifyingKey::from_bytes(&key_arr).context("constructing Ed25519 verifying key")
}

/// Full cryptographic verification of a `.zex` archive (Blake3 + Ed25519 + signature.b3).
pub fn verify_zex_archive(path: &Path, mode: SignatureVerificationMode) -> Result<()> {
    if mode == SignatureVerificationMode::Off {
        return Ok(());
    }

    let data = fs::read(path)
        .with_context(|| format!("reading .zex archive {}", path.display()))?;

    let parsed = verifier::parse(data).map_err(|e| anyhow::anyhow!("{e}"))?;

    if parsed.signature.ed25519_signature.is_none() {
        let msg = format!(
            "package '{}' has no ed25519_sig in manifest.toml",
            parsed.manifest.package.name
        );
        match mode {
            SignatureVerificationMode::Strict => bail!(msg),
            SignatureVerificationMode::Audit => {
                log::warn!("{msg} — continuing in audit mode");
                return Ok(());
            }
            SignatureVerificationMode::Off => return Ok(()),
        }
    }

    let key = match load_verifying_key() {
        Ok(k) => k,
        Err(e) => {
            let msg = format!("cannot load trust anchor: {e}");
            match mode {
                SignatureVerificationMode::Strict => bail!(msg),
                SignatureVerificationMode::Audit => {
                    log::warn!("{msg} — skipping signature verification");
                    return Ok(());
                }
                SignatureVerificationMode::Off => return Ok(()),
            }
        }
    };

    let ok = verifier::verify_signature(&parsed, &key)
        .map_err(|e| anyhow::anyhow!("signature verification error: {e}"))?;

    if ok {
        log::debug!(
            "Ed25519 + Blake3 verified for '{}'",
            parsed.manifest.package.name
        );
        return Ok(());
    }

    let msg = format!(
        "cryptographic verification FAILED for '{}' — package may be tampered",
        parsed.manifest.package.name
    );
    match mode {
        SignatureVerificationMode::Strict => bail!(msg),
        SignatureVerificationMode::Audit => {
            log::warn!("{msg}");
            Ok(())
        }
        SignatureVerificationMode::Off => Ok(()),
    }
}