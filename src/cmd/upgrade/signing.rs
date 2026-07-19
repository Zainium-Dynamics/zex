//! signing.rs — Ed25519 signature verification for .zex upgrade payloads.
//! Reads the Zainium trust anchor public key from
//! /overlayer/syshub/engine/services/trust.pub  (base64-encoded 32-byte key).

use anyhow::{Context, Result, bail};
use base64::Engine;
use std::path::Path;

const TRUST_KEY_PATH: &str =
    "/overlayer/syshub/engine/services/trust.pub";

/// Verify the Ed25519 signature on a downloaded .zex file.
///
/// Signature is expected to be in a sidecar file `<path>.sig` as a
/// 64-byte raw binary.  When `strict` is true (the default for syshub
/// upgrades), missing trust key or sidecar is a hard failure — aligned
/// with install-path `SignatureVerificationMode::Strict`.
pub fn verify_zex(zex_path: &Path, strict: bool) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let sig_path = zex_path.with_extension("zex.sig");

    if !Path::new(TRUST_KEY_PATH).exists() || !sig_path.exists() {
        if strict {
            bail!(
                "strict mode: trust key or .sig sidecar missing for {}",
                zex_path.display()
            );
        }
        log::warn!(
            "Signature verification skipped for {} (trust key or .sig absent)",
            zex_path.display()
        );
        return Ok(());
    }

    // Load the 32-byte Ed25519 public key (stored as base64 for readability).
    let key_b64 = std::fs::read_to_string(TRUST_KEY_PATH)
        .context("reading trust.pub")?;
    let key_bytes: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .context("decoding trust.pub as base64")?;
    if key_bytes.len() != 32 {
        bail!("trust.pub must be exactly 32 bytes, got {}", key_bytes.len());
    }
    let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .context("constructing Ed25519 verifying key")?;

    // Load the 64-byte raw signature.
    let sig_bytes = std::fs::read(&sig_path)
        .context("reading .sig sidecar")?;
    if sig_bytes.len() != 64 {
        bail!("signature file must be exactly 64 bytes, got {}", sig_bytes.len());
    }
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_arr);

    // Verify against the raw .zex bytes.
    let zex_bytes = std::fs::read(zex_path)
        .context("reading .zex file for signature verification")?;

    verifying_key.verify(&zex_bytes, &signature)
        .context("Ed25519 signature verification FAILED — package may be tampered")?;

    log::info!("Ed25519 signature verified for {}", zex_path.display());
    Ok(())
}

/// Strict verification — required for syshub upgrades and the default path.
pub fn verify_zex_strict(zex_path: &Path) -> Result<()> {
    verify_zex(zex_path, true)
}
