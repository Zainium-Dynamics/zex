use crate::cmd::fmt::error::Result;
use crate::cmd::fmt::utils::hash::sha512_hex;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub signed_by:         String,
    pub blake3_digest:     String,
    pub sha512_digest:     String,
    pub ed25519_signature: Option<String>,
    /// Blake3 over (manifest_toml_bytes ++ payload_blake3) — file-level integrity
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_b3:            String,
}

/// Holds the keypair used by the Zainium official builder.
/// In production this would be loaded from a secure key file, not
/// generated at random — `from_bytes` / `load` is the real entry point.
pub struct Signer128 {
    signing_key: SigningKey,
}

impl Signer128 {
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Signer128 {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Signs a pre-computed digest — `data` is the caller's already-hashed
    /// payload blake3 digest (its hex string's bytes), *not* raw payload
    /// bytes to hash here. Signs `data` directly and records it verbatim as
    /// `blake3_digest`.
    ///
    /// This used to call `blake3_hex(data)` again before signing, silently
    /// hashing the hash: `packer.rs` passes `payload_blake3.as_bytes()`
    /// (already a blake3 digest), so the stored `blake3_digest` field held
    /// a hash-of-a-hash that could never match `verifier::verify_signature`'s
    /// independently-recomputed payload blake3 — every real .zex signature
    /// was unverifiable against its own signing key until this was fixed.
    pub fn sign(&self, data: &[u8], signed_by: &str) -> Result<SignatureBlock> {
        let blake3_digest = String::from_utf8_lossy(data).into_owned();
        let sha512_digest = sha512_hex(data);

        let sig: Signature = self.signing_key.sign(data);

        Ok(SignatureBlock {
            signed_by: signed_by.to_string(),
            blake3_digest,
            sha512_digest,
            ed25519_signature: Some(hex::encode(sig.to_bytes())),
            sig_b3: String::new(),
        })
    }
}

/// Verifies a signature block against the original pre-computed digest
/// (`data`, matching `sign`'s contract above) and a known public key.
pub fn verify(
    data: &[u8],
    block: &SignatureBlock,
    public_key: &VerifyingKey,
) -> Result<bool> {
    let expected_blake3 = String::from_utf8_lossy(data);
    if expected_blake3 != block.blake3_digest {
        return Ok(false);
    }
    let expected_sha512 = sha512_hex(data);
    if expected_sha512 != block.sha512_digest {
        return Ok(false);
    }

    if let Some(sig_hex) = &block.ed25519_signature {
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| crate::cmd::fmt::error::ZexError::Other(e.to_string()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| crate::cmd::fmt::error::ZexError::Other(e.to_string()))?;
        if public_key
            .verify(block.blake3_digest.as_bytes(), &sig)
            .is_err()
        {
            return Ok(false);
        }
    }

    Ok(true)
}
