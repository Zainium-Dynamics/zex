//! Zainium package trust gate — Ed25519 verification for .zex archives.
//!
//! There is no fixed publisher signing key any more. `substrate pack`
//! generates a fresh, never-persisted Ed25519 keypair on every single
//! build and embeds the *verifying* key directly in the package's own
//! `manifest.toml` (`package.ed25519_pubkey`). This module therefore no
//! longer checks against an external trust anchor — it checks a package's
//! signature against the pubkey the package itself carries.
//!
//! What this proves: the manifest + payload bytes are exactly what was
//! signed at pack time (tamper-evidence). What it does NOT prove: that
//! the package came from any particular known publisher — nothing durable
//! ties a pubkey to an identity under this model. Reconciling that with a
//! real publisher-trust layer is server-side work (see `zex-server`,
//! handled separately).

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;

use crate::cmd::install::zex_manifest::ZexManifest;

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

/// Parsed contents of a `.zex` archive, enough to verify its signature.
struct ParsedZexForVerify {
    manifest: ZexManifest,
    manifest_raw: String,
    sig_b3: String,
    /// (archive path, bytes, symlink target). `target` is `Some(..)` for
    /// symlink entries — `bytes` is always empty for those (tar carries no
    /// body for a symlink), matching Substrate's `core/verifier.rs` exactly.
    payload_files: Vec<(String, Vec<u8>, Option<String>)>,
}

/// Decompress + tar-walk a `.zex` archive, pulling out `manifest.toml`,
/// `signature.b3`, and every `payload/` entry's bytes (sorted by path for
/// deterministic hashing). Does not verify anything — call
/// [`verify_embedded`] on the result.
fn parse_for_verification(data: Vec<u8>) -> Result<ParsedZexForVerify> {
    let dec = crate::zex_codec::decompress(&data).context("zexc decompress failed")?;
    let mut archive = tar::Archive::new(std::io::Cursor::new(&dec));

    let mut manifest_toml: Option<String> = None;
    let mut sig_b3_file: Option<String> = None;
    let mut payload_files: Vec<(String, Vec<u8>, Option<String>)> = Vec::new();

    for entry in archive.entries().context("tar read failed")? {
        let mut entry = entry.context("tar entry error")?;
        let path = entry
            .path()
            .context("tar path error")?
            .to_string_lossy()
            .to_string();

        if path.contains("../") || path.contains("/..") {
            bail!("SECURITY: path traversal in package: {path}");
        }

        // Symlink entries carry no body in the tar — their contribution to
        // the payload hash is the link TARGET string instead, exactly as
        // `substrate pack`'s packer.rs computed it at sign time. Reading
        // link_name() must happen before read_to_end() consumes the entry.
        let is_symlink = entry.header().entry_type().is_symlink();
        let link_target = if is_symlink {
            entry
                .link_name()
                .context("reading symlink target")?
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).context("reading tar entry")?;

        match path.as_str() {
            "manifest.toml" => {
                manifest_toml = Some(
                    String::from_utf8(bytes)
                        .map_err(|_| anyhow::anyhow!("manifest.toml is not valid UTF-8"))?,
                );
            }
            "signature.b3" => {
                sig_b3_file = Some(
                    String::from_utf8(bytes)
                        .map_err(|_| anyhow::anyhow!("signature.b3 is not valid UTF-8"))?,
                );
            }
            p if p.starts_with("payload/") => {
                payload_files.push((path, bytes, link_target));
            }
            _ => {}
        }
    }

    let manifest_raw =
        manifest_toml.ok_or_else(|| anyhow::anyhow!("manifest.toml missing from .zex archive"))?;
    let sig_b3 =
        sig_b3_file.ok_or_else(|| anyhow::anyhow!("signature.b3 missing from .zex archive"))?;

    let manifest: ZexManifest =
        toml::from_str(&manifest_raw).context("manifest.toml parse error")?;

    payload_files.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(ParsedZexForVerify {
        manifest,
        manifest_raw,
        sig_b3,
        payload_files,
    })
}

/// Verify a parsed `.zex` against the Ed25519 pubkey embedded in its own
/// manifest. Three checks, in order:
///   1. recomputed Blake3 over the sorted payload tree == manifest.blake3
///   2. Ed25519(computed_blake3, manifest.ed25519_sig) verifies under `key`
///   3. recomputed signature.b3 == the archive's own signature.b3 entry
fn verify_embedded(parsed: &ParsedZexForVerify, key: &VerifyingKey) -> Result<bool> {
    let mut payload_hasher = blake3::Hasher::new();
    for (path, bytes, target) in &parsed.payload_files {
        payload_hasher.update(path.as_bytes());
        match target {
            Some(t) => payload_hasher.update(t.as_bytes()),
            None => payload_hasher.update(bytes),
        };
    }
    let computed_blake3 = payload_hasher.finalize().to_hex().to_string();

    let expected_blake3 = parsed
        .manifest
        .package
        .blake3
        .as_deref()
        .unwrap_or_default();
    if computed_blake3 != expected_blake3 {
        return Ok(false); // payload tampered
    }

    if let Some(ref sig_hex) = parsed.manifest.package.ed25519_sig {
        let sig_bytes = hex::decode(sig_hex).context("decoding ed25519_sig as hex")?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .context("parsing ed25519_sig bytes")?;
        if key.verify_strict(computed_blake3.as_bytes(), &sig).is_err() {
            return Ok(false); // signature invalid
        }
    }

    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(parsed.manifest_raw.as_bytes());
    sig_hasher.update(computed_blake3.as_bytes());
    let computed_sig_b3 = sig_hasher.finalize().to_hex().to_string();

    if computed_sig_b3 != parsed.sig_b3 {
        return Ok(false); // manifest tampered after signing
    }

    Ok(true)
}

/// Full cryptographic verification of a `.zex` archive (Blake3 + Ed25519
/// against the pubkey embedded in the package's own manifest.toml).
pub fn verify_zex_archive(path: &Path, mode: SignatureVerificationMode) -> Result<()> {
    if mode == SignatureVerificationMode::Off {
        return Ok(());
    }

    let data =
        fs::read(path).with_context(|| format!("reading .zex archive {}", path.display()))?;

    let parsed = parse_for_verification(data)?;

    if parsed.manifest.package.ed25519_sig.is_none()
        || parsed.manifest.package.ed25519_pubkey.is_none()
    {
        let msg = format!(
            "package '{}' has no ed25519_sig/ed25519_pubkey in manifest.toml",
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

    let key = match parse_embedded_pubkey(&parsed.manifest) {
        Ok(k) => k,
        Err(e) => {
            let msg = format!(
                "cannot parse embedded ed25519_pubkey for '{}': {e}",
                parsed.manifest.package.name
            );
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

    let ok = verify_embedded(&parsed, &key)
        .map_err(|e| anyhow::anyhow!("signature verification error: {e}"))?;

    if ok {
        log::debug!(
            "Ed25519 + Blake3 verified for '{}' against embedded pubkey",
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

/// Decode the package's own embedded `ed25519_pubkey` (hex, 32 bytes).
fn parse_embedded_pubkey(manifest: &ZexManifest) -> Result<VerifyingKey> {
    let hex_str = manifest
        .package
        .ed25519_pubkey
        .as_deref()
        .context("manifest has no ed25519_pubkey")?;
    let key_bytes = hex::decode(hex_str).context("decoding ed25519_pubkey as hex")?;
    if key_bytes.len() != 32 {
        bail!(
            "ed25519_pubkey must be exactly 32 bytes, got {}",
            key_bytes.len()
        );
    }
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519_pubkey length invalid"))?;
    VerifyingKey::from_bytes(&key_arr).context("constructing Ed25519 verifying key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::install::zex_manifest::{HookMap, InstallMap, PackageMeta, RemoveMap};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_manifest(blake3: &str, sig_hex: &str, pubkey_hex: Option<&str>) -> ZexManifest {
        ZexManifest {
            package: PackageMeta {
                name: "testpkg".into(),
                version: "1.0.0".into(),
                description: "test".into(),
                license: "MIT".into(),
                maintainer: "test".into(),
                homepage: None,
                build_type: None,
                libc_target: None,
                edition: None,
                ed25519_sig: Some(sig_hex.to_string()),
                blake3: Some(blake3.to_string()),
                ed25519_pubkey: pubkey_hex.map(|s| s.to_string()),
                requires_syshub: None,
                depends: vec![],
                provides: vec![],
                tags: vec![],
            },
            install: InstallMap::default(),
            remove: RemoveMap::default(),
            editions: None,
            hooks: HookMap::default(),
        }
    }

    /// Builds a fully valid signed `ParsedZexForVerify` (as if produced by
    /// `substrate pack`) plus the verifying key, for a single payload file.
    fn build_valid() -> (ParsedZexForVerify, VerifyingKey) {
        let payload_files = vec![(
            "payload/bin/hello".to_string(),
            b"hello world".to_vec(),
            None,
        )];

        let mut hasher = blake3::Hasher::new();
        for (path, bytes, _) in &payload_files {
            hasher.update(path.as_bytes());
            hasher.update(bytes);
        }
        let payload_blake3 = hasher.finalize().to_hex().to_string();

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(payload_blake3.as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        let manifest = make_manifest(&payload_blake3, &sig_hex, Some(&pubkey_hex));
        let manifest_raw = toml::to_string_pretty(&manifest).unwrap();

        let mut sig_hasher = blake3::Hasher::new();
        sig_hasher.update(manifest_raw.as_bytes());
        sig_hasher.update(payload_blake3.as_bytes());
        let sig_b3 = sig_hasher.finalize().to_hex().to_string();

        (
            ParsedZexForVerify {
                manifest,
                manifest_raw,
                sig_b3,
                payload_files,
            },
            verifying_key,
        )
    }

    #[test]
    fn valid_signature_verifies() {
        let (parsed, key) = build_valid();
        assert!(verify_embedded(&parsed, &key).unwrap());
    }

    #[test]
    fn wrong_pubkey_fails_ed25519_check() {
        let (parsed, _correct_key) = build_valid();
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(!verify_embedded(&parsed, &wrong_key).unwrap());
    }

    #[test]
    fn tampered_payload_fails_blake3_check() {
        let (mut parsed, key) = build_valid();
        parsed.payload_files[0].1.push(b'!'); // payload changed after signing
        assert!(!verify_embedded(&parsed, &key).unwrap());
    }

    #[test]
    fn tampered_manifest_fails_sig_b3_check() {
        let (mut parsed, key) = build_valid();
        parsed.manifest_raw.push_str("\n# tampered\n"); // manifest bytes changed after signing
        assert!(!verify_embedded(&parsed, &key).unwrap());
    }

    /// Builds a real tar+zexc `.zex` archive end-to-end (matching
    /// `substrate pack`'s own layout) and drives it through the public
    /// `verify_zex_archive` entry point — proves the whole pipeline, not
    /// just the inner crypto check.
    fn write_real_archive(path: &std::path::Path, signed: bool) {
        let payload_files: Vec<(&str, &[u8])> = vec![("payload/bin/hello", b"hello world")];

        let mut hasher = blake3::Hasher::new();
        for (p, b) in &payload_files {
            hasher.update(p.as_bytes());
            hasher.update(b);
        }
        let payload_blake3 = hasher.finalize().to_hex().to_string();

        let (sig_hex, pubkey_hex) = if signed {
            let signing_key = SigningKey::generate(&mut OsRng);
            let sig = signing_key.sign(payload_blake3.as_bytes());
            (
                Some(hex::encode(sig.to_bytes())),
                Some(hex::encode(signing_key.verifying_key().to_bytes())),
            )
        } else {
            (None, None)
        };

        let manifest = make_manifest(
            &payload_blake3,
            sig_hex.as_deref().unwrap_or(""),
            pubkey_hex.as_deref(),
        );
        let mut manifest = manifest;
        if !signed {
            manifest.package.ed25519_sig = None;
        }
        let manifest_raw = toml::to_string_pretty(&manifest).unwrap();

        let mut sig_hasher = blake3::Hasher::new();
        sig_hasher.update(manifest_raw.as_bytes());
        sig_hasher.update(payload_blake3.as_bytes());
        let sig_b3 = sig_hasher.finalize().to_hex().to_string();

        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let append = |builder: &mut tar::Builder<&mut Vec<u8>>, path: &str, data: &[u8]| {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, data).unwrap();
            };
            append(&mut builder, "manifest.toml", manifest_raw.as_bytes());
            append(&mut builder, "signature.b3", sig_b3.as_bytes());
            for (p, b) in &payload_files {
                append(&mut builder, p, b);
            }
            builder.finish().unwrap();
        }

        let compressed = crate::zex_codec::compress(&tar_buf, 3).unwrap();
        fs::write(path, compressed).unwrap();
    }

    #[test]
    fn end_to_end_real_archive_verifies_strict() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("zex_trust_test_valid_{}.zex", std::process::id()));
        write_real_archive(&path, true);

        let result = verify_zex_archive(&path, SignatureVerificationMode::Strict);
        let _ = fs::remove_file(&path);
        result.expect("a freshly self-signed archive must verify against its own embedded pubkey");
    }

    #[test]
    fn end_to_end_missing_signature_rejected_strict_warned_audit() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "zex_trust_test_unsigned_{}.zex",
            std::process::id()
        ));
        write_real_archive(&path, false);

        let strict_result = verify_zex_archive(&path, SignatureVerificationMode::Strict);
        assert!(
            strict_result.is_err(),
            "unsigned package must be rejected in Strict mode"
        );

        let audit_result = verify_zex_archive(&path, SignatureVerificationMode::Audit);
        let _ = fs::remove_file(&path);
        audit_result.expect("unsigned package must warn-through in Audit mode");
    }
}
