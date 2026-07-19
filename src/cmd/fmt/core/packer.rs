//! packer.rs — Produce a canonical .zex package (tar + zexc).
//!
//! ONE consistent format for all .zex packages — used by both
//! `zex fmt pack` (authoring) and `zex install` / `zex syshub --u` (consuming).
//!
//! ## On-disk layout inside the zexc frame:
//!
//! ```text
//! package-1.0.0.zex  (tar compressed with zexc, magic ZEX1)
//! ├── manifest.toml       ← TOML; contains ed25519_sig + blake3 fields
//! ├── signature.b3        ← hex Blake3 over (manifest.toml bytes ++ payload blake3)
//! └── payload/
//!     ├── bin/            ← maps to [install].bin
//!     ├── lib/            ← maps to [install].lib
//!     ├── sbin/           ← maps to [install].sbin
//!     ├── share/          ← maps to [install].share
//!     └── hooks/          ← pre/post install scripts (not installed to disk)
//! ```
//!
//! ## Signing chain:
//!
//! 1. Walk `payload/` — compute Blake3 over all file bytes in sorted-path order.
//! 2. Sign Blake3 with Ed25519 key → write into `manifest.toml:package.ed25519_sig`.
//! 3. Compute Blake3 over (manifest.toml bytes ++ Blake3 of payload) → `signature.b3`.
//! 4. Pack everything into tar → compress with zexc.

use crate::cmd::fmt::core::manifest::ZexTomlManifest;
use crate::cmd::fmt::core::report::SecurityReport;
use crate::cmd::fmt::core::scanner;
use crate::cmd::fmt::error::Result;
use crate::cmd::fmt::security::c_audit;
use crate::cmd::fmt::security::root_guard;
use crate::cmd::fmt::security::rust_audit;
use crate::cmd::fmt::security::secrets_scan;
use crate::cmd::fmt::security::signer::Signer128;
use crate::cmd::fmt::utils::{compressor, hash};
use std::{io::Write, path::Path};

pub struct PackOptions {
    pub version:      String,
    pub description:  String,
    pub features:     Vec<String>,
    pub builder:      String,
    pub zstd_level:   i32,
    /// Union-layer root for install receipt absolute paths.
    pub install_root: String,
    /// Emit a `.zex.locked` maintainer-review artifact alongside the .zex.
    pub locked:       bool,
}

pub struct PackResult {
    pub output_path:       std::path::PathBuf,
    pub compressed_size:   u64,
    pub uncompressed_size: u64,
    pub report:            SecurityReport,
    pub receipt_path:      std::path::PathBuf,
    pub sbom_path:         std::path::PathBuf,
    pub locked_path:       Option<std::path::PathBuf>,
}

/// Pack `source_dir` into a canonical .zex at `output_path`.
///
/// `source_dir` must contain a `payload/` subdirectory and a `manifest.toml`.
/// If no `manifest.toml` exists, one is generated from `opts`.
pub fn pack(
    source_dir: &Path,
    output_path: &Path,
    opts: &PackOptions,
    signer: &Signer128,
) -> Result<PackResult> {
    // ── Step 1: Layout policy — no /usr/ refs ──────────────────────────
    let (layout_result, content_result) = root_guard::enforce_layout_policy(source_dir)?;

    // ── Step 2: Security passes ────────────────────────────────────────
    let secrets  = secrets_scan::scan_secrets(source_dir);
    if secrets.is_blocked() {
        return Err(crate::cmd::fmt::error::ZexError::Other(
            "secrets scan blocked packaging — remove hardcoded credentials from source".into(),
        ));
    }
    let rust_aud = rust_audit::run_rust_audit(source_dir);
    let c_aud    = c_audit::run_c_audit(source_dir);

    if rust_aud.has_failures() {
        return Err(crate::cmd::fmt::error::ZexError::Other(format!(
            "Rust security audit failed — package NOT built: {}",
            rust_aud.tools.iter()
                .filter(|t| t.outcome == crate::cmd::fmt::security::audit_common::ToolOutcome::Failed)
                .map(|t| format!("{}: {}", t.tool, t.summary))
                .collect::<Vec<_>>().join("; ")
        )));
    }

    // ── Step 3: Resolve payload/ directory ────────────────────────────
    let payload_dir = source_dir.join("payload");
    if !payload_dir.is_dir() {
        return Err(crate::cmd::fmt::error::ZexError::LayoutViolation(
            "source directory must contain a payload/ subdirectory".into(),
        ));
    }

    // ── Step 4: Read or generate manifest.toml ────────────────────────
    let manifest_src = source_dir.join("manifest.toml");
    let mut manifest: ZexTomlManifest = if manifest_src.exists() {
        let raw = std::fs::read_to_string(&manifest_src)?;
        toml::from_str(&raw).map_err(|e| {
            crate::cmd::fmt::error::ZexError::Other(format!("manifest.toml parse error: {e}"))
        })?
    } else {
        ZexTomlManifest::generate(source_dir, opts)?
    };

    // Stamp version from CLI if provided
    if !opts.version.is_empty() {
        manifest.package.version = opts.version.clone();
    }
    if !opts.description.is_empty() {
        manifest.package.description = opts.description.clone();
    }

    // ── Step 5: Walk payload/ — compute sizes + Blake3 ────────────────
    let mut payload_files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut uncompressed = 0u64;

    for entry in walkdir::WalkDir::new(&payload_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() { continue; }
        let rel = entry.path()
            .strip_prefix(source_dir)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();
        let bytes = std::fs::read(entry.path())?;
        uncompressed += bytes.len() as u64;
        payload_files.push((rel, bytes));
    }

    // ── Step 6: Blake3 over sorted payload files ───────────────────────
    // Explicit path sort so pack/verify/install all hash in the same order.
    payload_files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut payload_hasher = blake3::Hasher::new();
    for (path, bytes) in &payload_files {
        payload_hasher.update(path.as_bytes());
        payload_hasher.update(bytes);
    }
    let payload_blake3 = payload_hasher.finalize().to_hex().to_string();

    // ── Step 7: Ed25519 sign over payload Blake3 ─────────────────────
    let sig_block = signer.sign(payload_blake3.as_bytes(), &opts.builder)?;
    manifest.package.blake3      = Some(payload_blake3.clone());
    manifest.package.ed25519_sig = sig_block.ed25519_signature.clone();

    // ── Step 8: Serialize manifest.toml ───────────────────────────────
    let manifest_toml = toml::to_string_pretty(&manifest).map_err(|e| {
        crate::cmd::fmt::error::ZexError::Other(format!("manifest serialize error: {e}"))
    })?;

    // ── Step 9: signature.b3 = Blake3(manifest_bytes ++ payload_blake3) ─
    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(manifest_toml.as_bytes());
    sig_hasher.update(payload_blake3.as_bytes());
    let sig_b3 = sig_hasher.finalize().to_hex().to_string();

    // ── Step 10: Build tar in memory ──────────────────────────────────
    //
    // Structure:
    //   manifest.toml
    //   signature.b3
    //   payload/<files...>
    //
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);

        // manifest.toml at tar root
        append_bytes(&mut builder, "manifest.toml", manifest_toml.as_bytes(), 0o644)?;

        // signature.b3 at tar root
        append_bytes(&mut builder, "signature.b3", sig_b3.as_bytes(), 0o644)?;

        // payload/ files (already loaded)
        for (rel_path, bytes) in &payload_files {
            append_bytes(&mut builder, rel_path, bytes, 0o755)?;
        }

        builder.finish()?;
    }

    // ── Step 11: Compress tar with zexc (native .zex / ZEX1) ─────────
    let compressed = compressor::compress(&tar_buf, opts.zstd_level)?;
    let compressed_size = compressed.len() as u64;

    // ── Step 12: Write .zex file ──────────────────────────────────────
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, &compressed)?;

    // ── Step 12b: SPDX SBOM ───────────────────────────────────────────
    let sbom_path = output_path.with_extension("spdx.json");
    let sbom_json = crate::cmd::fmt::security::sbom::generate_spdx(
        source_dir,
        &manifest,
        &payload_files,
    )?;
    std::fs::write(&sbom_path, sbom_json)?;

    // ── Step 13: Write install receipt .toml ─────────────────────────
    let receipt_path = crate::cmd::fmt::core::receipt::write_receipt(
        output_path,
        &manifest,
        &payload_files,
        &opts.install_root,
    )?;

    // ── Step 14: Security report ──────────────────────────────────────
    let permission_audit = scanner::audit_permissions(&payload_dir)?;
    let manifest_integrity = scanner::ManifestIntegrityResult {
        result: scanner::CheckOutcome::Passed,
        description: "Payload hashed via Blake3 at pack time".into(),
        mismatches: Vec::new(),
    };
    let report = SecurityReport::new(
        layout_result,
        content_result,
        manifest_integrity,
        permission_audit,
        rust_aud,
        c_aud,
        secrets,
    );

    // ── Step 15: .zex.locked artifact (if requested) ─────────────────
    let locked_path = if opts.locked {
        let lp = crate::cmd::fmt::core::lock::write_locked(source_dir, &manifest, &report, output_path)?;
        Some(lp)
    } else {
        None
    };

    Ok(PackResult {
        output_path:       output_path.to_path_buf(),
        compressed_size,
        uncompressed_size: uncompressed,
        report,
        receipt_path,
        sbom_path,
        locked_path,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_mtime(0); // deterministic
    header.set_cksum();
    builder.append_data(&mut header, path, data)
        .map_err(crate::cmd::fmt::error::ZexError::Io)
}

/// Derive the package name from the output path stem.
pub fn manifest_name_from_path(output_path: &Path) -> String {
    output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("package")
        .split('_').next()
        .unwrap_or("package")
        .to_string()
}
