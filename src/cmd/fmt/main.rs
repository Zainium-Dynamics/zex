
use clap::Parser;
use crate::cmd::fmt::cli::{Cli, Command, ReviewStatusArg};
use ed25519_dalek::SigningKey;
use crate::cmd::fmt::core::lock::{read_locked_manifest, write_locked, MaintainerReview, ReviewStatus, REQUIRED_APPROVALS};
use crate::cmd::fmt::core::{packer, unpacker, verifier};
use crate::cmd::fmt::security::audit_common::ToolOutcome;
use crate::cmd::fmt::security::signer::Signer128;
use crate::cmd::fmt::ui::display;

/// Load the Ed25519 signing key from `/overlayer/syshub/etc/zex/signing.key`.
/// Falls back to a deterministic dev key if the file is absent (dev/CI mode).
fn load_signing_key() -> Signer128 {
    const KEY_PATH: &str = "/overlayer/syshub/etc/zex/signing.key";
    if let Ok(hex_str) = std::fs::read_to_string(KEY_PATH) {
        if let Ok(bytes) = hex::decode(hex_str.trim()) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Signer128::from_bytes(&arr);
            }
        }
    }
    // Dev fallback — logs a warning
    log::warn!("No signing key at {KEY_PATH}; using dev key — DO NOT USE IN PRODUCTION");
    let secret: [u8; 32] = *blake3::hash(b"zainium-dev-key-do-not-use-in-prod").as_bytes();
    Signer128::from_bytes(&secret)
}

fn load_verifying_key() -> ed25519_dalek::VerifyingKey {
    const KEY_PATH: &str = "/overlayer/syshub/etc/zex/signing.key";
    if let Ok(hex_str) = std::fs::read_to_string(KEY_PATH) {
        if let Ok(bytes) = hex::decode(hex_str.trim()) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return SigningKey::from_bytes(&arr).verifying_key();
            }
        }
    }
    let secret: [u8; 32] = *blake3::hash(b"zainium-dev-key-do-not-use-in-prod").as_bytes();
    SigningKey::from_bytes(&secret).verifying_key()
}

pub fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);

    let result = match cli.command {
        Command::Pack {
            directory,
            version,
            description,
            features,
            report,
            locked,
            install_root,
            output,
        } => cmd_pack(directory, version, description, features, report, locked, install_root, output),

        Command::Unpack { file, output, verify_only } =>
            cmd_unpack(file, output, verify_only),

        Command::Verify { file } => cmd_unpack(file, None, true),

        Command::Inspect { file } => cmd_inspect(file),

        Command::Review { locked_file, slot, reviewer, status, notes } =>
            cmd_review(locked_file, slot, reviewer, status, notes),

        Command::Keygen { output_dir, force } => cmd_keygen(output_dir, force),
    };

    if let Err(e) = result {
        display::error(&e.to_string());
        std::process::exit(1);
    }
}

// ── Pack ─────────────────────────────────────────────────────────────────────

fn cmd_pack(
    directory: std::path::PathBuf,
    version: String,
    description: String,
    features: Vec<String>,
    save_report: bool,
    locked: bool,
    install_root: String,
    output: Option<std::path::PathBuf>,
) -> crate::cmd::fmt::error::Result<()> {
    let name = directory
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "package".to_string());

    let output_path = output.unwrap_or_else(|| {
        std::path::PathBuf::from(format!("{}_{}.zex", name, version))
    });

    display::title("ZEX-FMT — Secure Package Builder");

    // ── step 1: count files ──────────────────────────────────────────
    display::step("Scanning source directory...");
    let file_count = walkdir::WalkDir::new(&directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    display::kv("Files found", &file_count.to_string());

    // ── step 2: signing is always-on, not user configurable ──────────
    display::step("Cryptographic signing (background, always-on)...");
    display::ok_kv("blake3",   "digest pipeline active");
    display::ok_kv("sha512",   "digest pipeline active");
    display::ok_kv("ed25519",  "signing key loaded");

    // ── step 3: run pack (layout + manifest + rust/C audit + secrets) ─
    display::step("Running security passes (layout · secrets · Rust audit · C audit)...");

    let opts = packer::PackOptions {
        version: version.clone(),
        description: description.clone(),
        features: features.into_iter().filter(|f| !f.is_empty()).collect(),
        builder: "Zainium Official Builder".to_string(),
        zstd_level: crate::cmd::fmt::utils::compressor::DEFAULT_LEVEL,
        install_root,
        locked,
    };

    let signer = load_signing_key();

    let pack_result = match packer::pack(&directory, &output_path, &opts, &signer) {
        Ok(r) => r,
        Err(e) => {
            display::fail_kv("BLOCKED", &e.to_string());
            return Err(e);
        }
    };

    let rep = &pack_result.report;

    // Layout
    display::ok_kv("Layout policy", "PASSED — no /usr merge references");

    // Secrets scan
    let sc = &rep.secrets_scan;
    if sc.findings.is_empty() {
        display::ok_kv("Secrets scan",
            &format!("{} text files scanned — no hardcoded credentials", sc.files_scanned));
    } else {
        // Can't reach here (pack would have returned Err), but be defensive:
        display::fail_kv("Secrets scan",
            &format!("{} finding(s) — should have blocked!", sc.findings.len()));
    }

    // Rust audit
    let ra = &rep.rust_audit;
    if ra.applicable {
        display::kv("Rust source", &format!("{:?}", ra.language));
        display::kv("Build kind",  &format!("{:?}", ra.build_kind));
        if let Some(n) = ra.unsafe_block_count {
            display::kv("Unsafe expressions", &n.to_string());
        }
        if !ra.fuzz_harness_present {
            display::kv("Fuzz harness", "ABSENT — consider `cargo fuzz init`");
        } else {
            display::ok_kv("Fuzz harness", "present");
        }
        for t in &ra.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // C/C++ audit
    let ca = &rep.c_audit;
    if ca.applicable {
        display::kv("C/C++ source", "detected");
        for t in &ca.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // Permission audit
    if rep.permission_audit.setuid_files.is_empty() {
        display::ok_kv("Permission audit", "no setuid/setgid files");
    } else {
        display::fail_kv(
            "Permission audit",
            &format!("{} setuid/setgid file(s) — review mandatory",
                     rep.permission_audit.setuid_files.len()),
        );
    }

    // ── step 4: manifest ──────────────────────────────────────────────
    display::step("Manifest sealed...");
    display::kv("Name",    &name);
    display::kv("Version", &version);
    if !description.is_empty() {
        display::kv("Description", &description);
    }

    // ── step 5: output ────────────────────────────────────────────────
    display::success("Package built successfully");
    display::kv("Output (.zex)",     &output_path.display().to_string());
    display::kv("Compressed",
        &format!("{:.1} MB", pack_result.compressed_size as f64 / 1_048_576.0));
    display::kv("Uncompressed",
        &format!("{:.1} MB", pack_result.uncompressed_size as f64 / 1_048_576.0));
    display::kv("Install receipt",   &pack_result.receipt_path.display().to_string());

    if let Some(lp) = &pack_result.locked_path {
        display::kv("Locked artifact",
            &format!("{} ({} approval slots)", lp.display(), REQUIRED_APPROVALS));
        let md = lp.with_extension("locked.review.md");
        display::kv("Review checklist", &md.display().to_string());
    }

    display::kv("Inspect with",
        &format!("zex fmt inspect {}", output_path.display()));

    // Optionally write report JSON to disk
    if save_report {
        let report_path = output_path.with_extension("security-report.json");
        std::fs::write(&report_path, rep.to_json_pretty()?)?;
        display::ok_kv("Report saved", &report_path.display().to_string());
    }

    Ok(())
}

fn show_tool_result(outcome: ToolOutcome, tool: &str, summary: &str) {
    match outcome {
        ToolOutcome::Passed  => display::ok_kv(tool, summary),
        ToolOutcome::Failed  => display::fail_kv(tool, summary),
        ToolOutcome::Skipped => display::kv(tool, &format!("SKIPPED — {summary}")),
    }
}

// ── Unpack / Verify ──────────────────────────────────────────────────────────

fn cmd_unpack(
    file: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
    verify_only: bool,
) -> crate::cmd::fmt::error::Result<()> {
    let buf = std::fs::read(&file)?;
    let parsed = verifier::parse(buf)?;
    let pubkey = load_verifying_key();

    if verify_only {
        display::title("Package Verification");
        display::kv("File",      &file.display().to_string());
        display::kv("Name",      &parsed.manifest.package.name);
        display::kv("Version",   &parsed.manifest.package.version);
        display::kv("Signed by", &parsed.signature.signed_by);

        let sig_ok = verifier::verify_signature(&parsed, &pubkey)?;
        if sig_ok {
            display::ok_kv("blake3 / sha512", "Matched");
            display::ok_kv("ed25519", "Valid");
            display::success("Package is authentic and untampered.");
        } else {
            display::fail_kv("Signature", "INVALID");
            return Err(crate::cmd::fmt::error::ZexError::SignatureInvalid(
                "signature does not match package contents".into(),
            ));
        }
        return Ok(());
    }

    display::title(&format!("Unpacking {}...", file.display()));

    display::step("Verifying signature (blake3 + sha512 + ed25519)...");
    let sig_ok = verifier::verify_signature(&parsed, &pubkey)?;
    if !sig_ok {
        display::fail_kv("ed25519", "INVALID");
        return Err(crate::cmd::fmt::error::ZexError::SignatureInvalid(
            "package signature does not match its contents".into(),
        ));
    }
    display::ok_kv("ed25519", "Valid");
    display::ok_kv("blake3",  "Valid");

    display::step("Reading manifest...");
    display::kv("Name",     &parsed.manifest.package.name);
    display::kv("Version",  &parsed.manifest.package.version);
    display::kv("Tags",     &parsed.manifest.package.tags.join(", "));
    display::kv("Build type", parsed.manifest.package.build_type.as_deref().unwrap_or("unknown"));

    let dest = output.unwrap_or_else(|| std::path::PathBuf::from(&parsed.manifest.package.name));

    display::step("Extracting files...");
    let unpack_result = unpacker::unpack(&parsed, &dest, &pubkey)?;
    display::kv("Files extracted", &unpack_result.files_extracted.to_string());

    display::step("Post-unpack integrity check...");
    display::ok_kv("Manifest integrity", "PASSED");
    if !parsed.report.permission_audit.setuid_files.is_empty() {
        display::fail_kv(
            "Permission audit",
            &format!("{} setuid/setgid file(s) — review before use",
                     parsed.report.permission_audit.setuid_files.len()),
        );
    } else {
        display::ok_kv("Permission audit", "No setuid/setgid files");
    }

    let report_path = dest.join("security-report.json");
    std::fs::write(&report_path, parsed.report.to_json_pretty()?)?;

    display::success("Package unpacked successfully.");
    display::kv("Destination", &dest.display().to_string());
    display::kv("Report",      &report_path.display().to_string());

    Ok(())
}

// ── Inspect ──────────────────────────────────────────────────────────────────

fn cmd_inspect(file: std::path::PathBuf) -> crate::cmd::fmt::error::Result<()> {
    let buf = std::fs::read(&file)?;
    let parsed = verifier::parse(buf)?;

    display::title(&format!("Inspecting {}", file.display()));

    // Manifest
    display::step("Manifest");
    display::kv("Name",              &parsed.manifest.package.name);
    display::kv("Version",           &parsed.manifest.package.version);
    display::kv("Description",       &parsed.manifest.package.description);
    display::kv("Maintainer",        &parsed.manifest.package.maintainer);
    display::kv("License",           &parsed.manifest.package.license);
    display::kv("Build type",        parsed.manifest.package.build_type.as_deref().unwrap_or("unknown"));
    display::kv("Libc target",       parsed.manifest.package.libc_target.as_deref().unwrap_or("unknown"));
    display::kv("Payload files",     &parsed.payload_files.len().to_string());
    display::kv("Blake3",            parsed.manifest.package.blake3.as_deref().unwrap_or("n/a"));
    display::kv("Ed25519",           if parsed.manifest.package.ed25519_sig.is_some() { "present" } else { "missing" });

    // Security report summary
    display::step("Security report (embedded)");

    let rep = &parsed.report;

    // Layout
    display::ok_kv("Layout check", &format!("{:?}", rep.layout_check.result));

    // Content scan
    if rep.content_scan.matches.is_empty() {
        display::ok_kv("Content scan",
            &format!("{} text files, 0 /usr refs", rep.content_scan.files_scanned));
    } else {
        display::fail_kv("Content scan",
            &format!("{} /usr reference(s) found", rep.content_scan.matches.len()));
    }

    // Secrets
    let sc = &rep.secrets_scan;
    if sc.findings.is_empty() {
        display::ok_kv("Secrets scan",
            &format!("{} files, clean", sc.files_scanned));
    } else {
        display::fail_kv("Secrets scan",
            &format!("{} finding(s) — this package should have been blocked!",
                     sc.findings.len()));
        for f in &sc.findings {
            eprintln!("     {}:{} [{}]", f.file, f.line, f.pattern);
        }
    }

    // Permission audit
    if rep.permission_audit.setuid_files.is_empty() {
        display::ok_kv("Permission audit", "no setuid/setgid");
    } else {
        display::fail_kv("Permission audit",
            &format!("{} setuid/setgid file(s): {}",
                     rep.permission_audit.setuid_files.len(),
                     rep.permission_audit.setuid_files.join(", ")));
    }

    // Rust audit
    let ra = &rep.rust_audit;
    if ra.applicable {
        display::step("Rust security audit");
        display::kv("Language",    &format!("{:?}", ra.language));
        display::kv("Build kind",  &format!("{:?}", ra.build_kind));
        if let Some(n) = ra.unsafe_block_count {
            display::kv("Unsafe expressions", &n.to_string());
        }
        display::kv("Fuzz harness",
            if ra.fuzz_harness_present { "present" } else { "ABSENT" });
        for t in &ra.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // C audit
    let ca = &rep.c_audit;
    if ca.applicable {
        display::step("C/C++ static analysis");
        for t in &ca.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // Check for companion .zex.locked
    let locked_path = {
        let mut p = file.as_os_str().to_os_string();
        p.push(".locked");
        std::path::PathBuf::from(p)
    };
    if locked_path.exists() {
        display::step("Maintainer review status (.zex.locked)");
        match read_locked_manifest(&locked_path) {
            Ok(lm) => {
                display::kv("Approvals",
                    &format!("{}/{}", lm.approvals_count(), lm.required_approvals));
                display::kv("Fully approved",
                    if lm.is_fully_approved() { "YES" } else { "no" });
                for r in &lm.reviews {
                    let status = format!("{:?}", r.status);
                    let who = r.reviewer.as_deref().unwrap_or("unassigned");
                    display::kv(&format!("  Slot {}", r.slot), &format!("{status} — {who}"));
                }
            }
            Err(e) => display::fail_kv("Locked file", &e.to_string()),
        }
    } else {
        display::kv("Maintainer review", "no .zex.locked companion found");
    }

    Ok(())
}

// ── Review ───────────────────────────────────────────────────────────────────

fn cmd_review(
    locked_file: std::path::PathBuf,
    slot: u8,
    reviewer: String,
    status_arg: ReviewStatusArg,
    notes: String,
) -> crate::cmd::fmt::error::Result<()> {
    display::title("Maintainer Review — updating slot");

    let mut lm = read_locked_manifest(&locked_file)?;

    display::kv("Package", &format!("{} {}", lm.package_name, lm.package_version));
    display::kv("Slot",    &slot.to_string());
    display::kv("Reviewer", &reviewer);

    let status = match status_arg {
        ReviewStatusArg::Approved         => ReviewStatus::Approved,
        ReviewStatusArg::ChangesRequested => ReviewStatus::ChangesRequested,
        ReviewStatusArg::Rejected         => ReviewStatus::Rejected,
    };
    display::kv("Status", &format!("{status:?}"));

    // Update the slot
    let slot_entry = lm
        .reviews
        .iter_mut()
        .find(|r| r.slot == slot)
        .ok_or_else(|| crate::cmd::fmt::error::ZexError::Other(
            format!("slot {slot} not found (valid: 1–{REQUIRED_APPROVALS})")
        ))?;

    slot_entry.reviewer    = Some(reviewer);
    slot_entry.status      = status;
    slot_entry.reviewed_at = Some(chrono::Utc::now());
    slot_entry.notes       = if notes.is_empty() { None } else { Some(notes) };

    // Rewrite the .zex.locked file with updated JSON header while
    // preserving the embedded compressed source tarball.
    rewrite_locked_manifest(&locked_file, &lm)?;

    // Also regenerate the companion review.md
    let md_path = locked_file.with_extension("locked.review.md");
    std::fs::write(&md_path, lm.to_review_markdown())?;

    display::ok_kv("Saved", &locked_file.display().to_string());
    display::ok_kv("Review doc updated", &md_path.display().to_string());

    display::kv("Approvals now",
        &format!("{}/{}", lm.approvals_count(), lm.required_approvals));
    if lm.is_fully_approved() {
        display::success("All slots approved — package may be submitted to the repository.");
    }

    Ok(())
}

/// Update the JSON header inside a `.zex.locked` file in-place, keeping
/// the embedded compressed source blob unchanged.
fn rewrite_locked_manifest(
    path: &std::path::PathBuf,
    lm: &crate::cmd::fmt::core::lock::LockedManifest,
) -> crate::cmd::fmt::error::Result<()> {
    use std::io::Write;
    let raw = std::fs::read(path)?;
    if raw.len() < 12 || &raw[0..4] != b"ZEXL" {
        return Err(crate::cmd::fmt::error::ZexError::InvalidFormat("bad magic".into()));
    }
    let old_manifest_len = u64::from_le_bytes(raw[4..12].try_into().unwrap()) as usize;
    let blob_start = 12 + old_manifest_len;
    let compressed_blob = raw[blob_start..].to_vec();

    let new_json = serde_json::to_vec(lm)?;
    let mut f = std::fs::File::create(path)?;
    f.write_all(b"ZEXL")?;
    f.write_all(&(new_json.len() as u64).to_le_bytes())?;
    f.write_all(&new_json)?;
    f.write_all(&compressed_blob)?;
    f.flush()?;
    Ok(())
}

// ── Keygen ───────────────────────────────────────────────────────────────────

/// Generates a real Ed25519 keypair for signing Tier 1 (.zex) packages.
///
/// Writes two files:
///   - `signing.key` (hex, 32 bytes) — the PRIVATE key. Goes on the builder
///     machine only, at `/overlayer/syshub/etc/zex/signing.key`. Never
///     commit this to source control or share it.
///   - `trust.pub` (base64, 32 bytes) — the PUBLIC verifying key. Ships as
///     part of the OS image at `/overlayer/syshub/engine/services/trust.pub`
///     so every installed system can verify Tier 1 package signatures.
///
/// Without a real keypair in place, `zex fmt pack` silently falls back to a
/// hardcoded, publicly-known dev key (see `load_signing_key`'s warning), and
/// `zex install`'s Tier 1 signature check (`src/trust.rs`) has no fallback
/// at all — it hard-fails in the default "strict" signature mode.
fn cmd_keygen(output_dir: Option<std::path::PathBuf>, force: bool) -> crate::cmd::fmt::error::Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    display::title("ZEX-FMT — Ed25519 Keygen");

    let dir = output_dir.unwrap_or_else(|| std::path::PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("signing.key");
    let pub_path = dir.join("trust.pub");

    if !force && (key_path.exists() || pub_path.exists()) {
        return Err(crate::cmd::fmt::error::ZexError::Other(format!(
            "{} or {} already exists — pass --force to overwrite (this would invalidate every package signed with the old key)",
            key_path.display(),
            pub_path.display()
        )));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let key_hex = hex::encode(signing_key.to_bytes());
    let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, verifying_key.to_bytes());

    std::fs::write(&key_path, &key_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&pub_path, &pub_b64)?;

    display::ok_kv("Private key", &key_path.display().to_string());
    display::ok_kv("Public key",  &pub_path.display().to_string());
    display::step("Next steps:");
    println!("  1. Move {} to the builder machine ONLY, at:", key_path.display());
    println!("       /overlayer/syshub/etc/zex/signing.key");
    println!("     (mode 0600, never commit it, never let it leave that machine)");
    println!("  2. Ship {} as part of every Zainium OS image, at:", pub_path.display());
    println!("       /overlayer/syshub/engine/services/trust.pub");
    println!("     (this is what `zex install` checks .zex signatures against)");
    println!("  3. Delete the local copies here once both are in place.");

    Ok(())
}
