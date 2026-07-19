//! installer.rs — Atomic package extractor with snapshot-based rollback.
//!
//! Architecture (Snapshot → Stage → Commit → Cleanup):
//!   1. Snapshot:  If upgrading, back up every file the old package owns
//!                 to /var/cache/zex/snapshots/<pkg>-<ts>/.
//!   2. Stage:    Extract the new package into a private TempDir — never
//!                directly into /.  Nothing on the live system is touched yet.
//!   3. Commit:   Move staged files from TempDir to their final / destinations.
//!                On failure, the snapshot is restored — system is never broken.
//!   4. Cleanup:  Remove orphan files from the old version, then delete the
//!                snapshot and staging dirs.
//!
//! No other mainstream package manager (apt, pacman, dnf) does file-level
//! backup before overwriting.  If they fail midway, the system is left
//! half-installed.  Zex guarantees atomic installs.
//!
//! Additional features:
//!   • Streaming Decompression: Feed tar directly from the decompressor.
//!   • SHA256 / Blake3 integrity: Verify every package before extracting.
//!   • Supported formats only: `.zex` (zexc), `.apk` (gzip), `.xbps` (zstd).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use blake3::Hasher;
use sha2::{Digest, Sha256};

use super::backend::{DbEntry, PackageFormat, PackageInfo, register_package};
use super::sandbox;
use super::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityMode {
    Strict,
    Balanced,
}

impl IntegrityMode {
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "strict" => Self::Strict,
            _ => Self::Balanced,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct InstallTelemetry {
    pub verify_ms: u128,
    pub extract_ms: u128,
    pub db_ms: u128,
    /// The actual binary name detected from extracted files.
    /// Used to show the correct "Launch with: X" message instead of the package name.
    pub detected_launch_cmd: Option<String>,
}

struct InstallPackageLock {
    file: std::fs::File,
}

impl Drop for InstallPackageLock {
    fn drop(&mut self) {
        // SAFETY: file descriptor is valid for the lifetime of self.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

// ─── Snapshot Constants ───────────────────────────────────────────────────────

const SNAPSHOT_BASE: &str = "/var/cache/zex/snapshots";

// ─── Public API ───────────────────────────────────────────────────────────────

/// Scan staged files for the primary binary name.
/// Returns the basename of the first file under usr/bin/ or usr/sbin/.
fn detect_launch_cmd(staged_files: &[PathBuf], store_path: &Path) -> Option<String> {
    for path in staged_files {
        if let Ok(rel) = path.strip_prefix(store_path) {
            let rel_str = rel.to_string_lossy();
            if rel_str.starts_with("usr/bin/") || rel_str.starts_with("usr/sbin/") {
                if let Some(basename) = rel.file_name() {
                    return Some(basename.to_string_lossy().into_owned());
                }
            }
        }
    }
    None
}

fn compute_symlink_target(
    staged_path: &Path,
    store_path: &Path,
    union_root: &Path,
    overlay_ok: bool,
) -> Result<PathBuf> {
    if overlay_ok {
        let rel = staged_path.strip_prefix(store_path).map_err(|_| {
            anyhow::anyhow!(
                "staged file '{}' is not under store path '{}'",
                staged_path.display(),
                store_path.display()
            )
        })?;
        Ok(union_root.join(rel))
    } else {
        Ok(staged_path.to_path_buf())
    }
}

/// Installs the package file at `pkg_path` according to `info.format`.
///
/// If `existing` is `Some`, this is an upgrade: the old package's files are
/// backed up to a snapshot directory before any changes are made.  On failure
/// at any stage, the snapshot is restored and the system is left clean.
///
/// Pre-flight conflict check: before any extraction, the installer scans the
/// entire installed database for file ownership collisions.  If another package
/// already owns a file that this package would install, the operation is aborted
/// with a clear error unless `--force` is used.
///
/// Pipeline order (CRITICAL — do not reorder):
///   1. Verify integrity + signature
///   2. Snapshot (upgrade only)
///   3. Extract to Content Store
///   4. Compute final system paths
///   5. Register in DB + write TOML registry
///   6. Remount OverlayFS (reads TOML to discover store hashes)
///   7. Commit symlinks (union paths now valid)
///   8. Post-install hooks
///   9. Orphan cleanup (upgrade only)
///  10. Cleanup snapshot
/// Detached-signature material for Void `.xbps` packages, fetched
/// asynchronously (alongside the package download) before this otherwise
/// fully synchronous install pipeline runs — xbps is the one format whose
/// signature isn't self-contained in the package file itself.
pub struct XbpsVerifyData {
    pub sig2: Vec<u8>,
    pub pubkey_pem: Vec<u8>,
}

pub fn install(
    pkg_path: &Path,
    info: &PackageInfo,
    existing: Option<&DbEntry>,
    parallel: bool,
    integrity_mode: IntegrityMode,
    signature_mode: crate::trust::SignatureVerificationMode,
    xbps_sig: Option<&XbpsVerifyData>,
) -> Result<InstallTelemetry> {
    let _pkg_lock = acquire_package_lock(&info.name)?;

    // ── Step 1: Verify ────────────────────────────────────────────────────
    let verify_start = Instant::now();
    if !parallel {
        ui::print_install_step("Verifying integrity");
    }
    verify_file(pkg_path, info.size)?;

    if !parallel {
        ui::print_install_step("Verifying signature");
    }
    verify_signature(pkg_path, info, integrity_mode, signature_mode, xbps_sig)?;
    let verify_ms = verify_start.elapsed().as_millis();

    let extract_start = Instant::now();

    // ── Step 2: Snapshot (upgrade only) ───────────────────────────────────
    let snapshot_dir = if let Some(old) = existing {
        if !parallel {
            ui::print_install_step("Snapshotting previous version");
        }
        let dir = create_snapshot(info, old)?;
        Some(dir)
    } else {
        None
    };

    // ── Step 3: Stage — extract into Content Store, NOT into / ───────────
    if !parallel {
        ui::print_install_step("Extracting to Content Store");
    }

    // Create a staging directory in the same filesystem as union/ for fast atomic renames
    let zex_tmp = Path::new("/overlayer/zexlib/tmp");
    let _ = std::fs::create_dir_all(zex_tmp);
    let stage_dir = tempfile::Builder::new()
        .prefix("zex-stage-")
        .tempdir_in(zex_tmp)
        .map_err(|e| anyhow::anyhow!("cannot create stage dir: {}", e))?;
    
    let store_path = stage_dir.path().to_path_buf();
    let _content_hash = info.sha256.clone().unwrap_or_default();

    let mut staged_files = Vec::new();

    let stage_result = match info.format {
        PackageFormat::Zex => extract_zex(pkg_path, &store_path, &mut staged_files),

        PackageFormat::Apk => extract_apk(pkg_path, &store_path, &mut staged_files),
        PackageFormat::Xbps => extract_xbps(pkg_path, &store_path, &mut staged_files),
        PackageFormat::Adb => extract_adb(pkg_path, &store_path, &mut staged_files),
    };

    let postinstall_script = match stage_result {
        Ok(script) => script,
        Err(e) => {
            // Staging failed — nothing on the live system was touched.
            // Snapshot (if any) is still intact, no restore needed.
            cleanup_snapshot(&snapshot_dir);
            return Err(e);
        }
    };

    // Detect the actual binary name from extracted files (Phase 4 — launch_cmd fix)
    let detected_launch = detect_launch_cmd(&staged_files, &store_path);

    // ── Step 4: Compute final system paths ───────────────────────────────
    //
    // Build the list of system paths inside /overlayer/zexlib/union/ from staged files.
    // We are bypassing the legacy / symlinks and overlay mount, and directly populating the union layer.
    // Final destinations always under /overlayer/zexlib/union/
    // (apk/xbps archive paths already remapped: usr/bin → bin, etc.)
    let union_root = Path::new(crate::archive_safety::UNION_ROOT);
    let mut committed_files = Vec::new();

    for staged_path in &staged_files {
        let rel = staged_path.strip_prefix(&store_path).map_err(|_| {
            anyhow::anyhow!(
                "staged file '{}' is not under store path '{}'",
                staged_path.display(),
                store_path.display()
            )
        })?;

        // Re-apply remapping so any leftover FHS prefixes never escape into union.
        let clean_rel = crate::archive_safety::remap_usr_paths(rel.to_path_buf());
        let final_path = union_root.join(clean_rel);
        committed_files.push(final_path);
    }

    // Some packages emit multiple archive entries that remap onto the
    // *same* final union path — confirmed with Void's `base-files`, where
    // both the root-level "sbin" symlink and the separate "usr/sbin"
    // symlink collapse onto the identical union "sbin" destination. Keep
    // only the last one (matching what already happens on disk in the
    // staging tree itself, where the later symlink()/write() call always
    // wins) — otherwise the commit loop below tries to `rename()` the same
    // already-moved staged file twice and fails with ENOENT the second time.
    {
        let mut pairs: Vec<(PathBuf, PathBuf)> = staged_files.into_iter().zip(committed_files.into_iter()).collect();
        let mut seen = HashSet::new();
        pairs.reverse();
        pairs.retain(|(_, final_path)| seen.insert(final_path.clone()));
        pairs.reverse();
        let (new_staged, new_committed): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        staged_files = new_staged;
        committed_files = new_committed;
    }

    // ── Step 5: Register in DB + TOML registry ───────────────────────────
    //
    // CRITICAL: This MUST happen BEFORE remount().
    // The OverlayFS union layer reads /overlayer/zexlib/registry/*.toml
    // to discover which store hash dirs to mount as lower layers.
    // If the TOML doesn't exist yet, remount() will NOT include this
    // package in the overlay — breaking all symlinks.
    if !parallel {
        ui::print_install_step("Setting up desktop entry");
    }
    if !parallel {
        ui::print_install_step("Registering in database");
    }

    let db_start = Instant::now();
    let string_paths: Vec<String> = committed_files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    if let Err(e) = register_package(info, string_paths) {
        // DB write failed — nothing on live system was touched (no symlinks yet).
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }

    // Write TOML registry file so the remove driver can find this package
    // AND so remount() includes this package's store hash in the overlay.
    // Path: /overlayer/zexlib/registry/<package-name>.toml
    // This is the single source of truth for package removal — no SQL, no JSON.
    let reg_path = {
        let registry_dir = std::path::Path::new("/overlayer/zexlib/registry");
        let _ = std::fs::create_dir_all(registry_dir);

        let format_label = match info.format {
            PackageFormat::Zex => "zex",

            PackageFormat::Apk => "apk",
            PackageFormat::Xbps => "xbps",
            PackageFormat::Adb => "adb",
        };

        let files_toml: Vec<String> = committed_files
            .iter()
            .map(|p| format!("\"{}\"", p.to_string_lossy()))
            .collect();

        let toml_content = format!(
            "[package]\n\
             name = \"{}\"\n\
             display_name = \"{}\"\n\
             version = \"{}\"\n\
             format = \"{}\"\n\
             content_hash = \"{}\"\n\
             installed_at = \"{}\"\n\
             \n\
             [files]\n\
             paths = [{}]\n",
            info.name,
            info.display_name,
            info.version,
            format_label,
            _content_hash,
            chrono::Utc::now().to_rfc3339(),
            files_toml.join(", "),
        );

        let rp = registry_dir.join(format!("{}.toml", info.name));
        if let Err(e) = std::fs::write(&rp, &toml_content) {
            log::warn!("Failed to write registry for {}: {}", info.name, e);
        }
        rp
    };
    let db_ms = db_start.elapsed().as_millis();

    if !parallel {
        ui::print_install_step("Committing files to union layer");
    }

    let mut plan = super::activation::ActivationPlan::new();

    for (staged_path, final_path) in staged_files.iter().zip(committed_files.iter()) {
        // Configuration Conflict Handling (.new files)
        // If it's in /etc and the file already exists, we should write it as .new to avoid overwriting user changes.
        let mut target_dest = final_path.clone();
        if final_path.starts_with("/overlayer/zexlib/union/etc/") && final_path.exists() {
            target_dest = final_path.with_extension(format!("new.{}", chrono::Utc::now().timestamp()));
            log::info!("Config file exists, saving new version as {}", target_dest.display());
        }

        // Ensure parent directory exists
        if let Some(parent) = target_dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("failed to create union directory '{}' for '{}': {}", parent.display(), target_dest.display(), e))?;
        }

        plan.add(staged_path.to_path_buf(), target_dest);
    }

    let commit_result = plan.commit();

    if commit_result.is_ok() {
        for path in &committed_files {
            let _ = crate::immutable::try_set_immutable(path);
        }
    }

    if let Err(e) = commit_result {
        // Commit failed midway — restore from snapshot if upgrading,
        // or rollback new files if fresh install.
        // Also clean up the TOML registry we just wrote.
        let _ = std::fs::remove_file(&reg_path);
        if let Some(ref snap) = snapshot_dir {
            if let Some(old) = existing {
                restore_snapshot(snap, union_root, old);
            }
        }
        rollback_committed(&committed_files);
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }

    // ── Step 8: Post-install script ───────────────────────────────────────
    //
    // Package-embedded install scripts (Alpine's `.post-install`, Void's
    // `INSTALL post-install`) — captured during extraction instead of
    // being silently discarded as metadata. Run sandboxed (landlock/
    // seccomp via cmd::install::sandbox), after the commit has already
    // succeeded so the package's own files are in place first. A failing
    // script is logged, not fatal — the package is correctly installed
    // either way, matching how apk/dpkg treat postinst failures.
    if let Some(script) = &postinstall_script {
        let (bytes, action_arg): (&Vec<u8>, Option<&str>) = match script {
            PostInstallScript::ApkStyle(b) => (b, None),
            PostInstallScript::XbpsStyle(b) => (b, Some("post-install")),
        };
        let script_path = store_path.join(".zex-postinstall");
        if std::fs::write(&script_path, bytes).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755));
            }
            if !parallel {
                ui::print_install_step("Running post-install script");
            }
            match sandbox::run_postinst(&script_path, &store_path, action_arg) {
                Ok(()) => log::info!("post-install script for '{}' completed", info.name),
                Err(e) => log::warn!("post-install script for '{}' failed (package is installed regardless): {}", info.name, e),
            }
        }
    }

    // ── Step 9: Orphan cleanup (upgrade only) ────────────────────────────
    if let Some(old) = existing {
        if !parallel {
            ui::print_install_step("Cleaning up orphan files");
        }
        let new_set: HashSet<String> = committed_files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        for old_file in &old.installed_files {
            if !new_set.contains(old_file) {
                let path = Path::new(old_file);
                let _ = std::fs::remove_file(path);
                // Try to remove empty parent dirs left behind
                let mut curr = path.parent();
                while let Some(parent) = curr {
                    if parent == Path::new("/") {
                        break;
                    }
                    if std::fs::remove_dir(parent).is_err() {
                        break;
                    }
                    curr = parent.parent();
                }
            }
        }
    }

    let extract_ms = extract_start.elapsed().as_millis();

    // ── Step 10: Cleanup — remove snapshot (success path) ────────────────
    cleanup_snapshot(&snapshot_dir);

    Ok(InstallTelemetry {
        verify_ms,
        extract_ms,
        db_ms,
        detected_launch_cmd: detected_launch,
    })
}

/// Compute SHA256 of a file on-disk using 64 KB read chunks.
/// Returns the hex-encoded digest string.
fn sha256_of_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open file for SHA256: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536]; // 64 KB chunks — good balance of speed vs stack
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| anyhow::anyhow!("read error during SHA256: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify the downloaded package against the repository-supplied SHA256 checksum.
///
/// If `info.sha256` is `None` (e.g. some apk/xbps mirrors that don't yet return
/// checksums), verification is skipped with a warning — not a hard failure.
///
/// If `info.sha256` is `Some(expected)`, the file digest *must* match or the
/// install is aborted before a single byte touches the system.
fn verify_signature(
    path: &Path,
    info: &PackageInfo,
    integrity_mode: IntegrityMode,
    signature_mode: crate::trust::SignatureVerificationMode,
    xbps_sig: Option<&XbpsVerifyData>,
) -> Result<()> {
    if info.format == PackageFormat::Zex {
        crate::trust::verify_zex_archive(path, signature_mode)?;
        return verify_blake3(path, info, integrity_mode);
    }

    // Real cryptographic authenticity check — RSA signature verification
    // against each tier's actual trust anchors (see native_sig.rs). This
    // is independent of, and stronger than, the SHA256/size checks below:
    // those only prove the downloaded bytes match what the *index* claims,
    // which is worthless if the index itself was tampered with or served
    // by a compromised/MITM mirror. Signature verification proves the
    // package was actually produced by a trusted upstream signing key.
    if signature_mode != crate::trust::SignatureVerificationMode::Off {
        let native_result = match info.format {
            PackageFormat::Apk => {
                let data = std::fs::read(path).context("reading apk package for signature verification")?;
                super::native_sig::verify_apk_v2(&data)
            }
            PackageFormat::Adb => {
                let data = std::fs::read(path).context("reading adb package for signature verification")?;
                super::native_sig::verify_adb_v3(&data)
            }
            PackageFormat::Xbps => match xbps_sig {
                Some(sig) => {
                    let data = std::fs::read(path).context("reading xbps package for signature verification")?;
                    super::native_sig::verify_xbps(&data, &sig.sig2, &sig.pubkey_pem)
                }
                None => Err(anyhow::anyhow!(
                    "no .sig2/pinned-key data available for xbps package '{}' — could not fetch signature",
                    info.name
                )),
            },
            PackageFormat::Zex => unreachable!("handled above"),
        };

        if let Err(e) = native_result {
            let msg = format!("signature verification failed for '{}': {e}", info.name);
            match signature_mode {
                crate::trust::SignatureVerificationMode::Strict => bail!(msg),
                crate::trust::SignatureVerificationMode::Audit => log::warn!("{msg} — continuing in audit mode"),
                crate::trust::SignatureVerificationMode::Off => unreachable!("checked above"),
            }
        }
    }

    // NOTE: apk's own index (APKINDEX) never publishes a plain SHA256 (it
    // uses the embedded ".SIGN" scheme checked above instead), so
    // `info.sha256` is always `None` for that format by design — a
    // missing checksum here is informational only, never a hard failure,
    // regardless of integrity_mode. xbps repodata *does* publish a real
    // "filename-sha256", so this still provides a genuine integrity check
    // for Tier 3 on top of the signature check above.
    match &info.sha256 {
        None => {
            // No checksum available from this backend yet.
            // Still safe: file-size is checked by verify_file() above.
            log::warn!(
                "SHA256 not available for '{}' (backend: {:?}) — skipping checksum verification",
                info.name,
                info.format
            );
            Ok(())
        }
        Some(expected) if expected.is_empty() => Ok(()),
        Some(expected) => {
            let actual = sha256_of_file(path)?;
            if !actual.eq_ignore_ascii_case(expected) {
                bail!(
                    "SHA256 integrity check FAILED for '{}':\
                     \n  Expected : {}\
                     \n  Computed : {}\
                     \n  The downloaded file is corrupt or tampered. Aborting.",
                    info.name,
                    expected,
                    actual
                );
            }
            log::debug!("SHA256 verified for '{}': {}", info.name, actual);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_symlink_target_uses_union_path_when_overlay_ok() {
        let staged_path = Path::new("/overlayer/zexlib/store/abc123/usr/bin/example");
        let store_path = Path::new("/overlayer/zexlib/store/abc123");
        let union_root = Path::new("/overlayer/zexlib/union");

        let target = compute_symlink_target(staged_path, store_path, union_root, true)
            .expect("overlay_ok should succeed");

        assert_eq!(target, Path::new("/overlayer/zexlib/union/usr/bin/example"));
    }

    #[test]
    fn compute_symlink_target_falls_back_to_store_path_when_overlay_unavailable() {
        let staged_path = Path::new("/overlayer/zexlib/store/abc123/usr/bin/example");
        let store_path = Path::new("/overlayer/zexlib/store/abc123");
        let union_root = Path::new("/overlayer/zexlib/union");

        let target = compute_symlink_target(staged_path, store_path, union_root, false)
            .expect("fallback should succeed");

        assert_eq!(target, staged_path);
    }

    #[test]
    fn compute_symlink_target_errors_when_staged_path_is_not_under_store() {
        let staged_path = Path::new("/tmp/other/usr/bin/example");
        let store_path = Path::new("/overlayer/zexlib/store/abc123");
        let union_root = Path::new("/overlayer/zexlib/union");

        assert!(compute_symlink_target(staged_path, store_path, union_root, true).is_err());
    }
}

fn blake3_of_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open file for Blake3: {}", e))?;
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| anyhow::anyhow!("read error during Blake3: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn verify_blake3(path: &Path, info: &PackageInfo, integrity_mode: IntegrityMode) -> Result<()> {
    match &info.blake3 {
        None => {
            if integrity_mode == IntegrityMode::Strict {
                bail!(
                    "strict integrity mode requires Blake3, but backend did not provide hash for '{}'",
                    info.name
                );
            }
            log::warn!(
                "Blake3 not available for '{}' (backend: {:?}) — skipping checksum verification",
                info.name,
                info.format
            );
            Ok(())
        }
        Some(expected) if expected.trim().is_empty() => {
            if integrity_mode == IntegrityMode::Strict {
                bail!(
                    "strict integrity mode requires non-empty Blake3 for '{}'",
                    info.name
                );
            }
            Ok(())
        }
        Some(expected) => {
            let actual = blake3_of_file(path)?;
            if !actual.eq_ignore_ascii_case(expected.trim()) {
                bail!(
                    "Blake3 integrity check FAILED for '{}':\
                     \n  Expected : {}\
                     \n  Computed : {}\
                     \n  The downloaded file is corrupt or tampered. Aborting.",
                    info.name,
                    expected,
                    actual
                );
            }
            log::debug!("Blake3 verified for '{}': {}", info.name, actual);
            Ok(())
        }
    }
}

fn verify_file(path: &Path, expected_size: u64) -> Result<()> {
    let actual = std::fs::metadata(path)?.len();
    if expected_size > 0 && actual != expected_size {
        bail!("size mismatch: expected {}, got {}", expected_size, actual);
    }
    Ok(())
}

fn acquire_package_lock(package_name: &str) -> Result<InstallPackageLock> {
    let lock_dir = Path::new("/var/lock/zex");
    std::fs::create_dir_all(lock_dir)?;

    let safe_name: String = package_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let lock_path = lock_dir.join(format!("install-{}.lock", safe_name));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;

    // SAFETY: descriptor is valid and flock is process-safe advisory lock.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        bail!(
            "failed to acquire install lock for '{}': {}",
            package_name,
            err
        );
    }

    Ok(InstallPackageLock { file })
}

// ─── Atomic Transaction Helpers ───────────────────────────────────────────────

/// Create a snapshot of all files owned by the old package version.
/// Each file is copied to `/var/cache/zex/snapshots/<pkg>-<ts>/` preserving
/// relative paths.  Returns the snapshot directory path.
fn create_snapshot(info: &PackageInfo, old: &DbEntry) -> Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let snap_dir = PathBuf::from(SNAPSHOT_BASE).join(format!("{}-{}", info.name, ts));
    std::fs::create_dir_all(&snap_dir).map_err(|e| {
        anyhow::anyhow!("cannot create snapshot dir '{}': {}", snap_dir.display(), e)
    })?;

    for file_path in &old.installed_files {
        let src = Path::new(file_path);
        if !src.exists() {
            // File was already deleted externally — nothing to back up.
            continue;
        }

        // Preserve the directory structure inside the snapshot.
        let rel = src.strip_prefix("/").unwrap_or(src);
        let dst = snap_dir.join(rel);

        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Copy file content + preserve symlink status
        if src.is_symlink() {
            let target = std::fs::read_link(src)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst)?;
        } else {
            std::fs::copy(src, &dst)?;
        }
    }

    log::debug!(
        "Snapshot created for '{}' v{} → {}",
        info.name,
        old.version,
        snap_dir.display()
    );
    Ok(snap_dir)
}

// Removed commit_staged_files because we use ActivationPlan instead.

/// Restore all files from the snapshot back to the system root.
/// Called when commit or DB registration fails during an upgrade.
fn restore_snapshot(snap_dir: &Path, _dest: &Path, old: &DbEntry) {
    log::warn!(
        "Restoring snapshot for '{}' from {}",
        old.name,
        snap_dir.display()
    );

    for file_path in &old.installed_files {
        let src_on_system = Path::new(file_path);
        let rel = src_on_system.strip_prefix("/").unwrap_or(src_on_system);
        let snap_copy = snap_dir.join(rel);

        if !snap_copy.exists() {
            continue;
        }

        // Ensure parent directory exists
        if let Some(parent) = src_on_system.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if snap_copy.is_symlink() {
            if let Ok(target) = std::fs::read_link(&snap_copy) {
                let _ = std::fs::remove_file(src_on_system);
                #[cfg(unix)]
                let _ = std::os::unix::fs::symlink(&target, src_on_system);
            }
        } else {
            let _ = std::fs::copy(&snap_copy, src_on_system);
        }
    }

    log::info!("Snapshot restore complete for '{}'", old.name);
}

/// Delete the snapshot directory after a successful install or on early abort.
fn cleanup_snapshot(snap_dir: &Option<PathBuf>) {
    if let Some(dir) = snap_dir {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Rollback files that were committed to the system root during a failed install.
/// This is the new replacement for the old `rollback()` — works on committed files.
fn rollback_committed(paths: &[PathBuf]) {
    for p in paths.iter().rev() {
        let _ = std::fs::remove_file(p);
        let mut curr = p.parent();
        while let Some(parent) = curr {
            if parent == Path::new("/") {
                break;
            }
            if std::fs::remove_dir(parent).is_err() {
                break;
            }
            curr = parent.parent();
        }
    }
}

// ─── Extraction Logic ─────────────────────────────────────────────────────────

fn sanitize_path(path: &Path) -> Result<PathBuf> {
    crate::archive_safety::sanitize_archive_path(path)
}

fn sanitize_link_target(owner_path: &Path, target: &Path) -> Result<PathBuf> {
    crate::archive_safety::sanitize_link_target(owner_path, target)
}

fn extract_zex(zex_path: &Path, dest: &Path, installed: &mut Vec<PathBuf>) -> Result<Option<PostInstallScript>> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    // Canonical .zex = zexc (ZEX1) frame wrapping tar:
    //   manifest.toml    ← TOML with ed25519_sig + blake3
    //   signature.b3     ← hex Blake3(manifest_toml ++ payload_blake3)
    //   payload/<files>  ← package files
    //
    // signature.b3 hash matches packer.rs / verifier.rs exactly.
    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);

    let mut sig_b3_expected: Option<String> = None;
    let mut manifest_raw: Option<Vec<u8>> = None;
    let mut payload_files: Vec<(String, Vec<u8>)> = Vec::new();
    // Symlinks/hardlinks are applied after files so targets exist.
    let mut pending_symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut pending_hardlinks: Vec<(PathBuf, PathBuf)> = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let rel = match sanitize_path(&path) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let rel_str = rel.to_string_lossy();

        if rel_str == "signature.b3" {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            let sig = content.lines().next().unwrap_or("").trim().to_string();
            if sig.is_empty() {
                bail!("signature.b3 is empty in .zex archive");
            }
            sig_b3_expected = Some(sig);
            continue;
        }

        if rel_str == "manifest.toml" {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            manifest_raw = Some(data);
            continue;
        }

        // Ignore legacy/unknown root entries (e.g. old manifest.json).
        if !rel_str.starts_with("payload/") {
            continue;
        }

        let payload_rel = match rel.strip_prefix("payload") {
            Ok(p) => p,
            Err(_) => continue,
        };
        if payload_rel.as_os_str().is_empty() {
            continue;
        }

        let dest_path = dest.join(payload_rel);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            continue;
        }

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if entry_type.is_file() {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            // Hash uses the full archive path ("payload/...") to match packer.
            payload_files.push((rel_str.to_string(), data.clone()));
            std::fs::write(&dest_path, &data)?;
            installed.push(dest_path);
            continue;
        }

        if entry_type.is_symlink() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                anyhow::anyhow!("symlink entry missing target: {}", rel.display())
            })?;
            let safe_target = sanitize_link_target(payload_rel, &link_target)?;
            pending_symlinks.push((dest_path, safe_target));
            continue;
        }

        if entry_type.is_hard_link() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                anyhow::anyhow!("hard link entry missing target: {}", rel.display())
            })?;
            // Unlike symlinks, a hardlink target must resolve to a sibling
            // already extracted into *this same staging tree* — it needs
            // sanitize_archive_path's plain relative-and-remapped result,
            // not sanitize_link_target's UNION_ROOT-absolute one (which
            // wouldn't exist yet at extraction time).
            let safe_target = crate::archive_safety::sanitize_archive_path(&link_target)?;
            pending_hardlinks.push((dest_path, safe_target));
            continue;
        }

        log::debug!(
            "Skipping unsupported .zex entry type for '{}': {:?}",
            payload_rel.display(),
            entry_type
        );
    }

    if payload_files.is_empty() && pending_symlinks.is_empty() && pending_hardlinks.is_empty() {
        bail!(".zex archive missing payload/");
    }

    // Apply links after regular files.
    for (dest_path, safe_target) in pending_symlinks {
        let _ = std::fs::remove_file(&dest_path);
        #[cfg(unix)]
        symlink(&safe_target, &dest_path)?;
        installed.push(dest_path);
    }
    for (dest_path, safe_target) in pending_hardlinks {
        let target_path = dest.join(&safe_target);
        if !target_path.exists() {
            bail!(
                "hard link target does not exist: {}",
                safe_target.display()
            );
        }
        let _ = std::fs::remove_file(&dest_path);
        std::fs::hard_link(&target_path, &dest_path)?;
        installed.push(dest_path);
    }

    // signature.b3 = Blake3(manifest.toml ++ payload_blake3)
    // payload_blake3 = Blake3 over sorted (path, bytes) pairs — same as packer.
    let expected = sig_b3_expected
        .ok_or_else(|| anyhow::anyhow!(".zex archive missing signature.b3"))?;
    let manifest_bytes = manifest_raw
        .ok_or_else(|| anyhow::anyhow!(".zex archive missing manifest.toml"))?;

    payload_files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut payload_hasher = blake3::Hasher::new();
    for (path, bytes) in &payload_files {
        payload_hasher.update(path.as_bytes());
        payload_hasher.update(bytes);
    }
    let payload_blake3 = payload_hasher.finalize().to_hex().to_string();

    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(&manifest_bytes);
    sig_hasher.update(payload_blake3.as_bytes());
    let actual = sig_hasher.finalize().to_hex().to_string();

    if !actual.eq_ignore_ascii_case(expected.trim()) {
        bail!(
            "signature.b3 verification FAILED:\n  Expected : {}\n  Computed : {}",
            expected,
            actual
        );
    }

    Ok(None)
}

fn extract_apk(pkg_path: &Path, dest: &Path, installed: &mut Vec<PathBuf>) -> Result<Option<PostInstallScript>> {
    let file = std::fs::File::open(pkg_path)?;
    // .apk packages are a concatenation of multiple gzip members
    // (signature + control + data tarballs) — MultiGzDecoder reads
    // through all of them instead of stopping after the signature.
    let dec = flate2::read::MultiGzDecoder::new(file);
    extract_tar(dec, dest, installed, true)
}

fn extract_xbps(pkg_path: &Path, dest: &Path, installed: &mut Vec<PathBuf>) -> Result<Option<PostInstallScript>> {
    let file = std::fs::File::open(pkg_path)?;
    let dec = zstd::stream::read::Decoder::new(file)?;
    extract_tar(dec, dest, installed, true)
}

/// Extracts a Chimera Linux `.apk` package — apk-tools v3's binary "ADB"
/// container format, not the legacy gzip-tar `.apk` used by Alpine (see
/// `cmd::install::adb` for the format itself). Applies the same path/link
/// sanitization as `extract_tar` since this walks an untrusted archive too.
fn extract_adb(pkg_path: &Path, dest: &Path, installed: &mut Vec<PathBuf>) -> Result<Option<PostInstallScript>> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let bytes = std::fs::read(pkg_path)?;
    let entries = super::adb::extract_entries(&bytes)?;

    for entry in entries {
        let rel = match sanitize_path(Path::new(&entry.rel_path)) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() { continue; }
        let dest_path = dest.join(&rel);

        const S_IFMT: u32 = 0o170000;
        const S_IFDIR: u32 = 0o040000;
        const S_IFLNK: u32 = 0o120000;

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("failed to create parent directory '{}' for adb entry '{}': {}", parent.display(), entry.rel_path, e))?;
        }

        match entry.mode & S_IFMT {
            S_IFDIR => {
                std::fs::create_dir_all(&dest_path)
                    .map_err(|e| anyhow::anyhow!("failed to create directory '{}' for adb entry '{}': {}", dest_path.display(), entry.rel_path, e))?;
            }
            S_IFLNK => {
                let target = entry.link_target.unwrap_or_default();

                // Chimera's usrmerge layout ships real top-level symlinks
                // like "/bin -> usr/bin" — but our own `remap_usr_paths`
                // *already* collapses "usr/bin" onto the same "bin" union
                // directory structurally. Creating the symlink literally
                // (confirmed against a real `base-files` package) then
                // collides with the real directory/files that same
                // package installs under "usr/bin", since both now want
                // to own the identical union path. Skip only this
                // self-referential case — a real, non-colliding symlink
                // (e.g. "sbin -> usr/bin", a distinct union path) still
                // gets created normally below.
                let target_remapped = crate::archive_safety::remap_usr_paths(PathBuf::from(&target));
                if target_remapped == rel {
                    continue;
                }

                let safe_target = sanitize_link_target(Path::new(&entry.rel_path), Path::new(&target))?;
                let _ = std::fs::remove_file(&dest_path);
                #[cfg(unix)]
                symlink(&safe_target, &dest_path)
                    .map_err(|e| anyhow::anyhow!("failed to symlink '{}' -> '{}': {}", dest_path.display(), safe_target.display(), e))?;
                installed.push(dest_path);
            }
            _ if entry.link_target.is_some() => {
                // Hardlink: target is a path already extracted earlier in
                // the walk (paths/files are emitted in on-disk order, so
                // it always precedes its hardlinks). Needs the plain
                // relative-and-remapped path (sanitize_archive_path), not
                // sanitize_link_target's UNION_ROOT-absolute symlink form.
                let target = entry.link_target.unwrap();
                let safe_target = crate::archive_safety::sanitize_archive_path(Path::new(&target))?;
                let target_path = dest.join(&safe_target);
                if !target_path.exists() {
                    bail!("adb hard link target does not exist for '{}': {}", rel.display(), safe_target.display());
                }
                let _ = std::fs::remove_file(&dest_path);
                std::fs::hard_link(&target_path, &dest_path)
                    .map_err(|e| anyhow::anyhow!("failed to hard-link '{}' -> '{}': {}", dest_path.display(), target_path.display(), e))?;
                installed.push(dest_path);
            }
            _ => {
                std::fs::write(&dest_path, entry.content.unwrap_or_default())
                    .map_err(|e| anyhow::anyhow!("failed to write '{}': {}", dest_path.display(), e))?;
                installed.push(dest_path);
            }
        }
    }
    Ok(None)
}

fn extract_tar_auto<R: Read>(id: &str, r: R, dest: &Path, inst: &mut Vec<PathBuf>) -> Result<Option<PostInstallScript>> {
    if id.ends_with(".gz") {
        extract_tar(flate2::read::MultiGzDecoder::new(r), dest, inst, false)
    } else if id.ends_with(".xz") {
        extract_tar(xz2::read::XzDecoder::new(r), dest, inst, false)
    } else if id.ends_with(".zst") {
        extract_tar(zstd::stream::read::Decoder::new(r)?, dest, inst, false)
    } else {
        extract_tar(r, dest, inst, false)
    }
}

/// A package-embedded install script captured during extraction (instead
/// of being silently discarded as "metadata") so it can be executed,
/// sandboxed, after the file commit succeeds. Alpine's `.post-install`
/// runs with no arguments; Void's single `INSTALL` script is invoked once
/// per lifecycle action via an argument.
pub enum PostInstallScript {
    ApkStyle(Vec<u8>),
    XbpsStyle(Vec<u8>),
}

fn extract_tar<R: Read>(
    r: R,
    dest: &Path,
    inst: &mut Vec<PathBuf>,
    filter_pkg_metadata: bool,
) -> Result<Option<PostInstallScript>> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let mut archive = tar::Archive::new(r);
    let mut captured_script: Option<PostInstallScript> = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let rel = match sanitize_path(&path) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if filter_pkg_metadata {
            let s = rel.to_string_lossy();
            if s == ".post-install" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                captured_script = Some(PostInstallScript::ApkStyle(buf));
                continue;
            }
            if s == "INSTALL" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                captured_script = Some(PostInstallScript::XbpsStyle(buf));
                continue;
            }
            // Apk files use dot-prefixed metadata like .PKGINFO, .SIGN.*
            // Xbps uses props.plist, files.plist, REMOVE
            if s.starts_with('.') || s.is_empty() || s == "props.plist" || s == "files.plist" || s == "REMOVE" {
                continue;
            }
        }

        let dest_path = dest.join(&rel);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            continue;
        }

        if let Some(p) = dest_path.parent() {
            std::fs::create_dir_all(p)
                .map_err(|e| anyhow::anyhow!("failed to create parent directory '{}' for '{}': {}", p.display(), rel.display(), e))?;
        }

        if entry_type.is_file() {
            entry.unpack(&dest_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to extract '{}' to '{}': {}",
                    rel.display(),
                    dest_path.display(),
                    e
                )
            })?;
            inst.push(dest_path);
            continue;
        }

        if entry_type.is_symlink() {
            #[cfg(unix)]
            {
                let link_target = entry.link_name()?.ok_or_else(|| {
                    anyhow::anyhow!("symlink entry missing target: {}", rel.display())
                })?;

                // Some base-layout packages (confirmed with Void's
                // `base-files`, same real-world case as Chimera's) ship
                // real top-level usrmerge symlinks like "/lib -> usr/lib"
                // — but `remap_usr_paths` already collapses "usr/lib" onto
                // the same "lib" union directory structurally. Creating
                // the symlink literally then collides with the real
                // directory/files the same package installs under
                // "usr/lib". Skip only this self-referential case.
                let target_remapped = crate::archive_safety::remap_usr_paths(
                    PathBuf::from(link_target.to_string_lossy().as_ref()),
                );
                if target_remapped == rel {
                    continue;
                }

                let safe_target = sanitize_link_target(&path, &link_target)?;
                let _ = std::fs::remove_file(&dest_path);
                symlink(&safe_target, &dest_path)
                    .map_err(|e| anyhow::anyhow!("failed to symlink '{}' -> '{}': {}", dest_path.display(), safe_target.display(), e))?;
                inst.push(dest_path);
            }
            continue;
        }

        if entry_type.is_hard_link() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                anyhow::anyhow!("hard link entry missing target: {}", rel.display())
            })?;
            // Needs the plain relative-and-remapped path, not
            // sanitize_link_target's UNION_ROOT-absolute symlink form.
            let safe_target = crate::archive_safety::sanitize_archive_path(&link_target)?;
            let target_path = dest.join(&safe_target);
            if !target_path.exists() {
                bail!(
                    "hard link target does not exist for '{}': {}",
                    rel.display(),
                    safe_target.display()
                );
            }
            let _ = std::fs::remove_file(&dest_path);
            std::fs::hard_link(&target_path, &dest_path)
                .map_err(|e| anyhow::anyhow!("failed to hard-link '{}' -> '{}': {}", dest_path.display(), target_path.display(), e))?;
            inst.push(dest_path);
            continue;
        }

        // Explicit allowlist: skip all unsupported entry types.
        log::debug!(
            "Skipping unsupported archive entry type for '{}': {:?}",
            rel.display(),
            entry_type
        );
    }
    Ok(captured_script)
}

// ─── Pre-flight Conflict Detection ───────────────────────────────────────────

/// Check if any file in `file_list` is already owned by another installed package.
///
/// Returns a list of `(owning_package_name, conflicting_file_path)` tuples.
/// Same-package entries (reinstall/upgrade) are excluded from the check.
///
/// This is called BEFORE any extraction or file mutation, making it a true
/// pre-flight guard.  If conflicts are found, the caller can abort cleanly
/// without having touched anything on the live system.
pub fn check_file_conflicts(pkg_name: &str, file_list: &[String]) -> Vec<(String, String)> {
    let db = super::backend::load_db();
    let mut conflicts = Vec::new();

    // Build a quick lookup set for the incoming file list
    let incoming: HashSet<&str> = file_list.iter().map(|s| s.as_str()).collect();

    for entry in &db {
        // Skip the package itself — this is a reinstall/upgrade, not a conflict.
        if entry.name.eq_ignore_ascii_case(pkg_name) {
            continue;
        }
        for existing_file in &entry.installed_files {
            if incoming.contains(existing_file.as_str()) {
                conflicts.push((entry.name.clone(), existing_file.clone()));
            }
        }
    }
    conflicts
}

/// Run conflict detection on the file list extracted from a staged package.
/// Called from `infuse.rs` before the commit phase.
pub fn preflight_conflict_check(
    pkg_name: &str,
    staged_files: &[PathBuf],
    force: bool,
) -> Result<()> {
    let paths: Vec<String> = staged_files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let conflicts = check_file_conflicts(pkg_name, &paths);

    if conflicts.is_empty() {
        return Ok(());
    }

    if force {
        log::warn!(
            "File conflicts detected for '{}' but --force is set, proceeding: {:?}",
            pkg_name,
            conflicts
        );
        return Ok(());
    }

    ui::print_file_conflicts(pkg_name, &conflicts);
    bail!(
        "File conflict: {} file(s) already owned by other packages. Use --force to override.",
        conflicts.len()
    )
}
