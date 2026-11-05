//! installer.rs: Atomic package extractor with snapshot-based rollback.

use std::collections::HashSet;
use std::io::{Read, Seek};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use super::backend::{DbEntry, PackageFormat, PackageInfo, register_package};
use super::sandbox;
use super::ui;

/// Set by `zex install --force`: file conflicts overwrite instead of aborting.
static FORCE: AtomicBool = AtomicBool::new(false);

pub fn set_force(on: bool) {
    FORCE.store(on, Ordering::Relaxed);
}

/// Set by `zex reinstall`: installed packages are fetched again and reinstalled, even unchanged.
static REINSTALL: AtomicBool = AtomicBool::new(false);

pub fn set_reinstall(on: bool) {
    REINSTALL.store(on, Ordering::Relaxed);
}

pub fn reinstalling() -> bool {
    REINSTALL.load(Ordering::Relaxed)
}

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
    /// Set when this call was a no-op because the dependency's files are
    /// already fully provided by syshub under a different package name
    /// (e.g. Void's `ncurses-libs` vs syshub's `ncurses`): nothing was
    /// staged, registered, or committed.
    pub skipped_syshub_satisfied: bool,
    /// Libraries the package links against that neither it nor the system provides.
    pub missing_libs: Vec<String>,
    /// Nothing was installed because of `missing_libs` (see `allow_missing_libs`).
    pub held_back: bool,
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

const SNAPSHOT_BASE: &str = "/overlayer/syshub/var/cache/zex/snapshots";

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

#[cfg(test)]
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
/// Pipeline order (CRITICAL: do not reorder):
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
/// fully synchronous install pipeline runs: xbps is the one format whose
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
    is_dependency: bool,
    allow_missing_libs: bool,
) -> Result<InstallTelemetry> {
    let _pkg_lock = acquire_package_lock(&info.name)?;
    let steps = (!parallel).then(crate::steps::Guard::new);

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

    let snapshot_dir = if let Some(old) = existing {
        if !parallel {
            ui::print_install_step("Snapshotting previous version");
        }
        let dir = create_snapshot(info, old)?;
        Some(dir)
    } else {
        None
    };

    if !parallel {
        ui::print_install_step("Extracting to Content Store");
    }

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
            cleanup_snapshot(&snapshot_dir);
            return Err(e);
        }
    };

    let detected_launch = detect_launch_cmd(&staged_files, &store_path);

    staged_files.retain(|staged| {
        let generated = staged.strip_prefix(&store_path).is_ok_and(|rel| {
            super::generated::is_generated(&crate::archive_safety::remap_usr_paths(
                rel.to_path_buf(),
            ))
        });
        if generated {
            let _ = std::fs::remove_file(staged);
        }
        !generated
    });

    if let Err(e) = super::elfpatch::patch_staged_elfs(&staged_files) {
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }
    if let Err(e) =
        super::pcpatch::patch_staged_pkgconfig(&staged_files, crate::archive_safety::UNION_ROOT)
    {
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }
    if let Err(e) = super::shebangpatch::patch_staged_scripts(&staged_files) {
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }
    super::libcheck::add_soname_links(&mut staged_files);

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

        let clean_rel = crate::archive_safety::remap_usr_paths(rel.to_path_buf());
        let final_path = union_root.join(clean_rel);
        committed_files.push(final_path);
    }

    {
        let mut pairs: Vec<(PathBuf, PathBuf)> = staged_files
            .into_iter()
            .zip(committed_files.into_iter())
            .collect();
        let mut seen = HashSet::new();
        pairs.reverse();
        pairs.retain(|(_, final_path)| seen.insert(final_path.clone()));
        pairs.reverse();
        let (new_staged, new_committed): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        staged_files = new_staged;
        committed_files = new_committed;
    }

    let missing_libs = super::libcheck::missing_libraries(&staged_files);
    if !missing_libs.is_empty() && !allow_missing_libs {
        cleanup_snapshot(&snapshot_dir);
        steps.map(crate::steps::Guard::ok);
        return Ok(InstallTelemetry {
            missing_libs,
            held_back: true,
            ..Default::default()
        });
    }

    let base_owned: HashSet<String> = check_file_conflicts(&info.name, &committed_files)
        .into_iter()
        .filter(|(owner, _)| owner == BASE_OWNER)
        .map(|(_, path)| path)
        .collect();
    if !base_owned.is_empty() {
        let pairs: Vec<(PathBuf, PathBuf)> = staged_files
            .into_iter()
            .zip(committed_files.into_iter())
            .filter(|(_, final_path)| !base_owned.contains(final_path.to_string_lossy().as_ref()))
            .collect();
        let (new_staged, new_committed): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        staged_files = new_staged;
        committed_files = new_committed;

        if committed_files.is_empty() {
            cleanup_snapshot(&snapshot_dir);
            if !is_dependency {
                bail!("'{}' is already provided by the base OS.", info.name);
            }
            steps.map(crate::steps::Guard::ok);
            return Ok(InstallTelemetry {
                skipped_syshub_satisfied: true,
                ..Default::default()
            });
        }
        if !is_dependency && !parallel {
            crate::steps::finish();
            let mut kept: Vec<&String> = base_owned.iter().collect();
            kept.sort();
            ui::print_base_files_kept(&info.name, &kept);
        }
    }

    if let Err(e) = preflight_conflict_check(&info.name, &committed_files) {
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }

    if info.format == PackageFormat::Xbps {
        if !parallel {
            ui::print_install_step("Updating alternatives");
        }
        match stage_xbps_alternatives(pkg_path, &store_path, union_root, &committed_files) {
            Ok(links) => {
                for (staged, final_path) in links {
                    staged_files.push(staged);
                    committed_files.push(final_path);
                }
            }
            Err(e) => log::warn!("'{}': alternatives not applied: {e:#}", info.name),
        }
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
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }
    let db_ms = db_start.elapsed().as_millis();

    if !parallel {
        ui::print_install_step("Committing files to union layer");
    }

    let mut plan = super::activation::ActivationPlan::new();

    for (staged_path, final_path) in staged_files.iter().zip(committed_files.iter()) {
        let mut target_dest = final_path.clone();
        if final_path.starts_with("/overlayer/zexlib/union/etc/") && final_path.exists() {
            target_dest =
                final_path.with_extension(format!("new.{}", chrono::Utc::now().timestamp()));
            log::info!(
                "Config file exists, saving new version as {}",
                target_dest.display()
            );
        }

        let live_dest = crate::archive_safety::live_path(&target_dest);
        if let Some(parent) = live_dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "failed to create directory '{}' for '{}': {}",
                    parent.display(),
                    live_dest.display(),
                    e
                )
            })?;
        }

        plan.add(staged_path.to_path_buf(), live_dest);
    }

    let commit_result = plan.commit();

    if commit_result.is_ok() {
        crate::triggers::note(&committed_files);
        crate::triggers::note_installed(&info.name);
        if info.format == PackageFormat::Zex {
            if let Ok(m) = super::zex_manifest::read_from_zex(pkg_path) {
                if let Some(cmd) = m.hooks.post_install.as_deref() {
                    crate::triggers::note_hook(&info.name, cmd);
                }
            }
        }
    }

    if let Err(e) = commit_result {
        if existing.is_some() {
            log::warn!(
                "'{}' upgrade failed after the registry was already updated — it may still describe the new version even though files were rolled back to the old one",
                info.name
            );
        } else {
            let _ = super::registry::unregister(&info.name);
        }
        if let Some(ref snap) = snapshot_dir {
            if let Some(old) = existing {
                restore_snapshot(snap, union_root, old);
            }
        }
        rollback_committed(&committed_files);
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }

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
                let _ =
                    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755));
            }
            if !parallel {
                ui::print_install_step("Running post-install script");
            }
            match sandbox::run_postinst(&script_path, &store_path, action_arg) {
                Ok(()) => log::info!("post-install script for '{}' completed", info.name),
                Err(e) => log::warn!(
                    "post-install script for '{}' failed (package is installed regardless): {}",
                    info.name,
                    e
                ),
            }
        }
    }

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

    cleanup_snapshot(&snapshot_dir);

    if !parallel {
        ui::print_install_step("Setting up desktop entry");
        crate::triggers::flush();
    }

    steps.map(crate::steps::Guard::ok);
    Ok(InstallTelemetry {
        verify_ms,
        extract_ms,
        db_ms,
        detected_launch_cmd: detected_launch,
        skipped_syshub_satisfied: false,
        missing_libs,
        held_back: false,
    })
}

/// Compute SHA256 of a file on-disk using 64 KB read chunks.
/// Returns the hex-encoded digest string.
fn sha256_of_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open file for SHA256: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
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
/// checksums), verification is skipped with a warning: not a hard failure.
///
/// If `info.sha256` is `Some(expected)`, the file digest *must* match or the
/// install is aborted before a single byte touches the system.
fn verify_signature(
    path: &Path,
    info: &PackageInfo,
    _integrity_mode: IntegrityMode,
    signature_mode: crate::trust::SignatureVerificationMode,
    xbps_sig: Option<&XbpsVerifyData>,
) -> Result<()> {
    if info.format == PackageFormat::Zex {
        return crate::trust::verify_zex_archive(path, signature_mode);
    }

    if signature_mode != crate::trust::SignatureVerificationMode::Off {
        let native_result = match info.format {
            PackageFormat::Apk => {
                let data = std::fs::read(path)
                    .context("reading apk package for signature verification")?;
                super::native_sig::verify_apk_v2(&data)
            }
            PackageFormat::Adb => {
                let data = std::fs::read(path)
                    .context("reading adb package for signature verification")?;
                super::native_sig::verify_adb_v3(&data)
            }
            PackageFormat::Xbps => match xbps_sig {
                Some(sig) => {
                    let data = std::fs::read(path)
                        .context("reading xbps package for signature verification")?;
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
                crate::trust::SignatureVerificationMode::Audit => {
                    log::warn!("{msg} — continuing in audit mode")
                }
                crate::trust::SignatureVerificationMode::Off => unreachable!("checked above"),
            }
        }
    }

    match &info.sha256 {
        None => {
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

fn verify_file(path: &Path, expected_size: u64) -> Result<()> {
    let actual = std::fs::metadata(path)?.len();
    if expected_size > 0 && actual != expected_size {
        bail!("size mismatch: expected {}, got {}", expected_size, actual);
    }
    Ok(())
}

fn acquire_package_lock(package_name: &str) -> Result<InstallPackageLock> {
    let lock_dir = Path::new("/run/lock/zex");
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
            continue;
        }

        let rel = src.strip_prefix("/").unwrap_or(src);
        let dst = snap_dir.join(rel);

        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }

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

/// Restore all files from the snapshot back to the system root.
/// Called when commit or DB registration fails during an upgrade.
fn restore_snapshot(snap_dir: &Path, _dest: &Path, old: &DbEntry) {
    log::warn!(
        "Restoring snapshot for '{}' from {}",
        old.name,
        snap_dir.display()
    );

    for file_path in &old.installed_files {
        let live = crate::archive_safety::live_path(Path::new(file_path));
        let src_on_system = live.as_path();
        let rel = Path::new(file_path)
            .strip_prefix("/")
            .unwrap_or(Path::new(file_path));
        let snap_copy = snap_dir.join(rel);

        if !snap_copy.exists() {
            continue;
        }

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
/// This is the new replacement for the old `rollback()`: works on committed files.
fn rollback_committed(paths: &[PathBuf]) {
    for p in paths.iter().rev() {
        let p = crate::archive_safety::live_path(p);
        let _ = crate::immutable::try_clear_immutable(&p);
        let _ = std::fs::remove_file(&p);
        let mut curr = p.parent();
        while let Some(parent) = curr {
            if parent == Path::new("/") || parent == Path::new(crate::archive_safety::LIVE_ROOT) {
                break;
            }
            if std::fs::remove_dir(parent).is_err() {
                break;
            }
            curr = parent.parent();
        }
    }
}

fn sanitize_path(path: &Path) -> Result<PathBuf> {
    crate::archive_safety::sanitize_archive_path(path)
}

fn sanitize_link_target(owner_path: &Path, target: &Path) -> Result<PathBuf> {
    crate::archive_safety::sanitize_link_target(owner_path, target)
}

fn extract_zex(
    zex_path: &Path,
    dest: &Path,
    installed: &mut Vec<PathBuf>,
) -> Result<Option<PostInstallScript>> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);

    let mut sig_b3_expected: Option<String> = None;
    let mut manifest_raw: Option<Vec<u8>> = None;
    let mut payload_files: Vec<(String, Vec<u8>, Option<String>)> = Vec::new();
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
            let mode = entry.header().mode().unwrap_or(0o644);
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            payload_files.push((rel_str.to_string(), data.clone(), None));
            std::fs::write(&dest_path, &data)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &dest_path,
                    std::fs::Permissions::from_mode(mode & 0o7777),
                )?;
            }
            installed.push(dest_path);
            continue;
        }

        if entry_type.is_symlink() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                anyhow::anyhow!("symlink entry missing target: {}", rel.display())
            })?;
            payload_files.push((
                rel_str.to_string(),
                Vec::new(),
                Some(link_target.to_string_lossy().to_string()),
            ));
            let safe_target = sanitize_link_target(payload_rel, &link_target)?;
            pending_symlinks.push((dest_path, safe_target));
            continue;
        }

        if entry_type.is_hard_link() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                anyhow::anyhow!("hard link entry missing target: {}", rel.display())
            })?;
            payload_files.push((rel_str.to_string(), Vec::new(), None));
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

    for (dest_path, safe_target) in pending_symlinks {
        let _ = std::fs::remove_file(&dest_path);
        #[cfg(unix)]
        symlink(&safe_target, &dest_path)?;
        installed.push(dest_path);
    }
    for (dest_path, safe_target) in pending_hardlinks {
        let target_path = dest.join(&safe_target);
        if !target_path.exists() {
            bail!("hard link target does not exist: {}", safe_target.display());
        }
        let _ = std::fs::remove_file(&dest_path);
        std::fs::hard_link(&target_path, &dest_path)?;
        installed.push(dest_path);
    }

    let expected =
        sig_b3_expected.ok_or_else(|| anyhow::anyhow!(".zex archive missing signature.b3"))?;
    let manifest_bytes =
        manifest_raw.ok_or_else(|| anyhow::anyhow!(".zex archive missing manifest.toml"))?;

    payload_files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut payload_hasher = blake3::Hasher::new();
    for (path, bytes, target) in &payload_files {
        payload_hasher.update(path.as_bytes());
        match target {
            Some(t) => payload_hasher.update(t.as_bytes()),
            None => payload_hasher.update(bytes),
        };
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

fn extract_apk(
    pkg_path: &Path,
    dest: &Path,
    installed: &mut Vec<PathBuf>,
) -> Result<Option<PostInstallScript>> {
    let file = std::fs::File::open(pkg_path)?;
    let dec = flate2::read::MultiGzDecoder::new(file);
    extract_tar(dec, dest, installed, true)
}

/// Void `.xbps` packages are tar archives compressed with **either** zstd
/// or xz: confirmed live: `figlet-2.2.5_6.x86_64-musl.xbps` from the real
/// Void mirror is XZ (`file` reports "XZ compressed data"), while other
/// packages (e.g. `kurly`) are zstd. The old code assumed zstd
/// unconditionally and failed on any xz-compressed package with zstd's own
/// "Unknown frame descriptor" error (a malformed-zstd-header message,
/// misleading here since the file was never zstd to begin with). Sniff
/// the real magic bytes instead of assuming.
/// Stages the symlinks of a package's xbps alternatives groups whose link
/// doesn't exist yet (first provider wins, as with xbps itself); returns
/// (staged, final union path) pairs to commit with the rest of the package.
fn stage_xbps_alternatives(
    pkg_path: &Path,
    store_path: &Path,
    union_root: &Path,
    committed: &[PathBuf],
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let Some(props) = read_xbps_member(pkg_path, "props.plist")? else {
        return Ok(Vec::new());
    };
    let props: plist::Value = plist::from_bytes(&props).context("parsing props.plist")?;
    let Some(groups) = props
        .as_dictionary()
        .and_then(|d| d.get("alternatives"))
        .and_then(|a| a.as_dictionary())
    else {
        return Ok(Vec::new());
    };

    let alt_root = store_path.join(".zex-alternatives");
    let mut out = Vec::new();
    for entries in groups.values().filter_map(|v| v.as_array()) {
        for entry in entries.iter().filter_map(|e| e.as_string()) {
            let Some((link, target)) = entry.split_once(':') else {
                continue;
            };
            let target = Path::new(target);
            let link_path = if link.starts_with('/') {
                PathBuf::from(link)
            } else {
                target.parent().unwrap_or(Path::new("/")).join(link)
            };
            let rel = crate::archive_safety::remap_usr_paths(link_path);
            let final_path = union_root.join(&rel);
            if final_path.symlink_metadata().is_ok() || committed.contains(&final_path) {
                continue;
            }
            let final_target =
                union_root.join(crate::archive_safety::remap_usr_paths(target.to_path_buf()));
            let value = if final_target.parent() == final_path.parent() {
                PathBuf::from(final_target.file_name().unwrap_or_default())
            } else {
                final_target
            };
            let staged = alt_root.join(&rel);
            if let Some(parent) = staged.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(&value, &staged)
                .with_context(|| format!("alternative link {}", staged.display()))?;
            out.push((staged, final_path));
        }
    }
    Ok(out)
}

/// Reads one metadata member (e.g. props.plist) out of a zstd or xz .xbps archive.
fn read_xbps_member(pkg_path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let mut file = std::fs::File::open(pkg_path)?;
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;
    file.rewind()?;
    let reader: Box<dyn Read> = if n >= 6 && magic == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        Box::new(xz2::read::XzDecoder::new(file))
    } else {
        Box::new(zstd::stream::read::Decoder::new(file)?)
    };
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.to_string_lossy().trim_start_matches("./") == name {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

fn extract_xbps(
    pkg_path: &Path,
    dest: &Path,
    installed: &mut Vec<PathBuf>,
) -> Result<Option<PostInstallScript>> {
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
    const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

    let mut file = std::fs::File::open(pkg_path)?;
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;
    file.rewind()?;

    if n >= 6 && magic == XZ_MAGIC {
        let dec = xz2::read::XzDecoder::new(file);
        extract_tar(dec, dest, installed, true)
    } else if n >= 4 && magic[..4] == ZSTD_MAGIC {
        let dec = zstd::stream::read::Decoder::new(file)?;
        extract_tar(dec, dest, installed, true)
    } else {
        bail!(
            "unrecognized .xbps compression for '{}' (neither zstd nor xz magic bytes)",
            pkg_path.display()
        );
    }
}

/// Extracts a Chimera Linux `.apk` package: apk-tools v3's binary "ADB"
/// container format, not the legacy gzip-tar `.apk` used by Alpine (see
/// `cmd::install::adb` for the format itself). Applies the same path/link
/// sanitization as `extract_tar` since this walks an untrusted archive too.
fn extract_adb(
    pkg_path: &Path,
    dest: &Path,
    installed: &mut Vec<PathBuf>,
) -> Result<Option<PostInstallScript>> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let bytes = std::fs::read(pkg_path)?;
    let entries = super::adb::extract_entries(&bytes)?;

    for entry in entries {
        let rel = match sanitize_path(Path::new(&entry.rel_path)) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let dest_path = dest.join(&rel);

        const S_IFMT: u32 = 0o170000;
        const S_IFDIR: u32 = 0o040000;
        const S_IFLNK: u32 = 0o120000;

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "failed to create parent directory '{}' for adb entry '{}': {}",
                    parent.display(),
                    entry.rel_path,
                    e
                )
            })?;
        }

        match entry.mode & S_IFMT {
            S_IFDIR => {
                std::fs::create_dir_all(&dest_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to create directory '{}' for adb entry '{}': {}",
                        dest_path.display(),
                        entry.rel_path,
                        e
                    )
                })?;
            }
            S_IFLNK => {
                let target = entry.link_target.unwrap_or_default();

                let target_remapped =
                    crate::archive_safety::remap_usr_paths(PathBuf::from(&target));
                if target_remapped == rel {
                    continue;
                }

                let safe_target =
                    sanitize_link_target(Path::new(&entry.rel_path), Path::new(&target))?;
                let _ = std::fs::remove_file(&dest_path);
                #[cfg(unix)]
                symlink(&safe_target, &dest_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to symlink '{}' -> '{}': {}",
                        dest_path.display(),
                        safe_target.display(),
                        e
                    )
                })?;
                installed.push(dest_path);
            }
            _ if entry.link_target.is_some() => {
                let target = entry.link_target.unwrap();
                let safe_target = crate::archive_safety::sanitize_archive_path(Path::new(&target))?;
                let target_path = dest.join(&safe_target);
                if !target_path.exists() {
                    bail!(
                        "adb hard link target does not exist for '{}': {}",
                        rel.display(),
                        safe_target.display()
                    );
                }
                let _ = std::fs::remove_file(&dest_path);
                std::fs::hard_link(&target_path, &dest_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to hard-link '{}' -> '{}': {}",
                        dest_path.display(),
                        target_path.display(),
                        e
                    )
                })?;
                installed.push(dest_path);
            }
            _ => {
                std::fs::write(&dest_path, entry.content.unwrap_or_default()).map_err(|e| {
                    anyhow::anyhow!("failed to write '{}': {}", dest_path.display(), e)
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &dest_path,
                        std::fs::Permissions::from_mode(entry.mode & 0o7777),
                    );
                }
                installed.push(dest_path);
            }
        }
    }
    Ok(None)
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
            if s.starts_with('.')
                || s.is_empty()
                || s == "props.plist"
                || s == "files.plist"
                || s == "REMOVE"
            {
                continue;
            }
        }

        let dest_path = dest.join(&rel);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            continue;
        }

        if let Some(p) = dest_path.parent() {
            std::fs::create_dir_all(p).map_err(|e| {
                anyhow::anyhow!(
                    "failed to create parent directory '{}' for '{}': {}",
                    p.display(),
                    rel.display(),
                    e
                )
            })?;
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

                let target_remapped = crate::archive_safety::remap_usr_paths(PathBuf::from(
                    link_target.to_string_lossy().as_ref(),
                ));
                if target_remapped == rel {
                    continue;
                }

                let safe_target = sanitize_link_target(&path, &link_target)?;
                let _ = std::fs::remove_file(&dest_path);
                symlink(&safe_target, &dest_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to symlink '{}' -> '{}': {}",
                        dest_path.display(),
                        safe_target.display(),
                        e
                    )
                })?;
                inst.push(dest_path);
            }
            continue;
        }

        if entry_type.is_hard_link() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                anyhow::anyhow!("hard link entry missing target: {}", rel.display())
            })?;
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
            std::fs::hard_link(&target_path, &dest_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to hard-link '{}' -> '{}': {}",
                    dest_path.display(),
                    target_path.display(),
                    e
                )
            })?;
            inst.push(dest_path);
            continue;
        }

        log::debug!(
            "Skipping unsupported archive entry type for '{}': {:?}",
            rel.display(),
            entry_type
        );
    }
    Ok(captured_script)
}

/// Base OS immutable layer. A zex package landing on a path that already
/// exists here would silently shadow it at read time (OverlayFS always
/// serves the upperdir/`zexlib/union` copy over the syshub lowerdir) —
/// that's a real, surprising behavior change and must not pass silently.
const SYSHUB_ROOT: &str = "/overlayer/syshub";
const BASE_OWNER: &str = "syshub (immutable base OS)";

/// Check whether any of `committed_files` (final `/overlayer/zexlib/union/...`
/// destinations, *not* staging-dir paths: those never match anything, which
/// is why this previously went unused) is already owned by another
/// installed package, or already exists under [`SYSHUB_ROOT`] (the
/// immutable base OS image, which zex never tracks in its own registry so
/// an ordinary DB-only check can't see it).
///
/// Returns `(owning_package_or_"syshub", conflicting_path)` tuples.
/// Same-package entries (reinstall/upgrade) are excluded.
pub fn check_file_conflicts(pkg_name: &str, committed_files: &[PathBuf]) -> Vec<(String, String)> {
    let db = super::backend::load_db();
    let union_root = Path::new(crate::archive_safety::UNION_ROOT);
    let mut conflicts = Vec::new();

    let incoming: HashSet<&Path> = committed_files.iter().map(|p| p.as_path()).collect();

    for entry in &db {
        if entry.name.eq_ignore_ascii_case(pkg_name) {
            continue;
        }
        for existing_file in &entry.installed_files {
            if incoming.contains(Path::new(existing_file.as_str())) {
                conflicts.push((entry.name.clone(), existing_file.clone()));
            }
        }
    }

    for file in committed_files {
        if let Ok(rel) = file.strip_prefix(union_root) {
            let merged = Path::new(SYSHUB_ROOT).join(rel);
            if merged.symlink_metadata().is_ok() && file.symlink_metadata().is_err() {
                conflicts.push((BASE_OWNER.to_string(), file.to_string_lossy().into_owned()));
            }
        }
    }

    conflicts
}

/// Run conflict detection on a package's final union destinations. Must run
/// after `committed_files` is computed (Step 4) and before registration
/// (Step 5): true pre-flight, nothing registered or committed yet if this
/// aborts.
///
/// With `zex install --force` another package's files are overwritten instead.
pub fn preflight_conflict_check(pkg_name: &str, committed_files: &[PathBuf]) -> Result<()> {
    let conflicts = check_file_conflicts(pkg_name, committed_files);

    if conflicts.is_empty() {
        return Ok(());
    }

    if FORCE.load(Ordering::Relaxed) {
        ui::print_forced_conflicts(pkg_name, &conflicts);
        for (_, path) in &conflicts {
            let _ = crate::immutable::try_clear_immutable(Path::new(path));
        }
        return Ok(());
    }

    ui::print_file_conflicts(pkg_name, &conflicts);
    bail!(
        "File conflict: {} file(s) already owned by another package or the base OS image.",
        conflicts.len()
    )
}
