//! apply.rs — Download and apply upgrades for userland and syshub.

use anyhow::Result;
use futures_util::StreamExt;
use indicatif::MultiProgress;
use std::{fs, io::Write, path::Path};
use walkdir::WalkDir;

use super::diff::UpgradePkg;
use super::ui;
use super::vercmp;

const UNION_PATH: &str = "/overlayer/zexlib/union";

/// Download + extract userland packages 2 at a time into union.
pub async fn apply_uland(
    upgrades: &[UpgradePkg],
    client:   &reqwest::Client,
    dl_tmp:   &Path,
    mp:       &MultiProgress,
    overall:  &indicatif::ProgressBar,
    sig_mode: crate::trust::SignatureVerificationMode,
) -> Result<u64> {
    let mut total_bytes = 0u64;
    let show_count      = upgrades.len().min(2); // show max 2 bars at once, then truncate

    // Show first 2, then "(N more)"
    for chunk in upgrades.chunks(2) {
        let mut handles = Vec::new();

        for pkg in chunk {
            let label = format!("{:<22} → {}", pkg.name, pkg.new_ver);
            let cl    = pkg.size_bytes;
            let bar   = ui::make_pkg_bar(mp, cl, &label);

            let url  = pkg.url.clone();
            let dest = dl_tmp.join(&pkg.filename);
            let cl2  = client.clone();
            let h = tokio::spawn(async move {
                download_with_bar(&cl2, &url, &dest, &bar).await
                    .map(|b| (dest, b))
            });
            handles.push(h);
        }

        for (pkg, handle) in chunk.iter().zip(handles) {
            if let Ok(Ok((zex_path, bytes))) = handle.await {
                total_bytes += bytes;
                // Ed25519 signature check — against the pubkey embedded in
                // the package's own manifest.toml.
                crate::trust::verify_zex_archive(&zex_path, sig_mode)?;
                extract_into(&zex_path, Path::new(UNION_PATH))?;
                update_receipt(&pkg.name, &pkg.new_ver)?;
                overall.inc(1);
            }
        }
    }

    // Print truncated count for remaining
    let shown = show_count * 2;
    if upgrades.len() > shown {
        ui::print_truncated(upgrades.len() - shown);
    }

    Ok(total_bytes)
}

/// Download + extract syshub packages 2 at a time into syshub.new then atomic overwrite.
pub async fn apply_syshub(
    upgrades:    &[UpgradePkg],
    client:      &reqwest::Client,
    dl_tmp:      &Path,
    mp:          &MultiProgress,
    overall:     &indicatif::ProgressBar,
    syshub_path: &str,
) -> Result<u64> {
    let staging = dl_tmp.join("syshub.new");
    fs::create_dir_all(&staging)?;

    let mut total_bytes = 0u64;

    for chunk in upgrades.chunks(2) {
        let mut handles = Vec::new();
        for pkg in chunk {
            let label = format!("{:<22} → {}", pkg.name, pkg.new_ver);
            let bar   = ui::make_pkg_bar(mp, pkg.size_bytes, &label);

            let url  = pkg.url.clone();
            let dest = dl_tmp.join(&pkg.filename);
            let cl2  = client.clone();
            let h = tokio::spawn(async move {
                download_with_bar(&cl2, &url, &dest, &bar).await
                    .map(|b| (dest, b))
            });
            handles.push(h);
        }

        for handle in handles {
            if let Ok(Ok((zex_path, bytes))) = handle.await {
                total_bytes += bytes;
                // Syshub core is always Strict, regardless of the
                // userland `require_signatures` config — same invariant
                // as `cmd::upgrade::syscore`.
                crate::trust::verify_zex_archive(&zex_path, crate::trust::SignatureVerificationMode::Strict)?;
                extract_into(&zex_path, &staging)?;
                overall.inc(1);
            }
        }
    }

    // Atomic overwrite into live syshub
    remount(syshub_path, true)?;
    let live = Path::new(syshub_path);
    for entry in WalkDir::new(&staging).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let rel  = entry.path().strip_prefix(&staging).unwrap();
        let dst  = live.join(rel);
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }
        if fs::rename(entry.path(), &dst).is_err() {
            fs::copy(entry.path(), &dst)?;
        }
    }
    remount(syshub_path, false)?;

    Ok(total_bytes)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn download_with_bar(
    client: &reqwest::Client,
    url:    &str,
    dest:   &Path,
    bar:    &indicatif::ProgressBar,
) -> Result<u64> {
    let resp = client.get(url).send().await?.error_for_status()?;
    if let Some(p) = dest.parent() { fs::create_dir_all(p)?; }
    let mut f   = std::io::BufWriter::new(fs::File::create(dest)?);
    let mut tot = 0u64;
    let mut s   = resp.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
        tot += chunk.len() as u64;
        f.write_all(&chunk)?;
        bar.set_position(tot);
    }
    bar.finish();
    Ok(tot)
}

/// Extracts a `.zex` archive's `payload/` tree into `dest`.
///
/// Uses the same `archive_safety` sanitization every other extractor in
/// this codebase does (`cmd::install::installer`, `local_install`,
/// `extract`) — this one previously joined raw, unsanitized archive paths
/// and symlink targets directly onto `dest` with no `..`/absolute-path
/// checks at all, a real path-traversal gap for a function that can write
/// into the live syshub base or userland union tree.
fn extract_into(zex_path: &Path, dest: &Path) -> Result<()> {
    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw  = entry.path()?.into_owned();
        let rel  = raw.to_string_lossy();
        if !rel.starts_with("payload/") { continue; }
        let inner = match raw.strip_prefix("payload") {
            Ok(p) => p,
            Err(_) => continue,
        };
        let clean = match crate::archive_safety::sanitize_archive_path(inner) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if clean.as_os_str().is_empty() { continue; }
        let dst = dest.join(&clean);
        let typ = entry.header().entry_type();
        if typ.is_dir() { fs::create_dir_all(&dst)?; continue; }
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }
        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))?;
                }
            }
        } else if typ.is_symlink() {
            if let Some(t) = entry.link_name()? {
                let safe_target = crate::archive_safety::sanitize_link_target(inner, &t)?;
                crate::archive_safety::create_sanitized_symlink(&safe_target, &dst)?;
            }
        }
    }
    Ok(())
}

/// Bumps a package's registered version after a successful update.
///
/// Previously did its own raw-text "find the word 'version' and patch that
/// line" surgery — the same fragile pattern already found and removed from
/// `cmd::upgrade::userland` this session (it can corrupt an unrelated line
/// if any other field name/string value happens to contain "version", and
/// duplicates the master-index sync `registry::update_version` already
/// does safely). `registry::update_version` preserves every other field
/// (installed_files, dependencies, conflicts, etc.) and keeps
/// `packages.toml` in sync as a side effect, so the old separate
/// `update_packages_toml` raw-text patcher is gone too — redundant now.
fn update_receipt(name: &str, new_ver: &str) -> Result<()> {
    if crate::cmd::install::registry::lookup(name).is_none() {
        return Ok(());
    }
    crate::cmd::install::registry::update_version(name, new_ver)
}

fn remount(path: &str, rw: bool) -> Result<()> {
    let flag = if rw { "remount,rw" } else { "remount,ro" };
    let st = std::process::Command::new("mount")
        .args(["-o", flag, path]).status()?;
    if !st.success() { anyhow::bail!("mount -o {} {} failed", flag, path); }
    Ok(())
}
