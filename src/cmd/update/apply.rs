//! apply.rs — Download and apply upgrades for userland and syshub.

use anyhow::{Context, Result};
use futures_util::{StreamExt, stream};
use indicatif::MultiProgress;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use super::diff::UpgradePkg;
use super::ui;

const UNION_PATH: &str = "/overlayer/zexlib/union";

/// Download + extract userland packages 2 at a time into union.
pub async fn apply_uland(
    upgrades: &[UpgradePkg],
    client: &reqwest::Client,
    dl_tmp: &Path,
    mp: &MultiProgress,
    overall: &indicatif::ProgressBar,
    sig_mode: crate::trust::SignatureVerificationMode,
) -> Result<u64> {
    let mut total_bytes = 0u64;

    // Sliding-window concurrency (`buffer_unordered`), not fixed pairs —
    // a fixed `chunks(2)` held both slots of a pair open until BOTH
    // finished, so a package that finished early just sat at 100% instead
    // of immediately picking up the next one while its chunk-mate kept
    // streaming (same fix as cmd::upgrade::syscore/userland).
    let mut in_flight = stream::iter(upgrades.iter())
        .map(|pkg| {
            let label = format!("{:<22} → {}", pkg.name, pkg.new_ver);
            let bar = ui::make_pkg_bar(mp, pkg.size_bytes, &label);

            let url = pkg.url.clone();
            let dest = dl_tmp.join(&pkg.filename);
            let name = pkg.name.clone();
            let new_ver = pkg.new_ver.clone();
            let cl2 = client.clone();
            let overall_h = overall.clone();
            async move {
                let result = download_with_bar(&cl2, &url, &dest, &bar, &overall_h).await;
                (name, new_ver, dest, result)
            }
        })
        .buffer_unordered(2);

    // `buffer_unordered` completes futures in COMPLETION order, not
    // submission order — each result carries its own package identity
    // (name/new_ver) rather than being matched back up by position, unlike
    // the old chunked loop where `chunk.iter().zip(handles)` could get
    // away with positional pairing.
    while let Some((name, new_ver, zex_path, result)) = in_flight.next().await {
        if let Ok(bytes) = result {
            total_bytes += bytes;
            // Ed25519 signature check — against the pubkey embedded in
            // the package's own manifest.toml.
            crate::trust::verify_zex_archive(&zex_path, sig_mode)?;
            // through the merged mount, so the update is visible right away
            let written = extract_into(
                &zex_path,
                &crate::archive_safety::live_path(Path::new(UNION_PATH)),
            )?;
            // No separate staging root here (UNION_PATH is live), so this
            // is the only "just written" window there is — same reasoning
            // as cmd::upgrade::userland's identical extract_*_into fix.
            crate::cmd::install::elfpatch::patch_staged_elfs(&written)?;
            crate::cmd::install::pcpatch::patch_staged_pkgconfig(
                &written,
                crate::archive_safety::UNION_ROOT,
            )?;
            crate::cmd::install::shebangpatch::patch_staged_scripts(&written)?;
            crate::triggers::note(&written);
            update_receipt(&name, &new_ver)?;
        }
    }

    Ok(total_bytes)
}

/// Download + extract syshub packages 2 at a time into syshub.new then atomic overwrite.
pub async fn apply_syshub(
    upgrades: &[UpgradePkg],
    client: &reqwest::Client,
    dl_tmp: &Path,
    mp: &MultiProgress,
    overall: &indicatif::ProgressBar,
    syshub_path: &str,
    remote_manifest: &str,
) -> Result<u64> {
    // staged outside zexlib; quantra-ramfs puts it into the base layer at the next boot
    let staging = crate::syshub_pending::begin()?;

    let mut total_bytes = 0u64;
    let mut staged_files: Vec<PathBuf> = Vec::new();

    // Sliding-window concurrency — same fix as apply_uland above.
    let mut in_flight = stream::iter(upgrades.iter())
        .map(|pkg| {
            let label = format!("{:<22} → {}", pkg.name, pkg.new_ver);
            let bar = ui::make_pkg_bar(mp, pkg.size_bytes, &label);

            let url = pkg.url.clone();
            let dest = dl_tmp.join(&pkg.filename);
            let cl2 = client.clone();
            let overall_h = overall.clone();
            async move {
                let result = download_with_bar(&cl2, &url, &dest, &bar, &overall_h).await;
                (dest, result)
            }
        })
        .buffer_unordered(2);

    while let Some((zex_path, result)) = in_flight.next().await {
        if let Ok(bytes) = result {
            total_bytes += bytes;
            // Syshub core is always Strict, regardless of the userland
            // `require_signatures` config — same invariant as
            // `cmd::upgrade::syscore`.
            crate::trust::verify_zex_archive(
                &zex_path,
                crate::trust::SignatureVerificationMode::Strict,
            )?;
            staged_files.extend(extract_into(&zex_path, &staging)?);
        }
    }

    // Patch while still in `staging`, mutable, before the atomic overwrite
    // below commits these files onto the live (and, once remounted ro at
    // the end, immutable) syshub base — same timing constraint as
    // `cmd::upgrade::syscore`'s identical staged elfpatch/pcpatch pass.
    crate::cmd::install::elfpatch::patch_staged_elfs(&staged_files)?;
    crate::cmd::install::pcpatch::patch_staged_pkgconfig(&staged_files, syshub_path)?;
    crate::cmd::install::shebangpatch::patch_staged_scripts(&staged_files)?;

    let staged_manifest = staging.join("engine/services/syshub.toml");
    fs::create_dir_all(staged_manifest.parent().unwrap())?;
    fs::write(&staged_manifest, remote_manifest)?;
    if let Err(e) = crate::syshub_pending::commit("update") {
        crate::syshub_pending::clear().ok();
        return Err(e);
    }

    Ok(total_bytes)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Retries the whole download from byte 0 on failure (not a range-resume)
/// — `cmd::install::downloader::download` already retries exactly this
/// failure mode (3 retries, backoff); this `zex update` downloader never
/// did, so a single mid-stream hiccup (confirmed live, repeatedly, in this
/// environment) hard-failed the whole update instead of just costing a
/// short delay. `overall`'s position may briefly over-count by a failed
/// attempt's partial bytes on a retry — an acceptable trade-off against
/// aborting outright.
async fn download_with_bar(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    bar: &indicatif::ProgressBar,
    overall: &indicatif::ProgressBar,
) -> Result<u64> {
    const DELAYS_MS: [u64; 4] = [0, 500, 1_000, 2_000];
    let mut last_err: Option<anyhow::Error> = None;
    for &delay in &DELAYS_MS {
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        match download_once(client, url, dest, bar, overall).await {
            Ok(tot) => {
                ui::finish_pkg_bar(bar);
                return Ok(tot);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap())
}

async fn download_once(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    bar: &indicatif::ProgressBar,
    overall: &indicatif::ProgressBar,
) -> Result<u64> {
    let resp = client.get(url).send().await?.error_for_status()?;
    if let Some(p) = dest.parent() {
        fs::create_dir_all(p)?;
    }
    let mut f = std::io::BufWriter::new(fs::File::create(dest)?);
    let mut tot = 0u64;
    let mut s = resp.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
        tot += chunk.len() as u64;
        f.write_all(&chunk)?;
        bar.set_position(tot);
        overall.inc(chunk.len() as u64);
    }
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
/// Returns the regular files it wrote (dirs/symlinks excluded) so callers
/// can run `elfpatch`/`pcpatch` over them — this extractor previously
/// never did either, unlike `installer.rs`/`local_install.rs`/
/// `cmd::upgrade::userland`'s equivalents, so a package upgraded through
/// `zex update` (as opposed to freshly installed via `zex install`) kept
/// its host-FHS `PT_INTERP`/RPATH and unpatched `.pc` `prefix=` intact.

/// A new file in place of the old one. Installed files are sealed with fs-verity
/// at boot, and a sealed file cannot be opened for writing (EPERM), so the old one
/// is unlinked first, as a reinstall does.
fn replace_file(dst: &Path) -> Result<fs::File> {
    if fs::symlink_metadata(dst).is_ok_and(|m| !m.is_dir()) {
        fs::remove_file(dst).with_context(|| format!("removing old {}", dst.display()))?;
    }
    fs::File::create(dst).with_context(|| format!("writing {}", dst.display()))
}

fn extract_into(zex_path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);
    let mut written: Vec<PathBuf> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let rel = raw.to_string_lossy();
        if !rel.starts_with("payload/") {
            continue;
        }
        let inner = match raw.strip_prefix("payload") {
            Ok(p) => p,
            Err(_) => continue,
        };
        let clean = match crate::archive_safety::sanitize_archive_path(inner) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if clean.as_os_str().is_empty() {
            continue;
        }
        let dst = dest.join(&clean);
        let typ = entry.header().entry_type();
        if typ.is_dir() {
            fs::create_dir_all(&dst)?;
            continue;
        }
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p)?;
        }
        if typ.is_file() {
            let mut out = replace_file(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))?;
                }
            }
            written.push(dst);
        } else if typ.is_symlink() {
            if let Some(t) = entry.link_name()? {
                let safe_target = crate::archive_safety::sanitize_link_target(inner, &t)?;
                crate::archive_safety::create_sanitized_symlink(&safe_target, &dst)?;
            }
        }
    }
    Ok(written)
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
