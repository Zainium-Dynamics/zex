//! syscore.rs: Syshub immutable-base upgrade engine.

use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream};
use indicatif::MultiProgress;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};
use walkdir::WalkDir;

use super::{
    audit::{self, AuditEntry},
    transaction::Transaction,
    ui,
    vercmp::is_upgrade,
};

/// Per-download temp dir: .zex files land here before extraction.
const DL_TMP: &str = "/overlayer/zexlib/tmp/syshub-dl";
const LOCAL_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";
const ZEX_SERVICES: &str = "/overlayer/syshub/engine/services/zex_services.toml";
const ROLLBACK_STAGE: &str = "/overlayer/zexlib/tmp/syshub-rollback";

#[derive(Debug, Deserialize, Clone)]
struct SyshubManifest {
    core_info: CoreInfo,
    packages: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct CoreInfo {
    build_version: String,
    #[allow(dead_code)]
    os_name: String,
}

#[derive(Debug, Deserialize)]
struct ZexServices {
    mirrors: Vec<Mirror>,
}

#[derive(Debug, Deserialize)]
struct Mirror {
    id: String,
    index_url: String,
    base_url: String,
    format: String,
    priority: u32,
}

#[derive(Clone)]
struct UpgradePkg {
    name: String,
    old_ver: String,
    new_ver: String,
    filename: String,
    url: String,
}

pub async fn execute() -> Result<()> {
    let started = Instant::now();

    let recovered = Transaction::recover_stale(Path::new(ROLLBACK_STAGE));
    if !recovered.is_empty() {
        ui::print_crash_recovery(&recovered);
    }

    ui::print_syshub_header();

    crate::syshub_pending::ensure_available()?;
    if let Some(txn) = crate::syshub_pending::waiting() {
        ui::print_pending_waiting(&txn);
    }

    if !online().await {
        ui::print_no_internet();
        std::process::exit(1);
    }

    let svc_raw = fs::read_to_string(ZEX_SERVICES).context("reading zex_services.toml")?;
    let services: ZexServices = toml::from_str(&svc_raw).context("parsing zex_services.toml")?;
    let mirror = services
        .mirrors
        .iter()
        .filter(|m| m.id.contains("syshub") && m.format == "zex")
        .min_by_key(|m| m.priority)
        .context("No Tier-1 syshub mirror in zex_services.toml")?;

    let local_raw = fs::read_to_string(LOCAL_MANIFEST)
        .context("Local syshub.toml missing — is syshub mounted?")?;
    let local: SyshubManifest =
        toml::from_str(&local_raw).context("Malformed local syshub.toml")?;
    let current_ver = local.core_info.build_version.clone();

    ui::print_checking(&current_ver);

    let client = crate::http_client::build("zex-syshub")?;
    let remote_raw = client
        .get(&mirror.index_url)
        .send()
        .await
        .context("fetching remote syshub.toml")?
        .error_for_status()?
        .text()
        .await?;
    let remote: SyshubManifest =
        toml::from_str(&remote_raw).context("Malformed remote syshub.toml")?;

    let upgrades = diff_packages(&local, &remote, &mirror.base_url);

    if upgrades.is_empty() {
        ui::print_syshub_uptodate(&current_ver, local.packages.len());
        return Ok(());
    }

    ui::print_syshub_found(upgrades.len());

    let pkg_list: Vec<(&str, &str, &str)> = upgrades
        .iter()
        .map(|u| (u.name.as_str(), u.old_ver.as_str(), u.new_ver.as_str()))
        .collect();
    ui::print_syshub_package_list(&pkg_list);

    let head_checks: Vec<u64> =
        futures_util::future::join_all(upgrades.iter().map(|u| content_length(&client, &u.url)))
            .await
            .into_iter()
            .map(|c| c.unwrap_or(0))
            .collect();
    let real_total_bytes: u64 = head_checks.iter().sum();
    ui::print_transaction_summary(upgrades.len(), real_total_bytes as f64 / 1_048_576.0);

    if !ui::print_proceed_prompt() {
        println!(
            "\n {DIM}Upgrade cancelled.{RST}",
            DIM = ui::DIM,
            RST = ui::RST
        );
        return Ok(());
    }

    ui::print_syshub_starting();

    let staging_root = crate::syshub_pending::begin()?;
    let staging = staging_root.as_path();

    let dl_tmp = Path::new(DL_TMP);
    if dl_tmp.exists() {
        fs::remove_dir_all(dl_tmp)?;
    }
    fs::create_dir_all(dl_tmp)?;

    let mp = MultiProgress::new();
    let overall = ui::make_overall_bar(&mp, real_total_bytes);
    overall.set_position(0);

    let mut downloaded: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    let sized_upgrades: Vec<(&UpgradePkg, u64)> =
        upgrades.iter().zip(head_checks.iter().copied()).collect();

    let mut in_flight = stream::iter(sized_upgrades.into_iter().map(|(pkg, content_len)| {
        let label = format!("{:<20} {} → {}", pkg.name, pkg.old_ver, pkg.new_ver);
        let bar = ui::make_pkg_bar(&mp, content_len, &label);

        let url = pkg.url.clone();
        let dest = dl_tmp.join(&pkg.filename);
        let name = pkg.name.clone();
        let overall_h = overall.clone();
        let client_h = client.clone();
        async move {
            let result = download_with_bar(&client_h, &url, &dest, &bar, &overall_h).await;
            (name, dest, result)
        }
    }))
    .buffer_unordered(2);

    while let Some((pkg_name, zex_path, result)) = in_flight.next().await {
        let bytes = match result {
            Ok(b) => b,
            Err(e) => {
                cleanup_dir(staging);
                cleanup_dir(dl_tmp);
                ui::print_download_interrupted(&pkg_name);
                log_audit(
                    "syshub",
                    &downloaded,
                    "rolled_back",
                    Some(&e.to_string()),
                    started.elapsed().as_millis() as u64,
                );
                std::process::exit(1);
            }
        };
        total_bytes += bytes;

        crate::trust::verify_zex_archive(
            &zex_path,
            crate::trust::SignatureVerificationMode::Strict,
        )?;

        extract_zex_into(&zex_path, staging).with_context(|| format!("extracting {pkg_name}"))?;

        downloaded.push(pkg_name);
    }

    overall.finish_and_clear();
    println!();

    let steps = crate::steps::Guard::new();
    ui::start_phase("Verifying integrity");
    verify_libc_boundaries(staging)?;

    let staged_files: Vec<PathBuf> = WalkDir::new(staging)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    crate::cmd::install::shebangpatch::patch_staged_scripts(&staged_files)?;

    let staged_manifest = staging.join(LOCAL_MANIFEST.trim_start_matches("/overlayer/syshub/"));
    if let Some(parent) = staged_manifest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&staged_manifest, &remote_raw).context("staging updated syshub.toml")?;
    ui::start_phase("Staging upgrade for next boot");
    let txn = match crate::syshub_pending::commit(&remote.core_info.build_version) {
        Ok(txn) => txn,
        Err(e) => {
            crate::steps::fail();
            crate::syshub_pending::clear().ok();
            cleanup_dir(dl_tmp);
            log_audit(
                "syshub",
                &downloaded,
                "rolled_back",
                Some(&e.to_string()),
                started.elapsed().as_millis() as u64,
            );
            return Err(e).context("staging syshub upgrade");
        }
    };

    cleanup_dir(dl_tmp);

    let elapsed = started.elapsed().as_secs();
    let total_mb = total_bytes as f64 / 1_048_576.0;

    steps.ok();
    ui::print_syshub_done(
        downloaded.len(),
        total_mb,
        elapsed,
        &remote.core_info.build_version,
        &txn,
    );
    log_audit(
        "syshub",
        &downloaded,
        "success",
        None,
        started.elapsed().as_millis() as u64,
    );
    Ok(())
}

fn is_pkg_pinned(name: &str) -> bool {
    const PINNED: &str = "/overlayer/zexlib/registry/pinned.toml";
    let Ok(raw) = std::fs::read_to_string(PINNED) else {
        return false;
    };
    #[derive(serde::Deserialize, Default)]
    struct PF {
        #[serde(default)]
        pinned: Vec<Pin>,
    }
    #[derive(serde::Deserialize)]
    struct Pin {
        name: String,
    }
    toml::from_str::<PF>(&raw)
        .map(|f| f.pinned.iter().any(|p| p.name.eq_ignore_ascii_case(name)))
        .unwrap_or(false)
}

fn diff_packages(
    local: &SyshubManifest,
    remote: &SyshubManifest,
    base_url: &str,
) -> Vec<UpgradePkg> {
    let mut out = Vec::new();
    for (name, rv) in &remote.packages {
        if name == "provides" || super::kernel::is_modules_package(name) {
            continue;
        }
        let rv_s = val_str(rv);
        let lv_s = local
            .packages
            .get(name)
            .map(val_str)
            .unwrap_or_else(|| "0".into());
        if is_upgrade(&lv_s, &rv_s) {
            if is_pkg_pinned(name) {
                log::info!("Syshub package '{}' is pinned — skipping", name);
                continue;
            }
            let filename = format!("{}-{}.zex", name, rv_s);
            let url = format!("{}/{}", base_url.trim_end_matches('/'), filename);
            out.push(UpgradePkg {
                name: name.clone(),
                old_ver: lv_s,
                new_ver: rv_s,
                filename,
                url,
            });
        }
    }
    out
}

pub(super) fn val_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0")
            .to_string(),
        other => other.to_string().trim_matches('"').to_string(),
    }
}

pub(super) async fn online() -> bool {
    let Ok(client) = crate::http_client::build("zex-syshub/ping") else {
        return false;
    };

    client
        .head("https://mirrors.edge.kernel.org/")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

pub(super) async fn content_length(client: &reqwest::Client, url: &str) -> Option<u64> {
    let r = client.head(url).send().await.ok()?;
    r.headers()
        .get(reqwest::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Retries the whole download from byte 0 on failure (not a range-resume)
///: `cmd::install::downloader::download` already retries exactly this
/// failure mode (3 retries, backoff) for the `zex install` path; this
/// upgrade-path downloader never did, so a single mid-stream hiccup
/// (confirmed live, repeatedly, in this environment) hard-failed the
/// entire syshub upgrade instead of just costing a short delay. `overall`'s
/// position may briefly over-count by a failed attempt's partial bytes on
/// a retry: an acceptable trade-off against aborting outright.
pub(super) async fn download_with_bar(
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
        use std::io::Write;
        f.write_all(&chunk)?;
        bar.set_position(tot);
        overall.inc(chunk.len() as u64);
    }
    Ok(tot)
}

/// Extract `payload/*` from a .zex (zexc / ZEX1) into `dest` root.
/// Multiple packages extract into the SAME dest → their trees merge naturally.
pub(super) fn extract_zex_into(zex_path: &Path, dest: &Path) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let rel = raw.to_string_lossy();

        if !rel.starts_with("payload/") {
            continue;
        }
        let inner = rel
            .strip_prefix("payload/")
            .unwrap_or("")
            .trim_start_matches('/');
        if inner.is_empty() {
            continue;
        }

        let dst = dest.join(inner);
        let typ = entry.header().entry_type();

        if typ.is_dir() {
            fs::create_dir_all(&dst)?;
            continue;
        }
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p)?;
        }

        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))?;
                }
            }
        } else if typ.is_symlink() {
            if let Some(target) = entry.link_name()? {
                let _ = fs::remove_file(&dst);
                #[cfg(unix)]
                symlink(&target, &dst)?;
            }
        }
    }
    Ok(())
}

/// Reject any .zex payload that contains glibc-versioned shared objects.
fn verify_libc_boundaries(staging: &Path) -> Result<()> {
    const BAD: &[&str] = &[
        "libc.so.6",
        "libpthread.so.0",
        "libm.so.6",
        "ld-linux-x86-64.so.2",
        "ld-linux-aarch64.so.1",
    ];
    for e in WalkDir::new(staging).into_iter().filter_map(|e| e.ok()) {
        let n = e.file_name().to_string_lossy();
        for bad in BAD {
            if n.as_ref() == *bad {
                bail!(
                    "glibc artifact detected: {}\n\
                     The base links against musl only; glibc is a userland package\n\
                     in its own directory.",
                    e.path().display()
                );
            }
        }
    }
    Ok(())
}

/// Best-effort cleanup that still surfaces a failure instead of silently
/// swallowing it: confirmed live that a bare `fs::remove_dir_all(...)
/// .ok()` left a stale `syshub.new` behind on a real drive with no
/// indication anything had gone wrong. Cleanup staying non-fatal is
/// still correct (the upgrade itself already succeeded or already
/// rolled back by the time this runs), but silent is not.
fn cleanup_dir(path: &Path) {
    if let Err(e) = fs::remove_dir_all(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "  {Y}WARN: could not clean up {}: {e}{RST}",
                path.display(),
                Y = ui::Y,
                RST = ui::RST
            );
        }
    }
}

fn log_audit(kind: &str, pkgs: &[String], outcome: &str, err: Option<&str>, ms: u64) {
    audit::append(AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        kind: kind.into(),
        outcome: outcome.into(),
        packages: pkgs.to_vec(),
        duration_ms: ms,
        error: err.map(str::to_string),
    })
    .ok();

    let _ = crate::cmd::install::history::record(
        crate::cmd::install::history::OperationType::Upgrade,
        pkgs.iter()
            .map(|name| crate::cmd::install::history::PackageRecord {
                name: name.clone(),
                version: String::new(),
                format: "zex".to_string(),
            })
            .collect(),
        outcome == "success",
        err.map(str::to_string),
        ms,
    );
}
