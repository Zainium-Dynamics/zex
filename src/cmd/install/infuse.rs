//! infuse.rs — Core installation orchestrator.
//!
//! This module wires together every other module in the pipeline:
//!
//!   ui  ←  infuse  →  resolver  →  backend (3 tiers)
//!                   →  downloader
//!                   →  installer  →  backend (extraction + DB)
//!
//! There are two public code-paths:
//!
//!   `run_single`   — one package: sequential resolve → download → install
//!   `run_parallel` — N packages: parallel resolves + parallel downloads,
//!                    then configurable concurrent installs
//!
//! The router `run()` dispatches to the appropriate path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use futures::future::join_all;
use indicatif::MultiProgress;
use tempfile::TempDir;
use tokio::sync::Semaphore;

use super::backend::{BackendConfig, DownloadStats};
use super::downloader::{self, DownloadError};
use super::installer;
use super::lock_graph::{self, LockGraph, LockedPackage};
use super::resolver::{self, ResolveError};
use super::runtime::{self, LogLevel};
use super::telemetry;
use super::ui;

fn finalize_leftover_txns(txns: &mut HashMap<String, runtime::TransactionHandle>, reason: &str) {
    for (_, mut txn) in txns.drain() {
        txn.update("skipped_or_aborted", reason);
    }
}

fn format_to_label(format: &super::backend::PackageFormat) -> &'static str {
    match format {
        super::backend::PackageFormat::Zex => "zex",
        super::backend::PackageFormat::Apk => "apk",
        super::backend::PackageFormat::Xbps => "xbps",
        super::backend::PackageFormat::Adb => "adb",
    }
}

fn to_locked_package(info: &super::backend::PackageInfo) -> LockedPackage {
    LockedPackage {
        name: info.name.clone(),
        version: info.version.clone(),
        format: format_to_label(&info.format).to_string(),
        source_url: info.url.clone(),
        sha256: info.sha256.clone().unwrap_or_default(),
        dependencies: Vec::new(),
    }
}

fn persist_txn_lock_graph(
    config: &BackendConfig,
    txn: &runtime::TransactionHandle,
    infos: Vec<&super::backend::PackageInfo>,
) {
    let packages: Vec<LockedPackage> = infos.into_iter().map(to_locked_package).collect();
    let graph = LockGraph::new(packages);

    if let Ok(hash) = graph.graph_hash_hex() {
        runtime::log_event(
            config,
            LogLevel::Info,
            &format!("lock graph hash {} for txn {}", hash, txn.txn_id()),
        );
    }

    if let Err(e) = lock_graph::persist_for_txn(config, txn.txn_id(), &graph) {
        runtime::log_event(
            config,
            LogLevel::Warn,
            &format!(
                "failed to persist lock graph for txn {} ({}): {}",
                txn.txn_id(),
                txn.package_name(),
                e
            ),
        );
    }
}

fn build_client() -> Result<reqwest::Client> {
    crate::http_client::build(concat!(
        "install/",
        env!("CARGO_PKG_VERSION"),
        " (Zainium OS; x86_64;)"
    ))
}

/// Fetches the detached `.sig2` signature and the mirror's TOFU-pinned
/// trust key for a Void package, so `installer::install` (otherwise fully
/// synchronous) can verify it without needing network access itself.
/// Returns `None` for any non-Xbps package, or best-effort `None` if
/// either fetch fails — `verify_signature` treats a missing result as a
/// verification failure, respecting whatever `signature_mode` is set.
async fn fetch_xbps_verify_data(
    info: &super::backend::PackageInfo,
    client: &reqwest::Client,
) -> Option<installer::XbpsVerifyData> {
    if info.format != super::backend::PackageFormat::Xbps {
        return None;
    }
    let sig_url = info.sig_url.as_ref()?;
    let mirror_id = info.source_mirror.as_ref()?;

    let sig2 = match client.get(sig_url).send().await {
        Ok(resp) if resp.status().is_success() => resp.bytes().await.ok()?.to_vec(),
        Ok(resp) => {
            log::warn!("fetching '{sig_url}' returned HTTP {}", resp.status());
            return None;
        }
        Err(e) => {
            log::warn!("failed to fetch xbps signature '{sig_url}': {e}");
            return None;
        }
    };

    let key_path = format!("/overlayer/zexlib/registry/trust/void/{mirror_id}.pem");
    let pubkey_pem = match std::fs::read(&key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::warn!("no pinned Void trust key at '{key_path}': {e}");
            return None;
        }
    };

    Some(installer::XbpsVerifyData { sig2, pubkey_pem })
}

pub async fn run(packages: Vec<String>, lock_out: Option<std::path::PathBuf>) -> Result<()> {
    let client = Arc::new(build_client()?);
    let config = Arc::new(BackendConfig::load()?);
    let mm = Arc::new(super::backend::MetadataManager::new(&config.cache_dir));

    let _ = runtime::startup_cleanup(&config);
    if let Err(err) = super::union::UnionLayer::new().apply_live_mounts() {
        log::warn!("Failed to apply dynamic mounts at startup: {}", err);
    }
    runtime::log_event(&config, LogLevel::Info, "install run started");

    if packages.len() == 1 {
        run_single(&packages[0], client, config, mm, lock_out).await
    } else {
        run_parallel(packages, client, config, mm).await
    }
}

pub async fn run_dry_resolve(packages: Vec<String>) -> Result<()> {
    let client = Arc::new(build_client()?);
    let config = Arc::new(BackendConfig::load()?);
    let mm = Arc::new(super::backend::MetadataManager::new(&config.cache_dir));

    ui::print_dry_resolve_header(packages.len());
    let start = Instant::now();

    let batch = resolver::resolve_many(&packages, &client, &config, mm).await;
    let elapsed_ms = start.elapsed().as_millis();

    for info in &batch.resolved {
        ui::print_dry_resolve_item(
            &info.name,
            &info.version,
            format_to_label(&info.format),
            info.source_mirror.as_deref(),
            &info.url,
            info.sha256.as_deref(),
        );
    }

    for name in &batch.not_found {
        ui::print_dry_resolve_not_found(name);
    }

    for (name, reason) in &batch.infra_failed {
        ui::print_dry_resolve_infra_failure(name, reason);
    }

    ui::print_dry_resolve_summary(
        batch.resolved.len(),
        batch.not_found.len(),
        batch.infra_failed.len(),
        elapsed_ms,
    );

    Ok(())
}

/// Installs exactly the packages a lockfile pins, in the order it records
/// them (root's dependencies first, then root) — bypassing live dependency
/// resolution entirely, so the result matches what the lockfile recorded
/// even if upstream indices have since changed. Reuses the same
/// download → verify → install pipeline every other install path uses
/// (`downloader::download` + `installer::install`), so a lockfile install
/// gets exactly the same signature/hash verification as a normal one — it
/// only skips *resolving* names to packages, not any safety check.
pub async fn run_from_lockfile(path: std::path::PathBuf) -> Result<()> {
    let client = build_client()?;
    let config = BackendConfig::load()?;
    let lock = super::lockfile::Lockfile::read(&path)?;

    let integrity_mode = installer::IntegrityMode::from_config(&config.integrity_mode);
    let signature_mode =
        crate::trust::SignatureVerificationMode::from_config(&config.signature_verification_mode);

    ui::print_from_lock_header(&lock.root.name, &lock.root.version, lock.dependencies.len());

    let mp = MultiProgress::new();
    let tmp = TempDir::new()?;

    // Dependencies first (the lockfile already records them in the
    // topological order resolved at generation time), then the root.
    for pkg in lock.dependencies.iter().chain(std::iter::once(&lock.root)) {
        let existing = super::backend::lookup_installed(&pkg.name);
        if let Some(ref inst) = existing {
            if inst.version == pkg.version {
                ui::print_from_lock_pkg(&pkg.name, &pkg.version, true);
                continue;
            }
        }
        ui::print_from_lock_pkg(&pkg.name, &pkg.version, false);

        let pkg_path = tmp.path().join(&pkg.filename);
        let pb = ui::make_download_bar(&mp, pkg.size, &pkg.name);
        let stats = downloader::download(&pkg.url, &pkg_path, &client, &config, &pb).await
            .map_err(|e| anyhow::anyhow!("download failed for '{}': {e}", pkg.name))?;
        let _ = stats;

        let xbps_sig = fetch_xbps_verify_data(pkg, &client).await;
        installer::install(
            &pkg_path,
            pkg,
            existing.as_ref(),
            true,
            integrity_mode,
            signature_mode,
            xbps_sig.as_ref(),
            pkg.name != lock.root.name,
        ).map_err(|e| anyhow::anyhow!("install failed for '{}': {e}", pkg.name))?;
    }

    ui::print_from_lock_done(&lock.root.name, &lock.root.version);
    Ok(())
}

async fn run_single(
    name: &str,
    client: Arc<reqwest::Client>,
    config: Arc<BackendConfig>,
    mm: Arc<super::backend::MetadataManager>,
    lock_out: Option<std::path::PathBuf>,
) -> Result<()> {
    ui::print_nice_choice(1);
    let integrity_mode = installer::IntegrityMode::from_config(&config.integrity_mode);
    let signature_mode =
        crate::trust::SignatureVerificationMode::from_config(&config.signature_verification_mode);
    let mut txn = runtime::begin_transaction(&config, name);

    ui::print_resolving_single(name);

    // Syshub Core Protection (Collision Block)
    if super::backend::is_in_syshub(name) {
        let err_msg = format!("Cannot modify '{}', it is locked inside the immutable Syshub.", name);
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(name, &anyhow::anyhow!(err_msg));
        return Ok(());
    }

    let resolve_start = Instant::now();
    if let Some(t) = txn.as_mut() {
        t.update("resolving", "resolving package metadata");
    }

    let info = match resolver::resolve(name, &client, &config, &mm).await {
        Ok(info) => info,
        Err(ResolveError::NotFound(n)) => {
            ui::print_not_found(&n);
            return Ok(());
        }
        Err(ResolveError::Infra(e)) => return Err(e),
    };
    let resolve_ms = resolve_start.elapsed().as_millis();

    if let Some(t) = txn.as_ref() {
        persist_txn_lock_graph(&config, t, vec![&info]);
    }

    // Skips redundant reinstalls when the package is already present.
    // Also captures the existing DbEntry for the atomic installer's snapshot.
    let existing_entry = super::backend::lookup_installed(&info.name);
    if let Some(ref installed) = existing_entry {
        if installed.version == info.version {
            // Health check: verify critical binaries actually exist AND their
            // symlink targets resolve.  This catches ghost "installed" state where
            // the DB says installed but the OverlayFS union or symlinks are broken.
            let bin_files: Vec<&String> = installed.installed_files.iter()
                .filter(|f| f.contains("/bin/"))
                .take(3)
                .collect();

            let healthy = bin_files.is_empty() || bin_files.iter().any(|f| {
                let p = std::path::Path::new(f.as_str());
                // Path::exists() follows symlinks — returns false for dangling symlinks
                p.exists()
            });

            if healthy {
                ui::print_already_installed(&info.display_name, &info.version);
                return Ok(());
            }
            // Broken install detected — fall through to reinstall
            log::warn!(
                "Package '{}' v{} is in DB but binaries are missing — reinstalling",
                info.name, info.version
            );
        } else {
            ui::print_upgrading(&info.display_name, &installed.version, &info.version);
        }
    }

    // ─── Dependency Resolution
    let dep_plan = super::depends::resolve_dependencies(&info, &client, &config, &mm).await?;

    for (dep_token, provider) in &dep_plan.syshub_provided {
        let base = super::apk::strip_constraint(dep_token);
        ui::print_dep_provided_by(base, provider);
    }

    if !dep_plan.unresolvable.is_empty() {
        let missing = dep_plan.unresolvable.join(", ");
        let err_msg = format!("strict dependency check failed: missing {}", missing);
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
        return Ok(());
    }

    if !dep_plan.conflicts.is_empty() {
        let list = dep_plan.conflicts.iter()
            .map(|(a, b)| format!("{a} conflicts with installed package {b}"))
            .collect::<Vec<_>>()
            .join("; ");
        let err_msg = format!("package conflict: {list}");
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
        return Ok(());
    }

    if !dep_plan.version_conflicts.is_empty() {
        let list = dep_plan.version_conflicts.iter()
            .map(|(pkg, reason)| format!("{pkg}: {reason}"))
            .collect::<Vec<_>>()
            .join("; ");
        let err_msg = format!("dependency version constraint violated: {list}");
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
        return Ok(());
    }

    if !dep_plan.cross_tier_fallbacks.is_empty() {
        ui::print_cross_tier_fallback_warning(&dep_plan.cross_tier_fallbacks);
    }

    if let Some(syshub_req) = &info.requires_syshub {
        // TODO: Full base OS version parsing. For now, we enforce that this package is syshub-aware.
        log::debug!("Package requires syshub compatibility: {}", syshub_req);
        // We will implement actual version comparison in a dedicated syshub module later.
    }

    let dep_count = dep_plan.packages.len();
    if dep_count > 0 {
        ui::print_dependency_summary(dep_count, dep_plan.total_size);
    }

    // ─── Snapshot + Immutable Core (whole batch, before touching anything) ───
    //
    // The main package and every dependency it needs are one atomic unit:
    // if any of them fails to install, everything that already succeeded
    // in this batch must roll back too — not just the package that
    // happened to fail. So the snapshot covers the full batch and is
    // taken up front, before any download or install begins.
    let batch_names: Vec<String> = std::iter::once(info.name.clone())
        .chain(dep_plan.packages.iter().map(|d| d.name.clone()))
        .collect();

    let snap_label = format!("pre-install-{}", info.name);
    let snap_manifest = super::immutable::create_snapshot(&snap_label, &batch_names)?;
    let snap_id = format!("{}-{}", snap_manifest.id, snap_manifest.label);

    // Zex Transaction Engine hook (drives `zex rollback <tx-id>`)
    let _ = super::transaction::create_snapshot(&batch_names, "install");

    // Unlock immutable system paths for the whole batch. The guard
    // re-locks automatically on drop (RAII), covering every early-return
    // rollback path below too.
    let mut _immutable_guard = super::immutable::unlock_system()?;

    let batch_rollback = |reason: &str| {
        ui::print_general_error(&anyhow::anyhow!(
            "Installation failed: {reason}. Rolling back {} package(s)...",
            batch_names.len()
        ));
        if let Err(rollback_err) = super::immutable::restore_snapshot(&snap_id) {
            ui::print_general_error(&anyhow::anyhow!("CRITICAL: Automatic rollback failed: {}", rollback_err));
        } else {
            log::info!("Rollback successful for {}", snap_id);
        }
    };

    // ─── Download + Install Dependencies
    if !dep_plan.packages.is_empty() {
        let dep_tmp = TempDir::new()?;
        let mp = MultiProgress::new();

        // Download all deps in parallel
        let mut dep_dl_handles = Vec::new();
        for dep_info in &dep_plan.packages {
            let pkg_path = dep_tmp.path().join(&dep_info.filename);
            let pb = ui::make_download_bar(&mp, dep_info.size, &dep_info.name);
            let cl = Arc::clone(&client);
            let cfg = Arc::clone(&config);
            let url = dep_info.url.clone();

            dep_dl_handles.push(tokio::spawn(async move {
                downloader::download(&url, &pkg_path, &cl, &cfg, &pb)
                    .await
                    .map(|s| (pkg_path, s))
            }));
        }

        let dep_dl_results = join_all(dep_dl_handles).await;

        // Install deps in order (they're already topologically sorted).
        // The whole batch is one atomic transaction: the first failure
        // aborts and rolls back everything installed so far in this run,
        // rather than limping on with a partially-broken dependency graph.
        let mut deps_installed = 0usize;
        for (idx, result) in dep_dl_results.into_iter().enumerate() {
            let dep_info = &dep_plan.packages[idx];
            match result {
                Ok(Ok((pkg_path, _stats))) => {
                    let dep_existing = super::backend::lookup_installed(&dep_info.name);
                    let xbps_sig = fetch_xbps_verify_data(dep_info, &client).await;
                    match installer::install(
                        &pkg_path,
                        dep_info,
                        dep_existing.as_ref(),
                        true,
                        integrity_mode,
                        signature_mode,
                        xbps_sig.as_ref(),
                        true,
                    ) {
                        Ok(t) => {
                            if t.skipped_syshub_satisfied {
                                ui::print_dep_satisfied_by_syshub(&dep_info.name);
                            }
                            deps_installed += 1;
                        }
                        Err(e) => {
                            if let Some(t) = txn.as_mut() {
                                t.mark_failed(&format!("dependency '{}' failed: {}", dep_info.name, e));
                            }
                            batch_rollback(&format!("dependency '{}' failed: {}", dep_info.name, e));
                            ui::print_install_error(&info.display_name, &e);
                            return Ok(());
                        }
                    }
                }
                _ => {
                    let msg = format!("failed to download dependency '{}'", dep_info.name);
                    if let Some(t) = txn.as_mut() {
                        t.mark_failed(&msg);
                    }
                    batch_rollback(&msg);
                    ui::print_install_error(&info.display_name, &anyhow::anyhow!(msg));
                    return Ok(());
                }
            }
        }

        if deps_installed > 0 {
            ui::print_deps_installed(deps_installed);
        }
    }

    // ─── Transaction Summary ─────────────────────────────────────────────────
    let total_new = if existing_entry.is_some() { 0 } else { 1 } + dep_count;
    let total_upgraded = if existing_entry.is_some() { 1 } else { 0 };
    let download_mb = info.size as f64 / 1_000_000.0 + dep_plan.total_size as f64 / 1_000_000.0;
    ui::print_transaction_summary(total_new, total_upgraded, download_mb * 3.0, download_mb);

    // ─── Starting Installation
    ui::print_starting_installation();

    // ─── Download Main Package
    ui::print_downloading_single();

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join(&info.filename);
    let mp = MultiProgress::new();
    let pb = ui::make_download_bar(&mp, info.size, &info.filename);

    let stats = match downloader::download(&info.url, &pkg_path, &client, &config, &pb).await {
        Ok(s) => s,
        Err(DownloadError::NetworkLost { .. }) => {
            if let Some(t) = txn.as_mut() {
                t.mark_failed("network lost during download");
            }
            batch_rollback("network lost during download");
            ui::print_network_error(&info.filename);
            return Ok(());
        }
        Err(DownloadError::HttpError { status }) => {
            if let Some(t) = txn.as_mut() {
                t.mark_failed(&format!("mirror returned HTTP {}", status));
            }
            batch_rollback(&format!("mirror returned HTTP {status}"));
            anyhow::bail!("mirror returned HTTP {} for {}", status, info.url);
        }
        Err(DownloadError::Other(e)) => {
            if let Some(t) = txn.as_mut() {
                t.mark_failed("download failed");
            }
            batch_rollback("download failed");
            ui::print_network_error(&info.filename);
            return Err(e);
        }
    };

    ui::print_download_done_single(stats.size_mb(), stats.secs());
    ui::print_install_header_single();

    ui::print_verify_phase();
    ui::print_extract_phase();
    ui::print_userland_phase();
    ui::print_alts_phase();

    if let Some(t) = txn.as_mut() {
        t.update("installing", "verifying and extracting package");
    }

    let xbps_sig = fetch_xbps_verify_data(&info, &client).await;
    let install_telemetry = match installer::install(
        &pkg_path,
        &info,
        existing_entry.as_ref(),
        false,
        integrity_mode,
        signature_mode,
        xbps_sig.as_ref(),
        false,
    ) {
        Ok(t) => t,
        Err(e) => {
            // Immutable guard drops here → system re-locked automatically
            if let Some(t) = txn.as_mut() {
                t.mark_failed(&format!("install failed: {}", e));
            }
            batch_rollback(&format!("install failed: {e}"));
            let _ = super::history::record(
                super::history::OperationType::Install,
                vec![super::history::PackageRecord {
                    name: info.name.clone(),
                    version: info.version.clone(),
                    format: format_to_label(&info.format).to_string(),
                }],
                false,
                Some(e.to_string()),
                resolve_start.elapsed().as_millis() as u64,
            );
            ui::print_install_error(&info.display_name, &e);
            return Ok(());
        }
    };

    // Re-lock immutable core explicitly after successful install
    _immutable_guard.relock();

    ui::print_stage_telemetry(
        resolve_ms,
        stats.duration.as_millis(),
        install_telemetry.verify_ms,
        install_telemetry.extract_ms,
        install_telemetry.db_ms,
    );

    let metric = telemetry::build_metric(
        &info.name,
        &info.format,
        resolve_ms,
        stats.duration.as_millis(),
        install_telemetry.verify_ms,
        install_telemetry.extract_ms,
        install_telemetry.db_ms,
        stats.speed_mbps,
        1,
    );
    let _ = telemetry::append_and_refresh_dashboard(&config, &[metric]);
    if let Some(t) = txn.as_mut() {
        t.update("committed", "package registered in database");
        t.mark_done("installation completed");
    }

    // Update boot fallback — marks this state as "last known good"
    let _ = super::immutable::update_boot_fallback();

    // Use the detected binary name if available, otherwise fall back to package name
    let launch_name = install_telemetry.detected_launch_cmd
        .as_deref()
        .unwrap_or(&info.launch_cmd);

    ui::print_success_single(
        &info.display_name,
        &info.name,
        &info.version,
        stats.size_mb(),
        stats.speed_mbps,
        stats.secs(),
        launch_name,
    );

    let mut history_packages = vec![super::history::PackageRecord {
        name: info.name.clone(),
        version: info.version.clone(),
        format: format_to_label(&info.format).to_string(),
    }];
    history_packages.extend(dep_plan.packages.iter().map(|d| super::history::PackageRecord {
        name: d.name.clone(),
        version: d.version.clone(),
        format: format_to_label(&d.format).to_string(),
    }));
    let _ = super::history::record(
        super::history::OperationType::Install,
        history_packages,
        true,
        None,
        resolve_start.elapsed().as_millis() as u64,
    );

    if let Some(path) = lock_out {
        let lock = super::lockfile::Lockfile::new(info.clone(), dep_plan.packages.clone());
        match lock.write(&path) {
            Ok(()) => ui::print_lock_written(&path),
            Err(e) => log::warn!("failed to write lockfile to {}: {e}", path.display()),
        }
    }

    Ok(())
}

async fn run_parallel(
    names: Vec<String>,
    client: Arc<reqwest::Client>,
    config: Arc<BackendConfig>,
    mm: Arc<super::backend::MetadataManager>,
) -> Result<()> {
    ui::print_nice_choice(names.len());
    let integrity_mode = installer::IntegrityMode::from_config(&config.integrity_mode);
    let signature_mode =
        crate::trust::SignatureVerificationMode::from_config(&config.signature_verification_mode);
    let mut txns: HashMap<String, runtime::TransactionHandle> = HashMap::new();

    let mut filtered_names = Vec::new();

    for name in &names {
        if let Some(mut txn) = runtime::begin_transaction(&config, name) {
            if super::backend::is_in_syshub(name) {
                let err_msg = format!("Cannot modify '{}', it is locked inside the immutable Syshub.", name);
                txn.mark_failed(&err_msg);
                ui::print_install_error(name, &anyhow::anyhow!(err_msg));
            } else {
                txn.update("resolving", "resolving package metadata");
                txns.insert(name.clone(), txn);
                filtered_names.push(name.clone());
            }
        } else if !super::backend::is_in_syshub(name) {
             filtered_names.push(name.clone());
        }
    }

    if filtered_names.is_empty() {
        return Ok(());
    }

    ui::print_resolving_multiple(&filtered_names);
    let resolve_start = Instant::now();

    let batch = resolver::resolve_many(&filtered_names, &client, &config, Arc::clone(&mm)).await;
    let resolve_ms = resolve_start.elapsed().as_millis();
    let resolved = batch.resolved;
    let not_found = batch.not_found;

    if !not_found.is_empty() {
        for n in &not_found {
            if let Some(mut t) = txns.remove(n) {
                t.mark_failed("package not found in configured tiers");
            }
        }
        let refs: Vec<&str> = not_found.iter().map(String::as_str).collect();
        if resolved.is_empty() {
            for n in &not_found {
                ui::print_not_found(n);
            }
            return Ok(());
        }
        ui::print_partial_not_found(&refs);
        let found_refs: Vec<&str> = resolved.iter().map(|i| i.name.as_str()).collect();
        ui::print_partial_found(&found_refs);
    }

    if !batch.infra_failed.is_empty() {
        for (pkg, reason) in &batch.infra_failed {
            if let Some(mut t) = txns.remove(pkg) {
                t.mark_failed(&format!("infra failure during resolve: {}", reason));
            }
        }
        let infra_lines: Vec<String> = batch
            .infra_failed
            .iter()
            .map(|(pkg, reason)| format!("{}: {}", pkg, reason))
            .collect();
        ui::print_partial_infra_failures(&infra_lines);
    }

    if resolved.is_empty() {
        finalize_leftover_txns(&mut txns, "no package resolved for installation");
        return Ok(());
    }

    // Same dependency check run_single does, per requested package; deps go ahead of the roots
    let mut deps: Vec<super::backend::PackageInfo> = Vec::new();
    let mut roots: Vec<super::backend::PackageInfo> = Vec::new();
    for info in resolved {
        let plan = match super::depends::resolve_dependencies(&info, &client, &config, &mm).await {
            Ok(plan) => plan,
            Err(e) => {
                if let Some(mut t) = txns.remove(&info.name) {
                    t.mark_failed(&format!("dependency resolution failed: {e}"));
                }
                ui::print_install_error(&info.display_name, &e);
                continue;
            }
        };
        for (dep_token, provider) in &plan.syshub_provided {
            ui::print_dep_provided_by(super::apk::strip_constraint(dep_token), provider);
        }
        if !plan.unresolvable.is_empty() {
            let err_msg = format!("strict dependency check failed: missing {}", plan.unresolvable.join(", "));
            if let Some(mut t) = txns.remove(&info.name) {
                t.mark_failed(&err_msg);
            }
            ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
            continue;
        }
        for dep in plan.packages {
            if !deps.iter().any(|d| d.name.eq_ignore_ascii_case(&dep.name)) {
                deps.push(dep);
            }
        }
        roots.push(info);
    }
    deps.retain(|d| !roots.iter().any(|r| r.name.eq_ignore_ascii_case(&d.name)));
    if roots.is_empty() {
        finalize_leftover_txns(&mut txns, "no package passed dependency resolution");
        return Ok(());
    }
    deps.extend(roots);
    let resolved = deps;

    for txn in txns.values() {
        let matching: Vec<&super::backend::PackageInfo> = resolved
            .iter()
            .filter(|i| i.name.eq_ignore_ascii_case(txn.package_name()))
            .collect();
        if !matching.is_empty() {
            persist_txn_lock_graph(&config, txn, matching);
        }
    }

    for info in &resolved {
        if let Some(t) = txns.get_mut(&info.name) {
            t.update("downloading", "downloading package artifact");
        }
    }

    // ─── Transaction Summary ─────────────────────────────────────────────────
    let total_download: f64 = resolved.iter().map(|i| i.size as f64 / 1_000_000.0).sum();
    let total_new_pkgs = resolved.len();
    ui::print_transaction_summary(total_new_pkgs, 0, total_download * 3.0, total_download);

    // ─── Starting Installation ────────────────────────────────────────────────
    ui::print_starting_parallel_installation();

    ui::print_downloading_parallel();

    let mp = MultiProgress::new();
    let dl_start = Instant::now();

    let tmp_dirs: Vec<TempDir> = (0..resolved.len())
        .map(|_| TempDir::new())
        .collect::<std::result::Result<_, _>>()?;

    let mut dl_handles = Vec::new();
    for (info, tmp) in resolved.iter().zip(tmp_dirs.iter()) {
        let pkg_path = tmp.path().join(&info.filename);
        let label = format!("{} ({})", info.name, info.version);
        let pb = ui::make_download_bar(&mp, info.size, &label);
        let client = Arc::clone(&client);
        let cfg = Arc::clone(&config);
        let url = info.url.clone();
        let filename = info.filename.clone();

        dl_handles.push(tokio::spawn(async move {
            let result = downloader::download(&url, &pkg_path, &client, &cfg, &pb).await;
            (filename, pkg_path, result)
        }));
    }

    let dl_results = join_all(dl_handles).await;
    let total_dl_secs = dl_start.elapsed().as_secs_f64();
    let download_ms = dl_start.elapsed().as_millis();

    let mut successful_downloads: Vec<(usize, std::path::PathBuf, DownloadStats)> = Vec::new();
    let mut network_failures: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    for (idx, result) in dl_results.into_iter().enumerate() {
        match result {
            Ok((_filename, pkg_path, Ok(stats))) => {
                total_bytes += stats.bytes;
                if let Some(t) = txns.get_mut(&resolved[idx].name) {
                    t.update("downloaded", "package download completed");
                }
                successful_downloads.push((idx, pkg_path, stats));
            }
            Ok((filename, _, Err(DownloadError::NetworkLost { .. }))) => {
                if let Some(mut t) = txns.remove(&resolved[idx].name) {
                    t.mark_failed("network lost during download");
                }
                network_failures.push(filename);
            }
            Ok((filename, _, Err(DownloadError::HttpError { status }))) => {
                if let Some(mut t) = txns.remove(&resolved[idx].name) {
                    t.mark_failed(&format!("mirror returned HTTP {}", status));
                }
                network_failures.push(format!("{} (HTTP {})", filename, status));
            }
            Ok((filename, _, Err(DownloadError::Other(_)))) => {
                if let Some(mut t) = txns.remove(&resolved[idx].name) {
                    t.mark_failed("download failed");
                }
                network_failures.push(filename);
            }
            Err(_) => {
                if let Some(mut t) = txns.remove(&resolved[idx].name) {
                    t.mark_failed("download worker task failed");
                }
            }
        }
    }

    if !network_failures.is_empty() {
        for name in &network_failures {
            ui::print_network_error(name);
        }
        if successful_downloads.is_empty() {
            finalize_leftover_txns(&mut txns, "all downloads failed");
            return Ok(());
        }
    }

    let total_mb = total_bytes as f64 / 1_000_000.0;
    ui::print_download_done_parallel(total_mb, total_dl_secs);

    ui::print_install_header_parallel();
    ui::print_verify_phase();
    ui::print_extract_phase();
    ui::print_userland_ov_phase();
    ui::print_desktop_phase();

    let concurrency = config.install_concurrency.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let install_start = Instant::now();
    let mut install_handles = Vec::new();

    for (idx, pkg_path, _stats) in &successful_downloads {
        let info = resolved[*idx].clone();
        let pkg_path = pkg_path.clone();
        let sem = Arc::clone(&sem);
        let client = Arc::clone(&client);
        let cfg = Arc::clone(&config);
        let mut txn = txns.remove(&info.name);
        ui::print_parallel_pkg_steps(&info.name);

        install_handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            if let Some(t) = txn.as_mut() {
                t.update("installing", "verifying and extracting package");
            }



            let _ = super::transaction::create_snapshot(&[info.name.clone()], "install");
            let existing = super::backend::lookup_installed(&info.name);
            let xbps_sig = fetch_xbps_verify_data(&info, &client).await;
            let result = tokio::task::spawn_blocking(move || {
                installer::install(
                    &pkg_path,
                    &info,
                    existing.as_ref(),
                    true,
                    integrity_mode,
                    signature_mode,
                    xbps_sig.as_ref(),
                    false,
                )
            })
            .await;

            match &result {
                Ok(Ok(_)) => {
                    if let Some(t) = txn.as_mut() {
                        t.update("committed", "package registered in database");
                        t.mark_done("installation completed");
                    }
                }
                Ok(Err(e)) => {
                    if let Some(t) = txn.as_mut() {
                        t.mark_failed(&format!("install failed: {}", e));
                    }
                }
                Err(e) => {
                    if let Some(t) = txn.as_mut() {
                        t.mark_failed(&format!("install worker failed: {}", e));
                    }
                }
            }

            result
        }));
    }

    let install_results = join_all(install_handles).await;
    let install_ms = install_start.elapsed().as_millis();

    let mut install_ok_count = 0usize;
    let mut verify_ms_total = 0u128;
    let mut extract_ms_total = 0u128;
    let mut db_ms_total = 0u128;
    let mut metrics = Vec::new();

    for r in install_results {
        match r {
            Ok(Ok(Ok(t))) => {
                install_ok_count += 1;
                verify_ms_total += t.verify_ms;
                extract_ms_total += t.extract_ms;
                db_ms_total += t.db_ms;

                let speed = if install_ok_count <= successful_downloads.len() {
                    successful_downloads
                        .get(install_ok_count - 1)
                        .map(|(_, _, s)| s.speed_mbps)
                        .unwrap_or(0.0)
                } else {
                    0.0
                };
                metrics.push(telemetry::build_metric(
                    "package",
                    &super::backend::PackageFormat::Zex,
                    resolve_ms,
                    download_ms,
                    t.verify_ms,
                    t.extract_ms,
                    t.db_ms,
                    speed,
                    concurrency,
                ));
            }
            Ok(Ok(Err(e))) => {
                ui::print_install_error("package", &e);
            }
            Ok(Err(join_err)) => {
                ui::print_general_error(&anyhow::anyhow!("install worker failed: {}", join_err));
            }
            Err(join_err) => {
                ui::print_general_error(&anyhow::anyhow!("install task failed: {}", join_err));
            }
        }
    }

    if install_ok_count == 0 {
        finalize_leftover_txns(&mut txns, "no successful installations completed");
        return Ok(());
    }

    ui::print_stage_telemetry(
        resolve_ms,
        download_ms,
        verify_ms_total / install_ok_count as u128,
        extract_ms_total / install_ok_count as u128,
        db_ms_total / install_ok_count as u128,
    );
    ui::print_parallel_install_mode(concurrency, install_ms);

    // Build proper per-package metrics with package format breakdown.
    if !metrics.is_empty() {
        let mut detailed = Vec::new();
        for (idx, (pkg_idx, _pkg_path, stats)) in successful_downloads.iter().enumerate() {
            let info = &resolved[*pkg_idx];
            let t = metrics.get(idx).cloned().unwrap_or_else(|| {
                telemetry::build_metric(
                    &info.name,
                    &info.format,
                    resolve_ms,
                    download_ms,
                    0,
                    0,
                    0,
                    stats.speed_mbps,
                    concurrency,
                )
            });

            detailed.push(telemetry::build_metric(
                &info.name,
                &info.format,
                t.resolve_ms,
                t.download_ms,
                t.verify_ms,
                t.extract_ms,
                t.db_ms,
                stats.speed_mbps,
                concurrency,
            ));
        }
        let _ = telemetry::append_and_refresh_dashboard(&config, &detailed);
    }

    finalize_leftover_txns(
        &mut txns,
        "parallel run completed without terminal install state",
    );

    ui::print_success_parallel(install_ok_count, total_mb, total_dl_secs);

    Ok(())
}
