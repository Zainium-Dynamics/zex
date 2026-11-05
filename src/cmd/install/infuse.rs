//! infuse.rs: Core installation orchestrator.

use std::collections::{HashMap, HashSet};
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

/// Errors were already printed per package; main only turns this into exit 1.
#[derive(Debug)]
pub struct InstallFailed;

impl std::fmt::Display for InstallFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("installation failed")
    }
}

impl std::error::Error for InstallFailed {}

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
/// either fetch fails: `verify_signature` treats a missing result as a
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
/// them (root's dependencies first, then root): bypassing live dependency
/// resolution entirely, so the result matches what the lockfile recorded
/// even if upstream indices have since changed. Reuses the same
/// download → verify → install pipeline every other install path uses
/// (`downloader::download` + `installer::install`), so a lockfile install
/// gets exactly the same signature/hash verification as a normal one: it
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
        let stats = downloader::download(&pkg.url, &pkg_path, &client, &config, &pb)
            .await
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
            true,
        )
        .map_err(|e| anyhow::anyhow!("install failed for '{}': {e}", pkg.name))?;
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
    let lib_ctx = LibContext {
        client: &client,
        config: &config,
        mm: &mm,
        integrity_mode,
        signature_mode,
        planned: Default::default(),
    };
    let mut txn = runtime::begin_transaction(&config, name);

    ui::print_resolving_single(name);

    if let Some(err_msg) = base_refusal(name) {
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(name, &anyhow::anyhow!(err_msg));
        return Err(InstallFailed.into());
    }

    let resolve_start = Instant::now();
    if let Some(t) = txn.as_mut() {
        t.update("resolving", "resolving package metadata");
    }

    let info = match resolver::resolve(name, &client, &config, &mm).await {
        Ok(info) => info,
        Err(ResolveError::NotFound(n)) => {
            ui::print_not_found(&n);
            return Err(InstallFailed.into());
        }
        Err(ResolveError::Infra(e)) if e.to_string() == resolver::UNREACHABLE => {
            ui::print_unreachable();
            return Err(InstallFailed.into());
        }
        Err(ResolveError::Infra(e)) => return Err(e),
    };
    let resolve_ms = resolve_start.elapsed().as_millis();

    if let Some(t) = txn.as_ref() {
        persist_txn_lock_graph(&config, t, vec![&info]);
    }

    let existing_entry = super::backend::lookup_installed(&info.name);
    if let Some(ref installed) = existing_entry {
        if installed.version == info.version {
            let bin_files: Vec<&String> = installed
                .installed_files
                .iter()
                .filter(|f| f.contains("/bin/"))
                .take(3)
                .collect();

            let healthy = bin_files.is_empty()
                || bin_files.iter().any(|f| {
                    let p = std::path::Path::new(f.as_str());
                    p.exists()
                });

            if super::installer::reinstalling() {
                ui::print_reinstalling(&info.display_name, &info.version);
            } else if healthy {
                ui::print_already_installed(&info.display_name, &info.version);
                return Ok(());
            } else {
                log::warn!(
                    "Package '{}' v{} is in DB but binaries are missing — reinstalling",
                    info.name,
                    info.version
                );
            }
        } else {
            ui::print_upgrading(&info.display_name, &installed.version, &info.version);
        }
    }

    let dep_plan = super::depends::resolve_dependencies(&info, &client, &config, &mm).await?;
    lib_ctx.plan(dep_plan.packages.iter().chain(std::iter::once(&info)));

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
        return Err(InstallFailed.into());
    }

    if !dep_plan.conflicts.is_empty() {
        let list = dep_plan
            .conflicts
            .iter()
            .map(|(a, b)| format!("{a} conflicts with installed package {b}"))
            .collect::<Vec<_>>()
            .join("; ");
        let err_msg = format!("package conflict: {list}");
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
        return Err(InstallFailed.into());
    }

    if !dep_plan.version_conflicts.is_empty() {
        let list = dep_plan
            .version_conflicts
            .iter()
            .map(|(pkg, reason)| format!("{pkg}: {reason}"))
            .collect::<Vec<_>>()
            .join("; ");
        let err_msg = format!("dependency version constraint violated: {list}");
        if let Some(t) = txn.as_mut() {
            t.mark_failed(&err_msg);
        }
        ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
        return Err(InstallFailed.into());
    }

    if !dep_plan.cross_tier_fallbacks.is_empty() {
        ui::print_cross_tier_fallback_warning(&dep_plan.cross_tier_fallbacks);
    }

    if let Some(syshub_req) = &info.requires_syshub {
        log::debug!("Package requires syshub compatibility: {}", syshub_req);
    }

    let dep_count = dep_plan.packages.len();
    if dep_count > 0 {
        ui::print_dependency_summary(dep_count, dep_plan.total_size);
    }

    let batch_names: Vec<String> = std::iter::once(info.name.clone())
        .chain(dep_plan.packages.iter().map(|d| d.name.clone()))
        .collect();

    let snap_label = format!("pre-install-{}", info.name);
    let snap_manifest = super::immutable::create_snapshot(&snap_label, &batch_names)?;
    let snap_id = format!("{}-{}", snap_manifest.id, snap_manifest.label);

    let _ = super::transaction::create_snapshot(&batch_names, "install");

    let mut _immutable_guard = super::immutable::unlock_system()?;

    let batch_rollback = |reason: &str| {
        ui::print_general_error(&anyhow::anyhow!(
            "Installation failed: {reason}. Rolling back {} package(s)...",
            batch_names.len()
        ));
        if let Err(rollback_err) = super::immutable::restore_snapshot(&snap_id) {
            ui::print_general_error(&anyhow::anyhow!(
                "CRITICAL: Automatic rollback failed: {}",
                rollback_err
            ));
        } else {
            log::info!("Rollback successful for {}", snap_id);
        }
    };

    if !dep_plan.packages.is_empty() {
        let dep_tmp = TempDir::new()?;
        let mp = MultiProgress::new();

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

        let mut deps_installed = 0usize;
        for (idx, result) in dep_dl_results.into_iter().enumerate() {
            let dep_info = &dep_plan.packages[idx];
            match result {
                Ok(Ok((pkg_path, _stats))) => {
                    let dep_existing = super::backend::lookup_installed(&dep_info.name);
                    match install_checked(
                        &pkg_path,
                        dep_info,
                        dep_existing.as_ref(),
                        true,
                        true,
                        &lib_ctx,
                        0,
                    )
                    .await
                    {
                        Ok(t) => {
                            if t.skipped_syshub_satisfied {
                                ui::print_dep_satisfied_by_syshub(&dep_info.name);
                            }
                            deps_installed += 1;
                        }
                        Err(e) => {
                            if let Some(t) = txn.as_mut() {
                                t.mark_failed(&format!(
                                    "dependency '{}' failed: {}",
                                    dep_info.name, e
                                ));
                            }
                            batch_rollback(&format!(
                                "dependency '{}' failed: {}",
                                dep_info.name, e
                            ));
                            ui::print_install_error(&dep_info.name, &e);
                            return Err(InstallFailed.into());
                        }
                    }
                }
                _ => {
                    let msg = format!("failed to download dependency '{}'", dep_info.name);
                    if let Some(t) = txn.as_mut() {
                        t.mark_failed(&msg);
                    }
                    batch_rollback(&msg);
                    ui::print_download_error(&dep_info.name, &msg);
                    return Err(InstallFailed.into());
                }
            }
        }

        if deps_installed > 0 {
            ui::print_deps_installed(deps_installed);
        }
    }

    let total_new = if existing_entry.is_some() { 0 } else { 1 } + dep_count;
    let total_upgraded = if existing_entry.is_some() { 1 } else { 0 };
    let download_mb = info.size as f64 / 1_000_000.0 + dep_plan.total_size as f64 / 1_000_000.0;
    ui::print_transaction_summary(total_new, total_upgraded, download_mb * 3.0, download_mb);

    ui::print_starting_installation();

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
            ui::print_network_error(&info.display_name);
            return Err(InstallFailed.into());
        }
        Err(DownloadError::HttpError { status }) => {
            if let Some(t) = txn.as_mut() {
                t.mark_failed(&format!("mirror returned HTTP {}", status));
            }
            batch_rollback(&format!("mirror returned HTTP {status}"));
            ui::print_download_error(
                &info.display_name,
                &format!("mirror returned HTTP {status} for {}", info.url),
            );
            return Err(InstallFailed.into());
        }
        Err(DownloadError::Other(e)) => {
            if let Some(t) = txn.as_mut() {
                t.mark_failed("download failed");
            }
            batch_rollback("download failed");
            ui::print_download_error(&info.display_name, &format!("{e:#}"));
            return Err(InstallFailed.into());
        }
    };

    ui::print_download_done_single(stats.size_mb(), stats.secs());
    ui::print_install_header_single();

    if let Some(t) = txn.as_mut() {
        t.update("installing", "verifying and extracting package");
    }

    let _xbps_sig = fetch_xbps_verify_data(&info, &client).await;
    let install_telemetry = match install_checked(
        &pkg_path,
        &info,
        existing_entry.as_ref(),
        false,
        false,
        &lib_ctx,
        0,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
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
            return Err(InstallFailed.into());
        }
    };

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

    let _ = super::immutable::update_boot_fallback();

    let launch_name = install_telemetry
        .detected_launch_cmd
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
    history_packages.extend(
        dep_plan
            .packages
            .iter()
            .map(|d| super::history::PackageRecord {
                name: d.name.clone(),
                version: d.version.clone(),
                format: format_to_label(&d.format).to_string(),
            }),
    );
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
    let lib_ctx = LibContext {
        client: &client,
        config: &config,
        mm: &mm,
        integrity_mode,
        signature_mode,
        planned: Default::default(),
    };
    let mut txns: HashMap<String, runtime::TransactionHandle> = HashMap::new();
    let mut failed: Vec<String> = Vec::new();

    let mut filtered_names = Vec::new();

    for name in &names {
        if let Some(mut txn) = runtime::begin_transaction(&config, name) {
            if let Some(err_msg) = base_refusal(name) {
                txn.mark_failed(&err_msg);
                ui::print_install_error(name, &anyhow::anyhow!(err_msg));
                failed.push(name.clone());
            } else {
                txn.update("resolving", "resolving package metadata");
                txns.insert(name.clone(), txn);
                filtered_names.push(name.clone());
            }
        } else if base_refusal(name).is_none() {
            filtered_names.push(name.clone());
        }
    }

    if filtered_names.is_empty() {
        return Err(InstallFailed.into());
    }

    ui::print_resolving_multiple(&filtered_names);
    let resolve_start = Instant::now();

    let batch = resolver::resolve_many(&filtered_names, &client, &config, Arc::clone(&mm)).await;
    let resolve_ms = resolve_start.elapsed().as_millis();
    let resolved = batch.resolved;
    let not_found = batch.not_found;

    if resolved.is_empty()
        && not_found.is_empty()
        && !batch.infra_failed.is_empty()
        && batch
            .infra_failed
            .iter()
            .all(|(_, r)| r == resolver::UNREACHABLE)
    {
        for (pkg, reason) in &batch.infra_failed {
            if let Some(mut t) = txns.remove(pkg) {
                t.mark_failed(&format!("infra failure during resolve: {}", reason));
            }
        }
        ui::print_unreachable();
        return Err(InstallFailed.into());
    }

    if !not_found.is_empty() {
        for n in &not_found {
            if let Some(mut t) = txns.remove(n) {
                t.mark_failed("package not found in configured tiers");
            }
        }
        let refs: Vec<&str> = not_found.iter().map(String::as_str).collect();
        let did_you_mean =
            resolver::joined_suggestions(&filtered_names, &not_found, &client, &config, &mm).await;
        if resolved.is_empty() {
            for n in &not_found {
                ui::print_not_found(n);
            }
            if !did_you_mean.is_empty() {
                ui::print_did_you_mean(&did_you_mean);
            }
            return Err(InstallFailed.into());
        }
        ui::print_partial_not_found(&refs);
        if !did_you_mean.is_empty() {
            ui::print_did_you_mean(&did_you_mean);
        }
        let found_refs: Vec<&str> = resolved.iter().map(|i| i.name.as_str()).collect();
        ui::print_partial_found(&found_refs);
        failed.extend(not_found.iter().cloned());
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
        failed.extend(batch.infra_failed.iter().map(|(pkg, _)| pkg.clone()));
    }

    if resolved.is_empty() {
        finalize_leftover_txns(&mut txns, "no package resolved for installation");
        return Err(InstallFailed.into());
    }

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
                failed.push(info.name.clone());
                continue;
            }
        };
        for (dep_token, provider) in &plan.syshub_provided {
            ui::print_dep_provided_by(super::apk::strip_constraint(dep_token), provider);
        }
        if !plan.unresolvable.is_empty() {
            let err_msg = format!(
                "strict dependency check failed: missing {}",
                plan.unresolvable.join(", ")
            );
            if let Some(mut t) = txns.remove(&info.name) {
                t.mark_failed(&err_msg);
            }
            ui::print_install_error(&info.display_name, &anyhow::anyhow!(err_msg));
            failed.push(info.name.clone());
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
        return Err(InstallFailed.into());
    }
    let root_names: HashSet<String> = roots.iter().map(|r| r.name.clone()).collect();
    deps.extend(roots);
    let resolved = deps;
    lib_ctx.plan(resolved.iter());

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

    let total_download: f64 = resolved.iter().map(|i| i.size as f64 / 1_000_000.0).sum();
    let total_new_pkgs = resolved.len();
    ui::print_transaction_summary(total_new_pkgs, 0, total_download * 3.0, total_download);

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
    let mut offline: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    for (idx, result) in dl_results.into_iter().enumerate() {
        let name = resolved[idx].name.clone();
        let reason = match result {
            Ok((_filename, pkg_path, Ok(stats))) => {
                total_bytes += stats.bytes;
                if let Some(t) = txns.get_mut(&name) {
                    t.update("downloaded", "package download completed");
                }
                successful_downloads.push((idx, pkg_path, stats));
                continue;
            }
            Ok((_, _, Err(DownloadError::NetworkLost { .. }))) => {
                offline.push(name.clone());
                "network lost during download".to_string()
            }
            Ok((_, _, Err(DownloadError::HttpError { status }))) => {
                format!("mirror returned HTTP {status}")
            }
            Ok((_, _, Err(DownloadError::Other(e)))) => format!("{e:#}"),
            Err(e) => format!("download worker task failed: {e}"),
        };
        if let Some(mut t) = txns.remove(&name) {
            t.mark_failed(&reason);
        }
        if !offline.contains(&name) {
            ui::print_download_error(&name, &reason);
        }
        failed.push(name);
    }

    if !offline.is_empty() {
        ui::print_network_error(&offline.join(", "));
    }

    let total_mb = total_bytes as f64 / 1_000_000.0;
    if successful_downloads.is_empty() {
        finalize_leftover_txns(&mut txns, "all downloads failed");
        ui::print_success_parallel(0, &failed, total_mb, total_dl_secs);
        return Err(InstallFailed.into());
    }

    ui::print_download_done_parallel(total_mb, total_dl_secs);

    ui::print_install_header_parallel();
    let n_pkgs = successful_downloads.len();
    ui::print_install_step(&format!(
        "Installing {n_pkgs} package{}",
        if n_pkgs == 1 { "" } else { "s" }
    ));

    let concurrency = config.install_concurrency.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let install_start = Instant::now();
    let mut install_handles = Vec::new();
    let mut install_pkgs = Vec::new();

    let mut retry_inputs = Vec::new();
    for (idx, pkg_path, stats) in &successful_downloads {
        let info = resolved[*idx].clone();
        install_pkgs.push((info.name.clone(), info.format.clone(), stats.speed_mbps));
        retry_inputs.push((
            pkg_path.clone(),
            info.clone(),
            !root_names.contains(&info.name),
        ));
        let pkg_path = pkg_path.clone();
        let sem = Arc::clone(&sem);
        let client = Arc::clone(&client);
        let _cfg = Arc::clone(&config);
        let mut txn = txns.remove(&info.name);
        let is_dependency = !root_names.contains(&info.name);
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
                    is_dependency,
                    false,
                )
            })
            .await;

            match &result {
                Ok(Ok(t)) if t.held_back => {}
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
    crate::steps::finish();
    let install_ms = install_start.elapsed().as_millis();

    let mut install_ok_count = 0usize;
    let mut verify_ms_total = 0u128;
    let mut extract_ms_total = 0u128;
    let mut db_ms_total = 0u128;
    let mut metrics = Vec::new();

    for (((name, format, speed), r), (retry_path, retry_info, retry_dep)) in install_pkgs
        .into_iter()
        .zip(install_results)
        .zip(retry_inputs)
    {
        let r = match r {
            Ok(Ok(Ok(t))) if t.held_back => {
                let existing = super::backend::lookup_installed(&retry_info.name);
                Ok(Ok(install_checked(
                    &retry_path,
                    &retry_info,
                    existing.as_ref(),
                    true,
                    retry_dep,
                    &lib_ctx,
                    0,
                )
                .await))
            }
            other => other,
        };
        match r {
            Ok(Ok(Ok(t))) => {
                install_ok_count += 1;
                verify_ms_total += t.verify_ms;
                extract_ms_total += t.extract_ms;
                db_ms_total += t.db_ms;
                metrics.push(telemetry::build_metric(
                    &name,
                    &format,
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
                ui::print_install_error(&name, &e);
                failed.push(name);
            }
            Ok(Err(join_err)) => {
                ui::print_install_error(
                    &name,
                    &anyhow::anyhow!("install worker failed: {}", join_err),
                );
                failed.push(name);
            }
            Err(join_err) => {
                ui::print_install_error(
                    &name,
                    &anyhow::anyhow!("install task failed: {}", join_err),
                );
                failed.push(name);
            }
        }
    }

    if install_ok_count == 0 {
        finalize_leftover_txns(&mut txns, "no successful installations completed");
        ui::print_success_parallel(0, &failed, total_mb, total_dl_secs);
        return Err(InstallFailed.into());
    }

    ui::print_stage_telemetry(
        resolve_ms,
        download_ms,
        verify_ms_total / install_ok_count as u128,
        extract_ms_total / install_ok_count as u128,
        db_ms_total / install_ok_count as u128,
    );
    ui::print_parallel_install_mode(concurrency, install_ms);

    if !metrics.is_empty() {
        let _ = telemetry::append_and_refresh_dashboard(&config, &metrics);
    }

    finalize_leftover_txns(
        &mut txns,
        "parallel run completed without terminal install state",
    );

    ui::print_success_parallel(install_ok_count, &failed, total_mb, total_dl_secs);

    if failed.is_empty() {
        Ok(())
    } else {
        Err(InstallFailed.into())
    }
}

/// What installing library providers needs from the surrounding install run.
struct LibContext<'a> {
    client: &'a reqwest::Client,
    config: &'a BackendConfig,
    mm: &'a super::backend::MetadataManager,
    integrity_mode: installer::IntegrityMode,
    signature_mode: crate::trust::SignatureVerificationMode,
    /// Libraries the packages of this same install provide.
    planned: std::cell::RefCell<HashSet<String>>,
}

impl LibContext<'_> {
    /// Remembers the libraries `packages` provide (their `so:`/library provides).
    fn plan<'p>(&self, packages: impl Iterator<Item = &'p super::backend::PackageInfo>) {
        let mut planned = self.planned.borrow_mut();
        for p in packages {
            for prov in &p.provides {
                let lib = prov
                    .split(['=', '>', '<', '~'])
                    .next()
                    .unwrap_or(prov)
                    .trim();
                let lib = lib.strip_prefix("so:").unwrap_or(lib);
                if lib.contains(".so") {
                    planned.insert(lib.to_string());
                }
            }
        }
    }

    /// `missing` without the libraries a package of this same install will provide.
    fn not_planned(&self, missing: &[String]) -> Vec<String> {
        let planned = self.planned.borrow();
        missing
            .iter()
            .filter(|l| !planned.contains(*l))
            .cloned()
            .collect()
    }
}

/// Deepest chain of "this library's package needs another library" followed.
const MAX_LIB_DEPTH: usize = 4;

/// Installs `info` only once every library its programs link against exists:
/// missing ones are installed from whichever repository provides them, and a
/// package whose libraries no repository provides is installed only if the
/// user confirms after checking it.
fn install_checked<'a>(
    pkg_path: &'a std::path::Path,
    info: &'a super::backend::PackageInfo,
    existing: Option<&'a super::backend::DbEntry>,
    parallel: bool,
    is_dependency: bool,
    ctx: &'a LibContext<'a>,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<installer::InstallTelemetry>> + 'a>>
{
    Box::pin(async move {
        let xbps_sig = fetch_xbps_verify_data(info, ctx.client).await;
        let attempt = |allow: bool| {
            installer::install(
                pkg_path,
                info,
                existing,
                parallel,
                ctx.integrity_mode,
                ctx.signature_mode,
                xbps_sig.as_ref(),
                is_dependency,
                allow,
            )
        };

        let t = attempt(false)?;
        if !t.held_back {
            return Ok(t);
        }
        let missing = ctx.not_planned(&t.missing_libs);
        if missing.is_empty() {
            return attempt(true);
        }
        ui::print_missing_libs(&info.display_name, &missing);
        if depth < MAX_LIB_DEPTH {
            install_library_providers(&missing, ctx, depth + 1).await;
        }

        let t = attempt(false)?;
        if !t.held_back {
            return Ok(t);
        }
        let missing = ctx.not_planned(&t.missing_libs);
        if missing.is_empty() {
            return attempt(true);
        }
        if ui::confirm_unprovided_libs(&info.display_name, &missing) {
            attempt(true)
        } else {
            anyhow::bail!(
                "not installed: no repository provides {}",
                missing.join(", ")
            )
        }
    })
}

/// Installs, for each missing library, the first package that really provides
/// it (see `libcheck::provider_requests`). Failures are left for the caller's
/// retry to report.
async fn install_library_providers(missing: &[String], ctx: &LibContext<'_>, depth: usize) {
    let Ok(tmp) = TempDir::new() else { return };
    for lib in super::libcheck::still_missing(missing) {
        if super::libcheck::still_missing(std::slice::from_ref(&lib)).is_empty() {
            continue;
        }
        for request in super::libcheck::provider_requests(&lib) {
            let Ok(provider) = resolver::resolve(&request, ctx.client, ctx.config, ctx.mm).await
            else {
                continue;
            };
            if !super::libcheck::provides_library(&provider.provides, &lib)
                || super::blocked::provided_by(&provider.name.to_ascii_lowercase()).is_some()
            {
                continue;
            }
            let existing = super::backend::lookup_installed(&provider.name);
            if existing
                .as_ref()
                .is_some_and(|e| e.version == provider.version)
            {
                continue;
            }
            ui::print_library_provider(&lib, &provider.name, &provider.version);
            let path = tmp.path().join(&provider.filename);
            let pb = indicatif::ProgressBar::hidden();
            if downloader::download(&provider.url, &path, ctx.client, ctx.config, &pb)
                .await
                .is_err()
            {
                continue;
            }
            match install_checked(&path, &provider, existing.as_ref(), true, true, ctx, depth).await
            {
                Ok(_) if super::libcheck::still_missing(std::slice::from_ref(&lib)).is_empty() => {
                    break;
                }
                Ok(_) => continue,
                Err(e) => log::warn!("installing {} for {lib} failed: {e:#}", provider.name),
            }
        }
    }
}

/// Why `name` can't go into userland: the base already provides it, either as a
/// syshub package or through the blocked list (`blocked.rs`).
fn base_refusal(name: &str) -> Option<String> {
    let bare = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    if let Some(provider) = super::blocked::provided_by(&bare) {
        return Some(format!(
            "'{bare}' is provided by {provider} in the immutable base, so it is not installed into userland."
        ));
    }
    if super::backend::is_in_syshub(&bare) {
        return Some(format!(
            "Cannot modify '{bare}', it is locked inside the immutable Syshub."
        ));
    }
    None
}
