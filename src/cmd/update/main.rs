//! elevate zex update
//!
//! Combined full-system update: userland + syshub in one command.
//! Diffs both the zex_ledger (userland) and syshub.toml (core) against
//! locally installed versions, then downloads and applies upgrades.

use anyhow::Result;
use clap::Parser;
use std::time::Instant;

use super::apply;
use super::diff;
use super::ui;
use super::vercmp;

const ZEX_SERVICES:    &str = "/overlayer/syshub/engine/services/zex_services.toml";
const PACKAGES_TOML:   &str = "/overlayer/zexlib/registry/packages.toml";
const INSTALLED_DIR:   &str = "/overlayer/zexlib/registry/installed";
const SYSHUB_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";
const DL_TMP:          &str = "/overlayer/zexlib/tmp/update-dl";
const SYSHUB_PATH:     &str = "/overlayer/syshub";

#[derive(Parser, Debug)]
#[command(
    name    = "update",
    about   = "Full system update — userland + syshub",
    version,
    override_usage = "elevate zex update"
)]
struct Cli {
    /// Only update userland packages, skip syshub.
    #[arg(long, default_value_t = false)]
    uland_only: bool,

    /// Only update syshub core, skip userland.
    #[arg(long, default_value_t = false)]
    syshub_only: bool,

    /// Skip confirmation prompt.
    #[arg(long, short = 'y', default_value_t = false)]
    yes: bool,
}

pub async fn run(raw_args: Vec<String>) -> Result<()> {
    let cli     = Cli::parse_from(&raw_args);
    let started = Instant::now();

    // Internet check
    if !online().await {
        ui::print_no_internet();
        std::process::exit(1);
    }

    ui::print_checking();

    // Load services config
    let services = diff::load_services(ZEX_SERVICES)?;
    let sig_mode = if services.trust.require_signatures {
        crate::trust::SignatureVerificationMode::Strict
    } else {
        crate::trust::SignatureVerificationMode::Audit
    };
    let client   = crate::http_client::build(concat!(
        "update/",
        env!("CARGO_PKG_VERSION"),
        " (Zainium OS)"
    ))?;

    #[cfg(target_arch = "x86_64")]  let arch = "x86_64";
    #[cfg(target_arch = "aarch64")] let arch = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = "x86_64";

    // Every tier's index first, so a dead mirror or stale TLS pin is visible before the diff
    crate::cmd::refresh::refresh_all(&client, arch).await;

    // ── Diff: userland ────────────────────────────────────────────────────────
    let uland_upgrades = if !cli.syshub_only {
        { let r: anyhow::Result<Vec<super::diff::UpgradePkg>> = diff::diff_userland(&services, &client, arch, INSTALLED_DIR).await; r }
            .unwrap_or_default()
    } else { vec![] };

    // ── Diff: syshub ──────────────────────────────────────────────────────────
    let (mut syshub_upgrades, syshub_remote_raw) = if !cli.uland_only {
        diff::diff_syshub(&services, &client, SYSHUB_MANIFEST).await.unwrap_or_default()
    } else { (vec![], String::new()) };
    // the base can only be upgraded on an installed system; userland still updates on a live one
    if !syshub_upgrades.is_empty() {
        if let Err(e) = crate::syshub_pending::ensure_available() {
            eprintln!(" \x1b[93m⚠\x1b[0m  Skipping {} System Hub update(s): {e}", syshub_upgrades.len());
            syshub_upgrades.clear();
        }
    }

    // ── Already up-to-date check ──────────────────────────────────────────────
    if uland_upgrades.is_empty() && syshub_upgrades.is_empty() {
        ui::print_uptodate(&local_core_version());
        return Ok(());
    }

    // ── Print what was found ──────────────────────────────────────────────────
    if !uland_upgrades.is_empty() {
        ui::print_uland_found(uland_upgrades.len());
    }
    if !syshub_upgrades.is_empty() {
        ui::print_syshub_found(syshub_upgrades.len());
    }

    // ── Transaction summary ───────────────────────────────────────────────────
    let total_bytes: u64 = uland_upgrades.iter().map(|u| u.size_bytes).sum::<u64>()
        + syshub_upgrades.iter().map(|u| u.size_bytes).sum::<u64>();
    let total_gb = total_bytes as f64 / 1_073_741_824.0;

    ui::print_transaction_summary(
        uland_upgrades.len(),
        syshub_upgrades.len(),
        total_gb,
    );

    if !cli.yes && !ui::print_proceed_prompt() {
        println!("\n {DIM}Update cancelled.{RST}", DIM = ui::DIM, RST = ui::RST);
        return Ok(());
    }

    ui::print_starting();

    // ── Prepare download dir ──────────────────────────────────────────────────
    let dl = std::path::Path::new(DL_TMP);
    if dl.exists() { std::fs::remove_dir_all(dl)?; }
    std::fs::create_dir_all(dl)?;

    let mp      = indicatif::MultiProgress::new();
    let overall = ui::make_overall_bar(&mp, total_bytes);
    overall.set_position(0);

    let mut total_dl = 0u64;

    // ── Download + apply userland ─────────────────────────────────────────────
    if !uland_upgrades.is_empty() {
        ui::print_section_label("Userland");
        let dl_bytes = apply::apply_uland(
            &uland_upgrades, &client, dl, &mp, &overall, sig_mode
        ).await?;
        total_dl += dl_bytes;
    }

    // ── Download + apply syshub ───────────────────────────────────────────────
    if !syshub_upgrades.is_empty() {
        ui::print_section_label("System Hub");
        let dl_bytes = apply::apply_syshub(
            &syshub_upgrades, &client, dl, &mp, &overall, SYSHUB_PATH, &syshub_remote_raw
        ).await?;
        total_dl += dl_bytes;
    }

    overall.finish_and_clear();
    println!();

    // ── Phase bars ────────────────────────────────────────────────────────────
    ui::print_phase("Verifying integrity");
    if !uland_upgrades.is_empty() {
        ui::print_phase("Applying updates to userland");
    }
    if !syshub_upgrades.is_empty() {
        ui::print_phase("Applying updates to immutable base");
    }
    ui::print_phase("Regenerating system manifest");

    // ── Clean up ──────────────────────────────────────────────────────────────
    std::fs::remove_dir_all(dl).ok();
    crate::triggers::flush();

    let elapsed = started.elapsed().as_secs();
    let mins    = elapsed / 60;
    let secs    = elapsed % 60;
    let total_gb = total_dl as f64 / 1_073_741_824.0;

    ui::print_success(
        uland_upgrades.len(),
        syshub_upgrades.len(),
        total_gb,
        mins, secs,
        !syshub_upgrades.is_empty(),
    );

    Ok(())
}

/// Reads the real local syshub core version instead of the hardcoded
/// placeholder "2026v3.2" `print_uptodate` used to always show — that
/// string never reflected the actual synced version, confirmed live after
/// a real syshub upgrade to 2026v1.1 still showed "2026v3.2" here.
fn local_core_version() -> String {
    #[derive(serde::Deserialize)]
    struct CoreInfo { build_version: String }
    #[derive(serde::Deserialize)]
    struct Manifest { core_info: CoreInfo }

    std::fs::read_to_string(SYSHUB_MANIFEST)
        .ok()
        .and_then(|raw| toml::from_str::<Manifest>(&raw).ok())
        .map(|m| m.core_info.build_version)
        .unwrap_or_else(|| "unknown".to_string())
}

async fn online() -> bool {
    let Ok(client) = crate::http_client::build("zex-update/ping") else { return false };

    // There is no more zex-server / API backend behind archive.zainiumdynamics.tech
    // to ping (it was decommissioned — the domain now only serves static
    // package files via Cloudflare/R2) — go straight to a generic
    // reachability probe rather than wasting a round-trip on a permanently
    // dead endpoint first.
    client.head("https://mirrors.edge.kernel.org/").send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}
