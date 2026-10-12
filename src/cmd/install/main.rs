//! main.rs — CLI entry-point for the `install` Zex Centric Driver.
//!
//! Invoked by the `zex` front-end dispatcher as:
//!   elevate zex install <pkg> [<pkg> …]
//!
//! This file owns nothing but argument parsing and the tokio runtime bootstrap.
//! All business logic lives in the modules below.

use clap::Parser;
use super::{infuse, ui};


// ─── CLI definition ───────────────────────────────────────────────────────────

/// Universal package installer for Zainium OS.
///
/// Accepts one or more package names.  When multiple names are given, downloads
/// are executed in parallel and installations follow sequentially.
#[derive(Parser, Debug)]
#[command(
    name        = "install",
    version     = env!("CARGO_PKG_VERSION"),
    about       = "Zainium package installer",
    disable_help_flag = false,
)]
struct Cli {
    /// One or more package names to install.
    #[arg(
        value_name = "PACKAGE",
        num_args = 1..,
        required_unless_present_any = [
            "emit_scorecard", "report_gates", "from_lock", "verify_lock"
        ]
    )]
    packages: Vec<String>,

    /// Write a reproducible-install lockfile after a successful install
    /// (single-package installs only) — records the exact resolved
    /// versions/mirrors/hashes so the same install can be repeated later.
    #[arg(long = "lock-out", value_name = "PATH")]
    lock_out: Option<std::path::PathBuf>,

    /// Install from a previously-generated lockfile instead of resolving
    /// by name — guarantees the exact same versions/mirrors/hashes as when
    /// the lockfile was written, bypassing live dependency resolution.
    #[arg(long = "from-lock", value_name = "PATH", conflicts_with = "packages")]
    from_lock: Option<std::path::PathBuf>,

    /// Check currently-installed packages against a lockfile without
    /// installing anything; reports any version/hash drift.
    #[arg(long = "verify-lock", value_name = "PATH", conflicts_with = "packages")]
    verify_lock: Option<std::path::PathBuf>,

    /// Resolve package sources only; skip download and installation.
    #[arg(long = "dry-resolve", default_value_t = false)]
    dry_resolve: bool,

    /// Emit automated readiness scorecard JSON.
    #[arg(long = "emit-scorecard", default_value_t = false)]
    emit_scorecard: bool,

    /// Emit certification hard-gate report.
    #[arg(long = "report-gates", default_value_t = false)]
    report_gates: bool,

    /// Offline mode — install from local cache only, no network.
    #[arg(long = "cache-only", default_value_t = false)]
    cache_only: bool,

    /// Overwrite files another package or the base OS already has instead of aborting.
    #[arg(long, short = 'f', default_value_t = false)]
    force: bool,

    /// Download and reinstall packages that are already installed, even unchanged (`zex reinstall`).
    #[arg(long, default_value_t = false)]
    reinstall: bool,




}

// ─── Entry-point ──────────────────────────────────────────────────────────────

/// `true` when the effective UID is 0 (root).
fn is_root() -> bool {
    // SAFETY: geteuid() is always safe — it never fails or has side-effects.
    unsafe { libc::geteuid() == 0 }
}

pub async fn run(raw_args: Vec<String>) {
    // Root gate — install operations modify system files and require elevated
    // privileges.  Refuse immediately with a clear message rather than failing
    // deep in the stack with a cryptic permission-denied error.
    if !is_root() {
        ui::print_root_required();
        std::process::exit(1);
    }

    let cli = Cli::parse_from(&raw_args);
    super::installer::set_force(cli.force);
    super::installer::set_reinstall(cli.reinstall);

    if cli.emit_scorecard || cli.report_gates {
        let cfg = match super::backend::BackendConfig::load() {
            Ok(c) => c,
            Err(err) => {
                ui::print_general_error(&err);
                std::process::exit(1);
            }
        };

        match super::scorecard::emit_scorecard_and_gate_report(&cfg) {
            Ok(summary) => {
                ui::print_scorecard_emitted(
                    &summary.scorecard_path,
                    &summary.gate_report_path,
                    summary.overall_score,
                    &summary.certification_status,
                    summary.blocking_gate_count,
                );
                if let Ok(text) = std::fs::read_to_string(&summary.scorecard_path) {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(readiness) =
                            value.get("os_injection_readiness").and_then(|v| v.as_str())
                        {
                            ui::print_os_injection_readiness(readiness);
                        }
                    }
                }
                return;
            }
            Err(err) => {
                ui::print_general_error(&err);
                std::process::exit(1);
            }
        }
    }

    if let Some(path) = cli.verify_lock {
        let result = match super::lockfile::Lockfile::read(&path) {
            Ok(lock) => {
                let drift = super::lockfile::verify_against_registry(&lock);
                ui::print_lock_verify_result(&lock, &drift);
                if drift.is_empty() { Ok(()) } else { std::process::exit(1); }
            }
            Err(e) => Err(e),
        };
        if let Err(err) = result {
            ui::print_general_error(&err);
            std::process::exit(1);
        }
        return;
    }

    if let Some(path) = cli.from_lock {
        let result = infuse::run_from_lockfile(path).await;
        crate::triggers::flush();
        if let Err(err) = result {
            ui::print_general_error(&err);
            std::process::exit(1);
        }
        return;
    }

    // Normalise to lower-case so "VLC" and "vlc" are treated identically.
    let packages: Vec<String> = cli.packages.iter().map(|p| p.to_lowercase()).collect();

    if cli.lock_out.is_some() && packages.len() != 1 {
        ui::print_general_error(&anyhow::anyhow!(
            "--lock-out only supports a single-package install right now"
        ));
        std::process::exit(1);
    }

    let result = if cli.dry_resolve {
        infuse::run_dry_resolve(packages).await
    } else {
        infuse::run(packages, cli.lock_out).await
    };
    crate::triggers::flush();

    if let Err(err) = result {
        if !err.is::<infuse::InstallFailed>() {
            ui::print_general_error(&err);
        }
        std::process::exit(1);
    }
}
