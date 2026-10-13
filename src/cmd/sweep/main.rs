//! elevate zex sweep — Zainium system cleaner.
//!
//! Scans and removes:
//!   • Package download cache     (/overlayer/zexlib/registry/cache)
//!   • Temp files                 (/overlayer/zexlib/tmp)
//!   • Old transaction records    (/overlayer/zexlib/transactions — keeps last 10)
//!   • Stale upgrade staging dirs (/overlayer/syshub.new, /overlayer/zexlib/tmp/*)
//!   • Old log files              (/overlayer/zexlib/union/var/log — > 30 days)
//!   • Orphaned .zex downloads    (DL_TMP dirs left by failed installs)

use anyhow::Result;
use clap::Parser;

use super::scanner;
use super::ui;

#[derive(Parser, Debug)]
#[command(
    name = "sweep",
    about = "Zainium Sweep Engine — System Cleaner",
    version,
    override_usage = "elevate zex sweep [--dry-run] [--aggressive]"
)]
struct Cli {
    /// Preview what would be cleaned without deleting anything.
    #[arg(long, short = 'n', default_value_t = false)]
    dry_run: bool,

    /// Aggressive mode: also clean old logs and transaction history.
    #[arg(long, short = 'a', default_value_t = false)]
    aggressive: bool,

    /// Skip confirmation prompt.
    #[arg(long, short = 'y', default_value_t = false)]
    yes: bool,
}

pub async fn run(raw_args: Vec<String>) -> Result<()> {
    let cli = Cli::parse_from(&raw_args);

    // Root check (not needed for dry-run)
    if !cli.dry_run {
        #[cfg(unix)]
        if unsafe { libc::geteuid() } != 0 {
            ui::print_error("Root privileges required.\nUse --dry-run to preview without root.");
            std::process::exit(1);
        }
    }

    ui::print_header();
    ui::print_scanning();

    // ── Scan all targets ──────────────────────────────────────────────────────
    let targets: Vec<scanner::SweepTarget> = scanner::scan_all(cli.aggressive).await;

    if targets.iter().all(|t| t.size_bytes == 0) {
        ui::print_already_clean();
        return Ok(());
    }

    // ── Print targets ─────────────────────────────────────────────────────────
    ui::print_targets(&targets);

    let total_bytes: u64 = targets.iter().map(|t| t.size_bytes).sum();
    ui::print_summary(total_bytes);

    if cli.dry_run {
        ui::print_dry_run_notice();
        return Ok(());
    }

    if !cli.yes && !ui::print_proceed_prompt() {
        println!(
            "\n {DIM}Sweep cancelled.{RST}",
            DIM = ui::DIM,
            RST = ui::RST
        );
        return Ok(());
    }

    // ── Clean ─────────────────────────────────────────────────────────────────
    let started = std::time::Instant::now();
    let (removed_count, freed_bytes) = scanner::clean_all(&targets).await;
    let elapsed = started.elapsed().as_secs_f64();

    ui::print_done(removed_count, freed_bytes, elapsed);
    Ok(())
}
