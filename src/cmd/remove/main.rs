//! main.rs — CLI entry-point for the `remove` Zex driver.
//!
//! Usage:
//!   elevate zex remove vim
//!   elevate zex remove vim nano htop
//!   elevate zex remove vim --dry-run

use clap::Parser;

use super::preflight;
use super::single;
use super::ui;

#[derive(Parser, Debug)]
#[command(
    name    = "remove",
    about   = "Zainium OS — package removal",
    version,
    override_usage = "elevate zex remove <PACKAGE>..."
)]
struct Cli {
    /// One or more package names to remove.
    #[arg(required = true, value_name = "PACKAGE")]
    packages: Vec<String>,

    /// Show what would be removed without making any changes.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Skip confirmation prompt (always yes).
    #[arg(long, short = 'y', default_value_t = false)]
    yes: bool,
}

pub async fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);

    // Preflight checks
    let pre = preflight::validate();
    if !pre.is_ok() {
        pre.report_fatal();
        std::process::exit(1);
    }

    let result = single::remove_packages(&cli.packages, cli.dry_run).await;
    crate::triggers::flush();
    if let Err(e) = result {
        ui::print_error(e.to_string().as_str());
        std::process::exit(1);
    }
}
