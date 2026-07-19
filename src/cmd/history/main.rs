//! elevate zex history [--package <name>] [-n <count>]
//!
//! Single, unified, cross-tier timeline of every install/remove/upgrade
//! recorded via `cmd::install::history` — previously a well-designed
//! module that existed but was never actually called from anywhere, so
//! this command had nothing to show. Complements (doesn't replace) the
//! tier-specific audit logs (`upgrade-audit.toml`, `remove-audit.toml`):
//! this is the one place that shows all of them together in one timeline.

use anyhow::Result;
use clap::Parser;

use crate::cmd::install::history::{self, HistoryEntry};

const G:   &str = "\x1b[92m";
const P:   &str = "\x1b[95m";
const B:   &str = "\x1b[96m";
const R:   &str = "\x1b[91m";
const DIM: &str = "\x1b[2m";
const RST: &str = "\x1b[0m";

#[derive(Parser, Debug)]
#[command(
    name  = "history",
    about = "Show the unified install/remove/upgrade history",
    override_usage = "elevate zex history [--package <NAME>] [-n <COUNT>]"
)]
struct Cli {
    /// Only show entries touching this package.
    #[arg(long)]
    package: Option<String>,

    /// Maximum number of entries to show (most recent first).
    #[arg(short = 'n', long = "limit", default_value_t = 20)]
    limit: usize,
}

pub fn run(raw_args: Vec<String>) -> Result<()> {
    let cli = Cli::parse_from(&raw_args);

    let mut entries: Vec<HistoryEntry> = match &cli.package {
        Some(name) => history::find_by_package(name),
        None => history::last_n(usize::MAX),
    };

    // Most recent first.
    entries.sort_by(|a, b| b.id.cmp(&a.id));
    entries.truncate(cli.limit);

    println!("\n {G}Zainium{RST} {DIM}|{RST} {G}History{RST} — unified operation timeline\n");

    if entries.is_empty() {
        println!(" {DIM}No history recorded yet.{RST}\n");
        return Ok(());
    }

    for e in &entries {
        let status = if e.success { format!("{G}✓{RST}") } else { format!("{R}✗{RST}") };
        let pkg_summary = if e.packages.len() == 1 {
            format!("{P}{}{RST} {B}{}{RST}", e.packages[0].name, e.packages[0].version)
        } else {
            format!("{P}{} package(s){RST}", e.packages.len())
        };

        println!(
            " {status}  {DIM}#{:<5}{RST} {DIM}{}{RST}  {:<8} {pkg_summary}  {DIM}({} ms, {}){RST}",
            e.id, e.timestamp, e.operation, e.duration_ms, e.user
        );

        if e.packages.len() > 1 {
            for p in &e.packages {
                println!("       {DIM}•{RST} {P}{}{RST} {B}{}{RST}", p.name, p.version);
            }
        }

        if let Some(err) = &e.error {
            println!("       {R}error:{RST} {err}");
        }
    }
    println!();

    Ok(())
}
