//! main.rs — CLI entry for the search driver.
//!
//! Usage: elevate zex search vim
//!        elevate zex search "text editor"

use clap::Parser;
use std::collections::HashSet;

use super::config;
use super::models;
use super::probers;
use super::suggest;
use super::ui;

#[derive(Parser, Debug)]
#[command(
    name    = "search",
    about   = "Search Zainium package repositories (all tiers)",
    version,
    override_usage = "elevate zex search <QUERY>"
)]
struct Cli {
    /// Package name or keyword to search for.
    #[arg(required = true, value_name = "QUERY")]
    query: Vec<String>,

    /// Limit results to a specific tier: zainium, alpine, void, chimera
    #[arg(long, value_name = "TIER")]
    tier: Option<String>,

    /// Show only installed packages matching the query.
    #[arg(long, default_value_t = false)]
    installed: bool,
}

pub async fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);
    let query = cli.query.join(" ");

    ui::print_searching();

    // Load config
    let services = config::ZexServices::load();

    // Detect arch
    #[cfg(target_arch = "x86_64")]  let arch = "x86_64";
    #[cfg(target_arch = "aarch64")] let arch = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = std::env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());

    // Load installed set from receipt dir
    let installed = load_installed_set();

    // Build HTTP client
    let client = crate::http_client::build(concat!(
        "search/",
        env!("CARGO_PKG_VERSION"),
        " (Zainium OS)"
    ))
    .expect("failed to build HTTP client");

    // Run all probers concurrently
    let mut results: Vec<crate::cmd::search::models::SearchResult> = probers::probe_all(
        &query, &client, &services, &arch, &installed
    ).await;

    // Filter by --tier if given
    if let Some(ref tier) = cli.tier {
        let t = tier.to_ascii_lowercase();
        results.retain(|r| r.origin.label().to_ascii_lowercase() == t);
    }

    // Filter by --installed if given
    if cli.installed {
        results.retain(|r| r.installed);
    }

    if results.is_empty() {
        let suggestions = suggest::fuzzy_suggest(&query, &services, &client).await;
        ui::print_not_found(&query, &suggestions);
        std::process::exit(0);
    }

    ui::print_results_header(&query);
    for r in &results {
        ui::print_result_row(r);
    }
    ui::print_found_count(results.len());
}

// ── Installed set ─────────────────────────────────────────────────────────────

fn load_installed_set() -> HashSet<String> {
    const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
    let mut set = HashSet::new();
    let Ok(dir) = std::fs::read_dir(INSTALLED_DIR) else { return set };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".toml") {
            set.insert(name.trim_end_matches(".toml").to_string());
        }
    }
    set
}
