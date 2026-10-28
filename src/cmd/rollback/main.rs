//! main.rs — Zex Rollback Engine.
//!
//! Usage:
//!   elevate zex rollback tx-2026-05-29-1432          → userland rollback
//!   elevate zex rollback syshub-tx-2026-05-28-0915   → syshub rollback
//!   elevate zex rollback --list                      → show available transactions

use clap::Parser;

use super::transaction;
use super::ui;
use super::ui::TxSummary;

#[derive(Parser, Debug)]
#[command(
    name = "rollback",
    about = "Zex Transaction Rollback Engine",
    version,
    override_usage = "elevate zex rollback <TX_ID>"
)]
struct Cli {
    /// Transaction ID to roll back (prefix 'syshub-' = syshub rollback).
    #[arg(value_name = "TX_ID")]
    tx_id: Option<String>,

    /// List available transactions.
    #[arg(long, short = 'l', default_value_t = false)]
    list: bool,
}

pub fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);

    // Root check
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        ui::print_error("Root privileges required. Run with: elevate zex rollback <TX_ID>");
        std::process::exit(1);
    }

    if cli.list {
        let txns = transaction::list_transactions();
        ui::print_list(
            &txns
                .iter()
                .map(|t| TxSummary {
                    id: t.transaction_id.clone(),
                    operation: t.operation.clone(),
                    target: t.target_package.clone(),
                })
                .collect::<Vec<_>>(),
        );
        return;
    }

    let Some(tx_id) = cli.tx_id else {
        ui::print_error(
            "No transaction ID provided.\n\
             Usage: elevate zex rollback <TX_ID>\n\
             List available: elevate zex rollback --list",
        );
        std::process::exit(1);
    };

    // Dispatch by prefix
    if tx_id.starts_with("syshub-") {
        if let Err(e) = transaction::rollback_syshub(&tx_id) {
            ui::print_error(e.to_string().as_str());
            std::process::exit(1);
        }
    } else {
        let result = transaction::rollback_userland(&tx_id);
        crate::triggers::note_all();
        crate::triggers::flush();
        if let Err(e) = result {
            ui::print_error(e.to_string().as_str());
            std::process::exit(1);
        }
    }
}
