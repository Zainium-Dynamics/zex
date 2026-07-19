//! ui.rs — Terminal UI for rollback driver. Same palette as all drivers.

use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};

pub const G:   &str = "\x1b[92m";
pub const P:   &str = "\x1b[95m";
pub const B:   &str = "\x1b[96m";
pub const Y:   &str = "\x1b[93m";
pub const R:   &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const BLD: &str = "\x1b[1m";
pub const RST: &str = "\x1b[0m";

const BAR_W: usize = 22;

pub fn print_arrow(msg: &str) {
    println!(" {G}→{RST} {msg}");
}

pub fn print_step(label: &str, ms: u64) {
    let dots = 48usize.saturating_sub(label.len() + 1);
    let prefix = format!("  {G}{label}{RST} {DIM}{}{RST} ", ".".repeat(dots));
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "{prefix}{G}[{{bar:{BAR_W}}}]{RST} {G}{{percent:>3}}%{RST}"
        ))
        .unwrap()
        .progress_chars("\u{2588}\u{2588}\u{2591}"),
    );
    let steps = 30u64;
    for i in 0..=steps {
        pb.set_position(i * 100 / steps);
        std::thread::sleep(Duration::from_millis((ms / steps).max(1)));
    }
    pb.finish_and_clear();
    let filled: String = std::iter::repeat('\u{2588}').take(BAR_W).collect();
    println!("  {G}{label}{RST} {DIM}{}{RST} {G}[{filled}]{RST} {G}done{RST}", ".".repeat(dots));
}

// ── Userland rollback ─────────────────────────────────────────────────────────
pub fn print_uland_header(tx_id: &str, operation: &str, target: &str, version: &str) {
    println!("\n {G}{BLD}Rolling back Userland Transaction{RST}\n");
    println!(" {DIM}Transaction ID     :{RST} {B}{tx_id}{RST}");
    println!(" {DIM}Operation          :{RST} {P}{operation}{RST}");
    println!(" {DIM}Target             :{RST} {P}{target} {B}{version}{RST}");
    println!();
}

pub fn print_uland_success(
    tx_id:      &str,
    pkg_count:  usize,
    pkg_names:  &str,
    file_count: usize,
    freed_mb:   f64,
    secs:       f64,
) {
    println!("\n {G}\u{2713} Userland rollback completed successfully{RST}\n");
    println!("{G}Rollback Summary{RST}");
    println!("  Transaction ID       : {B}{tx_id}{RST}");
    println!("  Packages reverted    : {G}{pkg_count} {DIM}({pkg_names}){RST}");
    println!("  Files restored       : {B}{file_count}{RST}");
    if freed_mb > 0.1 {
        println!("  Disk space freed     : {B}{freed_mb:.0} MB{RST}");
    }
    println!("  Time taken           : {B}{secs:.1} seconds{RST}\n");
    println!("{G}Userland has been successfully rolled back to previous state.{RST}\n");
}

// ── Syshub rollback ───────────────────────────────────────────────────────────
pub fn print_syshub_header(tx_id: &str, operation: &str) {
    println!("\n {G}{BLD}Rolling back System Hub (Immutable Core){RST}\n");
    println!(" {DIM}Transaction ID     :{RST} {B}{tx_id}{RST}");
    println!(" {DIM}Operation          :{RST} {P}{operation}{RST}");
    println!();
}

pub fn print_syshub_success(tx_id: &str, components: usize, secs: f64) {
    println!("\n {G}\u{2713} System Hub rollback completed successfully{RST}\n");
    println!("{G}Rollback Summary{RST}");
    println!("  Transaction ID             : {B}{tx_id}{RST}");
    println!("  Core components reverted   : {G}{components}{RST}");
    println!("  Time taken                 : {B}{secs:.1} seconds{RST}\n");
    println!("{G}Immutable base has been restored to previous snapshot.{RST}");
    println!("{Y}Reboot is required to complete the rollback.{RST}\n");
}

// ── Not found ─────────────────────────────────────────────────────────────────
pub fn print_not_found(tx_id: &str, recent: &[TxSummary]) {
    println!("\n {R}Error:{RST} Transaction {P}'{tx_id}'{RST} does not exist.\n");
    if !recent.is_empty() {
        println!("{G}Recent transactions:{RST}");
        for t in recent {
            println!(
                "  {DIM}•{RST} {B}{:<36}{RST} {DIM}({} {}){RST}",
                t.id, t.operation, t.target
            );
        }
        println!();
    }
    println!("{DIM}Please provide a valid transaction ID.{RST}\n");
}

pub struct TxSummary {
    pub id:        String,
    pub operation: String,
    pub target:    String,
}

pub fn print_list(transactions: &[TxSummary]) {
    if transactions.is_empty() {
        println!("\n {DIM}No transactions found.{RST}\n");
        return;
    }
    println!("\n{G}Available transactions:{RST}\n");
    for t in transactions {
        println!(
            "  {DIM}•{RST} {B}{:<36}{RST} {DIM}({} {}){RST}",
            t.id, t.operation, t.target
        );
    }
    println!();
}

pub fn print_error(msg: &str) {
    println!("\n {R}Error:{RST} {msg}\n");
}
