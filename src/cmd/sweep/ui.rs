//! ui.rs — Sweep driver visual output. Same palette as all other drivers.

use super::scanner::SweepTarget;

pub const G: &str = "\x1b[92m";
pub const P: &str = "\x1b[95m";
pub const B: &str = "\x1b[96m";
pub const Y: &str = "\x1b[93m";
pub const R: &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const BLD: &str = "\x1b[1m";
pub const RST: &str = "\x1b[0m";

const BAR_W: usize = 22;

pub fn print_header() {
    println!("\n {G}{BLD}Zainium Sweep Engine{RST}{G} — System Cleaner{RST}\n");
}

pub fn print_scanning() {
    println!(" {G}→{RST} Scanning for cleanable items...\n");
}

pub fn print_targets(targets: &[SweepTarget]) {
    println!("{G}Clean Targets:{RST}\n");
    for t in targets {
        if t.size_bytes == 0 {
            continue;
        }
        let size_str = human_bytes(t.size_bytes);
        println!(
            "  {DIM}•{RST} {P}{:<28}{RST} : {B}{:<10}{RST} {DIM}({}){RST}",
            t.label, size_str, t.path
        );
    }
}

pub fn print_summary(total_bytes: u64) {
    println!("\n{G}Transaction Summary{RST}");
    println!(
        "  Total reclaimable      : {G}{}{RST}\n",
        human_bytes(total_bytes)
    );
}

pub fn print_proceed_prompt() -> bool {
    print!("{G}Proceed with cleanup?{RST} {DIM}[Y/n]{RST} ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    let t = s.trim().to_ascii_lowercase();
    t.is_empty() || t == "y" || t == "yes"
}

pub fn print_step(label: &str) {
    crate::steps::start_bar(
        &format!("{G}{label}{RST}"),
        44usize.saturating_sub(label.len() + 1),
        BAR_W,
        "done",
    );
}

pub fn print_done(removed: usize, freed_bytes: u64, secs: f64) {
    println!("\n {G}\u{2713} Sweep completed successfully{RST}\n");
    println!("{G}Sweep Summary{RST}");
    println!("  Files removed          : {G}{removed}{RST}");
    println!(
        "  Disk space freed       : {B}{}{RST}",
        human_bytes(freed_bytes)
    );
    println!("  Time taken             : {B}{secs:.1} seconds{RST}\n");
    println!("{G}Zainium OS has been cleaned and optimized.{RST}\n");
}

pub fn print_already_clean() {
    println!(" {G}\u{2713} System is already clean.{RST}\n");
    println!("{G}System Status{RST}");
    println!("  Cache                  : {G}Empty{RST}");
    println!("  Temp files             : {G}Clean{RST}");
    println!("  Orphaned downloads     : {G}None{RST}\n");
    println!("{DIM}No cleanup needed.{RST}\n");
}

pub fn print_dry_run_notice() {
    println!("\n {Y}Dry run — no files were deleted.{RST}");
    println!(" Run without {DIM}--dry-run{RST} to actually clean.\n");
}

pub fn print_error(msg: &str) {
    println!("\n {R}Error:{RST} {msg}\n");
}

pub fn human_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}
