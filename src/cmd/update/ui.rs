//! ui.rs: Visual output for elevate zex update.

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

pub const G: &str = "\x1b[92m";
pub const P: &str = "\x1b[95m";
pub const B: &str = "\x1b[96m";
pub const Y: &str = "\x1b[93m";
pub const R: &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const BLD: &str = "\x1b[1m";
pub const RST: &str = "\x1b[0m";

const BAR_W: usize = 22;

/// Phases are reported after their work (downloads applied each package), so the line is final.
pub fn print_phase(label: &str) {
    let dots = 44usize.saturating_sub(label.len() + 1);
    println!(
        "  {G}{label}{RST} {DIM}{}{RST} {G}done{RST}",
        ".".repeat(dots)
    );
}

pub fn make_pkg_bar(mp: &MultiProgress, total: u64, label: &str) -> ProgressBar {
    let lbl = format!("  {DIM}•{RST} {P}{label:<36}{RST}");
    let pb = make_pkg_bar_inner(mp, total, &lbl);
    pb.set_prefix(label.to_string());
    pb
}

fn make_pkg_bar_inner(mp: &MultiProgress, total: u64, lbl: &str) -> ProgressBar {
    if total == 0 {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::with_template(&format!("{lbl}\n  {{spinner}} {{bytes}}"))
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    } else {
        let pb = mp.add(ProgressBar::new(total));
        pb.set_style(
            ProgressStyle::with_template(&format!(
                "{lbl}\n  {{total_bytes:<12}} {G}[{{bar:{BAR_W}}}]{RST} {G}{{percent:>3}}%{RST}"
            ))
            .unwrap()
            .progress_chars("\u{2588}\u{2588}\u{2591}"),
        );
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }
}

/// A finished download, drawn like a running one at 100%, as lines above the bars still
/// running, so many packages never push the running bars past the bottom of the terminal.
pub fn finish_pkg_bar(pb: &ProgressBar) {
    let bar = "\u{2588}".repeat(BAR_W);
    let size = format!("{}", indicatif::HumanBytes(pb.position()));
    pb.println(format!(
        "  {DIM}•{RST} {P}{:<36}{RST}\n  {size:<12} {G}[{bar}]{RST} {G}100%{RST}",
        pb.prefix()
    ));
    pb.finish_and_clear();
}

/// `total_bytes`: driven by cumulative bytes downloaded across every
/// package, not component-completion count. A count-driven bar sits frozen
/// at the same percentage for the entire duration of the largest file in a
/// batch (confirmed live in the syshub upgrade path this fixes the same
/// bug in), which reads as hung even while the per-package bar above it is
/// moving fine.
pub fn make_overall_bar(mp: &MultiProgress, total_bytes: u64) -> ProgressBar {
    let pb = mp.add(ProgressBar::new(total_bytes));
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "\n{G}Overall Progress{RST}\n  \
             {G}[{{bar:48}}]{RST} {G}{{percent:>3}}%{RST}   \
             {DIM}({{bytes}}/{{total_bytes}}){RST}"
        ))
        .unwrap()
        .progress_chars("\u{2588}\u{2588}\u{2591}"),
    );
    pb.enable_steady_tick(Duration::from_millis(200));
    pb
}

pub fn print_checking() {
    println!("\n {G}→{RST} Checking for updates...\n");
}

pub fn print_uland_found(n: usize) {
    println!("{G}Userland Packages{RST}");
    println!("  {G}→{RST} Found {G}{n}{RST} packages that can be upgraded\n");
}

pub fn print_syshub_found(n: usize) {
    println!("{G}System Hub (Immutable Core){RST}");
    println!("  {G}→{RST} Found {G}{n}{RST} core components that can be upgraded\n");
}

pub fn print_transaction_summary(uland: usize, syshub: usize, total_gb: f64) {
    println!("{G}Transaction Summary{RST}");
    if uland > 0 {
        println!("  Userland packages     : {G}{uland:02}{RST}");
    }
    if syshub > 0 {
        println!("  Core components       : {Y}{syshub:02}{RST}");
    }
    println!("  Total download        : {B}{total_gb:.2} GB{RST}\n");
}

pub fn print_proceed_prompt() -> bool {
    print!("{G}Proceed with full system update?{RST} {DIM}[Y/n]{RST} ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    let t = s.trim().to_ascii_lowercase();
    t.is_empty() || t == "y" || t == "yes"
}

pub fn print_starting() {
    println!("\n {G}Starting full system update...{RST}\n");
    println!("{DIM}Downloading & Upgrading...{RST}\n");
}

pub fn print_section_label(label: &str) {
    println!("\n {G}{BLD}{label}:{RST}");
}

pub fn print_truncated(remaining: usize) {
    if remaining > 0 {
        println!("  {DIM}... ({remaining} more){RST}");
    }
}

pub fn print_uptodate(core_version: &str) {
    println!("\nAll components are already at the latest version.\n");
    println!("{G}System Status{RST}");
    println!("  Core version         : {G}{core_version}{RST}");
    println!("  Up-to-date           : {G}100%{RST}\n");
    println!("{DIM}No updates available.{RST}\n");
}

pub fn print_success(uland: usize, syshub: usize, gb: f64, mins: u64, secs: u64, reboot: bool) {
    println!("\n {G}\u{2713} Full system update completed successfully{RST}\n");
    println!("{G}Update Summary{RST}");
    if uland > 0 {
        println!("  Userland packages upgraded : {G}{uland}{RST}");
    }
    if syshub > 0 {
        println!("  Core components staged     : {Y}{syshub}{RST}");
    }
    println!("  Total downloaded           : {B}{gb:.2} GB{RST}");
    println!("  Time taken                 : {B}{mins} minutes {secs} seconds{RST}\n");
    if syshub > 0 {
        println!("{Y}Reboot to apply the System Hub update to the immutable base.{RST}");
    } else {
        println!("{G}Zainium OS is now fully up to date.{RST}");
    }
    let _ = reboot;
    println!();
}

pub fn print_no_internet() {
    println!("\n {R}Error:{RST} No internet connection detected.\n");
    println!(" Please check your network and try again.\n");
}
