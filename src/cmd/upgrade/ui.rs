//! ui.rs — Real-time terminal UI for the upgrade driver.
//!
//! Covers both `elevate zex syshub --u` and `elevate zex uland --u`.
//! All output comes through this module — no println! anywhere else.
//!
//! Colors:
//!   GREEN  (#92)  — progress, success, version numbers, arrows
//!   PURPLE (#95)  — package names, titles
//!   CYAN   (#96)  — sizes, speeds, paths
//!   YELLOW (#93)  — warnings, reboot notice
//!   RED    (#91)  — errors
//!   DIM    (2m)   — secondary info, separators
//!   RESET  (0m)

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

// ── ANSI palette ─────────────────────────────────────────────────────────────
pub const G:   &str = "\x1b[92m";   // bright green
pub const P:   &str = "\x1b[95m";   // bright purple
pub const B:   &str = "\x1b[96m";   // bright cyan
pub const Y:   &str = "\x1b[93m";   // yellow
pub const R:   &str = "\x1b[91m";   // bright red
pub const DIM: &str = "\x1b[2m";
pub const RST: &str = "\x1b[0m";
pub const BLD: &str = "\x1b[1m";

// ── Bar characters ───────────────────────────────────────────────────────────
const FILLED:  char = '█';
const EMPTY:   char = '░';
const BAR_W:   usize = 22;   // inner bar width (matches visual spec)
const STEP_W:  usize = 45;   // width of the "step" label column

// ── Colour helpers ────────────────────────────────────────────────────────────

pub fn g(s: &str)   -> String { format!("{G}{s}{RST}") }
pub fn p(s: &str)   -> String { format!("{P}{s}{RST}") }
pub fn b(s: &str)   -> String { format!("{B}{s}{RST}") }
pub fn y(s: &str)   -> String { format!("{Y}{s}{RST}") }
pub fn r(s: &str)   -> String { format!("{R}{s}{RST}") }
pub fn dim(s: &str) -> String { format!("{DIM}{s}{RST}") }

// ── Static bar renderer (fake-fill for verify/apply/manifest steps) ───────────

/// Render a filled progress bar for "phase" steps that are not byte-based.
/// e.g. "Verifying integrity ...................... [██████████████████████] 100%"
pub fn phase_bar(label: &str, width: usize) -> String {
    let dots = width.saturating_sub(label.len() + 1);
    let bar: String = std::iter::repeat(FILLED).take(BAR_W).collect();
    format!(
        "  {G}{label}{RST} {DIM}{dots_str}{RST} {G}[{bar}]{RST} {G}100%{RST}",
        dots_str = ".".repeat(dots),
        bar = bar,
    )
}

// ── Indicatif-based real download progress bar ────────────────────────────────

/// Build a per-package download progress bar.
/// Template matches the visual spec:
///   "  rust-1.78.0       → 1.81.0  142.3/218.7 MB   [████████░░░░░░] 65%   19.4 MB/s  4s"
pub fn make_pkg_bar(
    mp:        &MultiProgress,
    total_b:   u64,
    pkg_label: &str,   // e.g. "rust-1.78.0       → 1.81.0"
) -> ProgressBar {
    let label = format!("  {P}{:<38}{RST}", pkg_label);
    if total_b == 0 {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::with_template(&format!(
                "{}  {{spinner}} {{bytes}} downloaded", label
            ))
            .unwrap()
            .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    } else {
        let pb = mp.add(ProgressBar::new(total_b));
        pb.set_style(
            ProgressStyle::with_template(&format!(
                "{{bytes:>10}}/{{total_bytes:<10}} {G}[{{bar:{BAR_W}}}]{RST} \
                 {G}{{percent:>3}}%{RST}   {B}{{binary_bytes_per_sec:<12}}{RST} \
                 {DIM}{{eta}}{RST}"
            ))
            .unwrap()
            .progress_chars(&format!("{FILLED}{FILLED}{EMPTY}")),
        );
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }
}

/// Build the "Overall Progress" bar shown below the per-package rows.
///
/// Driven by cumulative bytes downloaded across every package, not by
/// component-completion count — with only 2 downloads running concurrently,
/// a component-count bar sits frozen at the same percentage for the entire
/// duration of the largest file (confirmed live: stuck at "40% (2/5)" for
/// minutes while a 107MB package was still streaming in), which reads as
/// hung even though the per-package bar right above it is moving fine.
pub fn make_overall_bar(mp: &MultiProgress, total_bytes: u64) -> ProgressBar {
    let pb = mp.add(ProgressBar::new(total_bytes));
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "\n  {BLD}{G}Overall Progress{RST}\n  \
             {G}[{{bar:48}}]{RST} {G}{{percent:>3}}%{RST}   \
             {DIM}({{bytes}}/{{total_bytes}}){RST}"
        ))
        .unwrap()
        .progress_chars(&format!("{FILLED}{FILLED}{EMPTY}")),
    );
    pb.enable_steady_tick(Duration::from_millis(200));
    pb
}

// ── Syshub header / summary blocks ───────────────────────────────────────────

pub fn print_syshub_header() {
    println!("\n {G}{BLD}Zainium Syshub Upgrade{RST}\n");
}

pub fn print_crash_recovery(recovered: &[String]) {
    println!(
        "\n {Y}⚠{RST}  A previous upgrade was interrupted before it finished — {G}{}{RST} file(s) restored to their pre-upgrade state.",
        recovered.len()
    );
    for path in recovered {
        println!("   {DIM}•{RST} {path}");
    }
    println!();
}

pub fn print_checking(current_ver: &str) {
    println!(" {G}→{RST} Checking immutable base for updates...");
    println!("   Current core version : {G}{current_ver}{RST}");
}

pub fn print_syshub_found(count: usize) {
    println!("   {G}Found {count:02} core components that can be upgraded{RST}\n");
}

pub fn print_syshub_uptodate(version: &str, checked: usize) {
    println!("   {G}All immutable core components are already at the latest version.{RST}\n");
    println!(" {G}System Status{RST}");
    println!("   Core version         : {G}{version}{RST}");
    println!("   Components checked   : {B}{checked}{RST}");
    println!("   Up-to-date           : {G}100%{RST}\n");
    println!(" {DIM}No updates required.{RST}");
    println!(" {G}Zainium immutable base is fully up to date.{RST}\n");
}

pub fn print_syshub_package_list(pkgs: &[(&str, &str, &str)]) {
    // pkgs: (name, old_ver, new_ver)
    println!("{G}Packages to be upgraded {DIM}(System Hub){RST}{G}:{RST}");
    for (name, old, new) in pkgs {
        println!(
            "  {DIM}•{RST} {P}{name:<22}{RST}  {B}{old}{RST} {DIM}→{RST} {G}{new}{RST}"
        );
    }
}

pub fn print_transaction_summary(count: usize, total_mb: f64) {
    println!("\n{G}Transaction Summary{RST}");
    println!("  Core components   : {G}{count:02}{RST}");
    println!("  Total download    : {B}{total_mb:.0} MB{RST}\n");
}

pub fn print_proceed_prompt() -> bool {
    print!("{G}Proceed with system hub upgrade?{RST} {DIM}[Y/n]{RST} ");
    use std::io::{self, Write};
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let trimmed = input.trim().to_ascii_lowercase();
    trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
}

pub fn print_syshub_starting() {
    println!("\n {G}Starting Immutable Core Upgrade...{RST}\n");
    println!("{DIM}Downloading & Upgrading core components...{RST}\n");
}

pub fn print_phase(label: &str) {
    println!("{}", phase_bar(label, STEP_W));
}

pub fn print_syshub_done(count: usize, total_mb: f64, secs: u64, new_ver: &str) {
    println!("\n {G}✓ System Hub Upgrade Completed Successfully{RST}\n");
    println!("{G}Upgrade Summary{RST}");
    println!("  Core components upgraded : {G}{count:02}{RST}");
    println!("  Total downloaded         : {B}{total_mb:.2} MB{RST}");
    println!("  Time taken               : {B}{secs} seconds{RST}");
    println!("  New core version         : {G}{new_ver}{RST}\n");
    println!("{DIM}Immutable base is now up to date.{RST}");
    println!("{Y}Reboot is recommended to apply core changes.{RST}\n");
}

// ── Error display ─────────────────────────────────────────────────────────────

pub fn print_no_internet() {
    println!("\n {R}Error:{RST} No internet connection detected.\n");
    println!(" Upgrade requires an active internet connection to fetch updates.\n");
    println!(" Please check your network and try again.\n");
}

pub fn print_download_interrupted(pkg: &str) {
    println!("\n {R}Error:{RST} Internet connection interrupted.\n");
    println!(" Download failed for: {P}{pkg}{RST}\n");
    println!(" Upgrade process paused.");
    println!(" Some components were updated, but the process could not complete.\n");
    println!("{G}Suggestions:{RST}");
    println!("  {DIM}•{RST} Check your internet connection");
    println!("  {DIM}•{RST} Run: {P}elevate zex syshub --u{RST}  (to retry)");
    println!("  {DIM}•{RST} System consistency has been maintained.\n");
    println!(" {R}Operation failed.{RST}\n");
}

// ── Uland header / summary blocks ────────────────────────────────────────────

pub fn print_uland_header() {
    println!("\n {G}{BLD}Zainium Userland Upgrade{RST}\n");
}

pub fn print_uland_checking() {
    println!(" {G}→{RST} Checking for updates...");
}

pub fn print_uland_found(count: usize) {
    println!("   {G}Found {count:02} packages that can be upgraded{RST}\n");
}

pub fn print_uland_package_list(pkgs: &[(&str, &str, &str)]) {
    println!("{G}Packages to be upgraded:{RST}");
    for (name, old, new) in pkgs {
        let arrow = if old.is_empty() {
            format!("{DIM}→{RST} {G}{new}{RST}")
        } else {
            format!("{B}{old}{RST} {DIM}→{RST} {G}{new}{RST}")
        };
        println!("  {DIM}•{RST} {P}{name:<20}{RST}  {arrow}");
    }
}

pub fn print_uland_transaction(count: usize, total_gb: f64, est_secs: u64) {
    let mins = est_secs / 60;
    let secs = est_secs % 60;
    println!("\n{G}Transaction Summary{RST}");
    println!("  Packages to upgrade : {G}{count:02}{RST}");
    println!("  Total download      : {B}{total_gb:.2} GB{RST}");
    println!(
        "  Estimated time      : {DIM}~{mins} minutes {secs} seconds{RST}\n"
    );
}

pub fn print_uland_proceed_prompt() -> bool {
    print!("{G}Proceed with upgrade?{RST} {DIM}[Y/n]{RST} ");
    use std::io::{self, Write};
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let t = input.trim().to_ascii_lowercase();
    t.is_empty() || t == "y" || t == "yes"
}

pub fn print_uland_starting() {
    println!("\n {G}Starting Userland Upgrade...{RST}\n");
    println!("{DIM}Downloading & Upgrading packages...{RST}\n");
}

pub fn print_uland_done(count: usize, total_gb: f64, secs: u64, new_ver: &str) {
    println!("\n {G}✓ Userland Upgrade Completed Successfully{RST}\n");
    println!("{G}Upgrade Summary{RST}");
    println!("  Packages upgraded     : {G}{count:02}{RST}");
    println!("  Total downloaded      : {B}{total_gb:.2} GB{RST}");
    let mins = secs / 60;
    let rem  = secs % 60;
    println!("  Time taken            : {B}{mins} minutes {rem} seconds{RST}");
    println!("  New userland version  : {G}{new_ver}{RST}\n");
    println!("{G}Zainium OS is now running the latest userland components.{RST}\n");
}

pub fn print_uland_uptodate(version: &str, checked: usize) {
    println!("   {G}Found 0 packages that need upgrading{RST}\n");
    println!(" {G}All userland packages are already at the latest version.{RST}\n");
    println!("{G}System Status{RST}");
    println!("  Userland version     : {G}{version}{RST}");
    let checked_fmt = format!("{checked:>5}");
    println!("  Packages checked     : {B}{checked_fmt}{RST}");
    println!("  Up-to-date           : {G}100%{RST}\n");
    println!(" {DIM}No updates required.{RST}");
    println!(" {G}Zainium OS userland is fully up to date.{RST}\n");
}

pub fn print_uland_download_interrupted(pkg: &str) {
    println!("\n {R}Error:{RST} Internet connection interrupted.\n");
    println!(" Download failed for: {P}{pkg}{RST}\n");
    println!(" Upgrade process paused.");
    println!(" Some packages were downloaded successfully, but the process could not complete.\n");
    println!("{G}Suggestions:{RST}");
    println!("  {DIM}•{RST} Check your internet connection and try again");
    println!("  {DIM}•{RST} Run: {P}elevate zex uland --u{RST}");
    println!("  {DIM}•{RST} Partial updates have been cleaned up to maintain system consistency.\n");
    println!(" {R}Operation failed.{RST}\n");
}
