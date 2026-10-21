//! ui.rs — Terminal UI for doctor driver. Same palette as all other drivers.

pub const G: &str = "\x1b[92m";
pub const P: &str = "\x1b[95m";
pub const B: &str = "\x1b[96m";
pub const Y: &str = "\x1b[93m";
pub const R: &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const BLD: &str = "\x1b[1m";
pub const RST: &str = "\x1b[0m";

const BAR_W: usize = 22;

// ── Animated step bar (shared with install/upgrade/remove) ───────────────────
pub fn print_step(label: &str) {
    crate::steps::start_bar(
        &format!("{G}• {label}{RST}"),
        46usize.saturating_sub(label.len() + 1),
        BAR_W,
        "done",
    );
}

// ── Headers ───────────────────────────────────────────────────────────────────
pub fn print_audit_header() {
    println!("\n {G}{BLD}Zex Doctor{RST}{G} — System Health & Dependency Audit Engine{RST}\n");
}

pub fn print_fix_header() {
    println!("\n {G}{BLD}Zex Doctor{RST}{G} — System Repair Mode{RST}\n");
}

pub fn print_scanning(msg: &str) {
    println!(" {G}→{RST} {msg}...");
}

// ── Audit result row ──────────────────────────────────────────────────────────
pub fn print_audit_row(label: &str, ok: bool, detail: &str) {
    let (mark, _col) = if ok {
        (format!("{G}\u{2713}{RST}"), G)
    } else {
        (format!("{R}\u{2717}{RST}"), R)
    };
    let warn_mark = format!("{Y}\u{26a0}{RST}");
    let (m, c) = if detail.starts_with('\u{26a0}') {
        (warn_mark.as_str(), Y)
    } else {
        (mark.as_str(), if ok { G } else { R })
    };
    println!("  {DIM}•{RST} {label:<34} : {m} {c}{detail}{RST}");
}

pub fn print_audit_results_header() {
    println!("\n{G}Audit Results:{RST}\n");
}

pub fn print_repair_results_header() {
    println!("\n{G}Repair Operations:{RST}\n");
}

// ── Audit summary table ───────────────────────────────────────────────────────
pub fn print_audit_summary(registry_ok: bool, deps_ok: bool, fs_ok: bool, syshub_ok: bool) {
    println!("\n {G}Audit Summary{RST}");
    let tick = |ok: bool| {
        if ok {
            format!("{G}\u{2713} Perfect{RST}")
        } else {
            format!("{R}\u{2717} Issues found{RST}")
        }
    };
    let dep = |ok: bool| {
        if ok {
            format!("{G}\u{2713} 100% Satisfied{RST}")
        } else {
            format!("{R}\u{2717} Unsatisfied deps{RST}")
        }
    };
    let sys = |ok: bool| {
        if ok {
            format!("{G}\u{2713} Intact{RST}")
        } else {
            format!("{R}\u{2717} Corrupted{RST}")
        }
    };
    println!("   Registry Health          : {}", tick(registry_ok));
    println!("   Dependency Integrity     : {}", dep(deps_ok));
    println!("   Filesystem Integrity     : {}", tick(fs_ok));
    println!("   Syshub Core              : {}", sys(syshub_ok));
}

pub fn print_audit_pass() {
    println!("\n {G}\u{2713} Audit Passed: Zex Environment is 100% Healthy!{RST}\n");
    println!("{G}Zainium OS is in excellent condition.{RST}");
    println!("{DIM}No issues found.{RST}\n");
}

pub fn print_audit_fail() {
    println!("\n {R}\u{2717} Audit Failed: Issues detected.{RST}\n");
    println!("{G}Suggestions:{RST}");
    println!("  {DIM}•{RST} Run {P}'elevate zex doctor --fix'{RST} for automatic repair");
    println!("  {DIM}•{RST} Manual cleanup recommended for orphaned libraries\n");
}

// ── Fix / repair ──────────────────────────────────────────────────────────────
pub fn print_fix_healthy() {
    println!(" {G}→{RST} Starting automatic repair...");
    println!(" {G}→{RST} Scanning for issues...\n");
    println!("{G}No issues detected. System is already healthy.{RST}\n");
    println!("{DIM}No repair operations were needed.{RST}");
    println!("{G}Zainium OS is in perfect condition.{RST}\n");
}

pub fn print_fix_summary(
    fixed: usize,
    remaining: usize,
    files_removed: usize,
    freed_mb: f64,
    secs: f64,
) {
    if remaining == 0 {
        println!("\n {G}\u{2713} Automatic repair completed successfully{RST}\n");
    } else {
        println!("\n {Y}\u{26a0}{RST}  Some issues require manual intervention:\n");
    }
    println!("{G}Repair Summary{RST}");
    println!("  Issues fixed           : {G}{fixed}{RST}");
    if remaining > 0 {
        println!("  Issues remaining       : {Y}{remaining}{RST}");
    }
    if files_removed > 0 {
        println!("  Files removed          : {B}{files_removed}{RST}");
        println!("  Disk space freed       : {B}{freed_mb:.0} MB{RST}");
    }
    println!("  Time taken             : {B}{secs:.1} seconds{RST}\n");
    if remaining == 0 {
        println!("{G}System has been repaired and optimized.{RST}");
        println!("{DIM}Run 'elevate zex doctor' to verify.{RST}\n");
    } else {
        println!("{DIM}Partial repair completed.{RST}");
        println!("{DIM}Run 'elevate zex doctor' for full report.{RST}\n");
    }
}

pub fn print_manual_items(items: &[String]) {
    println!(" {Y}\u{26a0}{RST} Some issues require manual intervention:");
    for item in items {
        println!("  {DIM}•{RST} {Y}{item}{RST}");
    }
}

pub fn print_error(msg: &str) {
    println!("\n {R}Error:{RST} {msg}\n");
}
