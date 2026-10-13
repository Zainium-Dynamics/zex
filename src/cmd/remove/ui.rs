//! ui.rs — Terminal UI for the remove driver.
//! Same palette and conventions as install/upgrade drivers.
//! Zero hardcoded values — all data comes from receipt/registry at runtime.


pub const G:   &str = "\x1b[92m";
pub const P:   &str = "\x1b[95m";
pub const B:   &str = "\x1b[96m";
pub const Y:   &str = "\x1b[93m";
pub const R:   &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const BLD: &str = "\x1b[1m";
pub const RST: &str = "\x1b[0m";

const BAR_W:  usize = 22;
const STEP_W: usize = 50;

// ── Animated phase bar ────────────────────────────────────────────────────────
pub fn print_remove_step(label: &str) {
    crate::steps::start_bar(&format!("{G}{label}{RST}"), STEP_W.saturating_sub(label.len() + 1), BAR_W, "100%");
}

// ── Single removal header ─────────────────────────────────────────────────────
pub fn print_single_header(name: &str, scope: &str) {
    println!("\n {G}Removing package:{RST} {P}{name}{RST} {DIM}({scope}){RST}\n");
}

pub fn print_multi_header(names: &[String], scope: &str) {
    let joined = names.join(", ");
    println!("\n {G}Removing packages:{RST} {P}{joined}{RST} {DIM}({scope}){RST}\n");
}

// ── Dependency resolution lines ───────────────────────────────────────────────
pub fn print_resolving_reverse_deps() {
    println!(" {G}→{RST} Resolving reverse dependencies...");
}

pub fn print_preparing_removal(scope_path: &str) {
    println!(" {G}→{RST} Preparing safe removal from {B}{scope_path}{RST}...\n");
}

// ── Package list ──────────────────────────────────────────────────────────────
pub fn print_still_needed_by(name: &str, users: &[&str]) {
    println!(
        " {Y}⚠{RST}  {P}{name}{RST} is used by {B}{}{RST}; they may stop working without it.\n",
        users.join(", ")
    );
}

/// No terminal (or EOF) means no: dependencies are only removed on an explicit yes.
pub fn confirm_remove_unused_deps(names: &[&str]) -> bool {
    println!("{G}Dependencies no other package uses:{RST}");
    for n in names {
        println!("  {DIM}•{RST} {P}{n}{RST}");
    }
    print!("\n{G}Remove these {} dependencies too?{RST} {DIM}[y/N]{RST} ", names.len());
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut s = String::new();
    if std::io::stdin().read_line(&mut s).unwrap_or(0) == 0 {
        println!();
        return false;
    }
    matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub fn print_removing_list_header() {
    println!("{G}Removing packages...{RST}\n");
}

pub fn print_removing_item(name: &str, version: Option<&str>) {
    if let Some(v) = version {
        println!("  {DIM}•{RST} {P}{name:<24}{RST}  {B}{v}{RST}");
    } else {
        println!("  {DIM}•{RST} {P}{name}{RST}");
    }
}

// ── Phase lines (arrow style — matches spec exactly) ─────────────────────────
pub fn print_arrow_phase(msg: &str) {
    println!(" {G}→{RST} {msg}");
}

// ── Success ───────────────────────────────────────────────────────────────────
pub fn print_success_single(
    count:       usize,
    freed_mb:    f64,
    secs:        f64,
    scope:       &str,
) {
    println!("\n {G}\u{2713} Package removal completed successfully{RST}\n");
    println!("{G}Removal Summary{RST}");
    println!("  Packages removed       : {G}{count}{RST}");
    println!("  Disk space freed       : {B}{freed_mb:.0} MB{RST}");
    println!("  Time taken             : {B}{secs:.1} seconds{RST}");
    println!("  Scope                  : {B}{scope}{RST}\n");
    println!("{G}Zex {scope_lower} removal successful. System is updated.{RST}\n",
        scope_lower = scope.to_ascii_lowercase());
}

// ── Not installed ─────────────────────────────────────────────────────────────
pub fn print_not_installed(name: &str) {
    println!("\n {R}Error:{RST} Package {P}'{name}'{RST} is not installed.\n");
    println!("{DIM}Nothing to remove.{RST}\n");
}

// ── Syshub protected block ────────────────────────────────────────────────────
pub fn print_syshub_protected(name: &str) {
    println!("\n {R}Error:{RST} Cannot remove {P}'{name}'{RST}\n");
    println!("This is a protected {Y}System Hub{RST} {DIM}(immutable core){RST} package.");
    println!("Userland removal is not allowed for syshub components.\n");
    println!("{DIM}Use{RST} {P}'elevate zex syshub'{RST} {DIM}for core system upgrades only.{RST}\n");
}

// ── Partial not installed (multi-remove) ─────────────────────────────────────
pub fn print_partial_not_installed(missing: &[&str], removing: &[&str]) {
    println!("\n {Y}Warning:{RST} Some packages are not installed:");
    for n in missing { println!("  {DIM}•{RST} {R}{n}{RST}"); }
    if !removing.is_empty() {
        println!("\n{G}Continuing removal of installed packages:{RST}");
        for n in removing { println!("  {DIM}•{RST} {P}{n}{RST}"); }
        println!();
    }
}

// ── Dry run ───────────────────────────────────────────────────────────────────
pub fn print_dry_run(names: &[&str], total_mb: f64) {
    println!("\n {Y}\u{26a0}{RST}  {BLD}Dry run — no changes will be made{RST}\n");
    println!("{G}Would remove:{RST}");
    for n in names { println!("  {DIM}•{RST} {P}{n}{RST}"); }
    println!("\n  Estimated disk freed : {B}{total_mb:.0} MB{RST}");
    println!("  Use {DIM}--yes{RST} to actually remove.\n");
}

// ── General error ─────────────────────────────────────────────────────────────
pub fn print_error(msg: &str) {
    println!("\n {R}Error:{RST} {msg}\n");
}
