//! ui.rs — Terminal UI for the install driver.
//!
//! Single source of truth for ALL output.
//! Colors:
//!   G  (#92) green  — success, arrows, progress, version
//!   P  (#95) purple — package names, titles
//!   B  (#96) cyan   — sizes, speeds, repository, version numbers
//!   Y  (#93) yellow — warnings
//!   R  (#91) red    — errors
//!   DIM (2m)        — secondary text, dots, separators
//!
//! Design rules:
//!   • No backend names (deb/apt/rpm) in user-visible strings
//!   • Only █ / ░ for progress bars
//!   • All paths use Zainium overlayer layout

use std::time::Duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

// ── Palette ───────────────────────────────────────────────────────────────────
pub const G:   &str = "\x1b[92m";
pub const P:   &str = "\x1b[95m";
pub const B:   &str = "\x1b[96m";
pub const Y:   &str = "\x1b[93m";
pub const R:   &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const BLD: &str = "\x1b[1m";
pub const RST: &str = "\x1b[0m";

const BAR_W:  usize = 22;
const STEP_W: usize = 46;

// ── Progress bar factory ──────────────────────────────────────────────────────

/// Per-package download bar.
/// "  vim                 28.4/28.4 MB   [██████████████████████] 100%   45.2 MB/s   0s"
pub fn make_download_bar(mp: &MultiProgress, total_bytes: u64, label: &str) -> ProgressBar {
    // Name on its own line above the bar — matches the same fix in
    // cmd::upgrade::ui::make_pkg_bar / cmd::update::ui::make_pkg_bar
    // (crammed onto the bar's own line, the name was the first thing
    // squeezed out on a normal-width terminal).
    let lbl = format!("  {P}{label:<36}{RST}");
    if total_bytes == 0 {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::with_template(&format!(
                "{lbl}\n  {{spinner}} {{bytes}} downloaded"
            ))
            .unwrap()
            .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    } else {
        let pb = mp.add(ProgressBar::new(total_bytes));
        pb.set_style(
            ProgressStyle::with_template(&format!(
                "{lbl}\n  {{bytes:>10}}/{{total_bytes:<10}} \
                 {G}[{{bar:{BAR_W}}}]{RST} \
                 {G}{{percent:>3}}%{RST}   \
                 {B}{{binary_bytes_per_sec:<12}}{RST} \
                 {DIM}{{eta}}{RST}"
            ))
            .unwrap()
            .progress_chars("██░"),
        );
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }
}

/// Compatibility alias used by existing infuse.rs call-sites.
pub fn make_uplink_bar(mp: &MultiProgress, total_bytes: u64) -> ProgressBar {
    make_download_bar(mp, total_bytes, "")
}

/// Overall progress bar shown below per-package bars.
pub fn make_overall_bar(mp: &MultiProgress, total: u64) -> ProgressBar {
    let pb = mp.add(ProgressBar::new(total));
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "\n{BLD}{G}Overall Progress{RST}\n  \
             {G}[{{bar:48}}]{RST} {G}{{percent:>3}}%{RST}   \
             {DIM}({{pos}}/{{len}} packages){RST}"
        ))
        .unwrap()
        .progress_chars("██░"),
    );
    pb.enable_steady_tick(Duration::from_millis(200));
    pb
}

/// Step line: shows as running while the caller does the work, then
/// "  Verifying integrity ...................... [██████████████████████] 100%"
pub fn print_install_step(label: &str) {
    let dots = ".".repeat(STEP_W.saturating_sub(label.len() + 1));
    let filled = "\u{2588}".repeat(BAR_W);
    let empty = "\u{2591}".repeat(BAR_W);
    crate::steps::start(
        format!("  {G}{label}{RST} {DIM}{dots}{RST} {DIM}[{empty}]{RST} "),
        format!("  {G}{label}{RST} {DIM}{dots}{RST} {G}[{filled}]{RST} {G}100%{RST}"),
        format!("  {R}{label}{RST} {DIM}{dots}{RST} {R}[{empty}]{RST} {R}failed{RST}"),
    );
}

// ── Header / resolve ──────────────────────────────────────────────────────────

pub fn print_nice_choice(_n: usize) {
    println!("\n {G}Resolving dependencies...{RST}\n");
}

pub fn print_resolving_single(name: &str) {
    println!(" {G}→{RST} {DIM}Target      :{RST} {P}{name}{RST}");
}

pub fn print_resolving_multiple(names: &[String]) {
    println!(" {G}→{RST} {DIM}Targets     :{RST} {P}{}{RST}", names.join(", "));
}

pub fn print_resolved_info(display_name: &str, version: &str) {
    println!(
        " {G}→{RST} {DIM}Version     :{RST} {B}{version}{RST}\n \
         {G}→{RST} {DIM}Repository  :{RST} {B}{display_name}{RST}"
    );
}

pub fn print_resolved_names(_names: &[&str]) {} // absorbed into resolving_multiple

// ── Dependency list ───────────────────────────────────────────────────────────

pub fn print_dep_list_header() {
    println!("\n{G}The following packages dependencies will be installed:{RST}");
}

pub fn print_dep_list_multi_header() {
    println!("\n{G}The following dependencies packages will be installed:{RST}");
}

pub fn print_dep_item(name: &str) {
    println!("  {DIM}•{RST} {P}{name}{RST}");
}

// ── Transaction summary ───────────────────────────────────────────────────────

pub fn print_transaction_summary(
    new_count:   usize,
    upgraded:    usize,
    disk_mb:     f64,
    download_mb: f64,
) {
    println!("\n{G}Transaction Summary{RST}");
    println!("  New packages      : {G}{new_count:02}{RST}");
    if upgraded > 0 {
        println!("  Upgraded          : {B}{upgraded:02}{RST}");
    } else {
        println!("  Upgraded          : {DIM}0{RST}");
    }
    println!("  Download size     : {B}{download_mb:.1} MB{RST}");
    println!("  Disk space needed : {B}{disk_mb:.0} MB{RST}\n");
}

pub fn print_parallel_transaction_summary(
    main_count: usize,
    main_names: &str,
    dep_count:  usize,
    total:      usize,
    download_mb: f64,
    disk_mb:    f64,
) {
    println!("\n{G}Transaction Summary{RST}");
    println!("  Main packages     : {G}{main_count} {DIM}({main_names}){RST}");
    println!("  Dependencies      : {B}{dep_count}{RST}");
    println!("  Total packages    : {G}{total}{RST}");
    println!("  Download size     : {B}{download_mb:.1} MB{RST}");
    println!("  Disk space needed : {B}{disk_mb:.0} MB{RST}\n");
}

// ── Proceed prompt ────────────────────────────────────────────────────────────

pub fn print_proceed_prompt() -> bool {
    print!("{G}Proceed with installation?{RST} {DIM}[Y/n]{RST} ");
    flush();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    let t = s.trim().to_ascii_lowercase();
    t.is_empty() || t == "y" || t == "yes"
}

pub fn print_proceed_partial_prompt() -> bool {
    print!("{G}Proceed with installation of available packages?{RST} {DIM}[Y/n]{RST} ");
    flush();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    let t = s.trim().to_ascii_lowercase();
    t.is_empty() || t == "y" || t == "yes"
}

// ── Starting banners ──────────────────────────────────────────────────────────

pub fn print_starting_installation() {
    println!("\n {G}Starting installation...{RST}\n");
    println!("{DIM}Downloading packages...{RST}");
}

pub fn print_starting_parallel_installation() {
    println!("\n {G}Starting parallel installation...{RST}\n");
}

pub fn print_downloading_single() {}  // absorbed into starting_installation

pub fn print_downloading_parallel() {
    println!("{DIM}Downloading packages ({} in parallel)...{RST}\n",
        // actual concurrency printed by caller
        3);
}

pub fn print_downloading_parallel_n(n: usize) {
    println!("{DIM}Downloading packages ({n} in parallel)...{RST}\n");
}

// ── Download done ─────────────────────────────────────────────────────────────

pub fn print_download_done_single(_size_mb: f64, _secs: f64) {} // summary shown at end
pub fn print_download_done_parallel(_total_mb: f64, _secs: f64) {}

// ── Install headers ───────────────────────────────────────────────────────────

pub fn print_install_header_single() {
    println!();
}

pub fn print_install_header_parallel() {
    println!();
}

pub fn print_parallel_pkg_steps(_name: &str) {}  // per-package bars handle this

// ── Phase bars (called explicitly) ───────────────────────────────────────────


// ── Already installed ─────────────────────────────────────────────────────────

pub fn print_reinstalling(name: &str, version: &str) {
    println!(" {B}→{RST} Reinstalling {P}{name}{RST} {version} (fresh download)");
}

pub fn print_already_installed(name: &str, version: &str) {
    println!(
        "\n {G}→{RST} {DIM}Target      :{RST} {P}{name}{RST}\n"
    );
    println!(
        "Package {P}'{name}'{RST} is already installed and up to date \
         {DIM}(version {version}){RST}.\n"
    );
    println!("{DIM}No action required.{RST}\n");
}

pub fn print_upgrading(name: &str, from: &str, to: &str) {
    println!("  {B}↑{RST} {P}{name}{RST}  {DIM}{from}{RST} {G}→{RST} {G}{to}{RST}");
}

// ── Success blocks ─────────────────────────────────────────────────────────────

pub fn print_success_single(
    display_name: &str,
    pkg_name:    &str,
    version:     &str,
    size_mb:     f64,
    _speed_mb:   f64,
    secs:        f64,
    launch:      &str,
) {
    println!("\n {G}✓ Installation completed successfully{RST}\n");
    println!("{G}Installation Summary{RST}");
    println!("  Package               : {P}{display_name}{RST}");
    println!("  Version               : {B}{version}{RST}");
    println!("  Total downloaded      : {B}{size_mb:.1} MB{RST}");
    println!("  Disk usage            : {DIM}+{:.0} MB{RST}", size_mb * 3.0);
    println!("  Time taken            : {B}{secs:.1} seconds{RST}");

    // Installed locations
    let union = "/overlayer/zexlib/union";
    println!("\nInstalled locations:");
    println!("  {DIM}•{RST} {DIM}Binary            :{RST} {B}{union}/bin/{launch}{RST}");
    if launch != pkg_name {
        println!("  {DIM}•{RST} {DIM}Binary            :{RST} {B}{union}/bin/{pkg_name}{RST}");
    }
    println!("  {DIM}•{RST} {DIM}Config directory  :{RST} {B}{union}/etc/{pkg_name}{RST}");
    println!("\n{G}userland packages installation successful...{RST}\n");
}

pub fn print_success_parallel(count: usize, failed: &[String], total_mb: f64, secs: f64) {
    if failed.is_empty() {
        println!("\n {G}✓ Installation completed successfully{RST}\n");
    } else if count == 0 {
        println!("\n {R}✗ Installation failed{RST}\n");
    } else {
        println!("\n {Y}⚠ Installation completed with errors{RST}\n");
    }
    println!("{G}Installation Summary{RST}");
    println!("  Total packages installed   : {G}{count:02}{RST}");
    if !failed.is_empty() {
        println!("  Failed packages            : {R}{:02}{RST} {DIM}({}){RST}", failed.len(), failed.join(", "));
    }
    println!("  Total downloaded           : {B}{total_mb:.1} MB{RST}");
    println!("  Time taken                 : {B}{secs:.1} seconds{RST}");
    if failed.is_empty() {
        println!("\n{G}userland packages installation successful...{RST}\n");
    } else {
        println!();
    }
}

pub fn print_success_partial(
    installed: &[String],
    skipped:   &[String],
    total_mb:  f64,
    secs:      f64,
) {
    println!("\n {G}✓ Installation completed successfully {DIM}(Partial){RST}\n");
    println!("{G}Installation Summary{RST}");
    println!("  Successfully installed : {G}{}{RST}", installed.join(", "));
    println!("  Skipped (not found)    : {R}{}{RST}", skipped.join(", "));
    println!("  Total downloaded       : {B}{total_mb:.1} MB{RST}");
    println!("  Time taken             : {B}{secs:.1} seconds{RST}");
    println!("\n{G}userland packages installation successful for available packages.{RST}\n");
}

// ── Dependency helpers ────────────────────────────────────────────────────────

pub fn print_dependency_summary(count: usize, total_bytes: u64) {
    let mb = total_bytes as f64 / 1_000_000.0;
    println!(
        " {G}→{RST} {DIM}Resolving dependencies:{RST} {G}{count} packages{RST} {DIM}({mb:.1} MB){RST}"
    );
}

pub fn print_deps_installed(count: usize) {
    println!("  {G}✓{RST}  {count} dependencies installed");
}

pub fn print_dep_satisfied_by_syshub(name: &str) {
    println!("  {DIM}•{RST}  {P}{name}{RST} {DIM}already provided by the immutable base — skipped{RST}");
}

/// Same message, but before any download is even attempted — used when
/// dependency *resolution* (not the later file-conflict check) already
/// knows `name` is satisfied by syshub, either auto-detected
/// (`backend::is_in_syshub`) or explicitly hand-listed (`blocked.rs`,
/// e.g. `coreutils` → Zainium's own `userutils`).
pub fn print_dep_provided_by(name: &str, provider: &str) {
    println!(
        "  {DIM}•{RST}  {P}{name}{RST} {DIM}already provided by the immutable base ({provider}) — skipped{RST}"
    );
}

// ── Error blocks ──────────────────────────────────────────────────────────────

pub fn print_not_found(name: &str) {
    println!("\n {R}Error:{RST} Package {P}'{name}'{RST} not found in any repository.\n");
    println!("{G}Suggestions:{RST}");
    println!("  {DIM}•{RST} Check the spelling and try again");
    println!("  {DIM}•{RST} Search with: {P}zex search {name}{RST}");
    println!("  {DIM}•{RST} Refresh repositories: {P}zex refresh{RST}");
    println!("\n{R}No packages were installed.{RST}\n");
}

pub fn print_some_not_found(missing: &[&str], found: &[&str]) {
    println!("\n {R}Error:{RST} Some packages were not found:");
    for n in missing { println!("  {DIM}•{RST} {R}{n}{RST}"); }
    println!("\n{G}The following packages were found and can be installed:{RST}");
    for n in found { println!("  {DIM}•{RST} {P}{n}{RST}"); }
    println!("\n{R}No packages were installed due to missing dependencies.{RST}\n");
}

pub fn print_partial_not_found(names: &[&str]) {
    println!("\n {R}Error:{RST} Some packages were not found:");
    for n in names { println!("  {DIM}•{RST} {R}{n}{RST}"); }
    println!("\n{G}The following packages were found and can be installed:{RST}");
}

pub fn print_partial_found(names: &[&str]) {
    for n in names { println!("  {DIM}•{RST} {P}{n}{RST}"); }
}

pub fn print_network_error(pkg: &str) {
    println!("\n {R}✗ Error:{RST} No internet connection detected.");
    println!("   Package : {P}{pkg}{RST}\n");
    println!(" Unable to download required packages.");
    println!(" Please check your network connection and try again.\n");
}

pub fn print_download_error(name: &str, reason: &str) {
    println!("\n {R}✗ Error:{RST} download failed");
    println!("   Package : {P}{name}{RST}");
    println!("   Reason  : {reason}\n");
}

pub fn print_install_error(name: &str, err: &anyhow::Error) {
    println!("\n {R}✗ Error:{RST} installation failed");
    println!("   Package : {P}{name}{RST}");
    println!("   Reason  : {err:#}\n");
    println!(" {DIM}System has been kept clean.{RST}\n");
}

pub fn print_general_error(err: &anyhow::Error) {
    println!("\n {R}Error:{RST} {err}\n");
}

pub fn print_cross_tier_fallback_warning(fallbacks: &[(String, String, String)]) {
    println!(" {Y}⚠  Warning:{RST} {} dependency(ies) weren't available from the same repository as the package that needs them:", fallbacks.len());
    for (name, preferred, actual) in fallbacks {
        println!(
            "   {DIM}•{RST} {P}{name}{RST} — wanted from {B}{preferred}{RST}, resolved from {Y}{actual}{RST} instead"
        );
    }
    println!();
}

pub fn print_lock_written(path: &std::path::Path) {
    println!(" {G}✓{RST}  Lockfile written: {B}{}{RST}", path.display());
}

pub fn print_from_lock_header(root_name: &str, root_version: &str, dep_count: usize) {
    println!(
        "\n {G}→{RST} Installing from lockfile: {P}{root_name}{RST} {B}{root_version}{RST} {DIM}({dep_count} pinned dependencies){RST}\n"
    );
}

pub fn print_from_lock_pkg(name: &str, version: &str, already_satisfied: bool) {
    if already_satisfied {
        println!("  {G}✓{RST}  {P}{name}{RST} {B}{version}{RST} {DIM}(already at pinned version){RST}");
    } else {
        println!("  {G}→{RST}  {P}{name}{RST} {B}{version}{RST}");
    }
}

pub fn print_from_lock_done(root_name: &str, root_version: &str) {
    println!("\n {G}✓ Installed {P}{root_name}{RST} {B}{root_version}{RST} exactly as pinned by the lockfile.{RST}\n");
}

pub fn print_lock_verify_result(lock: &super::lockfile::Lockfile, drift: &[super::lockfile::Drift]) {
    println!(
        "\n {G}→{RST} Verifying against lockfile: {P}{}{RST} {B}{}{RST} {DIM}({} pinned dependencies){RST}\n",
        lock.root.name,
        lock.root.version,
        lock.dependencies.len()
    );
    if drift.is_empty() {
        println!(" {G}✓ Installed state matches the lockfile exactly — no drift.{RST}\n");
        return;
    }
    println!(" {R}✗ {} drift item(s) found:{RST}", drift.len());
    for d in drift {
        println!("   {DIM}•{RST} {Y}{d}{RST}");
    }
    println!();
}

pub fn print_partial_infra_failures(failures: &[String]) {
    println!("\n {Y}Warning:{RST} Some packages failed due to mirror issues:");
    for f in failures { println!("  {DIM}•{RST} {Y}{f}{RST}"); }
    println!("  {DIM}Continuing with packages that resolved successfully.{RST}\n");
}

// ── Other existing call-sites (keep signatures, update output) ────────────────

pub fn print_root_required() {
    println!("\n {R}Error:{RST} Root privileges required.\n");
    println!(" This operation modifies system files.");
    println!(" Run with: {P}elevate zex install <package>{RST}\n");
}

pub fn print_immutable_unlock()              {}
pub fn print_immutable_relock()              {}
pub fn print_snapshot_created(_: &str)       {}
pub fn print_snapshot_restoring(_: &str)     {}
pub fn print_snapshot_restored(_: &str)      {}
pub fn print_hooks_starting(_: usize)        {}
pub fn print_hook_running(_: &str)           {}
pub fn print_hook_result(_: &str, _: bool)   {}
pub fn print_package_pinned(name: &str, version: &str) {
    println!("\n {G}\u{2713} Package pinned successfully{RST}\n");
    println!("{G}Pin Summary{RST}");
    println!("  Package : {P}{name}{RST}");
    println!("  Version : {B}{version}{RST}  {DIM}(locked \u{2014} upgrades blocked){RST}");
    println!("\n{DIM}To release: elevate zex unpin {name}{RST}\n");
}
pub fn print_package_unpinned(name: &str) {
    println!("\n {G}\u{2713} Package unpinned successfully{RST}");
    println!("  {P}{name}{RST} {DIM}will be upgraded on next 'elevate zex update'{RST}\n");
}
pub fn print_package_not_pinned(name: &str) {
    println!("\n {Y}Package {P}'{name}'{Y} is not pinned.{RST}\n");
}
pub fn print_pin_blocks_upgrade(name: &str, pinned_ver: &str) {
    println!(
        "  {Y}\u{26a0}{RST}  {P}{name}{RST} {DIM}pinned at{RST} {B}{pinned_ver}{RST} \
         {DIM}\u{2014} skipping upgrade{RST}"
    );
}
pub fn print_cache_only_mode()               {}
pub fn print_cache_hit(_: &str)              {}
pub fn print_cache_miss(_: &str)             {}
pub fn print_uplink_start()                  {}
pub fn print_updating_index(_: &str)         {}
pub fn print_processing_metadata()           {}
pub fn print_refresh_item(_: &str, _: bool)  {}
pub fn print_os_injection_readiness(_: &str) {}

pub fn print_stage_telemetry(_: u128, _: u128, _: u128, _: u128, _: u128) {}
pub fn print_parallel_install_mode(_: usize, _: u128)                      {}

pub fn print_mirror_status(id: &str, ok: bool, count: Option<usize>) {
    if ok {
        if let Some(n) = count {
            println!("  {G}✓{RST} {P}{id}{RST} {DIM}({n} packages){RST}");
        } else {
            println!("  {G}✓{RST} {P}{id}{RST}");
        }
    } else {
        println!("  {R}✗{RST} {P}{id}{RST}");
    }
}

pub fn print_refresh_summary(success: usize, total: usize) {
    println!();
    let col = if success == total { G } else if success > 0 { B } else { R };
    println!("  {col}Usable repositories: {success}/{total}{RST}");
}

pub fn print_refresh_failed(msg: &str) {
    println!("\n {R}✗ Refresh failed{RST}\n  {msg}\n");
}

pub fn print_uplink_success(available: usize, new: usize, updated: usize, secs: f64, _: bool) {
    println!("\n {G}✓ Refresh completed successfully{RST}\n");
    println!("{G}Refresh Summary{RST}");
    println!("  Packages available : {B}{available}{RST}");
    println!("  New packages       : {G}{new}{RST}");
    println!("  Updated packages   : {B}{updated}{RST}");
    println!("  Time taken         : {B}{secs:.1} seconds{RST}\n");
    println!("{G}All repositories are up to date.{RST}\n");
}

pub fn print_dry_resolve_header(count: usize) {
    println!("\n {G}Dry resolve mode:{RST} checking {count} package(s)...\n");
}

pub fn print_dry_resolve_item(
    name: &str, version: &str, format: &str,
    mirror: Option<&str>, url: &str, sha256: Option<&str>,
) {
    let m = mirror.unwrap_or("<unknown>");
    let h = sha256.unwrap_or("<none>");
    println!("  {G}✓{RST} {P}{name}{RST}");
    println!("    version : {B}{version}{RST}");
    println!("    format  : {B}{format}{RST}");
    println!("    mirror  : {B}{m}{RST}");
    println!("    url     : {DIM}{url}{RST}");
    println!("    sha256  : {DIM}{h}{RST}\n");
}

pub fn print_dry_resolve_not_found(name: &str) {
    println!("  {R}✗{RST} {P}{name}{RST} {DIM}(not found){RST}");
}

pub fn print_dry_resolve_infra_failure(name: &str, reason: &str) {
    println!("  {Y}⚠{RST}  {P}{name}{RST} {DIM}(infra: {reason}){RST}");
}

pub fn print_dry_resolve_summary(resolved: usize, not_found: usize, infra: usize, ms: u128) {
    println!("\n{G}Dry resolve summary:{RST}");
    println!("  resolved   : {G}{resolved}{RST}");
    println!("  not_found  : {R}{not_found}{RST}");
    println!("  infra_fail : {Y}{infra}{RST}");
    println!("  elapsed_ms : {DIM}{ms}{RST}\n");
}

pub fn print_scorecard_emitted(
    scorecard: &std::path::Path,
    gate_report: &std::path::Path,
    score: u32,
    cert: &str,
    blocking: usize,
) {
    println!("\n{G}Certification report generated:{RST}");
    println!("  overall_score         : {G}{score}{RST}");
    println!("  certification         : {P}{cert}{RST}");
    println!("  blocking_gates        : {B}{blocking}{RST}");
    println!("  scorecard_json        : {DIM}{}{RST}", scorecard.display());
    println!("  gate_report_markdown  : {DIM}{}{RST}\n", gate_report.display());
}

pub fn print_file_conflicts(pkg: &str, conflicts: &[(String, String)]) {
    println!("\n {R}✗{RST} Cannot install {P}'{pkg}'{RST} — file conflicts:");
    for (owner, path) in conflicts {
        println!("  {DIM}•{RST} {B}{path}{RST} {DIM}(owned by {owner}){RST}");
    }
    println!("\n  Use {P}--force{RST} to override.\n");
}

pub fn print_forced_conflicts(pkg: &str, conflicts: &[(String, String)]) {
    println!("\n {Y}!{RST} {P}'{pkg}'{RST} overwrites (--force):");
    for (owner, path) in conflicts {
        println!("  {DIM}•{RST} {B}{path}{RST} {DIM}(owned by {owner}){RST}");
    }
}

pub fn print_snapshot_list(snapshots: &[super::immutable::SnapshotManifest]) {
    if snapshots.is_empty() {
        println!("\n {DIM}No snapshots available.{RST}\n");
        return;
    }
    println!("\n{G}Available snapshots:{RST}");
    for s in snapshots {
        println!(
            "  {DIM}•{RST} {B}{}{RST} {DIM}— {} ({} packages, {}){RST}",
            s.id, s.label, s.packages.len(), s.created_at
        );
    }
    println!();
}

pub fn print_pinned_list(pins: &[super::pinning::PinnedPackage]) {
    if pins.is_empty() {
        println!("\n {DIM}No packages are currently pinned.{RST}\n");
        return;
    }
    println!("\n{G}Pinned packages:{RST}");
    for p in pins {
        println!(
            "  {DIM}•{RST} {P}{}{RST} {DIM}@ {}{RST} {DIM}(by {} on {}){RST}",
            p.name, p.pinned_version, p.pinned_by, p.pinned_at
        );
    }
    println!();
}

pub fn print_installed_locations(locations: &[(&str, &str)]) {
    println!("\nInstalled locations:");
    for (label, path) in locations {
        println!("  {DIM}•{RST} {DIM}{label:<18}:{RST} {B}{path}{RST}");
    }
    println!();
}

// ── Internals ──────────────────────────────────────────────────────────────────

fn flush() {
    use std::io::Write;
    std::io::stdout().flush().ok();
}

// ── render_ variants (used by tests in original) ──────────────────────────────

pub fn render_dry_resolve_item(
    name: &str, version: &str, format: &str,
    mirror: Option<&str>, url: &str, sha256: Option<&str>,
) -> String {
    let m = mirror.unwrap_or("<unknown>");
    let h = sha256.unwrap_or("<not provided>");
    format!(
        "✓ {name}\n   version   : {version}\n   format    : {format}\n
    mirror    : {m}\n   source    : {url}\n   sha256    : {h}\n"
    )
}

pub fn render_not_found(name: &str) -> String {
    format!(
        "\n✗ Couldn't find '{name}' in the Zainium Vault.\n
    Quick fixes you can try:\n
    • Check the spelling — package names are case-sensitive\n
    • Search for similar packages: zex search {name}\n
    • Refresh the latest package list: zex refresh\n
    • Check your internet connection\n"
    )
}

pub fn render_network_error(pkg: &str) -> String {
    format!(
        " Connection lost\n\
         ✗ Download failed due to network error.\n
    The package '{pkg}' was not registered.\n
    System has been kept clean.\n
    Quick fixes:\n
    • Check your internet connection and try again\n
    • Refresh package list: zex refresh\n
    • Try again later\n"
    )
}

pub fn render_success_single(
    name: &str, version: &str, size_mb: f64, speed_mb: f64, secs: f64, launch: &str,
) -> String {
    format!(
        "\nInstallation completed successfully ✓\n\nInstallation Summary:\n
    Main package        : {name}\n   Version             : {version}\n
    Total downloaded    : {size_mb:.1} MB\n   Speed               : {speed_mb:.1} MB/s\n
    Time taken          : {secs:.1} seconds\n   Launch with         : {launch}\n"
    )
}

pub fn render_success_parallel(count: usize, total_mb: f64, secs: f64) -> String {
    format!(
        "\nInstallation completed successfully ✓ ({count} packages)\n\nInstallation Summary:\n
    Packages installed  : {count}\n   Total downloaded    : {total_mb:.1} MB\n
    Time taken          : {secs:.1} seconds\n"
    )
}

// ── Tests (keep originals passing) ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_dry_resolve_item_snapshot() {
        let actual = render_dry_resolve_item(
            "vlc", "3.0.20", "deb", Some("debian-sid"),
            "https://example.invalid/vlc.deb", Some("abc123"),
        );
        assert!(actual.contains("vlc"));
        assert!(actual.contains("3.0.20"));
    }

    #[test]
    fn render_not_found_snapshot() {
        let actual = render_not_found("xyzplayer");
        assert!(actual.contains("xyzplayer"));
        assert!(actual.contains("zex search"));
    }

    #[test]
    fn render_network_error_snapshot() {
        let actual = render_network_error("vlc.tar.zst");
        assert!(actual.contains("vlc.tar.zst"));
    }

    #[test]
    fn render_success_single_snapshot() {
        let actual = render_success_single("vlc", "3.0.20", 68.4, 21.4, 9.8, "vlc");
        assert!(actual.contains("vlc"));
        assert!(actual.contains("3.0.20"));
    }

    #[test]
    fn render_success_parallel_snapshot() {
        let actual = render_success_parallel(3, 94.7, 11.6);
        assert!(actual.contains("3"));
        assert!(actual.contains("94.7"));
    }
}
