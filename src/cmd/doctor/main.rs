//! main.rs: CLI entry-point for the doctor driver.

use clap::Parser;

use super::audit;
use super::fix;
use super::ui;

#[derive(Parser, Debug)]
#[command(
    name = "doctor",
    about = "Zex Doctor — System Health & Dependency Audit Engine",
    version,
    override_usage = "elevate zex doctor [--fix]"
)]
struct Cli {
    /// Automatically repair detected issues.
    #[arg(long, default_value_t = false)]
    fix: bool,
}

pub fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);

    if cli.fix {
        run_fix_mode();
    } else {
        run_audit_mode();
    }
}

fn run_audit_mode() {
    ui::print_audit_header();
    ui::print_scanning("Loading system manifests");
    ui::print_scanning("Scanning registry");
    ui::print_scanning("Running full system audit");

    let result = match audit::run_full_audit() {
        Ok(r) => r,
        Err(e) => {
            ui::print_error(e.to_string().as_str());
            return;
        }
    };

    ui::print_audit_results_header();

    let sym_ok = result.dangling_symlinks.is_empty();
    let sym_detail = if sym_ok {
        "\u{2713} 0 detected".to_string()
    } else {
        format!("{} detected", result.dangling_symlinks.len())
    };
    ui::print_audit_row("Dangling Symlinks", sym_ok, &sym_detail);

    let rcpt_ok = result.broken_receipts.is_empty();
    let rcpt_detail = if rcpt_ok {
        "\u{2713} 0 detected".to_string()
    } else {
        format!("{} broken", result.broken_receipts.len())
    };
    ui::print_audit_row("Broken Receipts", rcpt_ok, &rcpt_detail);

    let libc_ok = result.libc_violations.is_empty();
    let libc_detail = if libc_ok {
        "\u{2713} None".to_string()
    } else {
        format!(
            "{} glibc artifacts in userland",
            result.libc_violations.len()
        )
    };
    ui::print_audit_row("libc Boundary Violations", libc_ok, &libc_detail);

    let syshub_detail = if result.syshub_ok {
        format!(
            "\u{2713} Verified ({}/{} components clean)",
            result.syshub_clean, result.syshub_total
        )
    } else {
        let issues = result.missing_syshub_dirs.len() + result.missing_musl_files.len();
        format!("{issues} missing components")
    };
    ui::print_audit_row("Syshub Integrity", result.syshub_ok, &syshub_detail);

    let musl_ok = result.missing_musl_files.is_empty();
    let musl_det = if musl_ok {
        format!("✓ libc.so + ld-musl-x86_64.so.1 + libgcc_s + gcc")
    } else {
        format!("{} file(s) missing", result.missing_musl_files.len())
    };
    ui::print_audit_row("musl (x86_64-zainium-linux-musl)", musl_ok, &musl_det);

    let glibc_ok = result.missing_glibc_files.is_empty();
    let glibc_det = if !std::path::Path::new(super::layout::GLIBC_DIR).exists() {
        "not installed".to_string()
    } else if glibc_ok {
        "\u{2713} ld-linux-x86-64.so.2 + libc.so.6, in its own directory".to_string()
    } else {
        format!("{} file(s) missing", result.missing_glibc_files.len())
    };
    ui::print_audit_row("glibc (x86_64-zainium-linux-gnu)", glibc_ok, &glibc_det);

    let orp_ok = result.orphaned_packages.is_empty();
    let orp_detail = if orp_ok {
        "\u{2713} 0 detected".to_string()
    } else {
        format!("\u{26a0} {} detected", result.orphaned_packages.len())
    };
    ui::print_audit_row("Orphaned Packages", orp_ok, &orp_detail);

    let lib_ok = result.orphaned_libs.is_empty();
    let lib_detail = if lib_ok {
        "\u{2713} 0 detected".to_string()
    } else {
        format!("{} detected", result.orphaned_libs.len())
    };
    ui::print_audit_row("Orphaned Libraries", lib_ok, &lib_detail);

    let dep_ok = result.unsatisfied_deps.is_empty();
    let dep_detail = if dep_ok {
        "\u{2713} 100% Satisfied".to_string()
    } else {
        format!("{} unsatisfied", result.unsatisfied_deps.len())
    };
    ui::print_audit_row("Dependency Integrity", dep_ok, &dep_detail);

    ui::print_audit_summary(
        result.registry_ok(),
        result.deps_ok(),
        result.fs_ok(),
        result.syshub_ok,
    );

    if result.total_issues() == 0 {
        ui::print_audit_pass();
    } else {
        ui::print_audit_fail();
    }
}

fn run_fix_mode() {
    ui::print_fix_header();
    ui::print_scanning("Starting automatic repair");
    ui::print_scanning("Scanning for issues");
    println!();

    let audit = match audit::run_full_audit() {
        Ok(r) => r,
        Err(e) => {
            ui::print_error(e.to_string().as_str());
            return;
        }
    };

    if audit.total_issues() == 0 {
        ui::print_fix_healthy();
        return;
    }

    ui::print_repair_results_header();

    let report = match fix::run_fix(&audit) {
        Ok(r) => r,
        Err(e) => {
            ui::print_error(e.to_string().as_str());
            return;
        }
    };

    if !report.manual_items.is_empty() {
        ui::print_manual_items(&report.manual_items);
    }

    let freed_mb = report.freed_bytes as f64 / 1_048_576.0;
    ui::print_fix_summary(
        report.fixed,
        report.remaining,
        report.files_removed,
        freed_mb,
        report.elapsed,
    );
}
