//! fix.rs — Auto-repair operations for `elevate zex doctor --fix`.
//!
//! Operates on results from audit.rs.
//! Returns FixReport with counts of what was fixed vs what needs manual review.

use anyhow::Result;
use std::{fs, path::Path, time::Instant};

use super::audit::AuditResult;
use super::layout::*;
use super::ui;

#[derive(Debug, Default)]
pub struct FixReport {
    pub fixed:         usize,
    pub remaining:     usize,
    pub files_removed: usize,
    pub freed_bytes:   u64,
    pub manual_items:  Vec<String>,
    pub elapsed:       f64,
}

/// Run all auto-repair operations on the audit result.
/// Returns what was fixed, what remains, and what needs manual action.
pub fn run_fix(audit: &AuditResult) -> Result<FixReport> {
    let started = Instant::now();
    let mut rep = FixReport::default();

    if audit.total_issues() == 0 {
        return Ok(rep);
    }

    // ── 1. Fix dangling symlinks ──────────────────────────────────────────────
    if !audit.dangling_symlinks.is_empty() {
        ui::print_step(&format!("Fixing {} dangling symlinks", audit.dangling_symlinks.len()));
        for link in &audit.dangling_symlinks {
            if fs::remove_file(link).is_ok() {
                rep.fixed += 1;
                rep.files_removed += 1;
            } else {
                rep.remaining += 1;
                rep.manual_items.push(format!("dangling symlink (remove manually): {link}"));
            }
        }
    }

    // ── 2. Remove orphaned libs ───────────────────────────────────────────────
    if !audit.orphaned_libs.is_empty() {
        ui::print_step(&format!("Removing {} orphaned libraries", audit.orphaned_libs.len()));
        for lib in &audit.orphaned_libs {
            let size = fs::metadata(lib).map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(lib).is_ok() {
                rep.fixed += 1;
                rep.files_removed += 1;
                rep.freed_bytes += size;
            } else {
                rep.remaining += 1;
                rep.manual_items.push(format!("orphaned lib (remove manually): {lib}"));
            }
        }
    }

    // ── 3. Remove orphaned packages ───────────────────────────────────────────
    if !audit.orphaned_packages.is_empty() {
        ui::print_step(&format!("Cleaning {} orphaned packages", audit.orphaned_packages.len()));
        for pkg in &audit.orphaned_packages {
            let receipt = Path::new(INSTALLED_DIR).join(format!("{pkg}.toml"));
            if fs::remove_file(&receipt).is_ok() {
                rep.fixed += 1;
            } else {
                rep.remaining += 1;
                rep.manual_items.push(format!("orphaned package receipt: {pkg}.toml"));
            }
        }
    }

    // ── 4. Repair broken receipts (remove corrupt, can't auto-fix content) ────
    if !audit.broken_receipts.is_empty() {
        for path in &audit.broken_receipts {
            // Remove corrupt receipt — package needs reinstall
            if fs::remove_file(path).is_ok() {
                rep.fixed += 1;
                rep.files_removed += 1;
            }
        }
        rep.manual_items.push(format!(
            "{} corrupt receipts removed — reinstall affected packages",
            audit.broken_receipts.len()
        ));
    }

    // ── 5. Rebuild registry index (packages.toml consistency) ────────────────
    ui::print_step("Rebuilding registry index");
    if let Ok(()) = rebuild_registry_index() {
        rep.fixed += 1;
    }

    // ── 6. Verify syshub integrity ────────────────────────────────────────────
    ui::print_step("Verifying syshub integrity");
    // Syshub is read-only — missing files cannot be auto-restored,
    // only report them for manual action.
    for f in &audit.missing_syshub_dirs {
        rep.remaining += 1;
        rep.manual_items.push(format!("missing syshub dir (remount + restore): {f}"));
    }
    for f in &audit.missing_relibc_files {
        rep.remaining += 1;
        rep.manual_items.push(format!("missing relibc file (reinstall relibc): {f}"));
    }
    for f in &audit.missing_musl_files {
        rep.remaining += 1;
        rep.manual_items.push(format!("missing musl file (reinstall musl): {f}"));
    }
    if audit.missing_syshub_dirs.is_empty()
        && audit.missing_relibc_files.is_empty()
        && audit.missing_musl_files.is_empty()
    {
        // Syshub is intact — count as fixed
        rep.fixed += 1;
    }

    // ── 7. libc violations — cannot auto-remove (may be in use) ──────────────
    for v in &audit.libc_violations {
        rep.remaining += 1;
        rep.manual_items.push(format!(
            "{} libc boundary violation (manual review needed): {}",
            v.reason, v.path
        ));
    }

    // ── 8. Unsatisfied deps — cannot auto-resolve ─────────────────────────────
    for (pkg, dep) in &audit.unsatisfied_deps {
        rep.remaining += 1;
        rep.manual_items.push(format!(
            "missing dep '{dep}' for '{pkg}' — run: elevate zex install {dep}"
        ));
    }

    crate::steps::finish();
    rep.elapsed = started.elapsed().as_secs_f64();
    rep.freed_bytes += 0; // already accumulated above
    Ok(rep)
}

/// Repairs `packages.toml` so it exactly matches the actual installed
/// receipts under `installed/` — the real authoritative source. Previously
/// only pruned stale entries and explicitly left missing ones unfixed
/// ("that's the installer's job"); now does a full rebuild from scratch
/// via `registry::rebuild_master_index`, which covers *both* directions of
/// drift (stale entries AND a package that's genuinely installed but
/// missing from the index — e.g. after `packages.toml` was deleted,
/// corrupted, or predates the sync logic that keeps it in sync today).
fn rebuild_registry_index() -> Result<()> {
    let dir = Path::new(INSTALLED_DIR);
    if !dir.exists() { return Ok(()); }

    crate::cmd::install::registry::rebuild_master_index()?;
    Ok(())
}
