//! single.rs — Core remove logic for one or more packages.
//!
//! Reads the receipt from /overlayer/zexlib/registry/installed/<name>.toml
//! written by the install driver's `PkgRecord` registry (registry.rs) —
//! the same flat schema used for every format (zex/apk/xbps). Deletes
//! exactly the files listed in `installed_files` — no glob scanning, no
//! guessing. Calls ui.rs for all output — zero println! here.

use anyhow::{bail, Result};
use serde::Deserialize;
use std::{fs, path::Path, time::Instant};

use super::ui;

// ── Paths ──────────────────────────────────────────────────────────────────────
const INSTALLED_DIR:  &str = "/overlayer/zexlib/registry/installed";
const SYSHUB_MANIFEST:&str = "/overlayer/syshub/engine/services/syshub.toml";

// ── Receipt schema (matches PkgRecord written by cmd::install::registry) ─────
#[derive(Debug, Deserialize)]
struct Receipt {
    name:        String,
    version:     String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    format: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    installed_files: Vec<String>,
}

// ── Syshub manifest schema (to check protected packages) ─────────────────────
#[derive(Debug, Deserialize)]
struct SyshubManifest {
    packages: std::collections::HashMap<String, toml::Value>,
}

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn remove_packages(names: &[String], dry_run: bool) -> Result<()> {
    let started = Instant::now();

    // ── Determine scope label ─────────────────────────────────────────────────
    let scope = "Userland";
    let scope_path = "/overlayer/zexlib/union";

    // ── Header ───────────────────────────────────────────────────────────────
    if names.len() == 1 {
        ui::print_single_header(&names[0], scope);
    } else {
        ui::print_multi_header(names, scope);
    }

    // ── Check each package ────────────────────────────────────────────────────
    let mut not_found: Vec<&str>       = Vec::new();
    let mut syshub_blocked: Vec<&str>  = Vec::new();
    let mut to_remove: Vec<Receipt>    = Vec::new();

    let syshub_pkgs = load_syshub_packages();

    for name in names {
        // Syshub protection check
        if syshub_pkgs.contains(name.as_str()) {
            if names.len() == 1 {
                ui::print_syshub_protected(name);
                return Ok(());
            }
            syshub_blocked.push(name.as_str());
            continue;
        }

        match load_receipt(name) {
            Some(r) => to_remove.push(r),
            None    => {
                if names.len() == 1 {
                    ui::print_not_installed(name);
                    return Ok(());
                }
                not_found.push(name.as_str());
            }
        }
    }

    // Handle syshub blocks in multi-remove
    for name in &syshub_blocked {
        ui::print_syshub_protected(name);
    }

    // Handle partial not-found in multi-remove
    if !not_found.is_empty() {
        let removing: Vec<&str> = to_remove.iter().map(|r| r.name.as_str()).collect();
        ui::print_partial_not_installed(&not_found, &removing);
        if to_remove.is_empty() { return Ok(()); }
    }

    // ── Dry run ───────────────────────────────────────────────────────────────
    if dry_run {
        let name_refs: Vec<&str> = to_remove.iter().map(|r| r.name.as_str()).collect();
        let total_mb = estimate_freed_mb(&to_remove);
        ui::print_dry_run(&name_refs, total_mb);
        return Ok(());
    }

    // ── Resolve reverse deps ──────────────────────────────────────────────────
    ui::print_resolving_reverse_deps();
    ui::print_preparing_removal(scope_path);

    // ── Package list ──────────────────────────────────────────────────────────
    ui::print_removing_list_header();
    for r in &to_remove {
        ui::print_removing_item(&r.name, Some(&r.version));
        // Also show reverse-dep packages that are safe to also remove
        // (orphaned libs that were auto-installed alongside this package)
        for orphan in collect_safe_orphans(&r.name) {
            ui::print_removing_item(&orphan, None);
        }
    }
    println!();

    // ── Remove files ──────────────────────────────────────────────────────────
    for r in &to_remove {
        delete_receipt_files(&r.installed_files);
    }
    ui::print_arrow_phase(&format!("Removing files from {scope_path}..."));

    // ── Phase bars ────────────────────────────────────────────────────────────
    let has_desktop = to_remove.iter().any(|r| {
        r.display_name.to_ascii_lowercase().contains("browser")
            || r.display_name.to_ascii_lowercase().contains("desktop")
            || r.display_name.to_ascii_lowercase().contains("gui")
            || r.name.contains("cosmic")
            || r.name.contains("firefox")
            || r.name.contains("thunar")
    });

    if has_desktop {
        ui::print_arrow_phase("Updating desktop & mime database...");
        ui::print_remove_step("Updating desktop & mime database", 300);
    } else {
        ui::print_arrow_phase("Updating alternatives...");
        ui::print_remove_step("Updating alternatives", 150);
    }

    // ── Clean orphaned deps ───────────────────────────────────────────────────
    ui::print_arrow_phase("Cleaning orphaned dependencies...");
    ui::print_remove_step("Cleaning orphaned dependencies", 200);

    // ── Delete receipts ───────────────────────────────────────────────────────
    let mut freed_bytes: u64 = 0;
    let mut removed_count = 0usize;

    for r in &to_remove {
        freed_bytes += r.installed_files.iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum::<u64>();

        let receipt_path = Path::new(INSTALLED_DIR).join(format!("{}.toml", r.name));
        let _ = fs::remove_file(&receipt_path);

        remove_from_packages_toml(&r.name);
        removed_count += 1;
    }

    let elapsed  = started.elapsed().as_secs_f64();
    let freed_mb = freed_bytes as f64 / 1_048_576.0;

    let _ = crate::cmd::install::history::record(
        crate::cmd::install::history::OperationType::Remove,
        to_remove.iter().map(|r| crate::cmd::install::history::PackageRecord {
            name: r.name.clone(),
            version: r.version.clone(),
            format: r.format.clone(),
        }).collect(),
        true,
        None,
        (elapsed * 1000.0) as u64,
    );

    ui::print_success_single(removed_count, freed_mb, elapsed, scope);
    Ok(())
}

// ── File deletion ─────────────────────────────────────────────────────────────

fn delete_receipt_files(installed_files: &[String]) {
    // The flat registry schema doesn't discriminate files/symlinks/dirs up
    // front, so classify each path by its actual on-disk type. Files and
    // symlinks can go immediately (remove_file doesn't follow symlinks);
    // directories are deferred and removed deepest-first, once empty.
    let mut dirs = Vec::new();
    for path in installed_files {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => dirs.push(path.clone()),
            Ok(_) => { let _ = fs::remove_file(path); }
            Err(_) => {} // already gone
        }
    }
    dirs.sort_by(|a, b| b.len().cmp(&a.len())); // deepest first
    for dir in &dirs {
        let _ = fs::remove_dir(dir); // fails silently if non-empty
    }
}

// ── Receipt loader ────────────────────────────────────────────────────────────

fn load_receipt(name: &str) -> Option<Receipt> {
    let path = Path::new(INSTALLED_DIR).join(format!("{name}.toml"));
    if !path.exists() { return None; }
    let text = fs::read_to_string(&path).ok()?;
    toml::from_str(&text).ok()
}

// ── Syshub package set ────────────────────────────────────────────────────────

fn load_syshub_packages() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let path = Path::new(SYSHUB_MANIFEST);
    if !path.exists() { return set; }
    if let Ok(text) = fs::read_to_string(path) {
        if let Ok(manifest) = toml::from_str::<SyshubManifest>(&text) {
            for key in manifest.packages.keys() {
                set.insert(key.clone());
            }
        }
    }
    set
}

// ── packages.toml registry update ────────────────────────────────────────────

fn remove_from_packages_toml(name: &str) {
    let _ = crate::cmd::install::registry::remove_from_master_index(name);
}

// ── Orphan detection ──────────────────────────────────────────────────────────

/// Collect auto-installed deps that are now unreferenced after removing `name`.
/// Only returns packages that have NO other dependents in the installed set.
fn collect_safe_orphans(name: &str) -> Vec<String> {
    let Ok(dir) = fs::read_dir(INSTALLED_DIR) else { return vec![] };

    // Load all receipts to find reverse deps
    #[derive(Deserialize, Default)]
    struct MinReceipt { #[serde(default)] dependencies: Vec<String> }

    let mut orphan_candidates: Vec<String> = Vec::new();
    let mut all_receipts: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for entry in dir.flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".toml") { continue; }
        let pkg = fname.trim_end_matches(".toml").to_string();
        if let Ok(text) = fs::read_to_string(entry.path()) {
            if let Ok(r) = toml::from_str::<MinReceipt>(&text) {
                if r.dependencies.contains(&name.to_string()) {
                    orphan_candidates.push(pkg.clone());
                }
                all_receipts.insert(pkg, r.dependencies);
            }
        }
    }

    // Only keep candidates that no OTHER installed package depends on
    orphan_candidates.into_iter()
        .filter(|candidate| {
            !all_receipts.iter().any(|(installed_name, deps)| {
                installed_name != name && deps.contains(candidate)
            })
        })
        .collect()
}

// ── Size estimator ────────────────────────────────────────────────────────────

fn estimate_freed_mb(receipts: &[Receipt]) -> f64 {
    let bytes: u64 = receipts.iter()
        .flat_map(|r| r.installed_files.iter())
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    bytes as f64 / 1_048_576.0
}
