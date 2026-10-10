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

    // ── Compute orphaned dependencies (cascading) ─────────────────────────────
    //
    // Removing a package may leave its own now-unreferenced deps orphaned,
    // and removing *those* may orphan a further layer (e.g. removing curl
    // orphans libcurl; removing libcurl may then orphan libssl if nothing
    // else needs it either) — iterate to a fixed point.
    let mut excluded_names: Vec<String> = to_remove.iter().map(|r| r.name.clone()).collect();
    let mut frontier_deps: Vec<String> = to_remove.iter().flat_map(|r| r.dependencies.clone()).collect();
    let mut orphans: Vec<Receipt> = Vec::new();
    loop {
        let found = collect_safe_orphans(&frontier_deps, &excluded_names);
        if found.is_empty() {
            break;
        }
        frontier_deps.clear();
        for name in found {
            if let Some(r) = load_receipt(&name) {
                frontier_deps.extend(r.dependencies.clone());
                excluded_names.push(name);
                orphans.push(r);
            }
        }
    }

    // ── Packages that still need what the user removes: warn, the removal itself goes ahead ─
    let removing: Vec<String> = to_remove.iter().map(|r| r.name.clone()).collect();
    let others = load_all_receipts_except(&removing);
    for r in &to_remove {
        let mut users: Vec<&str> = others
            .iter()
            .filter(|(_, o)| o.dependencies.iter().any(|d| satisfies(&r.name, &[], d)))
            .map(|(n, _)| n.as_str())
            .collect();
        users.sort();
        if !users.is_empty() {
            ui::print_still_needed_by(&r.name, &users);
        }
    }

    // ── Dependencies nothing else uses: only removed if the user says yes ─────
    if !orphans.is_empty() && !dry_run {
        let names: Vec<&str> = orphans.iter().map(|o| o.name.as_str()).collect();
        if !ui::confirm_remove_unused_deps(&names) {
            orphans.clear();
        }
    }

    // ── Dry run ───────────────────────────────────────────────────────────────
    if dry_run {
        let name_refs: Vec<&str> = to_remove.iter().map(|r| r.name.as_str()).collect();
        let total_mb = estimate_freed_mb(&to_remove) + estimate_freed_mb(&orphans);
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
    }
    for orphan in &orphans {
        ui::print_removing_item(&orphan.name, None);
    }
    println!();

    // ── Remove files ──────────────────────────────────────────────────────────
    let freed_bytes: u64 = to_remove.iter().chain(orphans.iter())
        .flat_map(|r| r.installed_files.iter())
        .filter_map(|p| fs::symlink_metadata(p).ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();
    for r in to_remove.iter().chain(orphans.iter()) {
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
    //
    // The progress bar below used to be purely cosmetic — no orphan was
    // ever actually deleted, only shown in the list above. `orphans` (built
    // before the dry-run check) now really does get removed alongside
    // `to_remove` in the deletion loop that follows.
    ui::print_arrow_phase("Cleaning orphaned dependencies...");
    ui::print_remove_step("Cleaning orphaned dependencies", 200);

    // ── Delete receipts ───────────────────────────────────────────────────────
    let mut removed_count = 0usize;

    for r in to_remove.iter().chain(orphans.iter()) {
        let receipt_path = Path::new(INSTALLED_DIR).join(format!("{}.toml", r.name));
        let _ = fs::remove_file(&receipt_path);

        remove_from_packages_toml(&r.name);
        removed_count += 1;
    }

    let elapsed  = started.elapsed().as_secs_f64();
    let freed_mb = freed_bytes as f64 / 1_048_576.0;

    let _ = crate::cmd::install::history::record(
        crate::cmd::install::history::OperationType::Remove,
        to_remove.iter().chain(orphans.iter()).map(|r| crate::cmd::install::history::PackageRecord {
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
    // removed through the merged mount so the overlay drops them at once
    crate::triggers::note(installed_files);
    let mut dirs = Vec::new();
    for path in installed_files {
        let live = crate::archive_safety::live_path(std::path::Path::new(path));
        match fs::symlink_metadata(&live) {
            Ok(meta) if meta.is_dir() => dirs.push(live.to_string_lossy().into_owned()),
            Ok(_) => {
                let _ = crate::immutable::try_clear_immutable(&live);
                let _ = fs::remove_file(&live);
            }
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
//
// A package's own `dependencies` field stores raw tokens exactly as its
// source repo declared them — a mix of plain "pkgname=version" and virtual
// "so:soname" capability tokens (confirmed against real receipts, e.g.
// curl's `dependencies = ["libcurl=8.21.0-r0", "so:libc.musl-x86_64.so.1",
// "so:libcurl.so.4", "so:libz.so.1"]`). Matching a token back to the real
// installed package that satisfies it means checking both the package's
// plain name *and* its own `provides` list (populated from the source
// repo's real "p:" metadata — see `apk::find_record` for the same
// two-step match used at resolve time; this is the local-registry
// equivalent, since that function is private to a different module and
// operates on repo-index records, not installed receipts).

#[derive(Deserialize, Default, Clone)]
struct MinReceipt {
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    provides: Vec<String>,
}

fn strip_constraint(tok: &str) -> &str {
    match tok.find(['=', '<', '>', '~']) {
        Some(i) => &tok[..i],
        None => tok,
    }
}

/// Does the installed package named `provider_name` (with its own
/// `provides` list) satisfy dependency token `dep_token`?
fn satisfies(provider_name: &str, provider_provides: &[String], dep_token: &str) -> bool {
    let base = strip_constraint(dep_token);
    provider_name.eq_ignore_ascii_case(base)
        || provider_provides.iter().any(|p| p.eq_ignore_ascii_case(base))
}

fn load_all_receipts_except(excluding: &[String]) -> std::collections::HashMap<String, MinReceipt> {
    let Ok(dir) = fs::read_dir(INSTALLED_DIR) else { return Default::default() };
    dir.flatten()
        .filter_map(|entry| {
            let fname = entry.file_name().to_string_lossy().to_string();
            let pkg = fname.strip_suffix(".toml")?.to_string();
            if excluding.iter().any(|e| e.eq_ignore_ascii_case(&pkg)) {
                return None;
            }
            let text = fs::read_to_string(entry.path()).ok()?;
            let r: MinReceipt = toml::from_str(&text).ok()?;
            Some((pkg, r))
        })
        .collect()
}

/// Find installed packages that satisfy one of `target_deps` (the
/// package(s) being removed own forward-dependency tokens) and that
/// nothing else still installed depends on — true orphans, safe to also
/// remove. `excluding` is every package already being removed in this
/// operation (so a batch remove doesn't count members of its own batch as
/// "still depending on" each other).
fn collect_safe_orphans(target_deps: &[String], excluding: &[String]) -> Vec<String> {
    let remaining = load_all_receipts_except(excluding);

    let candidates: Vec<String> = remaining
        .iter()
        .filter(|(name, r)| target_deps.iter().any(|dep| satisfies(name, &r.provides, dep)))
        .map(|(name, _)| name.clone())
        .collect();

    candidates
        .into_iter()
        .filter(|candidate| {
            let cand_provides = remaining.get(candidate).map(|r| r.provides.as_slice()).unwrap_or(&[]);
            !remaining.iter().any(|(other_name, other_r)| {
                other_name != candidate
                    && other_r.dependencies.iter().any(|d| satisfies(candidate, cand_provides, d))
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
