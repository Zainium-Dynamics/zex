//! edition.rs — Package edition management.
//!
//! Some packages (Rust, GCC, Python) ship multiple editions inside one .zex.
//! An "edition" is a self-contained variant of a package:
//!   rust-1.87.0.zex
//!     payload/
//!       2015/          ← Rust 2015 edition toolchain
//!       2018/          ← Rust 2018 edition toolchain
//!       2021/          ← Rust 2021 edition toolchain (default)
//!       2024/          ← Rust 2024 edition toolchain
//!       bin/           ← shared binaries (rustc, cargo) — always installed
//!       lib/           ← shared libs — always installed
//!
//! Commands:
//!   elevate zex edition add rust 2024
//!   elevate zex edition remove rust 2018
//!   elevate zex edition list rust
//!   elevate zex edition set-default rust 2021

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use super::{
    ui,
    zex_manifest::{self, RemoveMap, ZexManifest},
};

const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
const CACHE_DIR: &str = "/overlayer/zexlib/registry/cache";

// ── Receipt with edition tracking ─────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct EditionReceipt {
    name: String,
    version: String,
    active_editions: Vec<String>,
    default_edition: String,
    /// Per-edition remove maps (files installed for each edition)
    edition_removes: std::collections::HashMap<String, RemoveMap>,
    /// Shared files (always installed, not edition-specific)
    shared_remove: RemoveMap,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all editions available in an installed package.
pub fn list_editions(pkg_name: &str) -> Result<()> {
    let receipt = load_edition_receipt(pkg_name)?;
    println!(
        "\n{G}Editions for {P}{pkg_name}{G}:{RST}",
        G = ui::G,
        P = ui::P,
        RST = ui::RST
    );
    for ed in &receipt.active_editions {
        let marker = if *ed == receipt.default_edition {
            format!(" {G}(default){RST}", G = ui::G, RST = ui::RST)
        } else {
            String::new()
        };
        println!(
            "  {DIM}•{RST} {B}{ed}{RST}{marker}",
            DIM = ui::DIM,
            RST = ui::RST,
            B = ui::B
        );
    }
    println!();
    Ok(())
}

/// Add a new edition to an already-installed package.
/// Requires the original .zex to still be in cache.
pub fn add_edition(pkg_name: &str, edition: &str) -> Result<()> {
    let mut receipt = load_edition_receipt(pkg_name)?;

    // Check already installed
    if receipt.active_editions.contains(&edition.to_string()) {
        println!(
            " {G}Edition {B}{edition}{G} is already installed for {P}{pkg_name}{G}.{RST}",
            G = ui::G,
            B = ui::B,
            P = ui::P,
            RST = ui::RST
        );
        return Ok(());
    }

    // Find cached .zex
    let zex_path = find_cached_zex(pkg_name, &receipt.version)?;
    let manifest = zex_manifest::read_from_zex(&zex_path)?;

    // Validate edition exists in manifest
    let editions = manifest
        .editions
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Package '{pkg_name}' does not support editions"))?;
    if !editions.available.contains(&edition.to_string()) {
        bail!(
            "Edition '{}' is not available for '{}'.\nAvailable: {}",
            edition,
            pkg_name,
            editions.available.join(", ")
        );
    }

    println!(
        "\n {G}Adding edition {B}{edition}{G} to {P}{pkg_name}{RST}...\n",
        G = ui::G,
        B = ui::B,
        P = ui::P,
        RST = ui::RST
    );

    // Extract only files for this specific edition from payload/<edition>/
    let steps = crate::steps::Guard::new();
    ui::print_install_step("Installing edition");
    let rm = extract_single_edition(&zex_path, &manifest, edition)?;
    receipt.active_editions.push(edition.to_string());
    receipt.edition_removes.insert(edition.to_string(), rm);
    save_edition_receipt(&receipt)?;
    steps.ok();

    println!(
        " {G}✓ Edition {B}{edition}{G} added successfully.{RST}\n",
        G = ui::G,
        B = ui::B,
        RST = ui::RST
    );
    Ok(())
}

/// Remove a specific edition from an installed package.
/// Cannot remove the last edition (use `zex remove <pkg>` for full removal).
pub fn remove_edition(pkg_name: &str, edition: &str) -> Result<()> {
    let mut receipt = load_edition_receipt(pkg_name)?;

    if !receipt.active_editions.contains(&edition.to_string()) {
        bail!("Edition '{}' is not installed for '{}'", edition, pkg_name);
    }
    if receipt.active_editions.len() == 1 {
        bail!(
            "Cannot remove the only installed edition '{}'.\n\
             Use 'elevate zex remove {}' to remove the entire package.",
            edition,
            pkg_name
        );
    }

    println!(
        "\n {G}Removing edition {B}{edition}{G} from {P}{pkg_name}{RST}...\n",
        G = ui::G,
        B = ui::B,
        P = ui::P,
        RST = ui::RST
    );

    let rm = receipt.edition_removes.remove(edition).unwrap_or_default();

    // Delete files
    let live = |p: &String| crate::archive_safety::live_path(std::path::Path::new(p));
    for file in &rm.files {
        let _ = fs::remove_file(live(file));
    }
    for link in &rm.symlinks {
        let _ = fs::remove_file(live(link));
    }
    for dir in rm.dirs.iter().rev() {
        let _ = fs::remove_dir(live(dir)); // only succeeds if empty
    }

    // Update default if needed
    if receipt.default_edition == edition {
        let next = receipt
            .active_editions
            .iter()
            .find(|e| e.as_str() != edition)
            .cloned()
            .unwrap_or_default();
        println!(
            " {Y}Default edition changed: {B}{next}{RST}",
            Y = ui::Y,
            B = ui::B,
            RST = ui::RST
        );
        receipt.default_edition = next;
    }

    receipt.active_editions.retain(|e| e != edition);
    save_edition_receipt(&receipt)?;

    println!(
        " {G}✓ Edition {B}{edition}{G} removed.{RST}\n",
        G = ui::G,
        B = ui::B,
        RST = ui::RST
    );
    Ok(())
}

/// Change the default edition for a package.
pub fn set_default_edition(pkg_name: &str, edition: &str) -> Result<()> {
    let mut receipt = load_edition_receipt(pkg_name)?;
    if !receipt.active_editions.contains(&edition.to_string()) {
        bail!(
            "Edition '{}' is not installed. Install it first with:\n  elevate zex edition add {} {}",
            edition,
            pkg_name,
            edition
        );
    }
    receipt.default_edition = edition.to_string();
    save_edition_receipt(&receipt)?;
    println!(
        " {G}✓ Default edition for {P}{pkg_name}{G} set to {B}{edition}{RST}.\n",
        G = ui::G,
        P = ui::P,
        B = ui::B,
        RST = ui::RST
    );
    Ok(())
}

// ── Edition-aware install (called by infuse.rs after download) ────────────────

/// Install a package using its manifest.toml, honouring the selected edition.
/// Returns the RemoveMap written into the receipt.
pub fn install_with_manifest(
    zex_path: &Path,
    manifest: &ZexManifest,
    selected_edition: Option<&str>,
) -> Result<RemoveMap> {
    let edition =
        selected_edition.or_else(|| manifest.editions.as_ref().map(|e| e.default.as_str()));

    let rm = zex_manifest::extract_payload(zex_path, manifest, edition)?;

    // Write receipt
    zex_manifest::write_receipt(manifest, &rm)?;

    // If editions exist, write edition receipt too
    if let Some(eds) = &manifest.editions {
        let ed_name = edition.unwrap_or(&eds.default).to_string();
        let ed_receipt = EditionReceipt {
            name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            active_editions: vec![ed_name.clone()],
            default_edition: ed_name.clone(),
            edition_removes: {
                let mut m = std::collections::HashMap::new();
                m.insert(ed_name, rm.clone());
                m
            },
            shared_remove: RemoveMap::default(),
        };
        save_edition_receipt(&ed_receipt)?;
    }

    Ok(rm)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn edition_receipt_path(pkg_name: &str) -> std::path::PathBuf {
    Path::new(INSTALLED_DIR).join(format!("{pkg_name}.editions.toml"))
}

fn load_edition_receipt(pkg_name: &str) -> Result<EditionReceipt> {
    let path = edition_receipt_path(pkg_name);
    if !path.exists() {
        bail!(
            "Package '{}' either is not installed or does not support editions.\n\
             Check with: elevate zex search {}",
            pkg_name,
            pkg_name
        );
    }
    let text = fs::read_to_string(&path)?;
    toml::from_str(&text).context("parsing edition receipt")
}

fn save_edition_receipt(r: &EditionReceipt) -> Result<()> {
    fs::create_dir_all(INSTALLED_DIR)?;
    let path = edition_receipt_path(&r.name);
    fs::write(path, toml::to_string_pretty(r)?)?;
    Ok(())
}

fn find_cached_zex(pkg_name: &str, version: &str) -> Result<std::path::PathBuf> {
    let candidates = [
        format!("{CACHE_DIR}/{pkg_name}-{version}.zex"),
        format!("{CACHE_DIR}/{pkg_name}/{pkg_name}-{version}.zex"),
    ];
    for c in &candidates {
        let p = Path::new(c);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }
    bail!(
        "Cached .zex not found for {pkg_name}-{version}.\n\
         Re-download with: elevate zex install {pkg_name}"
    )
}

/// Extract only the files belonging to a single edition from payload/<edition>/
fn extract_single_edition(
    zex_path: &Path,
    manifest: &ZexManifest,
    edition: &str,
) -> Result<RemoveMap> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);
    let install_map = &manifest.install.paths;
    let mut rm = RemoveMap::default();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let rel = raw.to_string_lossy();
        if !rel.starts_with("payload/") {
            continue;
        }
        let inner = rel
            .strip_prefix("payload/")
            .unwrap_or("")
            .trim_start_matches('/');
        // Only accept paths under payload/<edition>/
        let pfx = format!("{edition}/");
        if !inner.starts_with(&pfx) {
            continue;
        }
        let inner_rel = &inner[pfx.len()..];
        if inner_rel.is_empty() {
            continue;
        }

        // Map edition-relative path using install map
        let dest = super::zex_manifest::resolve_install_dest_pub(inner_rel, install_map)?;
        // recorded as the union path, written through the merged mount
        let live = crate::archive_safety::live_path(&dest);
        let typ = entry.header().entry_type();
        if typ.is_dir() {
            fs::create_dir_all(&live)?;
            continue;
        }
        if let Some(p) = live.parent() {
            fs::create_dir_all(p)?;
        }
        if typ.is_file() {
            let mut out = fs::File::create(&live)?;
            std::io::copy(&mut entry, &mut out)?;
            rm.files.push(dest.to_string_lossy().into_owned());
        } else if typ.is_symlink() {
            if let Some(t) = entry.link_name()? {
                let _ = fs::remove_file(&live);
                #[cfg(unix)]
                symlink(&t, &live)?;
                rm.symlinks.push(dest.to_string_lossy().into_owned());
            }
        }
    }
    Ok(rm)
}
