//! pinning.rs — Package Pinning for Zex.
//!
//! Allows users to pin packages to prevent them from being upgraded.
//!   elevate zex pin <pkg>            — lock at current version
//!   elevate zex pin <pkg> --reason   — lock with a reason
//!   elevate zex unpin <pkg>          — release the lock
//!
//! Pinned state is stored in /overlayer/zexlib/registry/pinned.toml
//! (TOML, consistent with the rest of the Zex registry).
//!
//! The upgrade drivers (userland.rs, syscore.rs) check is_pinned()
//! before upgrading any package and skip pinned ones with a warning.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::ui;

const PINNED_PATH: &str = "/overlayer/zexlib/registry/pinned.toml";
const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedPackage {
    /// Package name (lowercase)
    pub name:           String,
    /// Version locked at
    pub pinned_version: String,
    /// ISO 8601 timestamp
    pub pinned_at:      String,
    /// User who set the pin (from $SUDO_USER or $USER)
    pub pinned_by:      String,
    /// Optional reason
    pub reason:         Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PinnedFile {
    #[serde(default)]
    pinned: Vec<PinnedPackage>,
}

// ── Core API ──────────────────────────────────────────────────────────────────

pub fn load_pinned() -> Vec<PinnedPackage> {
    let path = Path::new(PINNED_PATH);
    if !path.exists() { return Vec::new(); }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| toml::from_str::<PinnedFile>(&raw).ok())
        .map(|f| f.pinned)
        .unwrap_or_default()
}

fn save_pinned(entries: &[PinnedPackage]) -> Result<()> {
    let file = PinnedFile { pinned: entries.to_vec() };
    let text = toml::to_string_pretty(&file)
        .context("serializing pinned.toml")?;

    let dir = Path::new(PINNED_PATH).parent()
        .unwrap_or(Path::new("/overlayer/zexlib/registry"));
    std::fs::create_dir_all(dir)?;

    // Atomic write: tmp → rename
    let tmp = format!("{PINNED_PATH}.tmp");
    std::fs::write(&tmp, &text).context("writing pinned.toml.tmp")?;
    std::fs::rename(&tmp, PINNED_PATH).context("committing pinned.toml")?;
    Ok(())
}

pub fn is_pinned(name: &str) -> bool {
    load_pinned().iter().any(|p| p.name.eq_ignore_ascii_case(name))
}

pub fn get_pin(name: &str) -> Option<PinnedPackage> {
    load_pinned().into_iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

// ── Public commands ───────────────────────────────────────────────────────────

/// Pin a package at its current installed version.
/// Returns error if the package is not installed.
pub fn pin(name: &str, reason: Option<&str>) -> Result<()> {
    // Read current version from receipt
    let receipt_path = Path::new(INSTALLED_DIR).join(format!("{}.toml", name.to_lowercase()));
    if !receipt_path.exists() {
        bail!(
            "Package '{}' is not installed — cannot pin.\n\
             Install it first with: elevate zex install {name}",
            name
        );
    }

    #[derive(Deserialize, Default)]
    struct R { version: String }
    let raw = std::fs::read_to_string(&receipt_path)
        .context("reading receipt")?;
    let receipt: R = toml::from_str(&raw).unwrap_or_default();
    let version = if receipt.version.is_empty() { "unknown".to_string() } else { receipt.version };

    // Re-pin replaces existing
    let mut pinned = load_pinned();
    pinned.retain(|p| !p.name.eq_ignore_ascii_case(name));

    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());

    pinned.push(PinnedPackage {
        name:           name.to_lowercase(),
        pinned_version: version.clone(),
        pinned_at:      chrono::Utc::now().to_rfc3339(),
        pinned_by:      user,
        reason:         reason.map(str::to_string),
    });

    save_pinned(&pinned)?;
    ui::print_package_pinned(name, &version);
    Ok(())
}

/// Unpin a package, allowing upgrades again.
pub fn unpin(name: &str) -> Result<()> {
    let mut pinned = load_pinned();
    let before = pinned.len();
    pinned.retain(|p| !p.name.eq_ignore_ascii_case(name));

    if pinned.len() == before {
        ui::print_package_not_pinned(name);
        return Ok(());
    }

    save_pinned(&pinned)?;
    ui::print_package_unpinned(name);
    Ok(())
}

pub fn list_pinned() -> Vec<PinnedPackage> { load_pinned() }

// ── Upgrade guard ─────────────────────────────────────────────────────────────

/// Called by upgrade drivers before upgrading a package.
/// Returns Some(pinned_version) if the package is pinned, None otherwise.
pub fn upgrade_blocked(name: &str) -> Option<String> {
    get_pin(name).map(|p| p.pinned_version)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_toml() {
        let pkg = PinnedPackage {
            name:           "gcc".to_string(),
            pinned_version: "14.2.0".to_string(),
            pinned_at:      "2026-06-25T12:00:00Z".to_string(),
            pinned_by:      "alizain".to_string(),
            reason:         Some("kernel build".to_string()),
        };
        let file   = PinnedFile { pinned: vec![pkg] };
        let text   = toml::to_string_pretty(&file).unwrap();
        let parsed: PinnedFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.pinned[0].name, "gcc");
        assert_eq!(parsed.pinned[0].pinned_version, "14.2.0");
    }
}
