//! zex_manifest.rs — Reads `manifest.toml` from inside a `.zex` archive.
//!
//! Every `.zex` file is a `tar.zst` with this layout:
//!
//!   archive.zex
//!   ├── manifest.toml      ← THIS file — package metadata + install map
//!   └── payload/           ← actual files to install
//!       ├── bin/
//!       ├── lib/
//!       ├── share/
//!       └── etc/
//!
//! `manifest.toml` schema:
//!
//!   [package]        — identity + metadata
//!   [install]        — where each payload dir maps to on disk
//!   [remove]         — files/dirs deleted on `zex remove`
//!   [editions]       — optional: available editions + default
//!   [edition.2021]   — per-edition overrides (Rust-style)
//!
//! The installer reads manifest.toml BEFORE extracting payload/ so it can:
//!   1. Verify ed25519 signature (package.ed25519_sig)
//!   2. Resolve install paths per-package (no hardcoding in the driver)
//!   3. Know exactly which files to remove on uninstall
//!   4. Handle edition selection

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

// ── Schema ────────────────────────────────────────────────────────────────────

/// Full contents of `manifest.toml` inside a `.zex` archive.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZexManifest {
    pub package: PackageMeta,
    pub install: InstallMap,
    #[serde(default)]
    pub remove: RemoveMap,
    #[serde(default)]
    pub editions: Option<EditionSet>,
    #[serde(default)]
    pub hooks: HookMap,
}

/// [package] — identity and metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    pub license: String,
    pub maintainer: String,
    #[serde(default)]
    pub homepage: Option<String>,
    /// "static" | "dynamic" | "firmware"
    #[serde(default)]
    pub build_type: Option<String>,
    /// "musl" | "gnu" (glibc) | "freestanding"
    #[serde(default)]
    pub libc_target: Option<String>,
    /// Active edition for this build (e.g. "2021" for Rust)
    #[serde(default)]
    pub edition: Option<String>,
    /// Ed25519 signature over the payload/ tree Blake3 hash
    #[serde(default)]
    pub ed25519_sig: Option<String>,
    /// Blake3 of entire payload/ tree
    #[serde(default)]
    pub blake3: Option<String>,
    /// Ed25519 verifying key embedded by `substrate pack` (hex, 32 bytes).
    /// Ephemeral per-build — there is no fixed publisher key any more, so
    /// this is what `trust.rs` verifies the signature against.
    #[serde(default)]
    pub ed25519_pubkey: Option<String>,
    /// Minimum syshub version required
    #[serde(default)]
    pub requires_syshub: Option<String>,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// [install] — maps payload/ subdirs to absolute on-disk destinations.
///
/// Keys are relative payload paths (e.g. "bin"), values are absolute
/// Zainium overlayer paths (e.g. "/overlayer/zexlib/union/bin").
///
/// Special keys:
///   _syshub = true   → install into /overlayer/syshub/ (requires elevate)
///
/// Example:
///   [install]
///   bin   = "/overlayer/zexlib/union/bin"
///   lib   = "/overlayer/zexlib/union/lib"
///   share = "/overlayer/zexlib/union/share"
///   etc   = "/overlayer/zexlib/union/etc"
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct InstallMap {
    /// Map of payload_subdir → absolute_dest_prefix
    #[serde(flatten)]
    pub paths: HashMap<String, String>,
    /// If true, install into syshub (immutable base). Requires root + remount.
    #[serde(default)]
    pub _syshub: bool,
}

/// [remove] — exact file/dir list written by the installer at install time.
/// Used verbatim by `zex remove` — no guessing, no glob scanning.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RemoveMap {
    /// Absolute paths of installed files (populated by installer, not shipped)
    #[serde(default)]
    pub files: Vec<String>,
    /// Absolute paths of installed dirs (removed only if empty after file deletion)
    #[serde(default)]
    pub dirs: Vec<String>,
    /// Absolute paths of created symlinks
    #[serde(default)]
    pub symlinks: Vec<String>,
}

/// [editions] — optional edition support (Rust-style).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EditionSet {
    /// All editions shipped in this .zex
    pub available: Vec<String>,
    /// Default edition if user doesn't specify
    pub default: String,
}

/// [edition.<name>] overrides — per-edition install path differences.
/// If a specific edition is selected, its overrides are merged into InstallMap.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HookMap {
    /// Script to run BEFORE extraction (relative to payload/ or absolute)
    #[serde(default)]
    pub pre_install: Option<String>,
    /// Script to run AFTER extraction
    #[serde(default)]
    pub post_install: Option<String>,
    /// Script to run BEFORE removal
    #[serde(default)]
    pub pre_remove: Option<String>,
    /// Script to run AFTER removal
    #[serde(default)]
    pub post_remove: Option<String>,
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Extract and parse `manifest.toml` from a `.zex` archive.
/// Does NOT extract payload/ — call `extract_payload` separately.
pub fn read_from_zex(zex_path: &Path) -> Result<ZexManifest> {
    let dec = crate::zex_codec::open_decoder(zex_path)
        .with_context(|| format!("opening {}", zex_path.display()))?;
    let mut archive = tar::Archive::new(dec);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.to_string_lossy() == "manifest.toml" {
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            let manifest: ZexManifest =
                toml::from_str(&text).context("parsing manifest.toml inside .zex")?;
            return Ok(manifest);
        }
    }
    bail!("manifest.toml not found inside {}", zex_path.display());
}

/// Extract `payload/` from a `.zex` into `dest`, applying the InstallMap.
///
/// Instead of dumping everything into a flat `dest` dir, this function reads
/// the InstallMap and places each file at its correct on-disk location.
///
/// Returns a RemoveMap filled with every file/dir/symlink that was installed,
/// ready to be written into the package receipt for clean removal later.
pub fn extract_payload(
    zex_path: &Path,
    manifest: &ZexManifest,
    edition: Option<&str>,
) -> Result<RemoveMap> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    // Build the install map — payload_prefix → dest_root
    let install_map = &manifest.install.paths;

    let dec = crate::zex_codec::open_decoder(zex_path)?;
    let mut archive = tar::Archive::new(dec);

    let mut rm = RemoveMap::default();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();
        let rel = raw_path.to_string_lossy();

        // Only process payload/ entries
        if !rel.starts_with("payload/") {
            continue;
        }
        let inner = rel
            .strip_prefix("payload/")
            .unwrap_or("")
            .trim_start_matches('/');
        if inner.is_empty() {
            continue;
        }

        // Match the first path component against the install map
        let dest_abs = resolve_install_dest(inner, install_map)?;

        let typ = entry.header().entry_type();

        // Edition filtering: if edition-specific subdir exists, only install
        // files from payload/<edition>/ and skip others for that component.
        if let Some(ed) = edition {
            let first_component = inner.split('/').next().unwrap_or("");
            let all_editions = manifest
                .editions
                .as_ref()
                .map(|e| e.available.as_slice())
                .unwrap_or(&[]);
            // If this is an edition-prefixed path for a *different* edition, skip
            if all_editions.contains(&first_component.to_string()) && first_component != ed {
                continue;
            }
        }

        if typ.is_dir() {
            fs::create_dir_all(&dest_abs)?;
            if !rm.dirs.contains(&dest_abs.to_string_lossy().into_owned()) {
                rm.dirs.push(dest_abs.to_string_lossy().into_owned());
            }
            continue;
        }

        if let Some(parent) = dest_abs.parent() {
            fs::create_dir_all(parent)?;
        }

        if typ.is_file() {
            let mut out = fs::File::create(&dest_abs)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                    fs::set_permissions(&dest_abs, fs::Permissions::from_mode(0o755))?;
                }
            }
            rm.files.push(dest_abs.to_string_lossy().into_owned());
        } else if typ.is_symlink() {
            if let Some(target) = entry.link_name()? {
                let _ = fs::remove_file(&dest_abs);
                #[cfg(unix)]
                symlink(&target, &dest_abs)?;
                rm.symlinks.push(dest_abs.to_string_lossy().into_owned());
            }
        }
    }

    Ok(rm)
}

/// Map a payload-relative path to its absolute install destination
/// using the InstallMap from manifest.toml.
///
/// payload/bin/vim          → /overlayer/zexlib/union/bin/vim
/// payload/lib/libfoo.so    → /overlayer/zexlib/union/lib/libfoo.so
/// payload/share/man/man1/x → /overlayer/zexlib/union/share/man/man1/x
/// Public wrapper for edition.rs
pub fn resolve_install_dest_pub(
    inner: &str,
    install_map: &HashMap<String, String>,
) -> Result<PathBuf> {
    resolve_install_dest(inner, install_map)
}

fn resolve_install_dest(inner: &str, install_map: &HashMap<String, String>) -> Result<PathBuf> {
    // Try longest prefix match first (e.g. "lib64" before "lib")
    let mut best_prefix = "";
    let mut best_dest = "";

    for (prefix, dest) in install_map {
        if prefix.starts_with('_') {
            continue;
        } // skip special keys
        let pfx = prefix.trim_end_matches('/');
        if (inner == pfx || inner.starts_with(&format!("{pfx}/"))) && pfx.len() > best_prefix.len()
        {
            best_prefix = pfx;
            best_dest = dest;
        }
    }

    if best_dest.is_empty() {
        // No explicit mapping — fall back to union root
        let fallback = "/overlayer/zexlib/union";
        return Ok(PathBuf::from(fallback).join(inner));
    }

    let remainder = if inner == best_prefix {
        ""
    } else {
        inner
            .strip_prefix(&format!("{best_prefix}/"))
            .unwrap_or(inner)
    };

    Ok(PathBuf::from(best_dest).join(remainder))
}

// ── Receipt writer ────────────────────────────────────────────────────────────

const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";

/// Write the final receipt TOML for a successfully installed package.
/// Includes the filled-in RemoveMap for clean `zex remove` later.
pub fn write_receipt(manifest: &ZexManifest, rm: &RemoveMap) -> Result<()> {
    #[derive(Serialize)]
    struct Receipt<'a> {
        name: &'a str,
        version: &'a str,
        description: &'a str,
        license: &'a str,
        maintainer: &'a str,
        build_type: Option<&'a str>,
        libc_target: Option<&'a str>,
        edition: Option<&'a str>,
        installed_at: String,
        remove: &'a RemoveMap,
    }

    let receipt = Receipt {
        name: &manifest.package.name,
        version: &manifest.package.version,
        description: &manifest.package.description,
        license: &manifest.package.license,
        maintainer: &manifest.package.maintainer,
        build_type: manifest.package.build_type.as_deref(),
        libc_target: manifest.package.libc_target.as_deref(),
        edition: manifest.package.edition.as_deref(),
        installed_at: chrono::Utc::now().to_rfc3339(),
        remove: rm,
    };

    fs::create_dir_all(INSTALLED_DIR)?;
    let path = Path::new(INSTALLED_DIR).join(format!("{}.toml", manifest.package.name));
    let content = toml::to_string_pretty(&receipt)?;
    fs::write(path, content)?;
    Ok(())
}

/// Read a receipt and return its RemoveMap for `zex remove`.
pub fn read_receipt_remove_map(name: &str) -> Result<RemoveMap> {
    #[derive(Deserialize)]
    struct Receipt {
        remove: RemoveMap,
    }

    let path = Path::new(INSTALLED_DIR).join(format!("{name}.toml"));
    if !path.exists() {
        bail!("package '{name}' is not installed (no receipt found)");
    }
    let text = fs::read_to_string(&path)?;
    let r: Receipt = toml::from_str(&text)?;
    Ok(r.remove)
}

/// Delete a receipt file after successful removal.
pub fn delete_receipt(name: &str) -> Result<()> {
    let path = Path::new(INSTALLED_DIR).join(format!("{name}.toml"));
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
