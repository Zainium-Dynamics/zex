//! manifest.rs — ZexTomlManifest — the canonical manifest.toml schema.
//!
//! This is the SINGLE manifest structure used by both:
//!   • `zex fmt pack`  (writer)
//!   • `zex install`   (reader, via zex_manifest.rs)
//!   • `zex syshub --u` (reader, via syscore.rs)
//!
//! On-disk format: TOML (not JSON). Always at the tar root as `manifest.toml`.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
use crate::cmd::fmt::error::{Result, ZexError};
use crate::cmd::fmt::core::packer::PackOptions;

// ── Top-level manifest ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZexTomlManifest {
    pub package:  PackageMeta,
    pub install:  InstallMap,
    pub remove:   RemoveMap,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editions: Option<EditionMap>,
    #[serde(default, skip_serializing_if = "HookMap::is_empty")]
    pub hooks:    HookMap,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub depends:  HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageMeta {
    pub name:          String,
    pub version:       String,
    pub description:   String,
    pub license:       String,
    pub maintainer:    String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage:      Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_type:    Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc_target:   Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition:       Option<String>,

    // Cryptographic fields — written by `zex fmt pack`, verified by `zex install`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_sig:   Option<String>,   // base64 Ed25519 over Blake3(payload)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3:        Option<String>,   // hex Blake3 over sorted payload files

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags:          Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends:       Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides:      Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_syshub: Option<String>,
}

/// [install] — maps payload/ subdirs to absolute on-disk destinations.
/// ALL paths MUST begin with /overlayer/.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstallMap {
    /// Flat key=value: payload_subdir → absolute_dest
    /// e.g. bin = "/overlayer/zexlib/union/bin"
    #[serde(flatten)]
    pub paths: HashMap<String, String>,

    /// If true, installs into /overlayer/syshub/ (syshub packages only)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub _syshub: bool,
}

/// [remove] — exact file list written by installer, used by `zex remove`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemoveMap {
    #[serde(default)] pub files:    Vec<String>,
    #[serde(default)] pub symlinks: Vec<String>,
    #[serde(default)] pub dirs:     Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EditionMap {
    pub available: Vec<String>,
    pub default:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookMap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_install:  Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_install: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_remove:   Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_remove:  Option<String>,
}

impl HookMap {
    pub fn is_empty(&self) -> bool {
        self.pre_install.is_none()
            && self.post_install.is_none()
            && self.pre_remove.is_none()
            && self.post_remove.is_none()
    }
}

// ── Per-file entry (for security report) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path:   String,
    pub size:   u64,
    pub mode:   u32,
    pub sha256: String,
}

// ── Generator ─────────────────────────────────────────────────────────────────

impl ZexTomlManifest {
    /// Generate a minimal manifest from source directory structure + pack opts.
    /// Used when the package author has not provided a manifest.toml.
    pub fn generate(source_dir: &Path, opts: &PackOptions) -> Result<Self> {
        let name = source_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("package")
            .to_string();

        // Auto-detect install paths from payload/ subdirectories
        let payload_dir = source_dir.join("payload");
        let mut install_paths = HashMap::new();

        if payload_dir.is_dir() {
            for entry in std::fs::read_dir(&payload_dir)
                .map_err(ZexError::Io)?.flatten()
            {
                if !entry.path().is_dir() { continue; }
                let subdir = entry.file_name().to_string_lossy().to_string();
                let dest = format!("{}/{}", opts.install_root.trim_end_matches('/'), subdir);
                install_paths.insert(subdir, dest);
            }
        }

        Ok(ZexTomlManifest {
            package: PackageMeta {
                name:        name.clone(),
                version:     opts.version.clone(),
                description: opts.description.clone(),
                license:     "UNKNOWN".into(),
                maintainer:  opts.builder.clone(),
                ..Default::default()
            },
            install: InstallMap { paths: install_paths, _syshub: false },
            remove:  RemoveMap::default(),
            editions: None,
            hooks:   HookMap::default(),
            depends: HashMap::new(),
        })
    }

    /// Validate that all install paths start with /overlayer/ and contain no traversal.
    pub fn validate_paths(&self) -> Result<()> {
        for (key, dest) in &self.install.paths {
            if key == "_syshub" { continue; }
            if !dest.starts_with("/overlayer/") {
                return Err(ZexError::LayoutViolation(
                    format!("[install].{key} = {dest:?} — must start with /overlayer/")
                ));
            }
            if dest.contains("../") || dest.contains("/..") {
                return Err(ZexError::LayoutViolation(
                    format!("[install].{key} contains path traversal: {dest:?}")
                ));
            }
        }
        for f in self.remove.files.iter()
            .chain(self.remove.symlinks.iter())
            .chain(self.remove.dirs.iter())
        {
            if !f.starts_with("/overlayer/") {
                return Err(ZexError::LayoutViolation(
                    format!("[remove] path {f:?} must start with /overlayer/")
                ));
            }
            if f.contains("../") {
                return Err(ZexError::LayoutViolation(
                    format!("[remove] path {f:?} contains path traversal")
                ));
            }
        }
        Ok(())
    }
}
