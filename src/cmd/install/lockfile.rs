//! lockfile.rs: Reproducible-install lockfiles.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::backend::PackageInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub generated_at: String,
    pub zex_version: String,
    pub root: PackageInfo,
    #[serde(default)]
    pub dependencies: Vec<PackageInfo>,
}

impl Lockfile {
    pub fn new(root: PackageInfo, dependencies: Vec<PackageInfo>) -> Self {
        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            zex_version: env!("CARGO_PKG_VERSION").to_string(),
            root,
            dependencies,
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let toml_str = toml::to_string_pretty(self).context("serializing lockfile")?;
        std::fs::write(path, toml_str)
            .with_context(|| format!("writing lockfile {}", path.display()))?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading lockfile {}", path.display()))?;
        toml::from_str(&raw).context("parsing lockfile")
    }

    /// All packages this lockfile pins, root first, in install order.
    pub fn all_packages(&self) -> Vec<&PackageInfo> {
        let mut v = vec![&self.root];
        v.extend(self.dependencies.iter());
        v
    }
}

/// Drift between what a lockfile pins and what's actually installed right now.
#[derive(Debug)]
pub enum Drift {
    Missing {
        name: String,
        expected_version: String,
    },
    VersionMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    HashMismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for Drift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Drift::Missing {
                name,
                expected_version,
            } => {
                write!(f, "{name}: missing (lockfile pins {expected_version})")
            }
            Drift::VersionMismatch {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{name}: version drift — lockfile pins {expected}, installed is {actual}"
                )
            }
            Drift::HashMismatch {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{name}: hash drift — lockfile records {expected}, installed file hashes to {actual}"
                )
            }
        }
    }
}

/// Compares a lockfile's pinned packages against the live registry. Reads
/// each package's own `registry/installed/<name>.toml` directly: not the
/// derived master index: so this is a genuine independent check, not
/// something that could be fooled by a stale/corrupted summary.
pub fn verify_against_registry(lock: &Lockfile) -> Vec<Drift> {
    let mut drift = Vec::new();
    for pkg in lock.all_packages() {
        let Some(rec) = super::registry::lookup(&pkg.name) else {
            drift.push(Drift::Missing {
                name: pkg.name.clone(),
                expected_version: pkg.version.clone(),
            });
            continue;
        };

        if rec.version != pkg.version {
            drift.push(Drift::VersionMismatch {
                name: pkg.name.clone(),
                expected: pkg.version.clone(),
                actual: rec.version.clone(),
            });
            continue;
        }

        if let Some(expected) = pkg.sha256.as_ref().filter(|s| !s.is_empty()) {
            if &rec.sha256 != expected {
                drift.push(Drift::HashMismatch {
                    name: pkg.name.clone(),
                    expected: expected.clone(),
                    actual: rec.sha256.clone(),
                });
            }
        } else if let Some(expected) = pkg.blake3.as_ref().filter(|s| !s.is_empty()) {
            if &rec.blake3 != expected {
                drift.push(Drift::HashMismatch {
                    name: pkg.name.clone(),
                    expected: expected.clone(),
                    actual: rec.blake3.clone(),
                });
            }
        }
    }
    drift
}
