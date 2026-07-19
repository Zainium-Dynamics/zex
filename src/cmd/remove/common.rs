//! common.rs — Shared remove driver types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageMeta {
    pub name:         String,
    pub display_name: String,
    pub version:      String,
    pub size_mb:      f64,
    pub origin:       String,
}

#[derive(Debug, Clone, Default)]
pub struct RunOpts {
    pub dry_run:    bool,
    pub force:      bool,
    pub quiet:      bool,
    pub recursive:  bool,
    pub yes:        bool,
    pub verbose:    bool,
}

pub fn confirm_removal(names: &[String], opts: &RunOpts) -> bool {
    if opts.yes || opts.dry_run {
        return !names.is_empty();
    }
    !names.is_empty()
}

/// Query package metadata from installed receipt.
pub async fn query_package(name: &str) -> Option<PackageMeta> {
    let path = format!("/overlayer/zexlib/registry/installed/{}.toml", name.to_lowercase());
    let raw = std::fs::read_to_string(&path).ok()?;
    #[derive(serde::Deserialize, Default)]
    struct R {
        name:        Option<String>,
        version:     Option<String>,
        display_name: Option<String>,
    }
    let r: R = toml::from_str(&raw).unwrap_or_default();
    let pkg_name = r.name.unwrap_or_else(|| name.to_string());
    Some(PackageMeta {
        display_name: r.display_name.unwrap_or_else(|| pkg_name.clone()),
        name: pkg_name,
        version: r.version.unwrap_or_default(),
        size_mb: 0.0,
        origin:  "tier1-zainium".into(),
    })
}