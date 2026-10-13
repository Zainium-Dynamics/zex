//! resolver.rs — Orchestrates the dynamic, multi-engine resolution pipeline.
//!
//! This is the public face of the resolution layer. Callers (infuse.rs) ask
//! for a package by name and receive either a fully-populated [`PackageInfo`]
//! or an unambiguous "not found" error.
//!
//! Resolution pipeline
//! ───────────────────
//!   1. Normalise: lower-case the name, strip leading/trailing whitespace.
//!   2. Iterate over all configured mirrors (from `zex_services.toml`).
//!   3. Dispatch concurrently based on `mirror.format` (apk, xbps, zex).
//!   4. Return the first match found, respecting the priority order.
//!   5. If all mirrors fail: return a typed `NotFound` error.

use super::backend::{self, BackendConfig, PackageInfo};
use std::sync::Arc;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Typed error returned when no backend can find a package.
#[derive(Debug)]
pub enum ResolveError {
    /// The package name was not present in any mirror.
    NotFound(String),
    /// A hard infrastructure error occurred (network down, parse failure, …).
    Infra(anyhow::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotFound(n) => write!(f, "package '{}' not found in any mirror", n),
            ResolveError::Infra(e) => write!(f, "{}", e),
        }
    }
}

impl From<anyhow::Error> for ResolveError {
    fn from(e: anyhow::Error) -> Self {
        ResolveError::Infra(e)
    }
}

/// Batched resolution result with explicit failure classification.
pub struct ResolveManyResult {
    pub resolved: Vec<PackageInfo>,
    pub not_found: Vec<String>,
    pub infra_failed: Vec<(String, String)>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Resolves `name` to a [`PackageInfo`] by trying all configured mirrors concurrently.
pub async fn resolve(
    name: &str,
    client: &reqwest::Client,
    config: &BackendConfig,
    mm: &backend::MetadataManager,
) -> std::result::Result<PackageInfo, ResolveError> {
    let normalised = name.trim().to_lowercase();

    if config.mirrors.is_empty() {
        return Err(ResolveError::Infra(anyhow::anyhow!(
            "No mirrors configured in BackendConfig"
        )));
    }

    // `zex install --void wget` arrives as "void/wget": only that repository's
    // mirrors (id "void" or "void-*") are asked; plain names ask every mirror
    let (repository, normalised) = match normalised.split_once('/') {
        Some((r, n)) if !r.is_empty() && !n.is_empty() => (Some(r.to_string()), n.to_string()),
        _ => (None, normalised),
    };

    let mut sorted_mirrors = config.mirrors.clone();
    if let Some(r) = &repository {
        sorted_mirrors.retain(|m| m.id == *r || m.id.starts_with(&format!("{r}-")));
    }
    sorted_mirrors.sort_by_key(|m| m.priority);

    // Ask every mirror at once but take the answers in priority order, and return as soon
    // as the best mirror that has the package answers instead of waiting for the slowest
    // index (Void's repodata alone is ~17 s). Dropping the rest cancels their downloads.
    let name_ref = &normalised;
    let mut answers: futures::stream::FuturesOrdered<_> = sorted_mirrors
        .iter()
        .map(|mirror| async move {
            match mirror.format.as_str() {
                "apk" => super::apk::resolve_apk(name_ref, client, config, mm, mirror).await,
                "xbps" => super::xbps::resolve_xbps(name_ref, client, config, mm, mirror).await,
                "adb" => super::adb::resolve_adb(name_ref, client, config, mm, mirror).await,
                "zex" => super::zex_backend::resolve_zex(name_ref, client, config, mm).await,
                _ => {
                    log::warn!("Unknown mirror format: {}", mirror.format);
                    Ok(None)
                }
            }
        })
        .collect();

    let mut i = 0;
    while let Some(result) = futures::StreamExt::next(&mut answers).await {
        match result {
            Ok(Some(info)) => return Ok(info),
            Ok(None) => { /* not found in this mirror */ }
            Err(e) => {
                log::warn!(
                    "[Mirror: {}] infrastructure error for '{}': {:#}",
                    sorted_mirrors[i].id,
                    normalised,
                    e
                );
            }
        }
        i += 1;
    }
    drop(answers);

    // All mirrors exhausted.
    Err(ResolveError::NotFound(normalised))
}

/// Result of [`resolve_preferring`] — same as a normal resolve, plus
/// whether the package had to be found on a *different* mirror than the
/// one preferred (tier-affinity fallback).
pub struct ResolvedWithAffinity {
    pub info: PackageInfo,
    /// `Some(preferred_mirror_id)` if a preference was given but the
    /// package wasn't found there and a cross-tier/cross-mirror fallback
    /// had to be used instead; `None` if either no preference was given,
    /// or the preferred mirror satisfied it directly.
    pub fell_back_from: Option<String>,
}

/// Resolves `name`, trying `preferred_mirror_id` (if given) *before*
/// falling back to the normal all-mirrors-by-priority search.
///
/// Dependency resolution used to always search every mirror in raw
/// priority order, with no notion of "this dependency belongs to the same
/// tier as the package that needs it" — so a dependency could silently
/// resolve from a *different* distro's repo than its own package came
/// from whenever that other tier happened to have higher priority and
/// also shipped a same-named package (confirmed repeatedly with real data:
/// `busybox`, `xbps`, `base-files` each exist in more than one of
/// Alpine/Void/Chimera's repos). Preferring the root package's own mirror
/// for its dependencies first — falling back cross-tier only when that
/// mirror genuinely doesn't have it, and telling the caller when that
/// happens — makes dependency resolution tier-consistent by default
/// instead of an accident of priority ordering.
pub async fn resolve_preferring(
    name: &str,
    client: &reqwest::Client,
    config: &BackendConfig,
    mm: &backend::MetadataManager,
    preferred_mirror_id: Option<&str>,
) -> std::result::Result<ResolvedWithAffinity, ResolveError> {
    let normalised = name.trim().to_lowercase();

    if let Some(pref_id) = preferred_mirror_id {
        if let Some(mirror) = config.mirrors.iter().find(|m| m.id == pref_id) {
            let result = match mirror.format.as_str() {
                "apk" => super::apk::resolve_apk(&normalised, client, config, mm, mirror).await,
                "xbps" => super::xbps::resolve_xbps(&normalised, client, config, mm, mirror).await,
                "adb" => super::adb::resolve_adb(&normalised, client, config, mm, mirror).await,
                "zex" => super::zex_backend::resolve_zex(&normalised, client, config, mm).await,
                _ => Ok(None),
            };
            match result {
                Ok(Some(info)) => {
                    return Ok(ResolvedWithAffinity {
                        info,
                        fell_back_from: None,
                    });
                }
                Ok(None) => { /* not in the preferred mirror — fall through */ }
                Err(e) => {
                    log::warn!(
                        "[Mirror: {}] infra error resolving '{}' from its preferred mirror: {:#}",
                        pref_id,
                        normalised,
                        e
                    );
                    /* fall through to the full search rather than hard-failing */
                }
            }
        }
    }

    let info = resolve(&normalised, client, config, mm).await?;
    Ok(ResolvedWithAffinity {
        info,
        fell_back_from: preferred_mirror_id.map(|s| s.to_string()),
    })
}

/// Resolves multiple package names concurrently.
pub async fn resolve_many(
    names: &[String],
    client: &reqwest::Client,
    config: &BackendConfig,
    mm: Arc<backend::MetadataManager>,
) -> ResolveManyResult {
    let mut futures = Vec::with_capacity(names.len());

    for name in names {
        let value = mm.clone();
        futures.push(async move { (name.clone(), resolve(name, client, config, &value).await) });
    }

    let mut resolved = Vec::new();
    let mut not_found = Vec::new();
    let mut infra_failed = Vec::new();

    let results = futures::future::join_all(futures).await;

    for result in results {
        match result {
            (_name, Ok(info)) => resolved.push(info),
            (name, Err(ResolveError::NotFound(_))) => not_found.push(name),
            (name, Err(ResolveError::Infra(e))) => {
                infra_failed.push((name, e.to_string()));
            }
        }
    }

    ResolveManyResult {
        resolved,
        not_found,
        infra_failed,
    }
}
