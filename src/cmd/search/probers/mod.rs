//! probers/mod.rs — Zainium 4-tier search probers.
//!
//! Each prober fetches the index for its tier and filters by query.
//! All probers run concurrently via tokio::join!.
//!
//! Tier routing (from zex_services.toml):
//!   Tier 1 (Zainium) → zainium-userland-zexlib  format=zex   TOML ledger
//!   Tier 2 (Alpine)  → alpine-main + community  format=apk   APKINDEX.tar.gz
//!   Tier 3 (Void)    → void-musl-current         format=xbps  zstd repodata
//!   Tier 4 (Chimera) → chimera-main + user       format=adb   Packages.adb (apk-tools v3)

pub mod adb;
pub mod apk;
pub mod xbps;
pub mod zex;

use crate::cmd::search::models::{Origin, SearchResult};

pub use adb::probe_adb;
pub use apk::probe_apk;
pub use xbps::probe_xbps;
pub use zex::probe_zex;

/// Run all 4 tiers concurrently and merge results, deduplicating
/// by (name, origin) — same package from two Alpine mirrors = one result.
pub async fn probe_all(
    query: &str,
    client: &reqwest::Client,
    services: &crate::cmd::search::config::ZexServices,
    arch: &str,
    installed: &std::collections::HashSet<String>,
) -> Vec<SearchResult> {
    let (t1, t2a, t2b, t3, t4a, t4b) = tokio::join!(
        probe_tier1(query, client, services),
        probe_apk_mirror(query, client, services, "alpine-main", arch, Origin::Alpine),
        probe_apk_mirror(
            query,
            client,
            services,
            "alpine-community",
            arch,
            Origin::Alpine
        ),
        probe_xbps_mirror(query, client, services, arch),
        probe_adb_mirror(query, client, services, "chimera-main", arch),
        probe_adb_mirror(query, client, services, "chimera-user", arch),
    );

    let mut all: Vec<SearchResult> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for mut r in t1
        .into_iter()
        .chain(t2a)
        .chain(t2b)
        .chain(t3)
        .chain(t4a)
        .chain(t4b)
    {
        let key = format!("{}:{}", r.name, r.origin.label());
        if seen.insert(key) {
            r.installed = installed.contains(&r.name);
            all.push(r);
        }
    }

    // Sort: Zainium first, then alphabetically, installed floated to top
    all.sort_by(|a, b| {
        b.installed
            .cmp(&a.installed)
            .then_with(|| (a.origin.label()).cmp(b.origin.label()))
            .then_with(|| a.name.cmp(&b.name))
    });
    all
}

// ── Internal per-tier helpers ─────────────────────────────────────────────────

async fn probe_tier1(
    query: &str,
    client: &reqwest::Client,
    services: &crate::cmd::search::config::ZexServices,
) -> Vec<SearchResult> {
    let Some(mirror) = services.mirror_by_id("zainium-userland-zexlib") else {
        return vec![];
    };
    probe_zex(query, client, &mirror.index_url)
        .await
        .unwrap_or_default()
}

async fn probe_apk_mirror(
    query: &str,
    client: &reqwest::Client,
    services: &crate::cmd::search::config::ZexServices,
    id: &str,
    arch: &str,
    origin: Origin,
) -> Vec<SearchResult> {
    let Some(mirror) = services.mirror_by_id(id) else {
        return vec![];
    };
    let index_url = mirror.index_url.replace("{arch}", arch);
    probe_apk(query, client, &index_url, origin)
        .await
        .unwrap_or_default()
}

async fn probe_xbps_mirror(
    query: &str,
    client: &reqwest::Client,
    services: &crate::cmd::search::config::ZexServices,
    arch: &str,
) -> Vec<SearchResult> {
    let Some(mirror) = services.mirror_by_id("void-musl-current") else {
        return vec![];
    };
    let index_url = mirror.index_url.replace("{arch}", arch);
    probe_xbps(query, client, &index_url)
        .await
        .unwrap_or_default()
}

async fn probe_adb_mirror(
    query: &str,
    client: &reqwest::Client,
    services: &crate::cmd::search::config::ZexServices,
    id: &str,
    arch: &str,
) -> Vec<SearchResult> {
    let Some(mirror) = services.mirror_by_id(id) else {
        return vec![];
    };
    let index_url = mirror.index_url.replace("{arch}", arch);
    probe_adb(query, client, &index_url)
        .await
        .unwrap_or_default()
}
