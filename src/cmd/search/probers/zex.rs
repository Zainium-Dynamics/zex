//! probers/zex.rs — Tier 1 Zainium native index search (TOML ledger).

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

use crate::cmd::search::models::{Origin, SearchResult};

#[derive(Deserialize)]
struct Ledger {
    #[serde(default)]
    packages: HashMap<String, LedgerEntry>,
}

#[derive(Deserialize)]
struct LedgerEntry {
    version: Option<String>,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    provides: Vec<String>,
}

pub async fn probe_zex(
    query: &str,
    client: &reqwest::Client,
    index_url: &str,
) -> Result<Vec<SearchResult>> {
    let q = query.to_ascii_lowercase();

    let bytes = client
        .get(index_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let raw = std::str::from_utf8(&bytes)?;
    let ledger: Ledger = toml::from_str(raw)?;

    let mut results = Vec::new();
    for (name, entry) in &ledger.packages {
        let lname = name.to_ascii_lowercase();
        let ldesc = entry
            .description
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let ltags: Vec<_> = entry.tags.iter().map(|t| t.to_ascii_lowercase()).collect();

        if lname.contains(&q)
            || ldesc.contains(&q)
            || ltags.iter().any(|t| t.contains(&q))
            || entry
                .provides
                .iter()
                .any(|p| p.to_ascii_lowercase().contains(&q))
        {
            results.push(SearchResult {
                name: name.clone(),
                version: entry.version.clone().unwrap_or_default(),
                origin: Origin::Zainium,
                description: entry.description.clone().unwrap_or_default(),
                installed: false,
                tags: entry.tags.clone(),
            });
        }
    }

    // Sort: exact name match first, then prefix match, then substring
    results.sort_by(|a, b| {
        let a_exact = a.name.to_ascii_lowercase() == q;
        let b_exact = b.name.to_ascii_lowercase() == q;
        let a_pfx = a.name.to_ascii_lowercase().starts_with(&q);
        let b_pfx = b.name.to_ascii_lowercase().starts_with(&q);
        b_exact
            .cmp(&a_exact)
            .then(b_pfx.cmp(&a_pfx))
            .then(a.name.cmp(&b.name))
    });

    Ok(results)
}
