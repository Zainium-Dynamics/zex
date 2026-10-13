//! probers/adb.rs — Chimera Linux search via apk-tools v3's binary "ADB"
//! database format (`Packages.adb`). See `cmd::install::adb` for the
//! format decoder itself — this just runs it against a search query.

use anyhow::Result;

use crate::cmd::search::models::{Origin, SearchResult};

pub async fn probe_adb(
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

    let q_inner = q.clone();
    let results = tokio::task::spawn_blocking(move || -> Vec<SearchResult> {
        let records = match crate::cmd::install::adb::parse_index(&bytes) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        records
            .into_iter()
            .filter(|r| {
                r.name.to_ascii_lowercase().contains(&q_inner)
                    || r.description.to_ascii_lowercase().contains(&q_inner)
            })
            .map(|r| SearchResult {
                name: r.name,
                version: r.version,
                origin: Origin::Chimera,
                description: r.description,
                installed: false,
                tags: Vec::new(),
            })
            .collect()
    })
    .await
    .unwrap_or_default();

    Ok(results)
}
