//! suggest.rs: Fuzzy "did you mean?" suggestions for not-found queries.

use super::config::ZexServices;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Default)]
struct Ledger {
    #[serde(default)]
    packages: HashMap<String, toml::Value>,
}

/// Return up to 4 fuzzy-similar package names from the Zainium Tier 1 index.
pub async fn fuzzy_suggest(
    query: &str,
    services: &ZexServices,
    client: &reqwest::Client,
) -> Vec<String> {
    let Some(mirror) = services.mirror_by_id("zainium-userland-zexlib") else {
        return vec![];
    };

    let Ok(resp) = client.get(&mirror.index_url).send().await else {
        return vec![];
    };
    let Ok(raw) = resp.text().await else {
        return vec![];
    };
    let Ok(ledger) = toml::from_str::<Ledger>(&raw) else {
        return vec![];
    };

    let q = query.to_ascii_lowercase();
    let mut scored: Vec<(usize, String)> = ledger
        .packages
        .keys()
        .map(|name| (edit_distance(&q, &name.to_ascii_lowercase()), name.clone()))
        .filter(|(d, _)| *d <= 4)
        .collect();

    scored.sort_by_key(|(d, _)| *d);
    scored.into_iter().take(4).map(|(_, n)| n).collect()
}

/// Basic Levenshtein edit distance.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n]
}
