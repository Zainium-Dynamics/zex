//! probers/xbps.rs: XBPS repodata search (Void Linux).

use anyhow::Result;
use std::io::Read;

use crate::cmd::search::models::{Origin, SearchResult};

pub async fn probe_xbps(
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
        let dec = match zstd::stream::read::Decoder::new(&bytes[..]) {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        let mut archive = tar::Archive::new(dec);
        let mut plist_bytes = Vec::new();

        for entry in archive.entries().into_iter().flatten() {
            let mut e = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let is_index = e
                .path()
                .ok()
                .and_then(|p| p.file_name().map(|n| n == "index.plist"))
                .unwrap_or(false);
            if is_index {
                let _ = e.read_to_end(&mut plist_bytes);
                break;
            }
        }

        if plist_bytes.is_empty() {
            return vec![];
        }

        let val = match plist::from_bytes::<plist::Value>(&plist_bytes) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let dict = match val.into_dictionary() {
            Some(d) => d,
            None => return vec![],
        };

        let mut out = Vec::new();
        for (key, meta_val) in dict {
            let Some(meta) = meta_val.as_dictionary() else {
                continue;
            };

            let name = key.clone();
            let pkgver = meta
                .get("pkgver")
                .and_then(|v| v.as_string())
                .unwrap_or(&key);
            let ver = pkgver
                .strip_prefix(&format!("{key}-"))
                .unwrap_or(pkgver)
                .to_string();
            let desc = meta
                .get("short_desc")
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();

            if name.is_empty() {
                continue;
            }

            let lname = name.to_ascii_lowercase();
            let ldesc = desc.to_ascii_lowercase();

            if lname.contains(&q_inner) || ldesc.contains(&q_inner) {
                out.push(SearchResult {
                    name,
                    version: ver,
                    origin: Origin::Void,
                    description: desc,
                    installed: false,
                    tags: Vec::new(),
                });
            }
        }
        out
    })
    .await
    .unwrap_or_default();

    Ok(results)
}
