//! probers/apk.rs — APK index search (Alpine / Chimera).
//! Parses APKINDEX.tar.gz exactly as the upgrade driver does.

use anyhow::Result;
use std::io::Read;

use crate::cmd::search::models::{Origin, SearchResult};

pub async fn probe_apk(
    query: &str,
    client: &reqwest::Client,
    index_url: &str,
    origin: Origin,
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
    let origin_c = origin.clone();
    let results = tokio::task::spawn_blocking(move || -> Vec<SearchResult> {
        // APKINDEX.tar.gz is a concatenation of multiple gzip members
        // (signature tarball + index tarball) — a plain GzDecoder only
        // reads the first member and silently truncates before APKINDEX.
        let dec = flate2::read::MultiGzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(dec);
        let mut text = String::new();

        for entry in archive.entries().into_iter().flatten() {
            let mut e = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let is_apkindex = e
                .path()
                .ok()
                .and_then(|p| p.file_name().map(|n| n == "APKINDEX"))
                .unwrap_or(false);
            if is_apkindex {
                let _ = e.read_to_string(&mut text);
                break;
            }
        }

        let mut out = Vec::new();
        for block in text.split("\n\n") {
            if block.trim().is_empty() {
                continue;
            }
            let mut name = String::new();
            let mut ver = String::new();
            let mut desc = String::new();

            for line in block.lines() {
                if line.len() < 2 {
                    continue;
                }
                match &line[..2] {
                    "P:" => name = line[2..].to_string(),
                    "V:" => ver = line[2..].to_string(),
                    "T:" => desc = line[2..].to_string(),
                    _ => {}
                }
            }

            if name.is_empty() {
                continue;
            }
            let lname = name.to_ascii_lowercase();
            let ldesc = desc.to_ascii_lowercase();

            if lname.contains(&q_inner) || ldesc.contains(&q_inner) {
                out.push(SearchResult {
                    name,
                    version: ver,
                    origin: origin_c.clone(),
                    description: desc,
                    installed: false,
                    tags: Vec::new(),
                });
            }
        }
        out
    })
    .await?;

    Ok(results)
}
