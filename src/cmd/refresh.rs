//! refresh.rs — Fetch every tier's package index into the zex cache.
//!
//! One request per mirror in zex_services.toml (Zainium core and userland,
//! Alpine, Void, Chimera), all at once. Each mirror prints OK with its size
//! or the full error chain, so a stale TLS pin or broken DNS shows up here
//! instead of as an empty search.

use std::path::PathBuf;

use anyhow::Result;

use crate::cmd::search::config::{Mirror, ZexServices};

const CACHE_DIR: &str = "/overlayer/zexlib/registry/cache";

pub async fn run(_raw_args: Vec<String>) -> Result<()> {
    let client = crate::http_client::build(concat!(
        "refresh/",
        env!("CARGO_PKG_VERSION"),
        " (Zainium OS)"
    ))?;
    if refresh_all(&client, arch()).await > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Fetch every mirror's index, caching it when the cache is writable; returns how many failed.
pub async fn refresh_all(client: &reqwest::Client, arch: &str) -> usize {
    let cache = std::env::var_os("ZEX_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CACHE_DIR));
    let save = std::fs::create_dir_all(&cache).is_ok() && writable(&cache);

    let mut mirrors: Vec<Mirror> = ZexServices::load()
        .mirrors
        .into_iter()
        .filter(|m| m.supported_archs.is_empty() || m.supported_archs.iter().any(|a| a == arch))
        .collect();
    mirrors.sort_by_key(|m| m.priority);

    println!("\n \x1b[96mRefreshing repositories...\x1b[0m\n");
    let tasks: Vec<_> = mirrors
        .into_iter()
        .map(|m| {
            let client = client.clone();
            let url = m.index_url.replace("{arch}", arch);
            let file = url.rsplit('/').next().unwrap_or("index").to_string();
            let dest = save.then(|| cache.join(format!("{}.{file}", m.id)));
            tokio::spawn(async move {
                let res = fetch(&client, &url, dest).await;
                (m, res)
            })
        })
        .collect();

    let mut failed = 0;
    for task in tasks {
        let Ok((m, res)) = task.await else {
            failed += 1;
            continue;
        };
        match res {
            Ok(len) => println!(
                "  \x1b[92m✓\x1b[0m {:<8} {:<28} {}",
                tier(&m.format),
                m.id,
                human(len)
            ),
            Err(e) => {
                failed += 1;
                println!("  \x1b[91m✗\x1b[0m {:<8} {:<28} {e}", tier(&m.format), m.id);
            }
        }
    }
    if !save {
        println!("\n  Indexes not cached: run with elevate to save them.");
    }
    println!();
    failed
}

async fn fetch(
    client: &reqwest::Client,
    url: &str,
    dest: Option<PathBuf>,
) -> Result<usize, String> {
    let resp = client.get(url).send().await.map_err(chain)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let body = resp.bytes().await.map_err(chain)?;
    if let Some(dest) = dest {
        let part = dest.with_extension("part");
        std::fs::write(&part, &body)
            .and_then(|_| std::fs::rename(&part, &dest))
            .map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    Ok(body.len())
}

/// reqwest's own message is just "error sending request"; the cause (DNS, TLS pin) is in the sources.
fn chain(e: reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(cause) = src {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        src = cause.source();
    }
    msg
}

fn writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".zex-refresh-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

fn tier(format: &str) -> &str {
    match format {
        "zex" => "Zainium",
        "apk" => "Alpine",
        "xbps" => "Void",
        "adb" => "Chimera",
        other => other,
    }
}

fn human(len: usize) -> String {
    if len >= 1 << 20 {
        format!("{:.1} MB", len as f64 / (1 << 20) as f64)
    } else {
        format!("{:.0} KB", len as f64 / 1024.0)
    }
}

fn arch() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    return "aarch64";
    #[cfg(not(target_arch = "aarch64"))]
    return "x86_64";
}
