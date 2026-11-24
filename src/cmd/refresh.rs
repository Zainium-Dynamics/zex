//! refresh.rs: Fetch every tier's package index into the zex cache.

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
            // `zex install` keeps its own copy of each index, named after the URL and reused
            // for two hours; refresh that one too, or install misses what was just published.
            // Same naming function install uses, so the two can never drift apart.
            let install_copy =
                save.then(|| cache.join(crate::cmd::install::backend::index_cache_name(&url)));
            tokio::spawn(async move {
                let res = fetch(&client, &url, dest.clone()).await;
                if res.is_ok()
                    && let (Some(dest), Some(copy)) = (&dest, &install_copy)
                {
                    let _ = std::fs::copy(dest, copy);
                }
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

#[cfg(test)]
mod tests {
    use crate::cmd::install::backend::index_cache_name;

    #[test]
    fn install_copy_name_matches_install_cache_name() {
        // refresh writes the extra copy under the same name install reads it by.
        let url = "https://archive.zainiumdynamics.tech/core/syshub/x86_64/syshub.toml";
        assert_eq!(
            index_cache_name(url),
            "https___archive_zainiumdynamics_tech_core_syshub_x86_64_syshub_toml"
        );
    }

    #[test]
    fn zainium_zex_mirrors_have_no_arch_placeholder() {
        // `zex install`'s zex backend fetches the zex mirror index by its RAW
        // index_url (no {arch} substitution), while refresh substitutes {arch}.
        // They name the same cache file only if the zex index_url has no {arch}.
        // Lock that invariant so a future config edit can't silently make
        // `zex refresh` stop feeding `zex install`.
        let toml_text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/zex_services.toml"));
        let v: toml::Value = toml::from_str(toml_text).expect("zex_services.toml parses");
        let mirrors = v
            .get("mirrors")
            .and_then(|m| m.as_array())
            .expect("[[mirrors]]");
        let mut checked = 0;
        for m in mirrors {
            if m.get("format").and_then(|f| f.as_str()) != Some("zex") {
                continue;
            }
            let url = m
                .get("index_url")
                .and_then(|u| u.as_str())
                .expect("index_url");
            assert!(
                !url.contains("{arch}"),
                "zex mirror index_url {url} uses {{arch}}, but the zex backend fetches it raw; \
                 refresh would cache it under a different name and install would miss it"
            );
            assert_eq!(
                index_cache_name(url),
                index_cache_name(&url.replace("{arch}", super::arch())),
                "refresh and install disagree on the cache name for {url}"
            );
            checked += 1;
        }
        assert!(checked >= 1, "expected at least one zex mirror in the config");
    }
}
