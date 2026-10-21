//! diff.rs — Compare installed vs remote for both userland and syshub.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs};

use super::vercmp::is_upgrade;

// ── zex_services schema ───────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct ZexServices {
    #[serde(default)]
    pub mirrors: Vec<Mirror>,
    #[serde(default)]
    pub trust: TrustConf,
}

#[derive(Debug, Deserialize, Default)]
pub struct TrustConf {
    #[serde(default)]
    pub require_signatures: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Mirror {
    pub id: String,
    pub base_url: String,
    pub index_url: String,
    pub format: String,
    pub priority: u32,
    #[serde(default)]
    pub supported_archs: Vec<String>,
}

pub fn load_services(path: &str) -> Result<ZexServices> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    toml::from_str(&raw).context("parsing zex_services.toml")
}

impl ZexServices {
    pub fn mirror_by_id(&self, id: &str) -> Option<&Mirror> {
        self.mirrors.iter().find(|m| m.id == id)
    }
}

// ── Upgrade record ────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct UpgradePkg {
    pub name: String,
    pub old_ver: String,
    pub new_ver: String,
    pub url: String,
    pub filename: String,
    pub size_bytes: u64,
}

// ── Userland diff ─────────────────────────────────────────────────────────────
pub async fn diff_userland(
    services: &ZexServices,
    client: &reqwest::Client,
    arch: &str,
    installed_dir: &str,
) -> Result<Vec<UpgradePkg>> {
    let Some(mirror) = services.mirror_by_id("zainium-userland-zexlib") else {
        return Ok(vec![]);
    };
    let index_url = mirror.index_url.replace("{arch}", arch);
    let base_url = mirror.base_url.replace("{arch}", arch);

    let raw = client
        .get(&index_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    #[derive(Deserialize)]
    struct Ledger {
        packages: HashMap<String, toml::Value>,
    }
    let ledger: Ledger = toml::from_str(&raw)?;

    // Read all installed receipts
    let mut installed: HashMap<String, String> = HashMap::new();
    if let Ok(dir) = fs::read_dir(installed_dir) {
        for entry in dir.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".toml") || fname.ends_with(".editions.toml") {
                continue;
            }
            #[derive(Deserialize, Default)]
            struct R {
                name: String,
                #[serde(default)]
                version: String,
            }
            if let Ok(raw) = fs::read_to_string(entry.path()) {
                if let Ok(r) = toml::from_str::<R>(&raw) {
                    installed.insert(r.name.to_ascii_lowercase(), r.version);
                }
            }
        }
    }

    let mut upgrades = Vec::new();
    for (name, val) in &ledger.packages {
        let new_ver = val_str(val);
        let key = name.to_ascii_lowercase();
        let Some(old_ver) = installed.get(&key) else {
            continue;
        };
        if !is_upgrade(old_ver, &new_ver) {
            continue;
        }

        let filename = format!("{name}-{new_ver}.zex");
        let url = format!("{}/{}", base_url.trim_end_matches('/'), filename);
        let size_bytes = content_length(client, &url).await.unwrap_or(0);

        upgrades.push(UpgradePkg {
            name: name.clone(),
            old_ver: old_ver.clone(),
            new_ver,
            url,
            filename,
            size_bytes,
        });
    }
    upgrades.sort_by_key(|u| u.name.clone());
    Ok(upgrades)
}

// ── Syshub diff ───────────────────────────────────────────────────────────────
pub async fn diff_syshub(
    services: &ZexServices,
    client: &reqwest::Client,
    local_manifest: &str,
) -> Result<(Vec<UpgradePkg>, String)> {
    let Some(mirror) = services.mirror_by_id("zainium-core-stable-syshub") else {
        return Ok((vec![], String::new()));
    };

    let remote_raw = client
        .get(&mirror.index_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let local_raw = fs::read_to_string(local_manifest).unwrap_or_default();

    #[derive(Deserialize, Default)]
    struct Manifest {
        packages: HashMap<String, toml::Value>,
    }
    let remote: Manifest = toml::from_str(&remote_raw).unwrap_or_default();
    let local: Manifest = toml::from_str(&local_raw).unwrap_or_default();

    let mut upgrades = Vec::new();
    for (name, rv) in &remote.packages {
        let new_ver = val_str(rv);
        let old_ver = local
            .packages
            .get(name)
            .map(val_str)
            .unwrap_or_else(|| "0".into());
        if !is_upgrade(&old_ver, &new_ver) {
            continue;
        }

        let filename = format!("{name}-{new_ver}.zex");
        let url = format!("{}/{}", mirror.base_url.trim_end_matches('/'), filename);
        let size_bytes = content_length(client, &url).await.unwrap_or(0);

        upgrades.push(UpgradePkg {
            name: name.clone(),
            old_ver,
            new_ver,
            url,
            filename,
            size_bytes,
        });
    }
    upgrades.sort_by_key(|u| u.name.clone());
    Ok((upgrades, remote_raw))
}

fn val_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0")
            .to_string(),
        other => other.to_string().trim_matches('"').to_string(),
    }
}

async fn content_length(client: &reqwest::Client, url: &str) -> Option<u64> {
    client
        .head(url)
        .send()
        .await
        .ok()?
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}
