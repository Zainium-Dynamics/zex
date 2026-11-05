//! persist_cache.rs: File-backed backend detection cache.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::backend::PackageBackend;

const CACHE_PATH: &str = "/overlayer/zexlib/registry/cache/backend-detect.toml";
const TTL_SECS: i64 = 3600;

#[derive(Debug, Serialize, Deserialize, Default)]
struct CacheFile {
    #[serde(default)]
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    backend: String,
    cached_at: i64,
}

pub struct PersistCache;

impl PersistCache {
    pub fn get(name: &str) -> anyhow::Result<Option<PackageBackend>> {
        let cache = load_cache()?;
        let key = name.to_ascii_lowercase();
        let Some(entry) = cache.entries.get(&key) else {
            return Ok(None);
        };
        let now = now_secs();
        if now.saturating_sub(entry.cached_at) > TTL_SECS {
            return Ok(None);
        }
        Ok(parse_backend(&entry.backend))
    }

    pub fn set(name: &str, backend: PackageBackend) -> anyhow::Result<()> {
        let mut cache = load_cache().unwrap_or_default();
        cache.entries.insert(
            name.to_ascii_lowercase(),
            CacheEntry {
                backend: backend.label().to_string(),
                cached_at: now_secs(),
            },
        );
        save_cache(&cache)
    }

    pub fn invalidate(name: &str) -> anyhow::Result<()> {
        let mut cache = load_cache().unwrap_or_default();
        cache.entries.remove(&name.to_ascii_lowercase());
        save_cache(&cache)
    }

    pub fn prune_stale() -> anyhow::Result<usize> {
        let mut cache = load_cache().unwrap_or_default();
        let now = now_secs();
        let before = cache.entries.len();
        cache
            .entries
            .retain(|_, e| now.saturating_sub(e.cached_at) <= TTL_SECS);
        save_cache(&cache)?;
        Ok(before.saturating_sub(cache.entries.len()))
    }
}

fn parse_backend(label: &str) -> Option<PackageBackend> {
    match label {
        "zex-store" => Some(PackageBackend::ZexStore),
        "apt" => Some(PackageBackend::Apt),
        "flatpak" => Some(PackageBackend::Flatpak),
        "snap" => Some(PackageBackend::Snap),
        _ => None,
    }
}

fn load_cache() -> anyhow::Result<CacheFile> {
    let path = Path::new(CACHE_PATH);
    if !path.exists() {
        return Ok(CacheFile::default());
    }
    let raw = fs::read_to_string(path)?;
    Ok(toml::from_str(&raw).unwrap_or_default())
}

fn save_cache(cache: &CacheFile) -> anyhow::Result<()> {
    let path = Path::new(CACHE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = format!("{CACHE_PATH}.tmp");
    let data = toml::to_string_pretty(cache)?;
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
