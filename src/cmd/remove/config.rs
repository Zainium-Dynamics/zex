// zex/src/config.rs
//
// Configuration File Support
// ──────────────────────────
// Reads config from:
//   1. ~/.config/zx/zai-remove.toml    (user config)
//   2. /etc/zx/zai-remove.toml         (system config)
//
// Schema:
// [defaults]
// recursive = true
// yes = false
// verbose = false
//
// [backends]
// enable_apt = true
// enable_flatpak = true
// enable_snap = true
//
// [cache]
// ttl_minutes = 30

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub backends: Backends,
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Defaults {
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub yes: bool,
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Backends {
    #[serde(default = "default_true")]
    pub enable_apt: bool,
    #[serde(default = "default_true")]
    pub enable_flatpak: bool,
    #[serde(default = "default_true")]
    pub enable_snap: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheConfig {
    #[serde(default = "default_cache_ttl")]
    pub ttl_minutes: u64,
}

fn default_true() -> bool {
    true
}
fn default_cache_ttl() -> u64 {
    30
}

impl Config {
    /// Load config from standard locations (user → system).
    /// Returns Default if no config files found.
    pub fn load() -> Result<Self> {
        // Try user config first
        let user_config = Self::from_path(Self::user_config_path());

        if user_config.is_ok() {
            return user_config;
        }

        // Try system config
        Self::from_path(Self::system_config_path()).or_else(|_| {
            // Return default if both fail
            Ok(Config::default())
        })
    }

    /// Load config from specific file path.
    fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(anyhow!("Config file not found: {}", path.display()));
        }

        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Get user config path (~/.config/zx/zai-remove.toml).
    fn user_config_path() -> std::path::PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        std::path::PathBuf::from(format!("{}/.config/zx/zai-remove.toml", home))
    }

    /// Get system config path (/etc/zx/zai-remove.toml).
    fn system_config_path() -> std::path::PathBuf {
        std::path::PathBuf::from("/etc/zx/zai-remove.toml")
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            defaults: Defaults::default(),
            backends: Backends {
                enable_apt: true,
                enable_flatpak: true,
                enable_snap: true,
            },
            cache: CacheConfig { ttl_minutes: 30 },
        }
    }
}
