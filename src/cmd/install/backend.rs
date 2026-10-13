//! backend.rs — Dual-Engine resolution backends.
//!
//! Architecture
//! ────────────
//! Two independent resolution backends are tried in strict priority order:
//!
//!   Tier 1 — Zainium (.zex)         Native Zainium packages.
//!   Tier 2 — Alpine  (.apk)         APK compat (Alpine/Chimera).
//!   Tier 3 — Void    (.xbps)        XBPS compat (Void Linux).
//!   Tier 4 — Chimera (.apk)         APK compat (Chimera Linux).
//!
//! Backend names are *never* surfaced to the user.
//! Resolution is fully dynamic and configured via /etc/zex/equip.toml or env vars.
//!
//! NOTE: Zex native repo (repo.zainiumdynamics.tech) is currently offline.
//! Re-enable when the repo goes live. Arch tier has been permanently removed.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

// ─── Configuration ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct MirrorConfig {
    pub id: String,
    pub description: Option<String>,
    pub base_url: String,
    pub index_url: String,
    pub format: String,
    pub priority: u32,
    pub supported_archs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct CoreConfigFile {
    cache_dir: Option<String>,
    install_concurrency: Option<usize>,
    integrity_mode: Option<String>,
    mirror_rtt_scoring: Option<bool>,
    signature_verification_mode: Option<String>,
    max_log_size_mb: Option<u64>,
    max_log_files: Option<usize>,
    txn_retention_hours: Option<u64>,
    stale_lock_ttl_minutes: Option<u64>,
    crash_cleanup_on_start: Option<bool>,
    debug_logging: Option<bool>,
}

// NOTE: ArchConfigFile removed — Arch tier permanently disabled.

#[derive(Debug, Deserialize, Default)]
struct AssayConfigFile {
    nvidia_url: Option<String>,
    amd_url: Option<String>,
    intel_url: Option<String>,
    intel_version: Option<String>,
    nvidia_driver_template: Option<String>,
    amd_driver_template: Option<String>,
    intel_driver_template: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NetworkConfigFile {
    http_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct ZexConfigFile {
    repo_base: Option<String>,
    index_url: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[non_exhaustive]
struct BackendConfigFile {
    // Flat legacy keys
    cache_dir: Option<String>,
    zex_repo_base: Option<String>,
    zex_index_url: Option<String>,
    nvidia_url: Option<String>,
    amd_url: Option<String>,
    intel_url: Option<String>,
    intel_version: Option<String>,
    nvidia_driver_template: Option<String>,
    amd_driver_template: Option<String>,
    intel_driver_template: Option<String>,
    install_concurrency: Option<usize>,
    integrity_mode: Option<String>,
    mirror_rtt_scoring: Option<bool>,
    signature_verification_mode: Option<String>,
    max_log_size_mb: Option<u64>,
    max_log_files: Option<usize>,
    txn_retention_hours: Option<u64>,
    stale_lock_ttl_minutes: Option<u64>,
    crash_cleanup_on_start: Option<bool>,
    debug_logging: Option<bool>,

    // Nested modern keys
    core: Option<CoreConfigFile>,
    zex: Option<ZexConfigFile>,
    network: Option<NetworkConfigFile>,
    mirrors: Option<Vec<MirrorConfig>>,
}

pub struct BackendConfig {
    pub cache_dir: String,
    pub zex_repo_base: String,
    pub zex_index_url: String,
    pub nvidia_url: String,
    pub amd_url: String,
    pub intel_url: String,
    pub intel_version: String,
    pub nvidia_driver_template: String,
    pub amd_driver_template: String,
    pub intel_driver_template: String,
    pub install_concurrency: usize,
    pub integrity_mode: String,
    pub mirror_rtt_scoring: bool,
    pub signature_verification_mode: String,
    pub max_log_size_mb: u64,
    pub max_log_files: usize,
    pub txn_retention_hours: u64,
    pub stale_lock_ttl_minutes: u64,
    pub crash_cleanup_on_start: bool,
    pub debug_logging: bool,
    pub http_timeout_secs: u64,
    pub metadata_ttl: u64,
    pub mirrors: Vec<MirrorConfig>,
}

impl BackendConfig {
    fn merge_mirrors(target: &mut Vec<MirrorConfig>, overlays: Vec<MirrorConfig>) {
        let mut seen = HashSet::new();
        let mut merged = Vec::with_capacity(target.len() + overlays.len());

        for mirror in overlays.into_iter().chain(target.drain(..)) {
            let key = format!("{}|{}", mirror.id, mirror.base_url);
            if seen.insert(key) {
                merged.push(mirror);
            }
        }

        *target = merged;
    }

    fn with_defaults() -> Self {
        Self {
            cache_dir: "/overlayer/zexlib/registry/cache".to_string(),
            zex_repo_base: "".to_string(),
            zex_index_url: "".to_string(),
            nvidia_url: "".to_string(),
            amd_url: "".to_string(),
            intel_url: "".to_string(),
            intel_version: "".to_string(),
            nvidia_driver_template: "".to_string(),
            amd_driver_template: "".to_string(),
            intel_driver_template: "".to_string(),
            install_concurrency: 5,
            integrity_mode: "strict".to_string(),
            mirror_rtt_scoring: false,
            signature_verification_mode: "strict".to_string(),
            max_log_size_mb: 50,
            max_log_files: 5,
            txn_retention_hours: 168, // 7 days
            stale_lock_ttl_minutes: 60,
            crash_cleanup_on_start: true,
            debug_logging: false,
            http_timeout_secs: 30,
            metadata_ttl: 7200,
            mirrors: Vec::new(),
        }
    }

    fn apply_file_overrides(&mut self, parsed: BackendConfigFile) {
        if let Some(v) = parsed.cache_dir {
            self.cache_dir = v;
        }
        if let Some(v) = parsed.zex_repo_base {
            self.zex_repo_base = v;
        }
        if let Some(v) = parsed.zex_index_url {
            self.zex_index_url = v;
        }

        if let Some(v) = parsed.nvidia_url {
            self.nvidia_url = v;
        }
        if let Some(v) = parsed.amd_url {
            self.amd_url = v;
        }
        if let Some(v) = parsed.intel_url {
            self.intel_url = v;
        }
        if let Some(v) = parsed.intel_version {
            self.intel_version = v;
        }
        if let Some(v) = parsed.nvidia_driver_template {
            self.nvidia_driver_template = v;
        }
        if let Some(v) = parsed.amd_driver_template {
            self.amd_driver_template = v;
        }
        if let Some(v) = parsed.intel_driver_template {
            self.intel_driver_template = v;
        }
        if let Some(v) = parsed.install_concurrency {
            self.install_concurrency = v;
        }
        if let Some(v) = parsed.integrity_mode {
            self.integrity_mode = v;
        }
        if let Some(v) = parsed.mirror_rtt_scoring {
            self.mirror_rtt_scoring = v;
        }
        if let Some(v) = parsed.signature_verification_mode {
            self.signature_verification_mode = v;
        }

        if let Some(v) = parsed.max_log_size_mb {
            self.max_log_size_mb = v;
        }
        if let Some(m) = parsed.mirrors {
            Self::merge_mirrors(&mut self.mirrors, m);
        }
        if let Some(v) = parsed.max_log_files {
            self.max_log_files = v;
        }
        if let Some(v) = parsed.txn_retention_hours {
            self.txn_retention_hours = v;
        }
        if let Some(v) = parsed.stale_lock_ttl_minutes {
            self.stale_lock_ttl_minutes = v;
        }
        if let Some(v) = parsed.crash_cleanup_on_start {
            self.crash_cleanup_on_start = v;
        }
        if let Some(v) = parsed.debug_logging {
            self.debug_logging = v;
        }

        if let Some(core) = parsed.core {
            if let Some(v) = core.cache_dir {
                self.cache_dir = v;
            }
            if let Some(v) = core.install_concurrency {
                self.install_concurrency = v;
            }
            if let Some(v) = core.integrity_mode {
                self.integrity_mode = v;
            }
            if let Some(v) = core.mirror_rtt_scoring {
                self.mirror_rtt_scoring = v;
            }
            if let Some(v) = core.signature_verification_mode {
                self.signature_verification_mode = v;
            }
            if let Some(v) = core.max_log_size_mb {
                self.max_log_size_mb = v;
            }
            if let Some(v) = core.max_log_files {
                self.max_log_files = v;
            }
            if let Some(v) = core.txn_retention_hours {
                self.txn_retention_hours = v;
            }
            if let Some(v) = core.stale_lock_ttl_minutes {
                self.stale_lock_ttl_minutes = v;
            }
            if let Some(v) = core.crash_cleanup_on_start {
                self.crash_cleanup_on_start = v;
            }
            if let Some(v) = core.debug_logging {
                self.debug_logging = v;
            }
        }
        if let Some(zex) = parsed.zex {
            if let Some(v) = zex.repo_base {
                self.zex_repo_base = v;
            }
            if let Some(v) = zex.index_url {
                self.zex_index_url = v;
            }
        }

        if let Some(network) = parsed.network {
            if let Some(v) = network.http_timeout_secs {
                self.http_timeout_secs = v;
            }
        }
    }

    /// Loads configuration from environment variables or /overlayer/zexlib/services/zex_services.toml.
    /// Priority: Env Vars > Config File > Internal Defaults
    pub fn load() -> Result<Self> {
        let mut config = BackendConfig::with_defaults();

        let env_path = std::env::var("ZEX_INSTALL_CONFIG").ok();
        let search_paths = [
            env_path.as_deref(),
            Some("/overlayer/syshub/engine/services/zex_services.toml"),
            Some("zex_services.toml"),
        ];

        for path_opt in search_paths {
            let Some(path) = path_opt else {
                continue;
            };
            if !Path::new(path).exists() {
                continue;
            }

            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path))?;
            let parsed: BackendConfigFile =
                toml::from_str(&content).with_context(|| format!("failed to parse {}", path))?;
            config.apply_file_overrides(parsed);
            break;
        }

        // Environment overrides
        // NOTE: ZEX_ARCH_MIRROR / ZEX_ARCH_API env vars removed — Arch tier disabled
        // NOTE: ZEX_RPM_REPO_BASE / ZEX_RPM_REPOMD env vars removed — RPM tier disabled
        if let Ok(c) = std::env::var("ZEX_CACHE_DIR") {
            config.cache_dir = c;
        }
        if let Ok(v) = std::env::var("ZEX_ZEX_REPO_BASE") {
            config.zex_repo_base = v;
        }
        if let Ok(v) = std::env::var("ZEX_ZEX_INDEX_URL") {
            config.zex_index_url = v;
        }
        if let Ok(n) = std::env::var("ZEX_NVIDIA_URL") {
            config.nvidia_url = n;
        }
        if let Ok(am) = std::env::var("ZEX_AMD_URL") {
            config.amd_url = am;
        }
        if let Ok(iu) = std::env::var("ZEX_INTEL_URL") {
            config.intel_url = iu;
        }
        if let Ok(iv) = std::env::var("ZEX_INTEL_VERSION") {
            config.intel_version = iv;
        }
        if let Ok(nt) = std::env::var("ZEX_NVIDIA_DRIVER_URL") {
            config.nvidia_driver_template = nt;
        }
        if let Ok(at) = std::env::var("ZEX_AMD_DRIVER_URL") {
            config.amd_driver_template = at;
        }
        if let Ok(it) = std::env::var("ZEX_INTEL_DRIVER_URL") {
            config.intel_driver_template = it;
        }
        if let Ok(ic) = std::env::var("ZEX_INSTALL_CONCURRENCY") {
            if let Ok(parsed) = ic.parse::<usize>() {
                config.install_concurrency = parsed;
            }
        }
        if let Ok(mode) = std::env::var("ZEX_INTEGRITY_MODE") {
            config.integrity_mode = mode;
        }
        if let Ok(rtt) = std::env::var("ZEX_MIRROR_RTT_SCORING") {
            let lowered = rtt.trim().to_ascii_lowercase();
            config.mirror_rtt_scoring = matches!(lowered.as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ZEX_SIGNATURE_VERIFICATION_MODE") {
            config.signature_verification_mode = v;
        }

        if let Ok(v) = std::env::var("ZEX_MAX_LOG_SIZE_MB") {
            if let Ok(parsed) = v.parse::<u64>() {
                config.max_log_size_mb = parsed;
            }
        }
        if let Ok(v) = std::env::var("ZEX_MAX_LOG_FILES") {
            if let Ok(parsed) = v.parse::<usize>() {
                config.max_log_files = parsed;
            }
        }
        if let Ok(v) = std::env::var("ZEX_TXN_RETENTION_HOURS") {
            if let Ok(parsed) = v.parse::<u64>() {
                config.txn_retention_hours = parsed;
            }
        }
        if let Ok(v) = std::env::var("ZEX_STALE_LOCK_TTL_MINUTES") {
            if let Ok(parsed) = v.parse::<u64>() {
                config.stale_lock_ttl_minutes = parsed;
            }
        }
        if let Ok(v) = std::env::var("ZEX_CRASH_CLEANUP_ON_START") {
            let lowered = v.trim().to_ascii_lowercase();
            config.crash_cleanup_on_start = matches!(lowered.as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ZEX_DEBUG_LOGGING") {
            let lowered = v.trim().to_ascii_lowercase();
            config.debug_logging = matches!(lowered.as_str(), "1" | "true" | "yes" | "on");
        }

        if config.mirrors.is_empty() {
            anyhow::bail!("equip config has no mirrors configured");
        }
        // NOTE: Arch tier permanently removed — no arch_mirror/arch_api validation
        // NOTE: RPM tier permanently removed
        if config.install_concurrency == 0 {
            config.install_concurrency = 1;
        }

        if config.max_log_size_mb == 0 {
            config.max_log_size_mb = 10;
        }
        if config.max_log_files == 0 {
            config.max_log_files = 5;
        }
        if config.txn_retention_hours == 0 {
            config.txn_retention_hours = 24;
        }
        if config.stale_lock_ttl_minutes == 0 {
            config.stale_lock_ttl_minutes = 30;
        }
        let mode = config.integrity_mode.trim().to_ascii_lowercase();
        if mode != "strict" && mode != "balanced" {
            anyhow::bail!(
                "equip config has invalid integrity_mode '{}'; expected strict|balanced",
                config.integrity_mode
            );
        }
        config.integrity_mode = mode;

        let sig_mode = config
            .signature_verification_mode
            .trim()
            .to_ascii_lowercase();
        if sig_mode != "off" && sig_mode != "audit" && sig_mode != "strict" {
            anyhow::bail!(
                "equip config has invalid signature_verification_mode '{}'; expected off|audit|strict",
                config.signature_verification_mode
            );
        }
        config.signature_verification_mode = sig_mode;

        let ensure_https = |label: &str, url: &str| -> Result<()> {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                anyhow::bail!("equip config has empty {}", label);
            }
            if !trimmed.to_ascii_lowercase().starts_with("https://") {
                anyhow::bail!("equip config requires https for {} (got '{}')", label, url);
            }
            Ok(())
        };

        // URL validation: only require a valid scheme (http or https).
        // Mirrors use separate SHA256 integrity verification so HTTP is acceptable.
        let ensure_valid_url = |label: &str, url: &str| -> Result<()> {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                anyhow::bail!("equip config has empty {}", label);
            }
            let lower = trimmed.to_ascii_lowercase();
            if !lower.starts_with("https://") && !lower.starts_with("http://") {
                anyhow::bail!(
                    "equip config requires http(s) for {} (got '{}')",
                    label,
                    url
                );
            }
            Ok(())
        };

        // Mirrors: allow HTTP — integrity verified separately via SHA256
        for (idx, mirror) in config.mirrors.iter().enumerate() {
            ensure_valid_url(&format!("mirrors[{}].base_url", idx), &mirror.base_url)?;
        }

        // Clamp timeout to sane range: 30s minimum, 600s maximum
        if config.http_timeout_secs < 30 {
            config.http_timeout_secs = 30;
        }
        if config.http_timeout_secs > 600 {
            config.http_timeout_secs = 600;
        }

        Ok(config)
    }
}

// ─── Metadata Management ─────────────────────────────────────────────────────

/// High-performance metadata manager with disk and memory caching.
/// Ensures large index files (like Packages.gz) are only fetched once.
pub struct MetadataManager {
    cache_dir: PathBuf,
    memory: Mutex<HashMap<String, Arc<Vec<u8>>>>,
}

impl MetadataManager {
    pub fn new(cache_dir: &str) -> Self {
        let path = PathBuf::from(cache_dir);
        let _ = std::fs::create_dir_all(&path);
        Self {
            cache_dir: path,
            memory: Mutex::new(HashMap::new()),
        }
    }

    pub async fn fetch(
        &self,
        url: &str,
        client: &reqwest::Client,
        force: bool,
    ) -> Result<(Arc<Vec<u8>>, bool)> {
        // 1. Check memory cache (only if not forcing)
        if !force {
            let mem = self.memory.lock().await;
            if let Some(data) = mem.get(url) {
                return Ok((Arc::clone(data), false));
            }
        }

        // 2. Check disk cache
        let safe_name = url.replace(|c: char| !c.is_alphanumeric(), "_");
        let cache_path = self.cache_dir.join(safe_name);

        if !force {
            if let Ok(meta) = std::fs::metadata(&cache_path) {
                let elapsed = meta.modified()?.elapsed()?.as_secs();
                // Intelligent Blocking (2 Hours TTL)
                if elapsed < 7200 {
                    if let Ok(data) = std::fs::read(&cache_path) {
                        let arc_data = Arc::new(data);
                        self.memory
                            .lock()
                            .await
                            .insert(url.to_owned(), Arc::clone(&arc_data));
                        return Ok((arc_data, false));
                    }
                }
            }
        }

        // Cache > 2 Hours Old (or missing): Block & Fetch
        log::info!("Refreshing index from {}", url);
        let resp = client.get(url).send().await?;
        let bytes = resp.bytes().await?.to_vec();
        let arc_data = Arc::new(bytes);

        // 4. Save to disk and memory
        let _ = std::fs::write(&cache_path, &*arc_data);
        self.memory
            .lock()
            .await
            .insert(url.to_owned(), Arc::clone(&arc_data));

        Ok((arc_data, true))
    }
}

// ─── Shared data types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageFormat {
    Zex,
    Apk,
    Xbps,
    /// apk-tools v3's binary "ADB" container format (Chimera Linux).
    Adb,
}

impl Default for PackageFormat {
    fn default() -> Self {
        Self::Zex
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub display_name: String,
    pub version: String,
    #[serde(default)]
    pub source_mirror: Option<String>,
    pub url: String,
    pub size: u64,
    pub launch_cmd: String,
    pub format: PackageFormat,
    pub filename: String,
    /// SHA256 checksum of the package file as provided by the repository index.
    /// `None` means the backend did not supply a checksum (will skip verification).
    pub sha256: Option<String>,
    /// Blake3 checksum for native Zex packages.
    #[serde(default)]
    pub blake3: Option<String>,
    /// Raw dependency names parsed from the repository index.
    /// Empty for backends that don't supply dependency info yet.
    #[serde(default)]
    pub depends: Vec<String>,
    /// Libraries or virtual packages this package provides
    #[serde(default)]
    pub provides: Vec<String>,
    /// Packages this one is incompatible with (Alpine's "D:!pkgname"
    /// negative-dependency convention — real data most backends silently
    /// discarded before). Installing this package while any of these is
    /// already installed (or installing one of these while this package
    /// is installed) is refused, not silently allowed.
    #[serde(default)]
    pub conflicts: Vec<String>,
    /// URL of the detached signature companion file (Void's `.sig2`).
    /// `None` for formats that embed their signature in the package itself.
    #[serde(default)]
    pub sig_url: Option<String>,
    /// Minimum syshub base OS version required by this package
    #[serde(default)]
    pub requires_syshub: Option<String>,
    /// Human-readable description (used by zex search)
    #[serde(default)]
    pub description: Option<String>,
    /// SPDX license identifier
    #[serde(default)]
    pub license: Option<String>,
    /// Package maintainer / packager
    #[serde(default)]
    pub maintainer: Option<String>,
    /// Search/classification tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Link type: "static" | "dynamic" | "firmware"
    #[serde(default)]
    pub build_type: Option<String>,
    /// libc family: "relibc" | "musl" | "freestanding"
    #[serde(default)]
    pub libc_target: Option<String>,
    /// Package edition (Rust-style) — None means latest/default
    #[serde(default)]
    pub edition: Option<String>,
    /// Ed25519 signature from the ledger
    #[serde(default)]
    pub ed25519_sig: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DownloadStats {
    pub bytes: u64,
    pub duration: std::time::Duration,
    pub speed_mbps: f64,
}

impl DownloadStats {
    pub fn size_mb(&self) -> f64 {
        self.bytes as f64 / 1_000_000.0
    }
    pub fn secs(&self) -> f64 {
        self.duration.as_secs_f64()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DbEntry {
    pub name: String,
    pub display_name: String,
    pub version: String,
    pub size: u64,
    pub format: PackageFormat,
    pub installed_at: String,
    pub installed_files: Vec<String>,
    /// SHA256 of the installed package file (for audit / reinstall verification)
    pub sha256: Option<String>,
    /// Blake3 of the installed native Zex package file (if available).
    #[serde(default)]
    pub blake3: Option<String>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Dynamic resolution for display name and launch command.
pub fn dynamic_metadata(name: &str, description: Option<&str>) -> (String, String) {
    let launch_cmd = name.to_owned();
    let display_name = if let Some(desc) = description {
        let first_line = desc.lines().next().unwrap_or("").trim();
        if !first_line.is_empty() && first_line.len() < 40 {
            first_line.trim_end_matches('.').to_owned()
        } else {
            capitalise(name)
        }
    } else {
        capitalise(name)
    };
    (display_name, launch_cmd)
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct MirrorScoreStore {
    /// Exponentially-smoothed RTT samples per mirror key (ms).
    /// Field name kept as `rtt_ms` — not Debian-related.
    rtt_ms: HashMap<String, f64>,
}

fn mirror_score_path(cache_dir: &str) -> PathBuf {
    PathBuf::from(cache_dir).join("mirror_scores.json")
}

fn load_mirror_scores(cache_dir: &str) -> MirrorScoreStore {
    let path = mirror_score_path(cache_dir);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<MirrorScoreStore>(&s).ok())
        .unwrap_or_default()
}

fn save_mirror_scores(cache_dir: &str, scores: &MirrorScoreStore) {
    let path = mirror_score_path(cache_dir);
    if let Ok(json) = serde_json::to_string_pretty(scores) {
        let _ = std::fs::write(path, json);
    }
}

fn update_rtt_score(scores: &mut MirrorScoreStore, mirror_key: &str, sample_ms: f64) {
    let alpha = 0.30;
    let prev = scores.rtt_ms.get(mirror_key).copied().unwrap_or(sample_ms);
    let next = (1.0 - alpha) * prev + alpha * sample_ms;
    scores.rtt_ms.insert(mirror_key.to_string(), next);
}

// ─── Syshub Core Manifest ───────────────────────────────────────────────────────

/// The real on-disk shape: `[packages]` holds plain `name = "version"`
/// entries *and* a nested `[packages.provides]` sub-table of virtual-name
/// aliases (`libc = "musl"`, `openssl = "libressl"`, ...) — confirmed
/// against the actual `syshub.toml` on this OS. The old struct declared
/// `provides` as a *top-level* field (expecting `[provides]`), which never
/// matches this file's real `[packages.provides]` nesting — `provides` was
/// silently always empty. `#[serde(flatten)]` correctly splits the two:
/// serde extracts the named `provides` field first, and flatten captures
/// every remaining `[packages]` key into `versions`.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
struct SyshubManifest {
    // Real syshub.toml is `[packages.<name>]` sub-tables (version, file,
    // size_bytes, depends, provides, build_type, libc_target — a genuine
    // TOML table), not `packages.<name> = "1.2.3"` flat strings. The old
    // `HashMap<String, String>` shape here made every `toml::from_str`
    // call fail with a type-mismatch error, which the caller's `let Ok(..)
    // else { return false }` swallowed silently — `is_in_syshub` always
    // returned false for every name, no matter what. Confirmed live: `zex
    // install jq` (Alpine) tried to also install `musl` as a plain
    // dependency and hit a real file conflict against syshub's own
    // ld-musl-x86_64.so.1, because the "musl is already provided by the
    // base OS" check never actually worked.
    packages: Option<HashMap<String, toml::Value>>,
}

/// Normalize a dependency token down to a bare library/package name for
/// matching against the syshub manifest. Handles the two real shapes seen
/// in the wild: Alpine/Void/Chimera's `so:`-prefixed soname tokens
/// (`so:libz.so.1`, `so:libc.musl-x86_64.so.1`), and plain package names.
fn normalize_dep_token(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let stripped = lower.strip_prefix("so:").unwrap_or(&lower);
    // musl's soname always embeds the architecture triple
    // (libc.musl-x86_64.so.1, libc.musl-aarch64.so.1, ...) — nobody would
    // author that exact versioned string as a manifest alias key, so
    // recognize the family directly rather than requiring an exact match.
    if stripped.starts_with("libc.musl") {
        return "libc".to_string();
    }
    stripped.to_string()
}

/// Checks if a package or virtual dependency is provided natively by Zainium OS's Syshub.
pub fn is_in_syshub(name: &str) -> bool {
    let path = "/overlayer/syshub/engine/services/syshub.toml";
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(manifest) = toml::from_str::<SyshubManifest>(&content) else {
        return false;
    };
    let Some(pkgs) = &manifest.packages else {
        return false;
    };

    let lower_name = name.to_ascii_lowercase();
    let normalized = normalize_dep_token(name);

    // Direct package-name match (e.g. a plain "curl" or "musl" token).
    if pkgs.keys().any(|k| k.eq_ignore_ascii_case(&lower_name)) {
        return true;
    }

    // Virtual-name alias match (e.g. "so:libz.so.1" -> normalized
    // "libz.so.1") against each package's own `provides` array — real
    // syshub.toml entries carry `provides` per-package
    // (`[packages.bash] provides = ["bash", "sh"]`), not as one flat
    // top-level alias table.
    pkgs.values().any(|v| {
        v.as_table()
            .and_then(|t| t.get("provides"))
            .and_then(|p| p.as_array())
            .is_some_and(|arr| {
                arr.iter().any(|item| {
                    item.as_str().is_some_and(|s| {
                        s.eq_ignore_ascii_case(&normalized) || s.eq_ignore_ascii_case(&lower_name)
                    })
                })
            })
    })
}

// ─── Package Database (TOML Registry) ─────────────────────────────────────────
//
// Backed by /overlayer/zexlib/registry/installed/*.toml
// One file per package — no SQLite, no JSON, no dpkg.

pub fn load_db() -> Vec<DbEntry> {
    super::registry::load_all()
        .into_iter()
        .map(|r| r.into_db_entry())
        .collect()
}

/// Look up a single installed package by name (case-insensitive).
/// Returns the `DbEntry` including the list of all files owned by this package.
pub fn lookup_installed(name: &str) -> Option<DbEntry> {
    super::registry::lookup(name).map(|r| r.into_db_entry())
}

/// Registers a package in the TOML registry (atomic write).
pub fn register_package(info: &PackageInfo, installed_files: Vec<String>) -> Result<()> {
    let record = super::registry::PkgRecord::from_install(info, installed_files);
    super::registry::register(&record)
}
