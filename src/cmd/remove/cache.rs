// zex/src/cache.rs
//
// Backend Detection Cache
// ────────────────────────
// Caches backend probing results to avoid redundant dpkg/flatpak/snap queries.
// Useful when removing multiple packages in parallel or re-checking dependencies.
//
// Thread-safe via RwLock.

use super::backend::PackageBackend;
use lazy_static::lazy_static;
use std::collections::HashMap;
use tokio::sync::RwLock;

lazy_static! {
    static ref BACKEND_CACHE: RwLock<HashMap<String, Option<PackageBackend>>> =
        RwLock::new(HashMap::new());
}

/// Get cached backend for a package, or None if not in cache.
#[allow(dead_code)]
pub async fn get_cached(name: &str) -> Option<Option<PackageBackend>> {
    let cache = BACKEND_CACHE.read().await;
    cache.get(name).cloned()
}

/// Store backend result in cache.
#[allow(dead_code)]
pub async fn set_cached(name: String, backend: Option<PackageBackend>) {
    let mut cache = BACKEND_CACHE.write().await;
    cache.insert(name, backend);
}

/// Clear the entire cache (useful for retries).
#[allow(dead_code)]
pub async fn clear() {
    let mut cache = BACKEND_CACHE.write().await;
    cache.clear();
}
