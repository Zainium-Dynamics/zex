//! stats.rs: Removal timing/size stats.
use std::time::Duration;

pub struct RemoveStats {
    pub bytes_freed: u64,
    pub duration: Duration,
}

impl RemoveStats {
    pub fn freed_mb(&self) -> f64 {
        self.bytes_freed as f64 / 1_048_576.0
    }
    pub fn secs(&self) -> f64 {
        self.duration.as_secs_f64()
    }
}

pub struct Stats;
impl Stats {
    pub async fn record_removal(_size_mb: f64) {}
    pub async fn record_cache_hit() {}
    pub async fn record_cache_miss() {}
}
