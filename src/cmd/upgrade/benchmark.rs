//! benchmark.rs — Upgrade/install hot-path timing helpers.

use std::time::Instant;

/// Lightweight benchmark guard — prints elapsed on drop.
pub struct Benchmark {
    label:   String,
    started: Instant,
    threshold_ms: u128,
}

impl Benchmark {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            started: Instant::now(),
            threshold_ms: 500,
        }
    }

    pub fn with_threshold(label: impl Into<String>, threshold_ms: u128) -> Self {
        Self {
            label: label.into(),
            started: Instant::now(),
            threshold_ms,
        }
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }
}

impl Drop for Benchmark {
    fn drop(&mut self) {
        let ms = self.elapsed_ms();
        if ms > self.threshold_ms {
            eprintln!("  \x1b[2m[bench] {}: {}ms\x1b[0m", self.label, ms);
        }
    }
}

/// Record a named phase duration for structured logging.
pub fn record_phase(phase: &str, started: Instant) {
    let ms = started.elapsed().as_millis();
    log::info!("phase {phase} completed in {ms}ms");
}
