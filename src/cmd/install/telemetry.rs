use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::backend::{BackendConfig, PackageFormat};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInstallMetric {
    pub ts_utc: String,
    pub package: String,
    pub format: String,
    pub resolve_ms: u128,
    pub download_ms: u128,
    pub verify_ms: u128,
    pub extract_ms: u128,
    pub db_ms: u128,
    pub total_ms: u128,
    pub download_speed_mbps: f64,
    pub install_concurrency: usize,
}

#[derive(Debug, Serialize)]
struct DashboardStat {
    p50_ms: u128,
    p95_ms: u128,
    p99_ms: u128,
    count: usize,
}

#[derive(Debug, Serialize)]
struct TelemetryDashboard {
    generated_at_utc: String,
    window_size: usize,
    overall_total_ms: DashboardStat,
    by_format_total_ms: HashMap<String, DashboardStat>,
}

fn format_to_str(fmt: &PackageFormat) -> &'static str {
    match fmt {
        PackageFormat::Zex => "zex",
        PackageFormat::Apk => "apk",
        PackageFormat::Xbps => "xbps",
        PackageFormat::Adb => "adb",
    }
}

fn metrics_dir(cache_dir: &str) -> PathBuf {
    Path::new(cache_dir).join("telemetry")
}

fn metrics_log_path(cache_dir: &str) -> PathBuf {
    metrics_dir(cache_dir).join("package_install_metrics.jsonl")
}

fn dashboard_path(cache_dir: &str) -> PathBuf {
    metrics_dir(cache_dir).join("rolling_dashboard.json")
}

fn percentile_ms(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

fn stats_for(values: &[u128]) -> DashboardStat {
    if values.is_empty() {
        return DashboardStat {
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            count: 0,
        };
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    DashboardStat {
        p50_ms: percentile_ms(&sorted, 0.50),
        p95_ms: percentile_ms(&sorted, 0.95),
        p99_ms: percentile_ms(&sorted, 0.99),
        count: sorted.len(),
    }
}

pub fn build_metric(
    package: &str,
    format: &PackageFormat,
    resolve_ms: u128,
    download_ms: u128,
    verify_ms: u128,
    extract_ms: u128,
    db_ms: u128,
    download_speed_mbps: f64,
    install_concurrency: usize,
) -> PackageInstallMetric {
    PackageInstallMetric {
        ts_utc: Utc::now().to_rfc3339(),
        package: package.to_string(),
        format: format_to_str(format).to_string(),
        resolve_ms,
        download_ms,
        verify_ms,
        extract_ms,
        db_ms,
        total_ms: resolve_ms + download_ms + verify_ms + extract_ms + db_ms,
        download_speed_mbps,
        install_concurrency,
    }
}

pub fn append_and_refresh_dashboard(
    config: &BackendConfig,
    metrics: &[PackageInstallMetric],
) -> anyhow::Result<()> {
    if metrics.is_empty() {
        return Ok(());
    }

    let dir = metrics_dir(&config.cache_dir);
    fs::create_dir_all(&dir)?;

    let log_path = metrics_log_path(&config.cache_dir);
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    for m in metrics {
        let line = serde_json::to_string(m)?;
        writeln!(f, "{}", line)?;
    }

    refresh_dashboard(config, 500)
}

fn refresh_dashboard(config: &BackendConfig, window: usize) -> anyhow::Result<()> {
    let log_path = metrics_log_path(&config.cache_dir);
    let content = fs::read_to_string(log_path).unwrap_or_default();

    let mut parsed: Vec<PackageInstallMetric> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<PackageInstallMetric>(l).ok())
        .collect();

    if parsed.len() > window {
        parsed = parsed.split_off(parsed.len() - window);
    }

    let overall: Vec<u128> = parsed.iter().map(|m| m.total_ms).collect();

    let mut by_format: HashMap<String, Vec<u128>> = HashMap::new();
    for m in &parsed {
        by_format
            .entry(m.format.clone())
            .or_default()
            .push(m.total_ms);
    }

    let mut by_format_stats = HashMap::new();
    for (fmt, values) in by_format {
        by_format_stats.insert(fmt, stats_for(&values));
    }

    let dashboard = TelemetryDashboard {
        generated_at_utc: Utc::now().to_rfc3339(),
        window_size: window,
        overall_total_ms: stats_for(&overall),
        by_format_total_ms: by_format_stats,
    };

    let dash_path = dashboard_path(&config.cache_dir);
    let json = serde_json::to_string_pretty(&dashboard)?;
    fs::write(dash_path, json)?;

    Ok(())
}
