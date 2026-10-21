use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::backend::BackendConfig;

static RATE_LIMIT_MAP: OnceLock<Mutex<HashMap<String, RateLimitState>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct RateLimitState {
    window_start: SystemTime,
    suppressed: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TxnJournal {
    txn_id: String,
    package: String,
    state: String,
    updated_at_utc: String,
    message: String,
}

pub struct TransactionHandle {
    path: PathBuf,
    journal: TxnJournal,
}

pub struct CleanupReport {
    pub removed_temp_artifacts: usize,
    pub removed_stale_locks: usize,
    pub removed_orphan_txn: usize,
}

fn is_terminal_state(state: &str) -> bool {
    matches!(state, "done" | "failed" | "skipped_or_aborted")
}

fn is_valid_transition(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }

    if is_terminal_state(from) {
        return false;
    }

    matches!(
        (from, to),
        ("planned", "resolving")
            | ("planned", "detected")
            | ("planned", "version_check")
            | ("planned", "cleanup")
            | ("planned", "downloading")
            | ("planned", "installing")
            | ("planned", "failed")
            | ("planned", "skipped_or_aborted")
            | ("detected", "version_check")
            | ("detected", "cleanup")
            | ("detected", "downloading_and_installing")
            | ("detected", "failed")
            | ("detected", "skipped_or_aborted")
            | ("version_check", "cleanup")
            | ("version_check", "downloading_and_installing")
            | ("version_check", "done")
            | ("version_check", "failed")
            | ("version_check", "skipped_or_aborted")
            | ("resolving", "downloading")
            | ("resolving", "failed")
            | ("resolving", "skipped_or_aborted")
            | ("downloading", "downloaded")
            | ("downloading", "installing")
            | ("downloading", "downloading_and_installing")
            | ("downloading", "failed")
            | ("downloading", "skipped_or_aborted")
            | ("downloaded", "installing")
            | ("downloaded", "failed")
            | ("downloaded", "skipped_or_aborted")
            | ("cleanup", "downloading_and_installing")
            | ("cleanup", "installing")
            | ("cleanup", "failed")
            | ("cleanup", "skipped_or_aborted")
            | ("downloading_and_installing", "committed")
            | ("downloading_and_installing", "done")
            | ("downloading_and_installing", "failed")
            | ("installing", "committed")
            | ("installing", "done")
            | ("installing", "failed")
            | ("committed", "done")
    )
}

fn zex_log_dir() -> PathBuf {
    PathBuf::from("/overlayer/syshub/var/log/zex")
}

fn zex_equip_log_path() -> PathBuf {
    zex_log_dir().join("equip.log")
}

fn zex_txn_dir() -> PathBuf {
    PathBuf::from("/overlayer/syshub/var/lib/zex/txn")
}

fn zex_lock_dir() -> PathBuf {
    PathBuf::from("/run/lock/zex")
}

fn atomic_write(path: &Path, content: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn rotate_logs_if_needed(max_size_mb: u64, max_files: usize) -> anyhow::Result<()> {
    let log_path = zex_equip_log_path();
    if !log_path.exists() {
        return Ok(());
    }
    let max_bytes = max_size_mb.saturating_mul(1024 * 1024);
    let len = fs::metadata(&log_path)?.len();
    if len < max_bytes {
        return Ok(());
    }

    for idx in (1..=max_files).rev() {
        let src = if idx == 1 {
            log_path.clone()
        } else {
            zex_log_dir().join(format!("equip.log.{}", idx - 1))
        };
        let dst = zex_log_dir().join(format!("equip.log.{}", idx));

        if dst.exists() {
            let _ = fs::remove_file(&dst);
        }
        if src.exists() {
            let _ = fs::rename(src, dst);
        }
    }

    Ok(())
}

pub fn log_event(config: &BackendConfig, level: LogLevel, message: &str) {
    let _ = fs::create_dir_all(zex_log_dir());
    let _ = rotate_logs_if_needed(config.max_log_size_mb, config.max_log_files.max(1));

    let line = format!(
        "{} [{}] {}\n",
        Utc::now().to_rfc3339(),
        level.as_str(),
        message
    );

    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(zex_equip_log_path())
    {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn log_error_rate_limited(config: &BackendConfig, key: &str, message: &str, window_secs: u64) {
    let now = SystemTime::now();
    let map = RATE_LIMIT_MAP.get_or_init(|| Mutex::new(HashMap::new()));

    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(_) => {
            log_event(config, LogLevel::Warn, message);
            return;
        }
    };

    let st = guard.entry(key.to_string()).or_insert(RateLimitState {
        window_start: now,
        suppressed: 0,
    });

    let elapsed = now
        .duration_since(st.window_start)
        .unwrap_or_else(|_| Duration::from_secs(window_secs + 1));

    if elapsed.as_secs() < window_secs {
        st.suppressed += 1;
        return;
    }

    if st.suppressed > 0 {
        log_event(
            config,
            LogLevel::Warn,
            &format!(
                "{} (suppressed {} repeated events in {}s)",
                message, st.suppressed, window_secs
            ),
        );
    } else {
        log_event(config, LogLevel::Warn, message);
    }

    st.window_start = now;
    st.suppressed = 0;
}

pub fn begin_transaction(config: &BackendConfig, package: &str) -> Option<TransactionHandle> {
    let _ = fs::create_dir_all(zex_txn_dir());
    let txn_id = format!(
        "txn-{}-{}",
        package,
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let path = zex_txn_dir().join(format!("{}.json", txn_id));

    let journal = TxnJournal {
        txn_id,
        package: package.to_string(),
        state: "planned".to_string(),
        updated_at_utc: Utc::now().to_rfc3339(),
        message: "transaction created".to_string(),
    };

    let content = serde_json::to_string_pretty(&journal).ok()?;
    if atomic_write(&path, &content).is_err() {
        return None;
    }

    log_event(
        config,
        LogLevel::Info,
        &format!("txn {} started for {}", journal.txn_id, package),
    );

    Some(TransactionHandle { path, journal })
}

impl TransactionHandle {
    pub fn txn_id(&self) -> &str {
        &self.journal.txn_id
    }

    pub fn package_name(&self) -> &str {
        &self.journal.package
    }

    pub fn update(&mut self, state: &str, msg: &str) {
        let current = self.journal.state.clone();
        if !is_valid_transition(&current, state) {
            self.journal.state = "failed".to_string();
            self.journal.updated_at_utc = Utc::now().to_rfc3339();
            self.journal.message = format!(
                "invalid transition blocked: {} -> {} ({})",
                current, state, msg
            );
            if let Ok(content) = serde_json::to_string_pretty(&self.journal) {
                let _ = atomic_write(&self.path, &content);
            }
            return;
        }

        self.journal.state = state.to_string();
        self.journal.updated_at_utc = Utc::now().to_rfc3339();
        self.journal.message = msg.to_string();
        if let Ok(content) = serde_json::to_string_pretty(&self.journal) {
            let _ = atomic_write(&self.path, &content);
        }
    }

    pub fn mark_failed(&mut self, msg: &str) {
        self.update("failed", msg);
    }

    pub fn mark_done(&mut self, msg: &str) {
        self.update("done", msg);
    }
}

pub fn startup_cleanup(config: &BackendConfig) -> CleanupReport {
    let mut report = CleanupReport {
        removed_temp_artifacts: 0,
        removed_stale_locks: 0,
        removed_orphan_txn: 0,
    };

    if !config.crash_cleanup_on_start {
        return report;
    }

    // temp artifacts
    for p in ["/tmp", "/var/tmp"] {
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with(".zex-install-") || name.starts_with("zex-equip-") {
                    if fs::remove_file(e.path()).is_ok() || fs::remove_dir_all(e.path()).is_ok() {
                        report.removed_temp_artifacts += 1;
                    }
                }
            }
        }
    }

    // stale locks
    let lock_ttl = Duration::from_secs(config.stale_lock_ttl_minutes.saturating_mul(60));
    if let Ok(rd) = fs::read_dir(zex_lock_dir()) {
        for e in rd.flatten() {
            if let Ok(meta) = e.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified.elapsed().unwrap_or_default() > lock_ttl {
                        if fs::remove_file(e.path()).is_ok() {
                            report.removed_stale_locks += 1;
                        }
                    }
                }
            }
        }
    }

    // orphan txn journals
    let txn_ttl = Duration::from_secs(config.txn_retention_hours.saturating_mul(3600));
    if let Ok(rd) = fs::read_dir(zex_txn_dir()) {
        for e in rd.flatten() {
            let path = e.path();
            let mut remove = false;
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(j) = serde_json::from_str::<TxnJournal>(&content) {
                    if j.state != "done" {
                        if let Ok(meta) = e.metadata() {
                            if let Ok(modified) = meta.modified() {
                                if modified.elapsed().unwrap_or_default() > txn_ttl {
                                    remove = true;
                                }
                            }
                        }
                    }
                }
            }
            if remove && fs::remove_file(&path).is_ok() {
                report.removed_orphan_txn += 1;
            }
        }
    }

    log_event(
        config,
        LogLevel::Info,
        &format!(
            "startup cleanup: temp_removed={}, stale_locks_removed={}, orphan_txn_removed={}",
            report.removed_temp_artifacts, report.removed_stale_locks, report.removed_orphan_txn
        ),
    );

    report
}

#[cfg(test)]
mod tests {
    use super::is_valid_transition;

    #[test]
    fn allows_expected_equip_transitions() {
        assert!(is_valid_transition("planned", "resolving"));
        assert!(is_valid_transition("resolving", "downloading"));
        assert!(is_valid_transition("downloading", "downloaded"));
        assert!(is_valid_transition("downloaded", "installing"));
        assert!(is_valid_transition("installing", "committed"));
        assert!(is_valid_transition("committed", "done"));
    }

    #[test]
    fn allows_expected_assay_transitions() {
        assert!(is_valid_transition("planned", "detected"));
        assert!(is_valid_transition("detected", "version_check"));
        assert!(is_valid_transition("version_check", "cleanup"));
        assert!(is_valid_transition("cleanup", "downloading_and_installing"));
        assert!(is_valid_transition(
            "downloading_and_installing",
            "committed"
        ));
    }

    #[test]
    fn blocks_invalid_and_terminal_transitions() {
        assert!(!is_valid_transition("planned", "committed"));
        assert!(!is_valid_transition("done", "installing"));
        assert!(!is_valid_transition("failed", "done"));
        assert!(!is_valid_transition("skipped_or_aborted", "resolving"));
    }
}
