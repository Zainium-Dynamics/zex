//! Zex upper-layer management: no kernel mount operations.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

const SYSHUB_ROOT: &str = "/overlayer/syshub";
const ZEXLIB_UNION: &str = "/overlayer/zexlib/union";
const ZEXLIB_WORK: &str = "/overlayer/zexlib/work";
const SYNC_STAMP: &str = "/run/quantra-system/zex-upperlayer-stamp";
const QUANTRA_CONTROL_SOCKET: &str = "/run/quantra-system/control";

#[derive(Debug, Serialize)]
pub struct ZexUpperlayerSyncEvent {
    pub event: &'static str,
    pub timestamp_ms: u128,
    pub upperdir: &'static str,
    pub workdir: &'static str,
    pub stamp_path: &'static str,
}

pub fn build_sync_event() -> ZexUpperlayerSyncEvent {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    ZexUpperlayerSyncEvent {
        event: "zex-upperlayer-sync",
        timestamp_ms,
        upperdir: ZEXLIB_UNION,
        workdir: ZEXLIB_WORK,
        stamp_path: SYNC_STAMP,
    }
}

pub struct UnionLayer {}

impl UnionLayer {
    pub fn new() -> Self {
        let _ = fs::create_dir_all(ZEXLIB_UNION);
        let _ = fs::create_dir_all(ZEXLIB_WORK);
        Self {}
    }

    /// Discover top-level directories from syshub and zexlib/union.
    fn discover_directories(&self) -> Vec<String> {
        let mut dirs = HashSet::new();

        for root in [SYSHUB_ROOT, ZEXLIB_UNION] {
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        dirs.insert(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
        }

        let mut sorted: Vec<String> = dirs.into_iter().collect();
        sorted.sort();
        sorted
    }

    /// Ensure upperdir subdirectories exist for every merged layer path.
    pub fn prepare_upperlayer(&self) -> Result<()> {
        fs::create_dir_all(ZEXLIB_UNION).context("create zexlib/union")?;
        fs::create_dir_all(ZEXLIB_WORK).context("create zexlib/work")?;

        for dir in self.discover_directories() {
            let upper = Path::new(ZEXLIB_UNION).join(&dir);
            let work = Path::new(ZEXLIB_WORK).join(&dir);
            fs::create_dir_all(&upper)
                .with_context(|| format!("create upperdir '{}'", upper.display()))?;
            fs::create_dir_all(&work)
                .with_context(|| format!("create workdir '{}'", work.display()))?;
        }
        Ok(())
    }

    /// Write a JSON sync stamp for Quantra inotify/watchers.
    fn touch_sync_stamp(&self) -> Result<()> {
        if let Some(parent) = Path::new(SYNC_STAMP).parent() {
            fs::create_dir_all(parent).ok();
        }

        let event = build_sync_event();
        let json =
            serde_json::to_string_pretty(&event).context("serialize zex upperlayer sync event")?;
        fs::write(SYNC_STAMP, json).with_context(|| format!("write sync stamp {SYNC_STAMP}"))?;

        ping_quantra_control();
        Ok(())
    }

    /// Called after install/remove: prepares upperlayer dirs and stamps sync.
    pub fn sync_after_package_change(&self) -> Result<()> {
        self.prepare_upperlayer()?;
        self.touch_sync_stamp()?;
        log::debug!("zexlib upperlayer synced (Quantra overlay owns mount(2))");
        Ok(())
    }

    /// Backward-compatible alias used by install/remove drivers.
    pub fn apply_live_mounts(&self) -> Result<()> {
        self.sync_after_package_change()
    }

    /// Backward-compatible alias: fstab is owned by Quantra, not zex.
    pub fn sync_fstab(&self) -> Result<()> {
        self.touch_sync_stamp()
    }
}

/// Best-effort reachability check for Quantra PID1 control socket.
/// Non-fatal when Quantra is not running (e.g. dev host or early boot).
fn ping_quantra_control() {
    #[cfg(unix)]
    {
        match UnixStream::connect(QUANTRA_CONTROL_SOCKET) {
            Ok(_) => log::debug!(
                "Quantra control socket reachable at {QUANTRA_CONTROL_SOCKET} after zex sync"
            ),
            Err(e) => log::debug!(
                "Quantra control socket not reachable at {QUANTRA_CONTROL_SOCKET} (non-fatal): {e}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_layer_constructs() {
        let _layer = UnionLayer::new();
    }

    #[test]
    fn sync_event_json_has_required_fields() {
        let event = build_sync_event();
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("zex-upperlayer-sync"));
        assert!(json.contains(ZEXLIB_UNION));
        assert!(json.contains(SYNC_STAMP));
    }
}
