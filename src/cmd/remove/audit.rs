//! audit.rs: Removal audit log.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

const AUDIT_PATH: &str = "/overlayer/zexlib/registry/remove-audit.toml";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub packages: Vec<String>,
    pub freed_mb: f64,
    pub duration_ms: u64,
    pub dry_run: bool,
}

pub fn append(entry: AuditEntry) -> Result<()> {
    let mut entries: Vec<AuditEntry> = if Path::new(AUDIT_PATH).exists() {
        let raw = fs::read_to_string(AUDIT_PATH)?;
        toml::from_str(&raw).unwrap_or_default()
    } else {
        Vec::new()
    };
    entries.push(entry);
    if entries.len() > 200 {
        entries.drain(0..entries.len() - 200);
    }
    #[derive(Serialize)]
    struct Root {
        entries: Vec<AuditEntry>,
    }
    if let Some(p) = Path::new(AUDIT_PATH).parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(AUDIT_PATH, toml::to_string_pretty(&Root { entries })?)?;
    Ok(())
}

pub async fn log_removal(name: &str, version: &str, origin: &str, size_mb: f64, dry_run: bool) {
    if !dry_run {
        log::info!(
            "Removed package: {} {} ({}) [{:.1} MB]",
            name,
            version,
            origin,
            size_mb
        );
    }
}
