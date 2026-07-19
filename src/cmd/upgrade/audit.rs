//! audit.rs — Upgrade audit log.
//! Writes a persistent record of every syshub/uland upgrade attempt
//! to /overlayer/zexlib/registry/upgrade-audit.toml.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp:   String,
    pub kind:        String,   // "syshub" | "uland"
    pub outcome:     String,   // "success" | "rolled_back" | "failed"
    pub packages:    Vec<String>,
    pub duration_ms: u64,
    pub error:       Option<String>,
}

const AUDIT_PATH: &str =
    "/overlayer/zexlib/registry/upgrade-audit.toml";

pub fn append(entry: AuditEntry) -> Result<()> {
    let mut entries: Vec<AuditEntry> = if Path::new(AUDIT_PATH).exists() {
        let raw = std::fs::read_to_string(AUDIT_PATH)?;
        toml::from_str(&raw).unwrap_or_default()
    } else {
        Vec::new()
    };

    entries.push(entry);
    // Keep the last 200 entries only — file stays small.
    if entries.len() > 200 {
        entries.drain(0..entries.len() - 200);
    }

    #[derive(Serialize)]
    struct Root { entries: Vec<AuditEntry> }
    let out = toml::to_string_pretty(&Root { entries })?;

    if let Some(p) = Path::new(AUDIT_PATH).parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(AUDIT_PATH, out)?;
    Ok(())
}
