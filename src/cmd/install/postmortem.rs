//! postmortem.rs: Pre-install evaluation engine.

use anyhow::Result;

pub enum PostmortemVerdict {
    /// Scenario A: The package is not in the registry at all.
    NewPackage,
    /// Scenario B: The package exists, but the incoming version is newer.
    Upgrade { old_version: String },
    /// Scenario C: The exact version already exists. Halt download.
    Duplicate { existing_version: String },
    /// Scenario D: The incoming version is older. Rejected.
    DowngradeRejected { reason: String },
}

/// The Postmortem Engine
/// Evaluates an incoming package request against the local TOML registry
/// *before* any network or disk extraction happens.
pub fn evaluate(name: &str, incoming_version: &str) -> Result<PostmortemVerdict> {
    let existing = super::registry::lookup(name);

    if let Some(record) = existing {
        if record.version == incoming_version {
            Ok(PostmortemVerdict::Duplicate {
                existing_version: record.version,
            })
        } else {
            Ok(PostmortemVerdict::Upgrade {
                old_version: record.version,
            })
        }
    } else {
        Ok(PostmortemVerdict::NewPackage)
    }
}
