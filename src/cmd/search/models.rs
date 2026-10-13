//! models.rs — Search result types for Zainium 4-tier search.

use serde::{Deserialize, Serialize};

/// Origin tier of a search result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    Zainium, // Tier 1 — native .zex
    Alpine,  // Tier 2 — .apk
    Void,    // Tier 3 — .xbps
    Chimera, // Tier 4 — .apk
}

impl Origin {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Zainium => "Zainium",
            Self::Alpine => "Alpine",
            Self::Void => "Void",
            Self::Chimera => "Chimera",
        }
    }

    /// Terminal color for the origin label.
    pub fn color(&self) -> &'static str {
        match self {
            Self::Zainium => "\x1b[92m", // green
            Self::Alpine => "\x1b[96m",  // cyan
            Self::Void => "\x1b[95m",    // purple
            Self::Chimera => "\x1b[93m", // yellow
        }
    }
}

/// A single search result entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub name: String,
    pub version: String,
    pub origin: Origin,
    pub description: String,
    pub installed: bool,
    pub tags: Vec<String>,
}

impl SearchResult {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        origin: Origin,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            origin,
            description: description.into(),
            installed: false,
            tags: Vec::new(),
        }
    }
}
