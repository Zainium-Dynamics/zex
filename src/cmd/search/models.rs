//! models.rs: Search result types for Zainium 4-tier search.

use serde::{Deserialize, Serialize};

/// Origin tier of a search result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    Zainium,
    Alpine,
    Void,
    Chimera,
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
            Self::Zainium => "\x1b[92m",
            Self::Alpine => "\x1b[96m",
            Self::Void => "\x1b[95m",
            Self::Chimera => "\x1b[93m",
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
