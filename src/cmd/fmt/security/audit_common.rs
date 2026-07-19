//! Shared types used across all language-specific audit modules.
//! Single source of truth — no duplication across rust_audit/c_audit/etc.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolOutcome {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditToolResult {
    pub tool: String,
    pub command: String,
    pub outcome: ToolOutcome,
    pub summary: String,
    /// Truncated raw output, kept short enough to embed in report without
    /// bloating the .zex. Full output belongs in build logs.
    pub output_excerpt: String,
}

impl AuditToolResult {
    pub fn skipped(tool: impl Into<String>, command: impl Into<String>, reason: impl Into<String>) -> Self {
        AuditToolResult {
            tool: tool.into(),
            command: command.into(),
            outcome: ToolOutcome::Skipped,
            summary: reason.into(),
            output_excerpt: String::new(),
        }
    }
}

pub const OUTPUT_EXCERPT_LIMIT: usize = 4000;

pub fn truncate_output(s: &str) -> String {
    if s.len() <= OUTPUT_EXCERPT_LIMIT {
        s.to_string()
    } else {
        format!(
            "{}\n... [truncated, {} bytes total — see build logs for full output]",
            &s[..OUTPUT_EXCERPT_LIMIT],
            s.len()
        )
    }
}

pub fn tool_on_path(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
