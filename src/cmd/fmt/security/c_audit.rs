//! Static analysis for C/C++ source trees.
//!   - `cppcheck`   — buffer overflows, null derefs, use-after-free, leaks
//!   - `clang-tidy` — broader lint + clang-analyzer security checks
//!
//! For other languages (Go, Python, shell): no scan is pretended.
//! The report records `applicable: false` so the gap is visible.

use crate::cmd::fmt::security::audit_common::{
    tool_on_path, truncate_output, AuditToolResult, ToolOutcome,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CAuditReport {
    pub applicable: bool,
    pub tools: Vec<AuditToolResult>,
}

impl CAuditReport {
    pub fn not_applicable() -> Self {
        CAuditReport { applicable: false, tools: Vec::new() }
    }

    pub fn has_failures(&self) -> bool {
        self.tools.iter().any(|t| t.outcome == ToolOutcome::Failed)
    }
}

fn has_c_sources(root: &Path) -> bool {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_type().is_file()
                && matches!(
                    e.path().extension().and_then(|x| x.to_str()),
                    Some("c") | Some("h") | Some("cpp") | Some("hpp") | Some("cc")
                )
        })
}

fn run_cppcheck(root: &Path) -> AuditToolResult {
    let tool = "cppcheck";
    let cmd = "cppcheck --enable=warning,style,performance,portability --error-exitcode=1 .";
    if !tool_on_path("cppcheck") {
        return AuditToolResult::skipped(tool, cmd,
            "cppcheck not found on PATH — install: `apt install cppcheck`");
    }
    match Command::new("cppcheck")
        .args([
            "--enable=warning,style,performance,portability",
            "--error-exitcode=1",
            "--quiet",
            ".",
        ])
        .current_dir(root)
        .output()
    {
        Ok(o) => {
            let out = format!(
                "{}\n{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let outcome = if o.status.success() { ToolOutcome::Passed } else { ToolOutcome::Failed };
            AuditToolResult {
                tool: tool.into(),
                command: cmd.into(),
                outcome,
                summary: if outcome == ToolOutcome::Passed {
                    "No cppcheck findings".into()
                } else {
                    "cppcheck found issues (buffer overflow / null-deref / leak patterns)".into()
                },
                output_excerpt: truncate_output(&out),
            }
        }
        Err(e) => AuditToolResult::skipped(tool, cmd, format!("exec failed: {e}")),
    }
}

fn run_clang_tidy(root: &Path) -> AuditToolResult {
    let tool = "clang-tidy";
    let cmd  = "clang-tidy <sources> [-- -std=c11]";
    if !tool_on_path("clang-tidy") {
        return AuditToolResult::skipped(tool, cmd,
            "clang-tidy not found on PATH — install: `apt install clang-tidy`");
    }

    let sources: Vec<_> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && matches!(
                    e.path().extension().and_then(|x| x.to_str()),
                    Some("c") | Some("cpp") | Some("cc")
                )
        })
        .map(|e| e.into_path())
        .collect();

    if sources.is_empty() {
        return AuditToolResult::skipped(tool, cmd,
            "no .c/.cpp/.cc translation units found");
    }

    let has_compile_db = root.join("compile_commands.json").exists();
    let mut proc = Command::new("clang-tidy");
    proc.current_dir(root);
    for s in &sources { proc.arg(s); }
    if !has_compile_db { proc.arg("--").arg("-std=c11"); }

    match proc.output() {
        Ok(o) => {
            let out = format!(
                "{}\n{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let outcome = if o.status.success() { ToolOutcome::Passed } else { ToolOutcome::Failed };
            let mut summary = if outcome == ToolOutcome::Passed {
                "No clang-tidy findings".to_string()
            } else {
                "clang-tidy found issues".to_string()
            };
            if !has_compile_db {
                summary.push_str(" (best-effort: no compile_commands.json — add `bear` or CMake export for accurate results)");
            }
            AuditToolResult {
                tool: tool.into(),
                command: cmd.into(),
                outcome,
                summary,
                output_excerpt: truncate_output(&out),
            }
        }
        Err(e) => AuditToolResult::skipped(tool, cmd, format!("exec failed: {e}")),
    }
}

pub fn run_c_audit(root: &Path) -> CAuditReport {
    if !has_c_sources(root) {
        return CAuditReport::not_applicable();
    }
    CAuditReport {
        applicable: true,
        tools: vec![run_cppcheck(root), run_clang_tidy(root)],
    }
}
