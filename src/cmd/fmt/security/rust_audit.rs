//! Runs external Rust security tooling against a package's source tree
//! at pack time, when the source looks like a Rust project (a
//! `Cargo.toml` is present at the root).
//!
//! Tools chained (each independently Passed/Failed/Skipped):
//!   - `cargo audit`   — RustSec known-vulnerable dependency advisories
//!   - `cargo clippy`  — lints including many insecure/buggy patterns
//!   - `cargo geiger`  — counts unsafe blocks; surfaces raw unsafe usage
//!                       for the human reviewer without auto-failing
//!
//! `cargo-fuzz` is NOT run automatically: fuzzing is long-running/open-ended
//! and belongs in CI. Zex only checks whether a fuzz harness EXISTS so
//! the review report can flag its absence.

use crate::cmd::fmt::security::audit_common::{
    tool_on_path, truncate_output, AuditToolResult, ToolOutcome,
};
pub use crate::cmd::fmt::security::audit_common::ToolOutcome as ToolOutcome_reexport;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BuildKind {
    #[default]
    Static,
    Dynamic,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SourceLanguage {
    #[default]
    Unknown,
    Rust,
    C,
    Mixed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RustAuditReport {
    pub applicable: bool,
    pub language: SourceLanguage,
    pub build_kind: BuildKind,
    pub unsafe_block_count: Option<u64>,
    pub fuzz_harness_present: bool,
    pub tools: Vec<AuditToolResult>,
}

impl RustAuditReport {
    pub fn not_applicable() -> Self {
        RustAuditReport {
            applicable: false,
            language: SourceLanguage::Unknown,
            build_kind: BuildKind::NotApplicable,
            unsafe_block_count: None,
            fuzz_harness_present: false,
            tools: Vec::new(),
        }
    }

    pub fn has_failures(&self) -> bool {
        self.tools.iter().any(|t| t.outcome == ToolOutcome::Failed)
    }
}

fn detect_language(root: &Path) -> SourceLanguage {
    let has_cargo = root.join("Cargo.toml").exists();
    let has_c = walkdir::WalkDir::new(root)
        .max_depth(6)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_type().is_file()
                && matches!(
                    e.path().extension().and_then(|x| x.to_str()),
                    Some("c") | Some("h") | Some("cpp") | Some("hpp") | Some("cc")
                )
        });
    match (has_cargo, has_c) {
        (true, true)  => SourceLanguage::Mixed,
        (true, false) => SourceLanguage::Rust,
        (false, true) => SourceLanguage::C,
        _             => SourceLanguage::Unknown,
    }
}

/// Reads `rust.toml` at the package root:
/// ```toml
/// [build]
/// kind = "dynamic"   # or "static" (default if file/key absent)
/// ```
pub fn detect_build_kind(root: &Path) -> BuildKind {
    let path = root.join("rust.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return BuildKind::Static;
    };
    let Ok(value) = text.parse::<toml::Value>() else {
        return BuildKind::Static;
    };
    match value
        .get("build")
        .and_then(|b| b.get("kind"))
        .and_then(|k| k.as_str())
    {
        Some(s) if s.eq_ignore_ascii_case("dynamic") => BuildKind::Dynamic,
        _ => BuildKind::Static,
    }
}

fn fuzz_harness_present(root: &Path) -> bool {
    root.join("fuzz").join("Cargo.toml").exists()
}

fn run_cargo_audit(root: &Path) -> AuditToolResult {
    let tool = "cargo-audit";
    let cmd  = "cargo audit --deny warnings";
    if !tool_on_path("cargo-audit") {
        return AuditToolResult::skipped(tool, cmd,
            "cargo-audit not found on PATH — install: `cargo install cargo-audit`");
    }
    match Command::new("cargo")
        .args(["audit", "--deny", "warnings"])
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
                    "No known-vulnerable dependencies (RustSec advisory DB)".into()
                } else {
                    "cargo-audit reported advisories against Cargo.lock dependencies".into()
                },
                output_excerpt: truncate_output(&out),
            }
        }
        Err(e) => AuditToolResult::skipped(tool, cmd, format!("exec failed: {e}")),
    }
}

fn run_clippy(root: &Path) -> AuditToolResult {
    let tool = "clippy";
    let cmd  = "cargo clippy --all-targets -- -D warnings";
    match Command::new("cargo")
        .args(["clippy", "--all-targets", "--", "-D", "warnings"])
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
                    "No clippy warnings/errors (deny-warnings mode)".into()
                } else {
                    "clippy found lint issues — see output_excerpt".into()
                },
                output_excerpt: truncate_output(&out),
            }
        }
        Err(e) => AuditToolResult::skipped(tool, cmd,
            format!("exec failed (clippy component installed?): {e}")),
    }
}

fn run_geiger(root: &Path) -> (AuditToolResult, Option<u64>) {
    let tool = "cargo-geiger";
    let cmd  = "cargo geiger --output-format Ascii";
    if !tool_on_path("cargo-geiger") {
        return (
            AuditToolResult::skipped(tool, cmd,
                "cargo-geiger not found on PATH — install: `cargo install cargo-geiger`"),
            None,
        );
    }
    match Command::new("cargo")
        .args(["geiger", "--output-format", "Ascii"])
        .current_dir(root)
        .output()
    {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let count  = parse_geiger_count(&stdout);
            let summary = match count {
                Some(n) if n > 0 =>
                    format!("{n} unsafe expression(s) — confirm they're isolated in a reviewed unsafe_core module"),
                Some(_) => "No unsafe code detected".into(),
                None    => "Ran but count could not be parsed from output".into(),
            };
            (
                AuditToolResult {
                    tool: tool.into(),
                    command: cmd.into(),
                    // geiger is always informational — unsafe isn't
                    // automatically wrong in an OS-level package
                    outcome: ToolOutcome::Passed,
                    summary,
                    output_excerpt: truncate_output(&stdout),
                },
                count,
            )
        }
        Err(e) => (
            AuditToolResult::skipped(tool, cmd, format!("exec failed: {e}")),
            None,
        ),
    }
}

fn parse_geiger_count(output: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut found = false;
    for line in output.lines() {
        if let Some(frac) = line.split_whitespace().find(|t| t.contains('/')) {
            if let Some((used, _)) = frac.split_once('/') {
                if let Ok(n) = used.trim_matches(|c: char| !c.is_ascii_digit()).parse::<u64>() {
                    total += n;
                    found = true;
                }
            }
        }
    }
    if found { Some(total) } else { None }
}

pub fn run_rust_audit(root: &Path) -> RustAuditReport {
    let language = detect_language(root);
    if !matches!(language, SourceLanguage::Rust | SourceLanguage::Mixed) {
        return RustAuditReport::not_applicable();
    }

    let build_kind   = detect_build_kind(root);
    let fuzz_present = fuzz_harness_present(root);
    let audit_result = run_cargo_audit(root);
    let clippy_result = run_clippy(root);
    let (geiger_result, unsafe_block_count) = run_geiger(root);

    RustAuditReport {
        applicable: true,
        language,
        build_kind,
        unsafe_block_count,
        fuzz_harness_present: fuzz_present,
        tools: vec![audit_result, clippy_result, geiger_result],
    }
}
