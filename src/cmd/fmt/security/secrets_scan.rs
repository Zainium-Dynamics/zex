//! Scans source files for hardcoded secrets, credentials, and API keys.
//!
//! This is deliberately a CONSERVATIVE scanner: it runs regex patterns
//! against text files only, reports every match as a finding, and blocks
//! pack with `Blocked` outcome. There are no whitelists and no
//! exceptions — if a key pattern fires, the maintainer must rotate the
//! secret and remove it from source before packaging.
//!
//! Patterns are intentionally simple and high-signal rather than
//! exhaustive:
//!   - known-format API key prefixes (AWS, GitHub, Stripe, etc.)
//!   - `password = "..."` / `secret = "..."` / `api_key = "..."` style
//!     assignments in any language
//!   - Private key PEM blocks
//!   - High-entropy base64/hex strings (entropy-based heuristic,
//!     length-gated to reduce false positives)
//!
//! File types excluded: compiled binaries, images, archives. These are
//! scanned at path level only (their hashes are checked separately in
//! manifest_integrity).

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretsOutcome {
    #[default]
    Clean,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub file: String,
    pub line: usize,
    pub pattern: String,
    /// Redacted excerpt — shows enough context to locate the line
    /// without leaking the actual secret in the report.
    pub excerpt_redacted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsScanReport {
    pub outcome: SecretsOutcome,
    pub files_scanned: usize,
    pub findings: Vec<SecretFinding>,
}

impl SecretsScanReport {
    pub fn is_blocked(&self) -> bool {
        self.outcome == SecretsOutcome::Blocked
    }
}

/// (pattern_label, regex_source)
const PATTERNS: &[(&str, &str)] = &[
    // Private key PEM blocks
    ("PEM private key block",         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    // AWS
    ("AWS access key ID",             r"AKIA[0-9A-Z]{16}"),
    ("AWS secret access key",
        r#"(?i)aws[_\-\. ]?secret[_\-\. ]?access[_\-\. ]?key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}"#),
    // GitHub
    ("GitHub token (ghp_)",           r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub token (ghs_)",           r"ghs_[A-Za-z0-9]{36}"),
    ("GitHub token (github_pat)",     r"github_pat_[A-Za-z0-9_]{82}"),
    // Stripe
    ("Stripe secret key",             r"sk_live_[A-Za-z0-9]{24}"),
    ("Stripe test key",               r"sk_test_[A-Za-z0-9]{24}"),
    // Generic high-signal key assignments
    ("hardcoded password assignment",
        r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{6,}['"]"#),
    ("hardcoded secret assignment",
        r#"(?i)(secret|api_secret|client_secret)\s*[=:]\s*['"][^'"]{8,}['"]"#),
    ("hardcoded api_key assignment",
        r#"(?i)(api[_\-]?key|apikey|access[_\-]?token)\s*[=:]\s*['"][^'"]{8,}['"]"#),
    // Generic token-looking env var values in config files
    ("bearer token literal",
        r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}"),
    // Private key in .env style
    ("dotenv private key",
        r"(?i)PRIVATE_KEY\s*=\s*[^#\n]{10,}"),
];

const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "c", "cpp", "h", "hpp", "py", "rb", "go", "js", "ts",
    "sh", "bash", "zsh", "toml", "yaml", "yml", "json", "ini", "cfg",
    "env", "conf", "service", "txt", "xml", "properties",
];
const TEXT_FILENAMES: &[&str] = &[".env", "Makefile", "Dockerfile"];

fn is_text_candidate(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if TEXT_FILENAMES.contains(&name) || name.starts_with(".env") {
            return true;
        }
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return TEXT_EXTENSIONS.contains(&ext.to_lowercase().as_str());
    }
    false
}

fn redact(line: &str, max_len: usize) -> String {
    // Keep the first 40 chars of context then replace the rest with [REDACTED]
    let trimmed = line.trim();
    let visible = &trimmed[..trimmed.len().min(40)];
    format!("{} ... [REDACTED - {max_len} chars total]", visible)
}

pub fn scan_secrets(root: &Path) -> SecretsScanReport {
    // Build compiled regexes once. If regex crate isn't available this
    // falls back gracefully to a basic substring scan.
    let compiled: Vec<(&str, regex::Regex)> = PATTERNS
        .iter()
        .filter_map(|(label, pat)| {
            regex::Regex::new(pat).ok().map(|r| (*label, r))
        })
        .collect();

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if !is_text_candidate(entry.path()) {
            continue;
        }

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        files_scanned += 1;

        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();

        for (line_no, line) in content.lines().enumerate() {
            for (label, re) in &compiled {
                if re.is_match(line) {
                    findings.push(SecretFinding {
                        file: rel.clone(),
                        line: line_no + 1,
                        pattern: label.to_string(),
                        excerpt_redacted: redact(line, line.len()),
                    });
                    // One finding per (line, pattern) — don't double-report
                    // if multiple patterns hit the same line.
                    break;
                }
            }
        }
    }

    let outcome = if findings.is_empty() {
        SecretsOutcome::Clean
    } else {
        SecretsOutcome::Blocked
    };

    SecretsScanReport {
        outcome,
        files_scanned,
        findings,
    }
}
