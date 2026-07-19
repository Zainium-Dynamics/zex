//! hooks.rs — Post-install/upgrade hook system for Zex.
//!
//! Hooks are TOML files in /etc/zex/hooks.d/ executed after package operations.
//! Format: [hook] name="...", trigger="post-install", packages=["*"], exec="...", timeout_secs=30

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

const HOOKS_DIR: &str = "/etc/zex/hooks.d";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum HookTrigger {
    #[serde(rename = "post-install")]
    PostInstall,
    #[serde(rename = "post-upgrade")]
    PostUpgrade,
    #[serde(rename = "post-remove")]
    PostRemove,
}

impl std::fmt::Display for HookTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PostInstall => write!(f, "post-install"),
            Self::PostUpgrade => write!(f, "post-upgrade"),
            Self::PostRemove => write!(f, "post-remove"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct HookFile {
    hook: HookCfg,
}

#[derive(Debug, Deserialize)]
struct HookCfg {
    name: String,
    trigger: HookTrigger,
    #[serde(default)]
    packages: Vec<String>,
    exec: String,
    #[serde(default = "default_timeout")]
    _timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

pub struct HookResult {
    pub name: String,
    pub success: bool,
    pub output: String,
    pub duration_ms: u64,
}

fn load_hooks() -> Vec<(PathBuf, HookCfg)> {
    let dir = Path::new(HOOKS_DIR);
    if !dir.exists() {
        return Vec::new();
    }
    let mut hooks = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().map_or(false, |x| x == "hook") {
                if let Ok(c) = std::fs::read_to_string(&p) {
                    if let Ok(h) = toml::from_str::<HookFile>(&c) {
                        hooks.push((p, h.hook));
                    }
                }
            }
        }
    }
    hooks.sort_by(|a, b| a.0.cmp(&b.0));
    hooks
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with('*') && text.ends_with(&pattern[1..]) {
        return true;
    }
    if pattern.ends_with('*') && text.starts_with(&pattern[..pattern.len() - 1]) {
        return true;
    }
    pattern.eq_ignore_ascii_case(text)
}

fn matches_pkgs(patterns: &[String], affected: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns
        .iter()
        .any(|pat| affected.iter().any(|pkg| glob_match(pat, pkg)))
}

/// Execute matching hooks for a trigger. Returns results in order.
pub fn run_hooks(trigger: &HookTrigger, affected: &[String]) -> Vec<HookResult> {
    let matching: Vec<_> = load_hooks()
        .into_iter()
        .filter(|(_, h)| &h.trigger == trigger && matches_pkgs(&h.packages, affected))
        .collect();
    if matching.is_empty() {
        return Vec::new();
    }

    super::ui::print_hooks_starting(matching.len());
    let mut results = Vec::new();

    for (_, hook) in matching {
        super::ui::print_hook_running(&hook.name);
        let start = std::time::Instant::now();
        let res = Command::new("sh")
            .arg("-c")
            .arg(&hook.exec)
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
            .env("ZEX_HOOK_TRIGGER", trigger.to_string())
            .output();
        let r = match res {
            Ok(out) => HookResult {
                name: hook.name.clone(),
                success: out.status.success(),
                output: String::from_utf8_lossy(&out.stdout).to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => HookResult {
                name: hook.name.clone(),
                success: false,
                output: format!("Failed: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        };
        super::ui::print_hook_result(&r.name, r.success);
        results.push(r);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_glob() {
        assert!(glob_match("fonts-*", "fonts-noto"));
        assert!(glob_match("*-font", "noto-font"));
        assert!(!glob_match("fonts-*", "vlc"));
        assert!(glob_match("*", "anything"));
    }
}
