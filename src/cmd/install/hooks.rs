//! hooks.rs: Post-install/upgrade hook system for Zex.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HOOKS_DIR: &str = "/overlayer/syshub/etc/zex/hooks.d";

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
    timeout_secs: u64,
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
        let res = run(&hook.exec, trigger, Duration::from_secs(hook.timeout_secs));
        let r = match res {
            Ok(success) => HookResult {
                name: hook.name.clone(),
                success,
                output: String::new(),
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

/// Runs one hook's command, killing it after `timeout`; Ok(exited successfully).
fn run(exec: &str, trigger: &HookTrigger, timeout: Duration) -> std::io::Result<bool> {
    let mut child = Command::new("/overlayer/syshub/bin/sh")
        .arg("-c")
        .arg(exec)
        .env_clear()
        .env("PATH", crate::triggers::TOOL_PATH)
        .env("ZEX_HOOK_TRIGGER", trigger.to_string())
        .stdin(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st.success());
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
