//! Post-transaction triggers: caches and daemons that must learn about files zex added or removed.
//! Paths are noted while a command runs; `flush` then runs each needed trigger once, as root.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::archive_safety::{LIVE_ROOT, UNION_ROOT};

static TOUCHED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static HOOKS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
static INSTALLED: Mutex<Vec<String>> = Mutex::new(Vec::new());
static REMOVED: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub const TOOL_PATH: &str =
    "/overlayer/syshub/bin:/overlayer/syshub/sbin:/overlayer/zexlib/union/bin";
const HOOK_TIMEOUT: Duration = Duration::from_secs(120);

/// Remember paths (union or live) a transaction wrote or removed.
pub fn note<P: AsRef<Path>>(paths: &[P]) {
    let mut t = TOUCHED.lock().unwrap_or_else(|e| e.into_inner());
    for p in paths {
        let p = p.as_ref();
        let rel = p
            .strip_prefix(UNION_ROOT)
            .or_else(|_| p.strip_prefix(LIVE_ROOT))
            .unwrap_or(p);
        t.push(rel.to_path_buf());
    }
}

/// For callers that don't track individual files: run every trigger.
pub fn note_all() {
    TOUCHED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(PathBuf::new());
}

/// A package's manifest `post_install` / `post_remove` command.
pub fn note_hook(pkg: &str, cmd: &str) {
    if !cmd.trim().is_empty() {
        HOOKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pkg.to_string(), cmd.to_string()));
    }
}

/// A package this command installed or upgraded, for hooks.d `post-install` hooks.
pub fn note_installed(pkg: &str) {
    INSTALLED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(pkg.to_string());
}

/// A package this command removed, for hooks.d `post-remove` hooks.
pub fn note_removed(pkg: &str) {
    REMOVED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(pkg.to_string());
}

pub fn flush() {
    let rels = std::mem::take(&mut *TOUCHED.lock().unwrap_or_else(|e| e.into_inner()));
    let hooks = std::mem::take(&mut *HOOKS.lock().unwrap_or_else(|e| e.into_inner()));
    let installed = std::mem::take(&mut *INSTALLED.lock().unwrap_or_else(|e| e.into_inner()));
    let removed = std::mem::take(&mut *REMOVED.lock().unwrap_or_else(|e| e.into_inner()));
    if rels.is_empty() && hooks.is_empty() && installed.is_empty() && removed.is_empty() {
        return;
    }
    let all = rels.iter().any(|r| r.as_os_str().is_empty());
    let has = |pfx: &str| all || rels.iter().any(|r| r.starts_with(pfx));
    let live = |rel: &str| format!("{LIVE_ROOT}/{rel}");

    for rel in crate::setuid::HELPERS {
        if all || rels.iter().any(|r| r == Path::new(rel)) {
            match crate::setuid::restore(Path::new(&live(rel))) {
                Ok(true) => log::info!("{rel}: restored setuid root"),
                Ok(false) => {}
                Err(e) => eprintln!("zex: could not make {rel} setuid root: {e}"),
            }
        }
    }

    if has("lib/systemd/system") || has("etc/systemd/system") {
        run("systemctl", &["daemon-reload"]);
    }
    if has("share/dbus-1") || has("etc/dbus-1") {
        run(
            "busctl",
            &[
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "ReloadConfig",
            ],
        );
    }
    if has("share/applications") {
        run(
            "update-desktop-database",
            &["-q", &live("share/applications")],
        );
    }
    if has("share/mime/packages") {
        run("update-mime-database", &[&live("share/mime")]);
    }
    if has("share/glib-2.0/schemas") {
        run("glib-compile-schemas", &[&live("share/glib-2.0/schemas")]);
    }
    if has("share/fonts") {
        run("fc-cache", &["-s"]);
    }
    let mut themes: Vec<String> = rels
        .iter()
        .filter_map(|r| {
            let mut c = r.components();
            (c.next()?.as_os_str() == "share" && c.next()?.as_os_str() == "icons").then(|| {
                c.next()
                    .map(|t| t.as_os_str().to_string_lossy().into_owned())
            })?
        })
        .collect();
    if all {
        themes.push("hicolor".into());
    }
    themes.sort();
    themes.dedup();
    for theme in themes {
        let dir = live(&format!("share/icons/{theme}"));
        if Path::new(&dir).join("index.theme").exists() {
            run("gtk-update-icon-cache", &["-q", "-t", "-f", &dir]);
        }
    }
    if has("etc/flatpak/remotes.d") {
        // flatpak adds static remotes on its first system-wide run
        run("flatpak", &["remotes"]);
    }

    for (pkg, cmd) in hooks {
        if let Err(e) = run_hook(&cmd) {
            warn(&format!("{pkg} hook"), &e);
        }
    }

    use crate::cmd::install::hooks::{HookTrigger, run_hooks};
    for (trigger, pkgs) in [
        (HookTrigger::PostInstall, installed),
        (HookTrigger::PostRemove, removed),
    ] {
        if !pkgs.is_empty() {
            for r in run_hooks(&trigger, &pkgs) {
                if !r.success {
                    warn(&format!("{} hook", r.name), "failed");
                }
            }
        }
    }
}

/// Missing tools are skipped: not every system ships every cache generator.
fn run(prog: &str, args: &[&str]) {
    let Some(bin) = which(prog) else {
        return;
    };
    match Command::new(&bin)
        .args(args)
        .env("PATH", TOOL_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn(prog, String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => warn(prog, &e.to_string()),
    }
}

// zex has no logger, so trigger problems are printed where the user sees them
fn warn(prog: &str, msg: &str) {
    eprintln!(" \x1b[93m⚠\x1b[0m  {prog}: {msg}");
}

fn run_hook(cmd: &str) -> Result<(), String> {
    let mut child = Command::new("/overlayer/syshub/bin/sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(LIVE_ROOT)
        .env("PATH", TOOL_PATH)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(st) if st.success() => return Ok(()),
            Some(st) => return Err(format!("exited with {st}")),
            None if start.elapsed() > HOOK_TIMEOUT => {
                let _ = child.kill();
                return Err("timed out".into());
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn which(prog: &str) -> Option<PathBuf> {
    TOOL_PATH
        .split(':')
        .map(|d| Path::new(d).join(prog))
        .find(|p| p.is_file())
}
