//! system.rs: `zex export` and `elevate zex import`: what is on this system, as one TOML
//! file, and the same system again on another machine.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
/// The admin's own settings: the union's etc, on top of the base's defaults.
/// Both export and import work here — `/overlayer/syshub/etc` is the sealed,
/// fs-verity, read-only base and cannot be written to.
const UNION_ETC: &str = "/overlayer/zexlib/union/etc";
const FLATPAK: &str = "/overlayer/syshub/bin/flatpak";

/// Settings that belong to one machine or hold secrets: never exported or imported.
const MACHINE_ONLY: &[&str] = &[
    "passwd",
    "shadow",
    "group",
    "gshadow",
    "subuid",
    "subgid",
    "machine-id",
    "hostname",
    "hosts",
    "fstab",
    "crypttab",
    "adjtime",
    "resolv.conf",
    "ld.so.cache",
    "ssh",
    "NetworkManager/system-connections",
    "iwd",
    "elevators",
    "credstore",
    "credstore.encrypted",
    "pki",
    "ssl/private",
    "systemd/network",
];
const MAX_ETC_FILE: u64 = 256 * 1024;

const G: &str = "\x1b[92m";
const Y: &str = "\x1b[93m";
const D: &str = "\x1b[2m";
const R: &str = "\x1b[0m";

#[derive(Serialize, Deserialize, Default)]
struct SystemFile {
    zainium: Header,
    #[serde(default)]
    packages: BTreeMap<String, Package>,
    #[serde(default)]
    flatpaks: Vec<Flatpak>,
    #[serde(default)]
    pins: Vec<String>,
    #[serde(default)]
    etc: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Header {
    format: u32,
    exported: String,
    host: String,
}

#[derive(Serialize, Deserialize)]
struct Package {
    version: String,
    source: String,
}

#[derive(Serialize, Deserialize)]
struct Flatpak {
    id: String,
    remote: String,
}

#[derive(Deserialize)]
struct Receipt {
    name: String,
    version: String,
    #[serde(default)]
    source_mirror: String,
    #[serde(default)]
    dependencies: Vec<String>,
}

pub fn export(args: Vec<String>) -> Result<()> {
    let out = args.iter().find(|a| !a.starts_with('-')).cloned();
    let toml = toml::to_string(&collect()?).context("writing the system file")?;
    match out {
        Some(path) => {
            fs::write(&path, toml).with_context(|| format!("writing {path}"))?;
            eprintln!("  {G}✓{R} system written to {path}");
        }
        None => print!("{toml}"),
    }
    Ok(())
}

fn collect() -> Result<SystemFile> {
    let mut receipts = Vec::new();
    for e in fs::read_dir(INSTALLED_DIR).into_iter().flatten().flatten() {
        if let Ok(text) = fs::read_to_string(e.path())
            && let Ok(r) = toml::from_str::<Receipt>(&text)
        {
            receipts.push(r);
        }
    }
    // only what nothing else pulls in: the rest comes back as dependencies
    let needed: BTreeSet<&str> = receipts
        .iter()
        .flat_map(|r| r.dependencies.iter().map(String::as_str))
        .collect();
    let packages = receipts
        .iter()
        .filter(|r| !needed.contains(r.name.as_str()))
        .map(|r| {
            (
                r.name.clone(),
                Package {
                    version: r.version.clone(),
                    source: r.source_mirror.clone(),
                },
            )
        })
        .collect();

    let mut etc = BTreeMap::new();
    walk_etc(Path::new(UNION_ETC), Path::new(UNION_ETC), &mut etc);

    Ok(SystemFile {
        zainium: Header {
            format: 1,
            exported: chrono::Local::now().to_rfc3339(),
            host: fs::read_to_string("/overlayer/syshub/etc/hostname")
                .unwrap_or_default()
                .trim()
                .to_string(),
        },
        packages,
        flatpaks: flatpaks(),
        pins: crate::pinning::load_pinned()
            .into_iter()
            .map(|p| p.name)
            .collect(),
        etc,
    })
}

fn machine_only(rel: &str) -> bool {
    MACHINE_ONLY
        .iter()
        .any(|m| rel == *m || rel.starts_with(&format!("{m}/")))
        || rel.ends_with('-')
        || rel.ends_with(".lock")
}

/// Reject a relative etc path that could escape `UNION_ETC` (traversal, absolute
/// or empty components). Imported files are untrusted input.
fn unsafe_rel(rel: &str) -> bool {
    rel.starts_with('/') || rel.split('/').any(|c| c == ".." || c.is_empty())
}

fn walk_etc(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(rel) = p.strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_string_lossy().into_owned();
        if machine_only(&rel) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            walk_etc(root, &p, out);
        } else if meta.is_file()
            && meta.len() <= MAX_ETC_FILE
            && let Ok(text) = fs::read_to_string(&p)
        {
            out.insert(rel, text);
        }
    }
}

fn flatpaks() -> Vec<Flatpak> {
    let Ok(o) = Command::new(FLATPAK)
        .args(["list", "--system", "--app", "--columns=application,origin"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let id = f.next()?.trim();
            let remote = f.next().unwrap_or("flathub").trim();
            (!id.is_empty()).then(|| Flatpak {
                id: id.into(),
                remote: remote.into(),
            })
        })
        .collect()
}

pub fn import(args: Vec<String>) -> Result<()> {
    let dry = args.iter().any(|a| a == "--dry-run");
    let Some(path) = args.iter().find(|a| !a.starts_with('-')) else {
        bail!("usage: elevate zex import <file.toml> [--dry-run]");
    };
    // SAFETY: geteuid(2) takes no arguments and cannot fail.
    if !dry && unsafe { libc::geteuid() } != 0 {
        bail!("root required: elevate zex import {path}");
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let sys: SystemFile =
        toml::from_str(&text).with_context(|| format!("{path} is not a Zainium system file"))?;
    if sys.zainium.format != 1 {
        bail!(
            "{path} is format {}, this zex reads format 1",
            sys.zainium.format
        );
    }
    println!(
        "\n  System from {}{}{} ({})\n  {} packages, {} apps, {} pins, {} settings files\n",
        G,
        if sys.zainium.host.is_empty() {
            "another machine"
        } else {
            &sys.zainium.host
        },
        R,
        sys.zainium.exported,
        sys.packages.len(),
        sys.flatpaks.len(),
        sys.pins.len(),
        sys.etc.len()
    );

    let mut by_source: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, p) in &sys.packages {
        if Path::new(INSTALLED_DIR)
            .join(format!("{name}.toml"))
            .exists()
        {
            continue;
        }
        by_source.entry(p.source.as_str()).or_default().push(name);
    }
    let zex = std::env::current_exe().unwrap_or_else(|_| "/overlayer/syshub/bin/zex".into());
    let mut failed = Vec::new();
    for (source, names) in &by_source {
        println!(
            "  {D}packages from {}:{R} {}",
            if source.is_empty() {
                "any source"
            } else {
                source
            },
            names.join(" ")
        );
        if dry {
            continue;
        }
        let mut cmd = Command::new(&zex);
        cmd.arg("install");
        if !source.is_empty() {
            cmd.arg(format!("--{source}"));
        }
        if !cmd.args(names).status().is_ok_and(|s| s.success()) {
            failed.extend(names.iter().map(|n| n.to_string()));
        }
    }

    for f in &sys.flatpaks {
        println!("  {D}app:{R} {} ({})", f.id, f.remote);
        if !dry
            && !Command::new(FLATPAK)
                .args([
                    "install",
                    "--system",
                    "-y",
                    "--noninteractive",
                    &f.remote,
                    &f.id,
                ])
                .status()
                .is_ok_and(|s| s.success())
        {
            failed.push(f.id.clone());
        }
    }

    for name in &sys.pins {
        println!("  {D}pin:{R} {name}");
        if !dry && let Err(e) = crate::pinning::pin(name, Some("from zex import")) {
            eprintln!("  {Y}!{R} pin {name}: {e}");
        }
    }

    for (rel, content) in &sys.etc {
        if machine_only(rel) || unsafe_rel(rel) {
            continue;
        }
        let dst = Path::new(UNION_ETC).join(rel);
        if fs::read_to_string(&dst).is_ok_and(|now| now == *content) {
            continue;
        }
        println!("  {D}setting:{R} etc/{rel}");
        if dry {
            continue;
        }
        if dst.exists() {
            let _ = fs::copy(&dst, dst.with_extension("before-import"));
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dst, content).with_context(|| format!("writing etc/{rel}"))?;
    }

    if dry {
        println!("\n  {D}--dry-run: nothing was changed{R}\n");
    } else if failed.is_empty() {
        println!("\n  {G}✓{R} system imported\n");
    } else {
        println!("\n  {Y}!{R} imported, except: {}\n", failed.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_written_to_the_writable_union_not_the_sealed_base() {
        // The sealed base (/overlayer/syshub/etc) is read-only fs-verity; import
        // must land in the union overlay, symmetric with what export reads.
        assert_eq!(UNION_ETC, "/overlayer/zexlib/union/etc");
        assert!(!UNION_ETC.starts_with("/overlayer/syshub"));
    }

    #[test]
    fn machine_only_skips_secrets_and_identity() {
        for p in [
            "shadow",
            "passwd",
            "machine-id",
            "ssh/ssh_host_ed25519_key",
            "NetworkManager/system-connections/Home.nmconnection",
            "ssl/private/site.key",
            "fstab",
        ] {
            assert!(machine_only(p), "{p} must be treated as machine-only");
        }
    }

    #[test]
    fn machine_only_allows_ordinary_settings() {
        for p in ["profile", "zex/zex_services.toml", "sysctl.d/99-tuning.conf"] {
            assert!(!machine_only(p), "{p} should be portable");
        }
    }

    #[test]
    fn unsafe_rel_rejects_traversal_and_absolute() {
        for p in ["../escape", "a/../../b", "/etc/passwd", "a//b", ""] {
            assert!(unsafe_rel(p), "{p:?} must be rejected");
        }
        for p in ["profile", "zex/services.toml", "a/b/c.conf"] {
            assert!(!unsafe_rel(p), "{p:?} should be allowed");
        }
    }
}
