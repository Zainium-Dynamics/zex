//! elevate zex why <package>

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::{fs, path::Path};

const G: &str = "\x1b[92m";
const P: &str = "\x1b[95m";
const B: &str = "\x1b[96m";
const Y: &str = "\x1b[93m";
const R: &str = "\x1b[91m";
const DIM: &str = "\x1b[2m";
const RST: &str = "\x1b[0m";

const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
const SYSHUB_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";

#[derive(Parser, Debug)]
#[command(
    name = "why",
    about = "Show which installed packages depend on <package>",
    override_usage = "elevate zex why <PACKAGE>"
)]
struct Cli {
    package: String,
}

#[derive(Deserialize, Default)]
struct SyshubManifest {
    packages: std::collections::HashMap<String, toml::Value>,
}

pub fn run(raw_args: Vec<String>) -> Result<()> {
    let cli = Cli::parse_from(&raw_args);
    let query = cli.package.to_ascii_lowercase();

    println!("\n {G}Zainium{RST} {DIM}|{RST} {G}Why{RST} — Reverse Dependency Query\n");
    println!(" {G}→{RST} {DIM}Package  :{RST} {P}{}{RST}", cli.package);

    let mut uland: Vec<(String, String, String)> = Vec::new();

    if let Ok(dir) = fs::read_dir(INSTALLED_DIR) {
        for entry in dir.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".toml") || fname.ends_with(".editions.toml") {
                continue;
            }
            let Ok(raw) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(r) = toml::from_str::<crate::cmd::install::registry::PkgRecord>(&raw) else {
                continue;
            };
            if r.name.to_ascii_lowercase() == query {
                continue;
            }
            let matches = r.dependencies.iter().any(|d| {
                crate::cmd::install::apk::strip_constraint(d).to_ascii_lowercase() == query
            });
            if matches {
                let origin_str =
                    crate::cmd::install::registry::derive_origin(&r.format, &r.source_mirror);
                let origin = tier_badge(&origin_str);
                uland.push((r.name, r.version, origin));
            }
        }
    }
    uland.sort_by(|a, b| a.0.cmp(&b.0));

    let mut syshub: Vec<(String, String)> = Vec::new();
    if let Ok(raw) = fs::read_to_string(SYSHUB_MANIFEST) {
        if let Ok(m) = toml::from_str::<SyshubManifest>(&raw) {
            for (name, val) in &m.packages {
                if name.to_ascii_lowercase() == query {
                    continue;
                }
                if let Some(deps) = val
                    .as_table()
                    .and_then(|t| t.get("depends"))
                    .and_then(|v| v.as_array())
                {
                    let hit = deps.iter().any(|d| {
                        d.as_str()
                            .map(|s| s.to_ascii_lowercase() == query)
                            .unwrap_or(false)
                    });
                    if hit {
                        let ver = val
                            .as_table()
                            .and_then(|t| t.get("version"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        syshub.push((name.clone(), ver));
                    }
                }
            }
        }
    }
    syshub.sort_by(|a, b| a.0.cmp(&b.0));

    let total = uland.len() + syshub.len();
    println!(" {G}→{RST} {DIM}Dependents:{RST} {G}{total} found{RST}\n");

    let pkg_exists = Path::new(INSTALLED_DIR)
        .join(format!("{query}.toml"))
        .exists();

    if total == 0 {
        if !pkg_exists {
            println!(
                " {R}Error:{RST} Package {P}'{}{RST}' is not installed.\n",
                cli.package
            );
            println!(
                "{DIM}Use 'elevate zex search {}' to find it.{RST}\n",
                cli.package
            );
        } else {
            println!(
                " {G}\u{2713}{RST} No packages depend on {P}'{}{RST}'.{RST}\n",
                cli.package
            );
            println!(" {DIM}This package can be safely removed.{RST}\n");
            println!(
                " {DIM}Run:{RST} {P}elevate zex remove {}{RST}\n",
                cli.package
            );
        }
        return Ok(());
    }

    println!("{G}Required by:{RST}\n");

    if !uland.is_empty() {
        println!("  {DIM}Userland  ({} packages){RST}", uland.len());
        for (name, ver, badge) in &uland {
            let ver_col = if ver.is_empty() {
                String::new()
            } else {
                format!("  {B}{ver}{RST}")
            };
            println!("  {DIM}\u{2502}{RST}");
            println!("  {DIM}\u{251c}\u{2500}{RST} {P}{name}{RST}{ver_col}  {badge}");
        }
        println!("  {DIM}\u{2514}{RST}\n");
    }

    if !syshub.is_empty() {
        println!(
            "  {Y}Syshub Core  ({} protected packages){RST}",
            syshub.len()
        );
        for (name, ver) in &syshub {
            let ver_col = if ver.is_empty() {
                String::new()
            } else {
                format!("  {B}{ver}{RST}")
            };
            println!("  {DIM}\u{2502}{RST}");
            println!(
                "  {DIM}\u{251c}\u{2500}{RST} {Y}{name}{RST}{ver_col}  {Y}\u{26a0} [syshub — protected]{RST}"
            );
        }
        println!("  {DIM}\u{2514}{RST}\n");
    }

    if !syshub.is_empty() {
        println!(
            " {Y}\u{26a0}  Warning:{RST} {P}'{}'{RST} is a core system dependency.",
            cli.package
        );
        println!(
            "    Removing it will break {Y}{} syshub component(s){RST}.\n",
            syshub.len()
        );
    } else {
        println!(
            " {Y}\u{26a0}{RST}  Removing {P}'{}'{RST} may break {Y}{} package(s){RST} above.",
            cli.package,
            uland.len()
        );
        println!("    Remove all dependents first, or use {DIM}--force{RST} to override.\n");
    }

    Ok(())
}

fn tier_badge(origin: &str) -> String {
    match origin {
        o if o.contains("tier1") || o.contains("zainium") => {
            format!("{G}[T1-Zainium]{RST}", G = G, RST = RST)
        }
        o if o.contains("tier2") || o.contains("alpine") => {
            format!("{B}[T2-Alpine]{RST}", B = B, RST = RST)
        }
        o if o.contains("tier3") || o.contains("void") => {
            format!("{P}[T3-Void]{RST}", P = P, RST = RST)
        }
        o if o.contains("tier4") || o.contains("chimera") => {
            format!("{Y}[T4-Chimera]{RST}", Y = Y, RST = RST)
        }
        _ => format!("{DIM}[userland]{RST}", DIM = DIM, RST = RST),
    }
}
