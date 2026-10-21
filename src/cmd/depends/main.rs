//! elevate zex depends <package>
//!
//! Shows the full recursive dependency tree of a package.

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

const G: &str = "\x1b[92m";
const P: &str = "\x1b[95m";
const B: &str = "\x1b[96m";
const Y: &str = "\x1b[93m";
const R: &str = "\x1b[91m";
const DIM: &str = "\x1b[2m";
const RST: &str = "\x1b[0m";

const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
const SYSHUB_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";
const LEDGER_CACHE: &str = "/overlayer/zexlib/registry/cache/tier1-zainium";

#[derive(Parser, Debug)]
#[command(
    name = "depends",
    about = "Show dependency tree for a package",
    override_usage = "elevate zex depends <PACKAGE>"
)]
struct Cli {
    package: String,
    /// Show only direct dependencies.
    #[arg(long, short = 'd', default_value_t = false)]
    direct: bool,
}

#[derive(Deserialize, Default, Clone)]
struct PkgEntry {
    #[serde(default)]
    depends: Vec<String>,
    #[serde(default)]
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    libc_target: Option<String>,
    #[serde(default)]
    provides: Vec<String>,
}

/// Resolves a raw dependency token (possibly version-pinned, e.g.
/// "xxd=9.2.0747-r0", or a virtual so:/cmd: capability) to the lowercase
/// key it's actually stored under in `pkgmap` — a direct name match first,
/// then a "provides" match, mirroring how the real resolver treats these
/// same token conventions.
fn resolve_key(
    token: &str,
    pkgmap: &HashMap<String, PkgEntry>,
    provides_index: &HashMap<String, String>,
) -> String {
    let base = crate::cmd::install::apk::strip_constraint(token).to_ascii_lowercase();
    if pkgmap.contains_key(&base) {
        return base;
    }
    provides_index.get(&base).cloned().unwrap_or(base)
}

#[derive(Deserialize, Default)]
struct SyshubManifest {
    packages: HashMap<String, toml::Value>,
}

pub fn run(raw_args: Vec<String>) -> Result<()> {
    let cli = Cli::parse_from(&raw_args);
    let query = cli.package.to_ascii_lowercase();

    // ── Build package map ─────────────────────────────────────────────────────
    let mut pkgmap: HashMap<String, PkgEntry> = HashMap::new();
    let mut syshub_set: HashSet<String> = HashSet::new();

    // 1. Installed receipts
    if let Ok(dir) = fs::read_dir(INSTALLED_DIR) {
        for entry in dir.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".toml") || fname.ends_with(".editions.toml") {
                continue;
            }
            let Ok(raw) = fs::read_to_string(entry.path()) else {
                continue;
            };
            // Matches the real registry::PkgRecord schema — the field is
            // `dependencies`, not `depends` (that name belongs only to the
            // separate T1 zex_ledger format parsed below), and there is no
            // `description`/`libc_target`/`origin` on an installed receipt;
            // `display_name`/`format` are the closest real equivalents.
            if let Ok(r) = toml::from_str::<crate::cmd::install::registry::PkgRecord>(&raw) {
                pkgmap.insert(
                    r.name.to_ascii_lowercase(),
                    PkgEntry {
                        depends: r.dependencies,
                        version: r.version,
                        description: r.display_name,
                        libc_target: Some(r.format),
                        provides: r.provides,
                    },
                );
            }
        }
    }

    // Index virtual so:/cmd: capabilities → the real package that
    // provides them, so version-pinned or virtual dependency tokens
    // (e.g. "xxd=9.2.0747-r0", "so:libncursesw.so.6") resolve to the
    // actual installed package instead of always showing "not installed".
    let mut provides_index: HashMap<String, String> = HashMap::new();
    for (key, entry) in &pkgmap {
        for p in &entry.provides {
            provides_index.insert(p.to_ascii_lowercase(), key.clone());
        }
    }

    // 2. Syshub manifest
    if let Ok(raw) = fs::read_to_string(SYSHUB_MANIFEST) {
        if let Ok(m) = toml::from_str::<SyshubManifest>(&raw) {
            for (name, val) in m.packages {
                let k = name.to_ascii_lowercase();
                syshub_set.insert(k.clone());
                let entry = pkgmap.entry(k).or_default();
                if let Some(t) = val.as_table() {
                    if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
                        entry.version = v.to_string();
                    }
                    if let Some(deps) = t.get("depends").and_then(|v| v.as_array()) {
                        if entry.depends.is_empty() {
                            entry.depends = deps
                                .iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect();
                        }
                    }
                }
            }
        }
    }

    // 3. Cached zex ledger
    for ledger_name in ["zex_ledger-x86_64.toml", "zex_ledger-aarch64.toml"] {
        let p = Path::new(LEDGER_CACHE).join(ledger_name);
        if !p.exists() {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(&p) {
            #[derive(Deserialize)]
            struct L {
                packages: HashMap<String, PkgEntry>,
            }
            if let Ok(l) = toml::from_str::<L>(&raw) {
                for (name, entry) in l.packages {
                    pkgmap.entry(name.to_ascii_lowercase()).or_insert(entry);
                }
            }
        }
    }

    // ── Header ────────────────────────────────────────────────────────────────
    println!("\n {G}Zainium{RST} {DIM}|{RST} {G}Depends{RST} — Dependency Tree\n");
    println!(" {G}→{RST} {DIM}Package  :{RST} {P}{}{RST}", cli.package);

    // ── Find root ─────────────────────────────────────────────────────────────
    let Some(root) = pkgmap.get(&query) else {
        println!(" {G}→{RST} {DIM}Status   :{RST} {R}Not found{RST}\n");
        println!(
            " {R}Package '{}{RST}' is not installed and not in the cached index.\n",
            cli.package
        );
        println!("{DIM}Run 'elevate zex update' to refresh indexes,{RST}");
        println!(
            "{DIM}then 'elevate zex search {}' to find it.{RST}\n",
            cli.package
        );
        return Ok(());
    };

    let installed = Path::new(INSTALLED_DIR)
        .join(format!("{query}.toml"))
        .exists();
    let in_syshub = syshub_set.contains(&query);

    let status = if in_syshub {
        format!("{Y}syshub (protected){RST}")
    } else if installed {
        format!("{G}installed{RST}")
    } else {
        format!("{DIM}not installed{RST}")
    };

    let fmt = root.libc_target.as_deref().unwrap_or("unknown");

    println!(" {G}→{RST} {DIM}Version  :{RST} {B}{}{RST}", root.version);
    println!(" {G}→{RST} {DIM}Status   :{RST} {status}");
    println!(" {G}→{RST} {DIM}Format   :{RST} {B}{fmt}{RST}");
    if !root.description.is_empty() {
        println!(
            " {G}→{RST} {DIM}About    :{RST} {DIM}{}{RST}",
            root.description
        );
    }

    if root.depends.is_empty() {
        println!(
            "\n {G}\u{2713}{RST} {P}'{}{RST}' has no dependencies.\n",
            cli.package
        );
        return Ok(());
    }

    let mode = if cli.direct {
        "direct only"
    } else {
        "recursive"
    };
    println!(" {G}→{RST} {DIM}Mode     :{RST} {DIM}{mode}{RST}\n");
    println!("{G}Dependency tree:{RST}\n");

    // ── Tree ──────────────────────────────────────────────────────────────────
    let mut visited = HashSet::new();
    let is_last_arr: Vec<bool> = Vec::new();
    print_tree(
        &cli.package,
        &root.version,
        &pkgmap,
        &syshub_set,
        &provides_index,
        &mut visited,
        &is_last_arr,
        cli.direct,
        true,
    );

    // ── Summary ───────────────────────────────────────────────────────────────
    println!();
    let total_unique = visited.len();
    let syshub_count = visited.iter().filter(|n| syshub_set.contains(*n)).count();
    let installed_count = visited
        .iter()
        .filter(|n| Path::new(INSTALLED_DIR).join(format!("{n}.toml")).exists())
        .count();

    println!("{G}Summary{RST}");
    println!("  Total unique deps   : {G}{total_unique}{RST}");
    println!("  Already installed   : {B}{installed_count}{RST}");
    if syshub_count > 0 {
        println!("  Syshub (protected)  : {Y}{syshub_count}{RST}");
    }
    // `installed_count` and `syshub_count` can overlap in principle (a
    // syshub-provided package the user also separately zex-installed), so
    // don't just subtract both — subtract the union's size.
    let accounted = visited
        .iter()
        .filter(|n| {
            syshub_set.contains(*n) || Path::new(INSTALLED_DIR).join(format!("{n}.toml")).exists()
        })
        .count();
    let missing = total_unique.saturating_sub(accounted);
    if missing > 0 {
        println!("  To be installed     : {P}{missing}{RST}");
    }
    println!();

    Ok(())
}

fn print_tree(
    name: &str,
    version: &str,
    pkgmap: &HashMap<String, PkgEntry>,
    syshub_set: &HashSet<String>,
    provides_index: &HashMap<String, String>,
    visited: &mut HashSet<String>,
    is_last_arr: &[bool],
    direct: bool,
    is_root: bool,
) {
    let key = resolve_key(name, pkgmap, provides_index);

    // Build tree prefix from parent is_last array
    let mut prefix = String::new();
    for (i, &last) in is_last_arr.iter().enumerate() {
        if i == is_last_arr.len() - 1 {
            prefix.push_str(if last {
                "  \u{2514}\u{2500} "
            } else {
                "  \u{251c}\u{2500} "
            });
        } else {
            prefix.push_str(if last { "     " } else { "  \u{2502}  " });
        }
    }

    // Badges
    let in_syshub = syshub_set.contains(&key);
    let installed = Path::new(INSTALLED_DIR)
        .join(format!("{key}.toml"))
        .exists();
    let cycle = !is_root && visited.contains(&key);

    let badge = if in_syshub {
        format!("  {Y}[syshub]{RST}")
    } else if installed {
        format!("  {G}[installed]{RST}")
    } else {
        format!("  {DIM}[not installed]{RST}")
    };

    let ver_str = if version.is_empty() {
        String::new()
    } else {
        format!("  {B}{version}{RST}")
    };

    let name_col = if in_syshub {
        format!("{Y}{name}{RST}")
    } else if installed {
        format!("{P}{name}{RST}")
    } else {
        format!("{DIM}{name}{RST}")
    };

    if cycle {
        println!("{DIM}{prefix}{RST}{name_col}{ver_str}  {DIM}(circular ref){RST}");
        return;
    }

    println!("{DIM}{prefix}{RST}{name_col}{ver_str}{badge}");

    if direct && !is_root {
        return;
    }

    // Mark visited before recursing to catch cycles
    visited.insert(key.clone());

    let Some(entry) = pkgmap.get(&key) else {
        return;
    };
    let deps = &entry.depends;
    if deps.is_empty() {
        return;
    }

    for (i, dep) in deps.iter().enumerate() {
        let is_last = i == deps.len() - 1;
        let dep_key = resolve_key(dep, pkgmap, provides_index);
        let dep_ver = pkgmap
            .get(&dep_key)
            .map(|e| e.version.as_str())
            .unwrap_or("");
        let mut next_arr = is_last_arr.to_vec();
        next_arr.push(is_last);
        print_tree(
            dep,
            dep_ver,
            pkgmap,
            syshub_set,
            provides_index,
            visited,
            &next_arr,
            direct,
            false,
        );
    }
}
