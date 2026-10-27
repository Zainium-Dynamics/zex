//! inspect.rs — Package deep inspection for Zainium OS.
//!
//! Reads from installed receipts — not dpkg, not rpm, not pacman.
//! Uses readelf to detect shared library deps from actual binaries.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path, process::Command};

const G: &str = "\x1b[92m";
const P: &str = "\x1b[95m";
const B: &str = "\x1b[96m";
const Y: &str = "\x1b[93m";
const R: &str = "\x1b[91m";
const DIM: &str = "\x1b[2m";
const BLD: &str = "\x1b[1m";
const RST: &str = "\x1b[0m";

const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
const SYSHUB_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";
const SYSHUB_PATH: &str = "/overlayer/syshub";

#[derive(Debug, Deserialize, Default)]
struct SyshubManifest {
    packages: std::collections::HashMap<String, toml::Value>,
}

// ── Entry point ───────────────────────────────────────────────────────────────
pub async fn run(name: &str) -> Result<()> {
    let key = name.to_ascii_lowercase();

    // Try installed receipt first
    let receipt_path = Path::new(INSTALLED_DIR).join(format!("{key}.toml"));

    // Also check syshub
    let syshub_entry = syshub_lookup(&key);
    let in_syshub = syshub_entry.is_some();

    if !receipt_path.exists() && !in_syshub {
        bail!(
            "Package '{name}' is not installed.\n\
             Use 'elevate zex search {name}' to find it."
        );
    }

    // ── Header ────────────────────────────────────────────────────────────────
    println!("\n {G}{BLD}Zainium{RST}{G} | Package Inspection{RST}\n");
    println!(" {G}→{RST} {DIM}Inspecting:{RST} {P}{name}{RST}\n");

    if receipt_path.exists() {
        inspect_from_receipt(name, &receipt_path).await?;
    } else if let Some(entry) = syshub_entry {
        inspect_syshub_entry(name, &entry);
    }

    Ok(())
}

// ── Receipt-based inspection (userland packages) ──────────────────────────────
async fn inspect_from_receipt(_name: &str, path: &Path) -> Result<()> {
    use crate::cmd::install::registry::{PkgRecord, derive_origin};

    let raw = fs::read_to_string(path).context("reading receipt")?;
    let receipt = toml::from_str::<PkgRecord>(&raw).context("parsing receipt")?;

    let scope = derive_origin(&receipt.format, &receipt.source_mirror);
    let tier = tier_badge(&scope);

    println!("{G}Package Information{RST}");
    println!("  {DIM}Name         :{RST} {P}{}{RST}", receipt.name);
    println!("  {DIM}Version      :{RST} {B}{}{RST}", receipt.version);
    if !receipt.display_name.is_empty() && receipt.display_name != receipt.name {
        println!(
            "  {DIM}Description  :{RST} {DIM}{}{RST}",
            receipt.display_name
        );
    }
    println!("  {DIM}Status       :{RST} {G}installed{RST}");
    println!("  {DIM}Scope        :{RST} {tier}");
    println!("  {DIM}Format       :{RST} {B}{}{RST}", receipt.format);
    if !receipt.source_mirror.is_empty() {
        println!(
            "  {DIM}Mirror       :{RST} {B}{}{RST}",
            receipt.source_mirror
        );
    }
    if !receipt.sha256.is_empty() {
        println!("  {DIM}SHA256       :{RST} {DIM}{}{RST}", receipt.sha256);
    }
    if !receipt.blake3.is_empty() {
        println!("  {DIM}BLAKE3       :{RST} {DIM}{}{RST}", receipt.blake3);
    }
    if let Some(req) = &receipt.requires_syshub {
        println!("  {DIM}Needs syshub :{RST} {B}{req}{RST}");
    }
    if !receipt.installed_at.is_empty() {
        println!(
            "  {DIM}Installed at :{RST} {DIM}{}{RST}",
            receipt.installed_at
        );
    }

    // Classify the flat installed_files list by actual on-disk type —
    // the registry doesn't distinguish files/symlinks/dirs up front.
    let mut files: Vec<&String> = Vec::new();
    let mut symlinks: Vec<&String> = Vec::new();
    for f in &receipt.installed_files {
        if Path::new(f).is_symlink() {
            symlinks.push(f);
        } else {
            files.push(f);
        }
    }

    // ── Disk usage ────────────────────────────────────────────────────────────
    let total_size: u64 = files
        .iter()
        .map(|f| fs::metadata(f).map(|m| m.len()).unwrap_or(0))
        .sum();
    let file_count = files.len();

    println!("\n{G}Disk Usage{RST}");
    println!("  {DIM}Files        :{RST} {B}{file_count}{RST}");
    println!("  {DIM}Symlinks     :{RST} {B}{}{RST}", symlinks.len());
    println!(
        "  {DIM}Total size   :{RST} {G}{}{RST}",
        human_bytes(total_size)
    );

    // ── Installed locations ───────────────────────────────────────────────────
    if !files.is_empty() {
        println!("\n{G}Installed Locations{RST}");
        for f in files.iter().take(12) {
            let missing = if !Path::new(f).exists() {
                format!("  {R}[missing]{RST}")
            } else {
                String::new()
            };
            println!("  {DIM}•{RST} {B}{f}{RST}{missing}");
        }
        if files.len() > 12 {
            println!("  {DIM}... and {} more files{RST}", files.len() - 12);
        }
    }

    // ── Symlinks ──────────────────────────────────────────────────────────────
    if !symlinks.is_empty() {
        println!("\n{G}Symlinks{RST}");
        for link in &symlinks {
            let target = if Path::new(link).is_symlink() {
                fs::read_link(link)
                    .map(|t| format!(" {DIM}→{RST} {DIM}{}{RST}", t.display()))
                    .unwrap_or_default()
            } else {
                format!("  {R}[broken]{RST}")
            };
            println!("  {DIM}•{RST} {B}{link}{RST}{target}");
        }
    }

    // ── Dependencies / provides ────────────────────────────────────────────────
    if !receipt.dependencies.is_empty() {
        println!("\n{G}Dependencies{RST}");
        println!("  {DIM}{}{RST}", receipt.dependencies.join(", "));
    }
    if !receipt.provides.is_empty() {
        println!("\n{G}Provides{RST}");
        println!("  {DIM}{}{RST}", receipt.provides.join(", "));
    }

    // ── Shared library deps (from binaries) ───────────────────────────────────
    let file_owned: Vec<String> = files.iter().map(|s| s.to_string()).collect();
    let libs = detect_shared_libs(&file_owned);
    if !libs.is_empty() {
        println!("\n{G}Shared Library Dependencies{RST}");
        for lib in &libs {
            let libc_type = classify_lib(lib);
            println!("  {DIM}•{RST} {B}{lib:<32}{RST} {DIM}{libc_type}{RST}");
        }
    }

    // ── Integrity check ───────────────────────────────────────────────────────
    let missing: Vec<&String> = files
        .iter()
        .filter(|f| !Path::new(f).exists())
        .cloned()
        .collect();

    println!("\n{G}Integrity{RST}");
    if missing.is_empty() {
        println!("  {G}\u{2713}{RST} All {file_count} files present");
    } else {
        println!(
            "  {R}\u{2717}{RST} {}/{file_count} files present",
            file_count - missing.len()
        );
        for f in &missing {
            println!("    {R}missing:{RST} {f}");
        }
    }

    println!();
    Ok(())
}

// ── Syshub manifest entry inspection ─────────────────────────────────────────
fn inspect_syshub_entry(name: &str, entry: &toml::Value) {
    println!("{G}Package Information{RST}");
    println!("  {DIM}Name         :{RST} {P}{name}{RST}");

    if let Some(t) = entry.as_table() {
        if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
            println!("  {DIM}Version      :{RST} {B}{v}{RST}");
        }
        if let Some(bt) = t.get("build_type").and_then(|v| v.as_str()) {
            println!("  {DIM}Build type   :{RST} {B}{bt}{RST}");
        }
        if let Some(lc) = t.get("libc_target").and_then(|v| v.as_str()) {
            println!("  {DIM}libc         :{RST} {B}{lc}{RST}");
        }
        if let Some(deps) = t.get("depends").and_then(|v| v.as_array()) {
            if !deps.is_empty() {
                let dep_strs: Vec<_> = deps.iter().filter_map(|d| d.as_str()).collect();
                println!(
                    "  {DIM}Depends      :{RST} {DIM}{}{RST}",
                    dep_strs.join(", ")
                );
            }
        }
        if let Some(provs) = t.get("provides").and_then(|v| v.as_array()) {
            if !provs.is_empty() {
                let p_strs: Vec<_> = provs.iter().filter_map(|p| p.as_str()).collect();
                println!("  {DIM}Provides     :{RST} {DIM}{}{RST}", p_strs.join(", "));
            }
        }
    }

    println!("  {DIM}Status       :{RST} {Y}syshub (protected){RST}");
    println!("  {DIM}Scope        :{RST} {Y}[syshub — immutable base]{RST}");

    // Find files in syshub
    let syshub_files = find_syshub_files(name);
    if !syshub_files.is_empty() {
        println!("\n{G}Installed Locations  {DIM}(syshub){RST}");
        for (path, size) in syshub_files.iter().take(10) {
            println!(
                "  {DIM}•{RST} {B}{}{RST}  {DIM}{}{RST}",
                path,
                human_bytes(*size)
            );
        }
    }
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn syshub_lookup(name: &str) -> Option<toml::Value> {
    let raw = fs::read_to_string(SYSHUB_MANIFEST).ok()?;
    let m: SyshubManifest = toml::from_str(&raw).ok()?;
    m.packages.get(name).cloned()
}

/// Scan syshub dirs for files whose path contains the package name.
fn find_syshub_files(name: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for base in [
        &format!("{SYSHUB_PATH}/bin"),
        &format!("{SYSHUB_PATH}/lib"),
        &format!("{SYSHUB_PATH}/lib64"),
        &format!("{SYSHUB_PATH}/sbin"),
    ] {
        let p = Path::new(base);
        if !p.exists() {
            continue;
        }
        for entry in fs::read_dir(p).into_iter().flatten().flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname
                .to_ascii_lowercase()
                .contains(&name.to_ascii_lowercase())
            {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.push((entry.path().to_string_lossy().into_owned(), size));
            }
        }
    }
    out
}

/// Run `readelf -d` on binary files and collect NEEDED library names.
fn detect_shared_libs(files: &[String]) -> Vec<String> {
    let mut libs: HashSet<String> = HashSet::new();
    for f in files {
        let path = Path::new(f);
        // Only check ELF files (binaries and .so)
        if !is_elf(path) {
            continue;
        }
        if let Ok(out) = Command::new("readelf").args(["-d", f]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if line.contains("(NEEDED)") {
                    if let Some(lib) = extract_needed(line) {
                        libs.insert(lib);
                    }
                }
            }
        }
    }
    let mut sorted: Vec<String> = libs.into_iter().collect();
    sorted.sort();
    sorted
}

fn is_elf(path: &Path) -> bool {
    if let Ok(mut f) = fs::File::open(path) {
        let mut magic = [0u8; 4];
        use std::io::Read;
        if f.read_exact(&mut magic).is_ok() {
            return magic == [0x7f, b'E', b'L', b'F'];
        }
    }
    false
}

fn extract_needed(line: &str) -> Option<String> {
    // Format: "  0x... (NEEDED) Shared library: [libfoo.so.1]"
    let start = line.find('[')? + 1;
    let end = line.find(']')?;
    Some(line[start..end].to_string())
}

fn classify_lib(lib: &str) -> &'static str {
    if lib == "ld-musl-x86_64.so.1" || lib == "libc.so" {
        "musl"
    } else if lib == "libc.so.6" || lib.starts_with("ld-linux") {
        "glibc"
    } else if lib.starts_with("libstdc++") || lib.starts_with("libgcc") {
        "GCC runtime"
    } else if lib.starts_with("libpthread") || lib.starts_with("libdl") {
        "POSIX thread/dl"
    } else {
        "userland"
    }
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

fn human_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{} KB", b / 1024)
    } else {
        format!("{b} B")
    }
}
