//! pinning.rs: Core package pinning for the zex multicall binary.

use anyhow::{Result, bail};

const PINNED_PATH: &str = "/overlayer/zexlib/registry/pinned.toml";
const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";

const G: &str = "\x1b[92m";
const P: &str = "\x1b[95m";
const B: &str = "\x1b[96m";
const Y: &str = "\x1b[93m";
const DIM: &str = "\x1b[2m";
const RST: &str = "\x1b[0m";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinnedPackage {
    pub name: String,
    pub pinned_version: String,
    pub pinned_at: String,
    pub pinned_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct PinnedFile {
    #[serde(default)]
    pinned: Vec<PinnedPackage>,
}

pub fn load_pinned() -> Vec<PinnedPackage> {
    let path = std::path::Path::new(PINNED_PATH);
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| toml::from_str::<PinnedFile>(&raw).ok())
        .map(|f| f.pinned)
        .unwrap_or_default()
}

fn save_pinned(entries: &[PinnedPackage]) -> Result<()> {
    let file = PinnedFile {
        pinned: entries.to_vec(),
    };
    let text = toml::to_string_pretty(&file)?;
    if let Some(p) = std::path::Path::new(PINNED_PATH).parent() {
        std::fs::create_dir_all(p)?;
    }
    let tmp = format!("{PINNED_PATH}.tmp");
    std::fs::write(&tmp, &text)?;
    std::fs::rename(&tmp, PINNED_PATH)?;
    Ok(())
}

pub fn is_pinned(name: &str) -> bool {
    load_pinned()
        .iter()
        .any(|p| p.name.eq_ignore_ascii_case(name))
}

pub fn get_pin(name: &str) -> Option<PinnedPackage> {
    load_pinned()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Pin a package at its currently installed version.
pub fn pin(name: &str, reason: Option<&str>) -> Result<()> {
    let receipt = std::path::Path::new(INSTALLED_DIR).join(format!("{}.toml", name.to_lowercase()));
    if !receipt.exists() {
        bail!(
            "Package '{}' is not installed — cannot pin.\n\
             Install it first: elevate zex install {name}",
            name
        );
    }
    let raw = std::fs::read_to_string(&receipt)?;
    let version = raw
        .lines()
        .find(|l| l.starts_with("version"))
        .and_then(|l| l.split('"').nth(1))
        .unwrap_or("unknown")
        .to_string();

    let mut pinned = load_pinned();
    pinned.retain(|p| !p.name.eq_ignore_ascii_case(name));

    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".into());

    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let s = secs;
        let days = s / 86400;
        format!("unix-{days}T00:00:00Z")
    };

    pinned.push(PinnedPackage {
        name: name.to_lowercase(),
        pinned_version: version.clone(),
        pinned_at: now,
        pinned_by: user,
        reason: reason.map(str::to_string),
    });

    save_pinned(&pinned)?;

    println!("\n {G}\u{2713} Package pinned successfully{RST}\n");
    println!("{G}Pin Summary{RST}");
    println!("  Package : {P}{name}{RST}");
    println!("  Version : {B}{version}{RST}  {DIM}(locked \u{2014} upgrades blocked){RST}");
    if let Some(r) = reason {
        println!("  Reason  : {DIM}{r}{RST}");
    }
    println!("\n{DIM}To release: elevate zex unpin {name}{RST}\n");
    Ok(())
}

/// Unpin a package.
pub fn unpin(name: &str) -> Result<()> {
    let mut pinned = load_pinned();
    let before = pinned.len();
    pinned.retain(|p| !p.name.eq_ignore_ascii_case(name));

    if pinned.len() == before {
        println!("\n {Y}Package {P}'{name}'{Y} is not pinned.{RST}\n");
        return Ok(());
    }

    save_pinned(&pinned)?;
    println!("\n {G}\u{2713} Package unpinned{RST}");
    println!("  {P}{name}{RST} {DIM}will now be upgraded on 'elevate zex update'{RST}\n");
    Ok(())
}

/// Print all pinned packages (for `elevate zex pins`).
pub fn print_pins(pins: &[PinnedPackage]) {
    if pins.is_empty() {
        println!("\n {DIM}No packages are currently pinned.{RST}\n");
        return;
    }
    println!(
        "\n{G}Pinned Packages{RST}  {DIM}({} total){RST}\n",
        pins.len()
    );
    for p in pins {
        let reason = p
            .reason
            .as_deref()
            .map(|r| format!("  {DIM}\u{2014} {r}{RST}"))
            .unwrap_or_default();
        println!(
            "  {DIM}\u{2022}{RST} {P}{:<22}{RST}  {B}{:<16}{RST} {DIM}by {}{RST}{}",
            p.name, p.pinned_version, p.pinned_by, reason
        );
    }
    println!();
}
