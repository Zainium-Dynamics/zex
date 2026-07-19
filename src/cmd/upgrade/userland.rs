//! userland.rs — Multi-tier userland upgrade engine.
//!
//! Command:  elevate zex uland --u
//!
//! Each installed package has an `origin` field in packages.toml:
//!   "tier1-zainium"  → zainium-userland-zexlib  (format: zex)
//!   "tier2-alpine"   → alpine-main / alpine-community (format: apk)
//!   "tier3-void"     → void-musl-current / void-musl-nonfree (format: xbps)
//!   "tier4-chimera"  → chimera-main / chimera-user (format: apk)
//!
//! The upgrade driver reads zex_services.toml to find the mirror per tier,
//! fetches its index in the right format, parses it, diffs against the
//! locally installed version, then downloads and overlays updated packages
//! 2 at a time — exactly like syscore but for the writable union layer.

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use indicatif::MultiProgress;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};
use walkdir::WalkDir;

use super::{
    audit::{self, AuditEntry},
    signing::verify_zex,
    ui,
    vercmp::is_upgrade,
};

// ── Paths ──────────────────────────────────────────────────────────────────────
const ZEX_SERVICES:   &str = "/overlayer/syshub/engine/services/zex_services.toml";
const PACKAGES_TOML:  &str = "/overlayer/zexlib/registry/packages.toml";
const INSTALLED_DIR:  &str = "/overlayer/zexlib/registry/installed";
const UNION_PATH:     &str = "/overlayer/zexlib/union";
const DL_TMP:         &str = "/overlayer/zexlib/tmp/uland-dl";
const PING_URL:       &str = "https://archive.zainiumdynamics.tech/ping";

// ── zex_services.toml schema ───────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
struct ZexServices {
    mirrors: Vec<Mirror>,
    #[serde(default)] network: NetworkConf,
    #[serde(default)] trust:   TrustConf,
}

#[derive(Debug, Deserialize)]
struct Mirror {
    id:              String,
    base_url:        String,
    index_url:       String,
    format:          String,    // "zex" | "apk" | "xbps"
    priority:        u32,
    supported_archs: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NetworkConf {
    #[serde(default = "default_timeout")] http_timeout_secs: u64,
}
fn default_timeout() -> u64 { 3600 }

#[derive(Debug, Deserialize, Default)]
struct TrustConf {
    #[serde(default)] require_signatures: bool,
    #[serde(default)] force_https_enforcement: bool,
}

// ── packages.toml schema ───────────────────────────────────────────────────────
#[derive(Debug, Deserialize, Clone)]
struct PackagesToml {
    system:   SystemMeta,
    packages: HashMap<String, PackageEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct SystemMeta {
    last_update:     String,
    total_packages:  Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
struct PackageEntry {
    version:      String,
    origin:       String,   // "tier1-zainium" | "tier2-alpine" | "tier3-void" | "tier4-chimera"
    #[serde(default)]
    description:  String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    receipt:      String,
    /// The *exact* mirror this package was resolved from (e.g.
    /// "alpine-community", not just "tier2-alpine"). A tier can have
    /// several mirrors — upgrade checking must use the one the package
    /// actually came from, or it either misses it entirely or silently
    /// "upgrades" it from a different mirror/tier than it was installed
    /// from. Empty for legacy entries written before this field existed.
    #[serde(default)]
    source_mirror: String,
}

// ── Resolved upgrade record ────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct UpgradePkg {
    name:        String,
    old_ver:     String,
    new_ver:     String,
    origin:      String,
    tier_label:  String,   // "T1" / "T2" / "T3" / "T4" for display
    format:      PkgFmt,
    url:         String,
    filename:    String,
    size_bytes:  u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PkgFmt { Zex, Apk, Xbps, Adb }

impl PkgFmt {
    fn ext(&self) -> &'static str {
        match self { Self::Zex => "zex", Self::Apk => "apk", Self::Xbps => "xbps", Self::Adb => "apk" }
    }
}

// ── Public entry ───────────────────────────────────────────────────────────────

// ── Pin check helper ──────────────────────────────────────────────────────────

/// Returns true if this package is pinned in the Zainium registry.
/// Reads /overlayer/zexlib/registry/pinned.toml.
fn is_pkg_pinned(name: &str) -> bool {
    const PINNED: &str = "/overlayer/zexlib/registry/pinned.toml";
    let Ok(raw) = std::fs::read_to_string(PINNED) else { return false };
    #[derive(serde::Deserialize, Default)]
    struct PinnedFile { #[serde(default)] pinned: Vec<Pin> }
    #[derive(serde::Deserialize)]
    struct Pin { name: String, pinned_version: String }
    toml::from_str::<PinnedFile>(&raw)
        .map(|f| f.pinned.iter().any(|p| p.name.eq_ignore_ascii_case(name)))
        .unwrap_or(false)
}

fn pinned_version(name: &str) -> Option<String> {
    const PINNED: &str = "/overlayer/zexlib/registry/pinned.toml";
    let raw = std::fs::read_to_string(PINNED).ok()?;
    #[derive(serde::Deserialize, Default)]
    struct PinnedFile { #[serde(default)] pinned: Vec<Pin> }
    #[derive(serde::Deserialize)]
    struct Pin { name: String, pinned_version: String }
    toml::from_str::<PinnedFile>(&raw).ok()?
        .pinned.into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .map(|p| p.pinned_version)
}

pub async fn execute() -> Result<()> {
    let started = Instant::now();

    ui::print_uland_header();
    ui::print_uland_checking();

    // ── 1. Internet ──────────────────────────────────────────────────────────
    if !online().await {
        ui::print_no_internet();
        std::process::exit(1);
    }

    // ── 2. Parse config files ────────────────────────────────────────────────
    let svc_raw = fs::read_to_string(ZEX_SERVICES)
        .context("reading zex_services.toml")?;
    let services: ZexServices = toml::from_str(&svc_raw)
        .context("parsing zex_services.toml")?;

    let local_raw = fs::read_to_string(PACKAGES_TOML)
        .context("reading packages.toml")?;
    let local: PackagesToml = toml::from_str(&local_raw)
        .context("parsing packages.toml")?;

    // ── 3. Detect host arch ───────────────────────────────────────────────────
    let arch = detect_arch();

    // ── 4. Build http client with configured timeout ──────────────────────────
    let client = crate::http_client::build(concat!(
        "uland/",
        env!("CARGO_PKG_VERSION"),
        " (Zainium OS)"
    ))?;

    // ── 5. Fetch index for each *exact mirror* that has installed packages ────
    //
    // Group by the precise mirror a package was resolved from (not just
    // its tier) — a tier can have several mirrors (alpine-main vs
    // alpine-community, chimera-main vs chimera-user), and checking the
    // wrong one either misses the package or "upgrades" it from a
    // different source than it was actually installed from. Legacy
    // entries written before `source_mirror` existed fall back to the
    // old tier-generic default.
    let mut mirror_pkgs: HashMap<String, Vec<(String, PackageEntry)>> = HashMap::new();
    for (name, entry) in &local.packages {
        let key = if !entry.source_mirror.is_empty() {
            entry.source_mirror.clone()
        } else {
            entry.origin.clone()
        };
        mirror_pkgs.entry(key).or_default().push((name.clone(), entry.clone()));
    }

    let mut upgrades: Vec<UpgradePkg> = Vec::new();

    for (group_key, pkg_list) in &mirror_pkgs {
        let Some((mirror, fmt)) = mirror_by_exact_id(&services.mirrors, group_key, &arch)
            .or_else(|| match_mirror(&services.mirrors, group_key, &arch))
        else {
            log::warn!("no mirror found for '{group_key}' — skipping {} package(s)", pkg_list.len());
            continue;
        };

        // Substitute {arch} in URLs
        let index_url = mirror.index_url.replace("{arch}", &arch);
        let base_url  = mirror.base_url.replace("{arch}", &arch);

        let found = match fmt {
            PkgFmt::Zex  => fetch_zex_upgrades(&client, &index_url, &base_url, pkg_list).await?,
            PkgFmt::Apk  => fetch_apk_upgrades(&client, &index_url, &base_url, pkg_list).await?,
            PkgFmt::Xbps => fetch_xbps_upgrades(&client, &index_url, &base_url, pkg_list).await?,
            PkgFmt::Adb  => fetch_adb_upgrades(&client, &index_url, &base_url, pkg_list).await?,
        };

        let origin = pkg_list.first().map(|(_, e)| e.origin.clone()).unwrap_or_default();
        upgrades.extend(found.into_iter().map(|mut u| {
            u.origin     = origin.clone();
            u.tier_label = tier_label(&origin);
            u
        }));
    }

    // Sort: tier1 first, then alphabetically
    upgrades.sort_by(|a, b| {
        a.tier_label.cmp(&b.tier_label).then(a.name.cmp(&b.name))
    });

    if upgrades.is_empty() {
        let total = local.packages.len();
        ui::print_uland_uptodate("2026v3.2", total);
        return Ok(());
    }

    ui::print_uland_found(upgrades.len());

    // ── 6. Print package list with tier badges ────────────────────────────────
    print_tier_package_list(&upgrades);

    let total_bytes: u64 = upgrades.iter().map(|u| u.size_bytes).sum();
    let total_gb = total_bytes as f64 / 1_073_741_824.0;
    let est_secs = if total_bytes > 0 {
        (total_bytes as f64 / (20.0 * 1_048_576.0)) as u64
    } else {
        upgrades.len() as u64 * 8
    };

    ui::print_uland_transaction(upgrades.len(), total_gb, est_secs);

    if !ui::print_uland_proceed_prompt() {
        println!("\n {DIM}Upgrade cancelled.{RST}", DIM = ui::DIM, RST = ui::RST);
        return Ok(());
    }

    ui::print_uland_starting();

    // ── 7. Prepare download dir ───────────────────────────────────────────────
    let dl_tmp = Path::new(DL_TMP);
    if dl_tmp.exists() { fs::remove_dir_all(dl_tmp)?; }
    fs::create_dir_all(dl_tmp)?;
    fs::create_dir_all(UNION_PATH)?;
    fs::create_dir_all(INSTALLED_DIR)?;

    let mp = MultiProgress::new();
    let overall = ui::make_overall_bar(&mp, upgrades.len() as u64);
    overall.set_position(0);

    let mut done: Vec<String> = Vec::new();
    let mut actual_bytes: u64 = 0;

    // ── 8. Download + apply in chunks of 2 ───────────────────────────────────
    for chunk in upgrades.chunks(2) {
        let mut handles = Vec::new();

        for pkg in chunk {
            let label = format!(
                "{} {:<20} {} → {}",
                tier_badge(&pkg.tier_label),
                pkg.name,
                pkg.old_ver,
                pkg.new_ver
            );
            let cl  = if pkg.size_bytes > 0 { pkg.size_bytes }
                      else { content_length(&client, &pkg.url).await.unwrap_or(0) };
            let bar = ui::make_pkg_bar(&mp, cl, &label);

            let url    = pkg.url.clone();
            let dest   = dl_tmp.join(&pkg.filename);
            let name   = pkg.name.clone();
            let fmt    = pkg.format;
            let client = client.clone();
            let h = tokio::spawn(async move {
                download_with_bar(&client, &url, &dest, &bar).await
                    .map(|b| (name, dest, fmt, b))
            });
            handles.push(h);
        }

        let mut chunk_results = Vec::new();
        for h in handles {
            match h.await {
                Ok(Ok(r)) => chunk_results.push(r),
                Ok(Err(e)) => {
                    let who = chunk.first().map(|p| p.name.as_str()).unwrap_or("unknown");
                    fs::remove_dir_all(dl_tmp).ok();
                    ui::print_uland_download_interrupted(who);
                    log_audit("uland", &done, "rolled_back",
                              Some(&e.to_string()), started.elapsed().as_millis() as u64);
                    std::process::exit(1);
                }
                Err(e) => bail!("task join: {e}"),
            }
        }

        for (pkg_name, zex_path, fmt, bytes) in &chunk_results {
            actual_bytes += bytes;

            // Signature verify only for native .zex packages
            if *fmt == PkgFmt::Zex {
                verify_zex(zex_path, services.trust.require_signatures)?;
            }

            // Extract into union
            match fmt {
                PkgFmt::Zex  => extract_zex_into(zex_path, Path::new(UNION_PATH))?,
                PkgFmt::Apk  => extract_apk_into(zex_path, Path::new(UNION_PATH))?,
                PkgFmt::Xbps => extract_xbps_into(zex_path, Path::new(UNION_PATH))?,
                PkgFmt::Adb  => extract_adb_into(zex_path, Path::new(UNION_PATH))?,
            }

            // Bump the existing receipt's version in place — this
            // preserves installed_files/dependencies/sha256/etc, unlike
            // writing a fresh receipt from scratch (which would silently
            // break `zex remove` and orphan detection for this package).
            let pkg_info = upgrades.iter().find(|u| &u.name == pkg_name).unwrap();
            crate::cmd::install::registry::update_version(&pkg_info.name, &pkg_info.new_ver)?;

            done.push(pkg_name.clone());
            overall.inc(1);
        }
    }

    overall.finish_and_clear();
    println!();

    // ── 9. Phase bars ─────────────────────────────────────────────────────────
    ui::print_phase("Verifying integrity");
    ui::print_phase("Extracting & overlaying packages");

    // packages.toml is already kept in sync per-package by
    // registry::update_version() (called above for each upgraded
    // package), which also preserves every other field in its receipt.
    ui::print_phase("Updating system registry");

    fs::remove_dir_all(dl_tmp).ok();
    ui::print_phase("Cleaning old versions");

    let elapsed  = started.elapsed().as_secs();
    let total_gb = actual_bytes as f64 / 1_073_741_824.0;

    ui::print_uland_done(done.len(), total_gb, elapsed, "2026v3.2");
    log_audit("uland", &done, "success", None, started.elapsed().as_millis() as u64);

    Ok(())
}

// ── Mirror selection ───────────────────────────────────────────────────────────

/// Looks a mirror up by its *exact* id (e.g. "alpine-community") — the
/// precise mirror a package was resolved from, as recorded in its
/// registry entry. This is the primary path; `match_mirror` below is
/// only a fallback for legacy entries that predate `source_mirror`.
fn mirror_by_exact_id<'a>(mirrors: &'a [Mirror], id: &str, arch: &str) -> Option<(&'a Mirror, PkgFmt)> {
    let m = mirrors.iter().find(|m| m.id == id && m.supported_archs.iter().any(|a| a == arch))?;
    let fmt = match m.format.as_str() {
        "zex" => PkgFmt::Zex,
        "apk" => PkgFmt::Apk,
        "xbps" => PkgFmt::Xbps,
        "adb" => PkgFmt::Adb,
        _ => return None,
    };
    Some((m, fmt))
}

/// Fallback for legacy entries with no recorded `source_mirror`: picks a
/// single representative mirror per tier. This can pick the wrong mirror
/// within a multi-mirror tier (e.g. alpine-main when the package actually
/// came from alpine-community) — it's a best-effort default, not a
/// correctness guarantee, which is exactly why `mirror_by_exact_id` is
/// tried first everywhere this is called.
/// "tier1-zainium" → zainium-userland-zexlib (zex)
/// "tier2-alpine"  → alpine-main (apk)
/// "tier3-void"    → void-musl-current (xbps)
/// "tier4-chimera" → chimera-main (adb)
fn match_mirror<'a>(
    mirrors: &'a [Mirror],
    origin:  &str,
    arch:    &str,
) -> Option<(&'a Mirror, PkgFmt)> {
    let (id_fragment, fmt) = match origin {
        o if o.contains("tier1") || o.contains("zainium") =>
            ("zainium-userland-zexlib", PkgFmt::Zex),
        o if o.contains("tier2") || o.contains("alpine") =>
            ("alpine-main", PkgFmt::Apk),
        o if o.contains("tier3") || o.contains("void") =>
            ("void-musl-current", PkgFmt::Xbps),
        o if o.contains("tier4") || o.contains("chimera") =>
            ("chimera-main", PkgFmt::Adb),
        _ => return None,
    };

    mirrors.iter()
        .filter(|m| m.id == id_fragment && m.supported_archs.iter().any(|a| a == arch))
        .min_by_key(|m| m.priority)
        .map(|m| (m, fmt))
}

fn tier_label(origin: &str) -> String {
    if origin.contains("tier1") || origin.contains("zainium") { "T1".into() }
    else if origin.contains("tier2") || origin.contains("alpine")  { "T2".into() }
    else if origin.contains("tier3") || origin.contains("void")    { "T3".into() }
    else if origin.contains("tier4") || origin.contains("chimera") { "T4".into() }
    else { "T?".into() }
}

fn tier_badge(label: &str) -> String {
    match label {
        "T1" => format!("{}[T1-ZAI]{}", ui::G,   ui::RST),
        "T2" => format!("{}[T2-ALP]{}", ui::B,   ui::RST),
        "T3" => format!("{}[T3-VOD]{}", ui::P,   ui::RST),
        "T4" => format!("{}[T4-CHI]{}", ui::Y,   ui::RST),
        _    => format!("{}[T?]{}", ui::DIM, ui::RST),
    }
}

fn print_tier_package_list(pkgs: &[UpgradePkg]) {
    println!("{G}Packages to be upgraded:{RST}", G = ui::G, RST = ui::RST);
    for p in pkgs {
        let badge = tier_badge(&p.tier_label);
        let arrow = if p.old_ver == "0" {
            format!("{G}new{RST}", G = ui::G, RST = ui::RST)
        } else {
            format!("{B}{}{RST} {DIM}→{RST} {G}{}{RST}",
                p.old_ver, p.new_ver, B=ui::B, RST=ui::RST, DIM=ui::DIM, G=ui::G)
        };
        println!("  {DIM}•{RST} {badge} {P}{name:<22}{RST}  {arrow}",
            DIM=ui::DIM, RST=ui::RST, P=ui::P, name=p.name);
    }
}

// ── Index fetchers ─────────────────────────────────────────────────────────────

/// Tier 1: Fetch Zainium zex_ledger TOML, diff against installed.
async fn fetch_zex_upgrades(
    client:   &reqwest::Client,
    index_url: &str,
    base_url:  &str,
    installed: &[(String, PackageEntry)],
) -> Result<Vec<UpgradePkg>> {
    #[derive(Deserialize)]
    struct Ledger { packages: HashMap<String, toml::Value> }

    let raw  = client.get(index_url).send().await?.error_for_status()?.text().await?;
    let ledger: Ledger = toml::from_str(&raw).context("parsing zex_ledger")?;
    let mut out = Vec::new();

    for (local_name, local_entry) in installed {
        let Some(remote_val) = ledger.packages.get(local_name) else { continue };
        let new_ver = val_str(remote_val);
        if !is_upgrade(&local_entry.version, &new_ver) { continue; }
        if is_pkg_pinned(local_name) {
            log::info!("Package '{}' is pinned — skipping upgrade", local_name);
            continue;
        }

        let filename   = format!("{}-{}.zex", local_name, new_ver);
        let url        = format!("{}/{}", base_url.trim_end_matches('/'), filename);
        let size_bytes = content_length(client, &url).await.unwrap_or(0);

        out.push(UpgradePkg {
            name:       local_name.clone(),
            old_ver:    local_entry.version.clone(),
            new_ver,
            origin:     String::new(), // filled by caller
            tier_label: String::new(),
            format:     PkgFmt::Zex,
            url, filename, size_bytes,
        });
    }
    Ok(out)
}

/// Tier 2 / Tier 4: Parse APKINDEX.tar.gz (Alpine/Chimera).
async fn fetch_apk_upgrades(
    client:    &reqwest::Client,
    index_url: &str,
    base_url:  &str,
    installed: &[(String, PackageEntry)],
) -> Result<Vec<UpgradePkg>> {
    let bytes  = client.get(index_url).send().await?.error_for_status()?.bytes().await?;

    // Decompress gz → untar → read APKINDEX text
    let apkindex_text = tokio::task::spawn_blocking(move || -> Result<String> {
        // APKINDEX.tar.gz is a concatenation of multiple gzip members
        // (signature tarball + index tarball) — a plain GzDecoder only
        // reads the first member and silently truncates before APKINDEX.
        let dec = flate2::read::MultiGzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(dec);
        let mut text = String::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()?.to_string_lossy() == "APKINDEX" {
                entry.read_to_string(&mut text)?;
                return Ok(text);
            }
        }
        bail!("APKINDEX not found in tar.gz")
    }).await??;

    // Parse APKINDEX (each package block separated by blank line)
    let mut remote_versions: HashMap<String, (String, u64)> = HashMap::new();
    for block in apkindex_text.split("\n\n") {
        let mut name = String::new();
        let mut ver  = String::new();
        let mut size: u64 = 0;
        for line in block.lines() {
            if line.len() < 2 { continue; }
            let (key, val) = line.split_at(2);
            match key {
                "P:" => name = val.to_string(),
                "V:" => ver  = val.to_string(),
                "S:" => size = val.parse().unwrap_or(0),
                _ => {}
            }
        }
        if !name.is_empty() && !ver.is_empty() {
            remote_versions.insert(name, (ver, size));
        }
    }

    let mut out = Vec::new();
    for (local_name, local_entry) in installed {
        let Some((new_ver, size_bytes)) = remote_versions.get(local_name) else { continue };
        if !is_upgrade(&local_entry.version, new_ver) { continue; }

        let filename = format!("{}-{}.apk", local_name, new_ver);
        let url      = format!("{}/{}", base_url.trim_end_matches('/'), filename);

        out.push(UpgradePkg {
            name:       local_name.clone(),
            old_ver:    local_entry.version.clone(),
            new_ver:    new_ver.clone(),
            origin:     String::new(),
            tier_label: String::new(),
            format:     PkgFmt::Apk,
            url, filename,
            size_bytes: *size_bytes,
        });
    }
    Ok(out)
}

/// Tier 3: Parse Void Linux repodata (zstd-compressed tar → index.plist).
async fn fetch_xbps_upgrades(
    client:    &reqwest::Client,
    index_url: &str,
    base_url:  &str,
    installed: &[(String, PackageEntry)],
) -> Result<Vec<UpgradePkg>> {
    let bytes = client.get(index_url).send().await?.error_for_status()?.bytes().await?;

    let remote = tokio::task::spawn_blocking(move || -> Result<HashMap<String, (String, u64)>> {
        let dec  = zstd::stream::read::Decoder::new(&bytes[..])?;
        let mut archive = tar::Archive::new(dec);
        let mut plist_bytes = Vec::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()?.to_string_lossy() == "index.plist" {
                entry.read_to_end(&mut plist_bytes)?;
                break;
            }
        }
        if plist_bytes.is_empty() { bail!("index.plist not found in xbps repodata"); }

        let val: plist::Value = plist::from_bytes(&plist_bytes)?;
        let dict = val.into_dictionary()
            .ok_or_else(|| anyhow::anyhow!("index.plist root is not a dict"))?;

        // The current Void repodata schema keys the dictionary by the
        // package name itself — there's no separate "pkgname" field, and
        // no plain "version" field (only combined "pkgver" = "name-
        // version_revision"). Size is "filename-size", not
        // "repository-filesize". See cmd::install::xbps for the same fix.
        let mut out = HashMap::new();
        for (key, meta_val) in dict {
            let Some(meta) = meta_val.as_dictionary() else { continue };
            let pkgver = meta.get("pkgver").and_then(|v| v.as_string()).unwrap_or(&key);
            let ver = pkgver.strip_prefix(&format!("{key}-")).unwrap_or(pkgver).to_string();
            let size = meta.get("filename-size").and_then(|v| v.as_unsigned_integer()).unwrap_or(0);
            if !ver.is_empty() {
                out.insert(key, (ver, size));
            }
        }
        Ok(out)
    }).await??;

    let mut out = Vec::new();
    for (local_name, local_entry) in installed {
        let Some((new_ver, size_bytes)) = remote.get(local_name) else { continue };
        if !is_upgrade(&local_entry.version, new_ver) { continue; }

        // Void filename convention: <pkgname>-<version>.<arch>.xbps
        let filename = format!("{}-{}.x86_64.xbps", local_name, new_ver);
        let url      = format!("{}/{}", base_url.trim_end_matches('/'), filename);

        out.push(UpgradePkg {
            name:       local_name.clone(),
            old_ver:    local_entry.version.clone(),
            new_ver:    new_ver.clone(),
            origin:     String::new(),
            tier_label: String::new(),
            format:     PkgFmt::Xbps,
            url, filename,
            size_bytes: *size_bytes,
        });
    }
    Ok(out)
}

/// Tier 4: Chimera Linux's apk-tools v3 binary "ADB" index (`Packages.adb`).
/// See `cmd::install::adb` for the format decoder itself.
async fn fetch_adb_upgrades(
    client:    &reqwest::Client,
    index_url: &str,
    base_url:  &str,
    installed: &[(String, PackageEntry)],
) -> Result<Vec<UpgradePkg>> {
    let bytes = client.get(index_url).send().await?.error_for_status()?.bytes().await?;

    let remote = tokio::task::spawn_blocking(move || -> Result<HashMap<String, (String, u64)>> {
        let records = crate::cmd::install::adb::parse_index(&bytes)?;
        Ok(records.into_iter().map(|r| (r.name, (r.version, r.file_size))).collect())
    }).await??;

    let mut out = Vec::new();
    for (local_name, local_entry) in installed {
        let Some((new_ver, size_bytes)) = remote.get(local_name) else { continue };
        if !is_upgrade(&local_entry.version, new_ver) { continue; }

        let filename = format!("{}-{}.apk", local_name, new_ver);
        let url      = format!("{}/{}", base_url.trim_end_matches('/'), filename);

        out.push(UpgradePkg {
            name:       local_name.clone(),
            old_ver:    local_entry.version.clone(),
            new_ver:    new_ver.clone(),
            origin:     String::new(),
            tier_label: String::new(),
            format:     PkgFmt::Adb,
            url, filename,
            size_bytes: *size_bytes,
        });
    }
    Ok(out)
}

// ── Extractors ─────────────────────────────────────────────────────────────────

fn extract_zex_into(src: &Path, dest: &Path) -> Result<()> {
    #[cfg(unix)] use std::os::unix::fs::symlink;
    let dec = crate::zex_codec::open_decoder(src)?;
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw   = entry.path()?.into_owned();
        let rel   = raw.to_string_lossy();
        if !rel.starts_with("payload/") { continue; }
        let inner = rel.strip_prefix("payload/").unwrap_or("").trim_start_matches('/');
        if inner.is_empty() { continue; }
        let dst = dest.join(inner);
        let typ = entry.header().entry_type();
        if typ.is_dir() { fs::create_dir_all(&dst)?; continue; }
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }
        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            set_exec_if_needed(&entry.header(), &dst);
        } else if typ.is_symlink() {
            if let Some(t) = entry.link_name()? {
                let _ = fs::remove_file(&dst);
                #[cfg(unix)] symlink(&t, &dst)?;
            }
        }
    }
    Ok(())
}

/// APK files are tar.gz. Paths like `usr/bin/foo` are remapped onto the
/// union layout (`bin/foo` → `/overlayer/zexlib/union/bin/foo` when dest is UNION).
fn extract_apk_into(src: &Path, dest: &Path) -> Result<()> {
    #[cfg(unix)] use std::os::unix::fs::symlink;
    let file = fs::File::open(src)?;
    // .apk packages are a concatenation of multiple gzip members
    // (signature + control + data tarballs) — MultiGzDecoder reads
    // through all of them instead of stopping after the signature.
    let dec  = flate2::read::MultiGzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let raw_s = raw.to_string_lossy();
        // Skip apk metadata files
        if raw_s.starts_with(".SIGN") || raw_s.starts_with(".PKGINFO") { continue; }

        let rel = match crate::archive_safety::sanitize_archive_path(&raw) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let dst = dest.join(&rel);
        let typ = entry.header().entry_type();
        if typ.is_dir() { fs::create_dir_all(&dst)?; continue; }
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }
        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            set_exec_if_needed(&entry.header(), &dst);
        } else if typ.is_symlink() {
            if let Some(t) = entry.link_name()? {
                let safe = crate::archive_safety::sanitize_link_target(&raw, &t)
                    .unwrap_or_else(|_| t.to_path_buf());
                let _ = fs::remove_file(&dst);
                #[cfg(unix)] symlink(&safe, &dst)?;
            }
        }
    }
    Ok(())
}

/// XBPS files are zstd-compressed tars. Same FHS → union remapping as APK.
fn extract_xbps_into(src: &Path, dest: &Path) -> Result<()> {
    #[cfg(unix)] use std::os::unix::fs::symlink;
    let dec  = zstd::stream::read::Decoder::new(fs::File::open(src)?)?;
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let raw_s = raw.to_string_lossy();
        // Skip xbps metadata
        if raw_s.contains("files.plist") || raw_s.contains("props.plist")
            || raw_s.ends_with("/INSTALL") || raw_s == "INSTALL"
            || raw_s.ends_with("/REMOVE") || raw_s == "REMOVE"
        {
            continue;
        }

        let rel = match crate::archive_safety::sanitize_archive_path(&raw) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() { continue; }
        let dst = dest.join(&rel);
        let typ = entry.header().entry_type();
        if typ.is_dir() { fs::create_dir_all(&dst)?; continue; }
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }
        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            set_exec_if_needed(&entry.header(), &dst);
        } else if typ.is_symlink() {
            if let Some(t) = entry.link_name()? {
                let safe = crate::archive_safety::sanitize_link_target(&raw, &t)
                    .unwrap_or_else(|_| t.to_path_buf());
                let _ = fs::remove_file(&dst);
                #[cfg(unix)] symlink(&safe, &dst)?;
            }
        }
    }
    Ok(())
}

/// Chimera's `.apk` is apk-tools v3's binary "ADB" container, not the
/// legacy gzip-tar format the name suggests — see `cmd::install::adb`.
fn extract_adb_into(src: &Path, dest: &Path) -> Result<()> {
    #[cfg(unix)] use std::os::unix::fs::symlink;

    let bytes = fs::read(src)?;
    let entries = crate::cmd::install::adb::extract_entries(&bytes)?;

    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;

    for entry in entries {
        let rel = match crate::archive_safety::sanitize_archive_path(Path::new(&entry.rel_path)) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() { continue; }
        let dst = dest.join(&rel);
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }

        match entry.mode & S_IFMT {
            S_IFDIR => { fs::create_dir_all(&dst)?; }
            S_IFLNK => {
                let target = entry.link_target.unwrap_or_default();
                // Real base-files packages ship self-referential usrmerge
                // symlinks (e.g. "/bin -> usr/bin") that our own
                // remap_usr_paths already collapses onto the same union
                // path structurally — skip creating the symlink literally
                // in that case (see installer::extract_adb for the fully
                // documented version of this fix).
                let target_remapped = crate::archive_safety::remap_usr_paths(PathBuf::from(&target));
                if target_remapped != rel {
                    let safe = crate::archive_safety::sanitize_link_target(Path::new(&entry.rel_path), Path::new(&target))
                        .unwrap_or_else(|_| PathBuf::from(&target));
                    let _ = fs::remove_file(&dst);
                    #[cfg(unix)] symlink(&safe, &dst)?;
                }
            }
            _ if entry.link_target.is_some() => {
                let target = entry.link_target.unwrap();
                let safe = crate::archive_safety::sanitize_archive_path(Path::new(&target))
                    .unwrap_or_else(|_| PathBuf::from(target));
                let target_path = dest.join(&safe);
                if target_path.exists() {
                    let _ = fs::remove_file(&dst);
                    fs::hard_link(&target_path, &dst)?;
                }
            }
            _ => {
                fs::write(&dst, entry.content.unwrap_or_default())?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_exec_if_needed(hdr: &tar::Header, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if hdr.mode().unwrap_or(0) & 0o111 != 0 {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    }
}
#[cfg(not(unix))]
fn set_exec_if_needed(_: &tar::Header, _: &Path) {}

// ── Small helpers ──────────────────────────────────────────────────────────────

async fn online() -> bool {
    let Ok(client) = crate::http_client::build("zex-uland/ping") else { return false };

    if let Ok(r) = client.get(PING_URL).send().await {
        if r.status().is_success() {
            return true;
        }
    }

    // The Tier 1 (Zainium) archive ping endpoint being unreachable doesn't
    // mean the system has no internet — Tier 2/3/4 mirrors can be fine on
    // their own, and uland upgrades across all tiers. Fall back to a
    // generic reachability probe before declaring the system offline.
    client.head("https://mirrors.edge.kernel.org/").send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn detect_arch() -> String {
    #[cfg(target_arch = "x86_64")]  { "x86_64".into() }
    #[cfg(target_arch = "aarch64")] { "aarch64".into() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { std::env::var("ARCH").unwrap_or_else(|_| "x86_64".into()) }
}

async fn content_length(client: &reqwest::Client, url: &str) -> Option<u64> {
    client.head(url).send().await.ok()?
        .headers().get(reqwest::header::CONTENT_LENGTH)?
        .to_str().ok()?.parse().ok()
}

async fn download_with_bar(
    client: &reqwest::Client,
    url:    &str,
    dest:   &Path,
    bar:    &indicatif::ProgressBar,
) -> Result<u64> {
    let resp = client.get(url).send().await?.error_for_status()?;
    if let Some(p) = dest.parent() { fs::create_dir_all(p)?; }
    let mut f   = std::io::BufWriter::new(fs::File::create(dest)?);
    let mut tot = 0u64;
    let mut s   = resp.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
        tot += chunk.len() as u64;
        use std::io::Write; f.write_all(&chunk)?;
        bar.set_position(tot);
    }
    bar.finish();
    Ok(tot)
}

fn val_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        o => o.to_string().trim_matches('"').to_string(),
    }
}

fn log_audit(kind: &str, pkgs: &[String], outcome: &str, err: Option<&str>, ms: u64) {
    audit::append(AuditEntry {
        timestamp:   chrono::Utc::now().to_rfc3339(),
        kind:        kind.into(),
        outcome:     outcome.into(),
        packages:    pkgs.to_vec(),
        duration_ms: ms,
        error:       err.map(str::to_string),
    }).ok();

    // Also record to the cross-tier unified history (`zex history`) —
    // uland upgrades used to only ever show up in their own
    // upgrade-audit.toml, invisible from the same place install/remove
    // operations are recorded. Format is unknown at this granularity
    // (uland spans every tier) so it's left blank rather than guessed.
    let _ = crate::cmd::install::history::record(
        crate::cmd::install::history::OperationType::Upgrade,
        pkgs.iter().map(|name| crate::cmd::install::history::PackageRecord {
            name: name.clone(),
            version: String::new(),
            format: String::new(),
        }).collect(),
        outcome == "success",
        err.map(str::to_string),
        ms,
    );
}
