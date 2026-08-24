//! syscore.rs — Syshub immutable-base upgrade engine.
//!
//! Command:  elevate zex syshub --u
//!
//! Correct staging model (one syshub.new for ALL packages):
//!
//!   /overlayer/syshub.new/          ← single staging root
//!       bin/
//!       lib64/
//!       share/
//!       ...
//!
//! Flow:
//!   1. Fetch remote syshub.toml → diff against local
//!   2. Prompt user
//!   3. Download ALL packages (2 concurrent) into /overlayer/zexlib/tmp/dl/
//!   4. Verify all (signature + libc-boundary)
//!   5. Extract ALL into ONE /overlayer/syshub.new/  ← merged tree
//!   6. Remount syshub rw
//!   7. Detect zex self-upgrade → swap binary via swap::maybe_swap_zex()
//!      (must come after the rw remount, not before — confirmed live:
//!      /overlayer/syshub is genuinely read-only until then, so writing
//!      the swapped-in binary's new directory entry fails otherwise)
//!   8. Walk syshub.new → atomic_place every file onto /overlayer/syshub/
//!   9. Update local manifest
//!  10. Remount syshub ro
//!  11. Cleanup + audit

use anyhow::{Context, Result, bail};
use futures_util::{stream, StreamExt};
use indicatif::MultiProgress;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};
use walkdir::WalkDir;

use super::{
    audit::{self, AuditEntry},
    swap,
    transaction::Transaction,
    ui,
    vercmp::is_upgrade,
};

// ── Paths ──────────────────────────────────────────────────────────────────────
const SYSHUB_PATH:    &str = "/overlayer/syshub";
/// Single staging root — ALL packages are extracted here before any overwrite.
const STAGING_NEW:    &str = "/overlayer/syshub.new";
/// Per-download temp dir — .zex files land here before extraction.
const DL_TMP:         &str = "/overlayer/zexlib/tmp/syshub-dl";
const LOCAL_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";
const ZEX_SERVICES:   &str = "/overlayer/syshub/engine/services/zex_services.toml";
const ROLLBACK_STAGE: &str = "/overlayer/zexlib/tmp/syshub-rollback";

// ── TOML schemas ───────────────────────────────────────────────────────────────
#[derive(Debug, Deserialize, Clone)]
struct SyshubManifest {
    core_info: CoreInfo,
    packages:  HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct CoreInfo {
    build_version: String,
    #[allow(dead_code)] os_name: String,
}

#[derive(Debug, Deserialize)]
struct ZexServices {
    mirrors: Vec<Mirror>,
}

#[derive(Debug, Deserialize)]
struct Mirror {
    id:        String,
    index_url: String,
    base_url:  String,
    format:    String,
    priority:  u32,
}

// ── Package to upgrade ─────────────────────────────────────────────────────────
#[derive(Clone)]
struct UpgradePkg {
    name:     String,
    old_ver:  String,
    new_ver:  String,
    filename: String,
    url:      String,
}

// ── Public entry ───────────────────────────────────────────────────────────────
pub async fn execute() -> Result<()> {
    let started = Instant::now();

    // ── 0. Crash recovery ─────────────────────────────────────────────────────
    // Finish any transaction a previous `zex syshub` run left interrupted
    // (killed, power loss, OOM) before it could commit or roll back
    // itself — otherwise a partially-upgraded, possibly unbootable syshub
    // could sit there indefinitely with no automatic way back to a
    // consistent state.
    let recovered = Transaction::recover_stale(Path::new(ROLLBACK_STAGE));
    if !recovered.is_empty() {
        ui::print_crash_recovery(&recovered);
    }

    ui::print_syshub_header();

    // ── 1. Internet check ─────────────────────────────────────────────────────
    if !online().await {
        ui::print_no_internet();
        std::process::exit(1);
    }

    // ── 2. Read zex_services.toml ─────────────────────────────────────────────
    let svc_raw = fs::read_to_string(ZEX_SERVICES)
        .context("reading zex_services.toml")?;
    let services: ZexServices = toml::from_str(&svc_raw)
        .context("parsing zex_services.toml")?;
    let mirror = services.mirrors.iter()
        .filter(|m| m.id.contains("syshub") && m.format == "zex")
        .min_by_key(|m| m.priority)
        .context("No Tier-1 syshub mirror in zex_services.toml")?;

    // ── 3. Load manifests ─────────────────────────────────────────────────────
    let local_raw = fs::read_to_string(LOCAL_MANIFEST)
        .context("Local syshub.toml missing — is syshub mounted?")?;
    let local: SyshubManifest = toml::from_str(&local_raw)
        .context("Malformed local syshub.toml")?;
    let current_ver = local.core_info.build_version.clone();

    ui::print_checking(&current_ver);

    // Pinned client, not a bare `reqwest::get()` — the manifest fetch is
    // exactly the request that most needs TLS pinning (it's what tells
    // this whole run what to trust as "the real syshub index"), and an
    // unpinned call here was silently exempt from the same protection
    // every other zex HTTP request goes through.
    // Built once and reused for every request this run makes (manifest
    // fetch, all HEAD content-length probes, all package downloads) —
    // building a fresh client per call was measurably wasteful: each one
    // reloads the webpki root store and re-reads the TLS pins config file
    // from disk, and a real 5-package upgrade was doing this 10+ times
    // for what should be one client's worth of connections.
    let client = crate::http_client::build("zex-syshub")?;
    let remote_raw = client.get(&mirror.index_url).send().await
        .context("fetching remote syshub.toml")?
        .error_for_status()?
        .text().await?;
    let remote: SyshubManifest = toml::from_str(&remote_raw)
        .context("Malformed remote syshub.toml")?;

    // ── 4. Diff ───────────────────────────────────────────────────────────────
    let upgrades = diff_packages(&local, &remote, &mirror.base_url);

    if upgrades.is_empty() {
        ui::print_syshub_uptodate(&current_ver, local.packages.len());
        return Ok(());
    }

    ui::print_syshub_found(upgrades.len());

    let pkg_list: Vec<(&str, &str, &str)> = upgrades.iter()
        .map(|u| (u.name.as_str(), u.old_ver.as_str(), u.new_ver.as_str()))
        .collect();
    ui::print_syshub_package_list(&pkg_list);

    // Real sizes, not a flat per-component estimate — confirmed live that
    // "48MB × component count" was wildly off (240MB estimated vs 114.65MB
    // actually downloaded for 5 real packages), and this same total feeds
    // the overall progress bar below, so it needs to be accurate for that
    // bar's percentage to mean anything. Fetched concurrently — these are
    // header-only HEAD requests, but sequential round-trips still add up
    // once there are more than a couple of components.
    let head_checks: Vec<u64> = futures_util::future::join_all(
        upgrades.iter().map(|u| content_length(&client, &u.url))
    ).await.into_iter().map(|c| c.unwrap_or(0)).collect();
    let real_total_bytes: u64 = head_checks.iter().sum();
    ui::print_transaction_summary(upgrades.len(), real_total_bytes as f64 / 1_048_576.0);

    if !ui::print_proceed_prompt() {
        println!("\n {DIM}Upgrade cancelled.{RST}", DIM = ui::DIM, RST = ui::RST);
        return Ok(());
    }

    ui::print_syshub_starting();

    // ── 5. Prepare directories ────────────────────────────────────────────────
    // ONE syshub.new for everything
    let staging = Path::new(STAGING_NEW);
    if staging.exists() { fs::remove_dir_all(staging)?; }
    fs::create_dir_all(staging)?;

    // Per-download temp dir for .zex files
    let dl_tmp = Path::new(DL_TMP);
    if dl_tmp.exists() { fs::remove_dir_all(dl_tmp)?; }
    fs::create_dir_all(dl_tmp)?;

    // ── 6. Download ALL packages (2 concurrent), extract into syshub.new ─────
    let mp = MultiProgress::new();
    let overall = ui::make_overall_bar(&mp, real_total_bytes);
    overall.set_position(0);

    let mut downloaded: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    // Paired with head_checks so the per-package bar's length reuses the
    // HEAD probe already done above instead of firing a second, redundant
    // request for the exact same URL.
    let sized_upgrades: Vec<(&UpgradePkg, u64)> = upgrades.iter().zip(head_checks.iter().copied()).collect();

    // Sliding-window concurrency (`buffer_unordered`), not fixed pairs.
    // The old `for chunk in sized_upgrades.chunks(2)` held BOTH slots of a
    // pair open until BOTH finished — confirmed live: a 914KB package
    // finished and just sat at its bar's 100% for minutes while its
    // much-larger chunk-mate kept streaming, wasting the freed slot
    // instead of immediately starting package #3. `buffer_unordered(2)`
    // keeps exactly 2 downloads in flight at all times — the instant one
    // finishes, the next queued package starts, no matter which slot or
    // pairing it happened to land in.
    let mut in_flight = stream::iter(sized_upgrades.into_iter().map(|(pkg, content_len)| {
        let label = format!("{:<20} {} → {}", pkg.name, pkg.old_ver, pkg.new_ver);
        let bar = ui::make_pkg_bar(&mp, content_len, &label);

        let url       = pkg.url.clone();
        let dest      = dl_tmp.join(&pkg.filename);
        let name      = pkg.name.clone();
        let overall_h = overall.clone();
        let client_h  = client.clone();
        async move {
            let result = download_with_bar(&client_h, &url, &dest, &bar, &overall_h).await;
            (name, dest, result)
        }
    }))
    .buffer_unordered(2);

    while let Some((pkg_name, zex_path, result)) = in_flight.next().await {
        let bytes = match result {
            Ok(b) => b,
            Err(e) => {
                // Clean up staging + dl_tmp
                fs::remove_dir_all(staging).ok();
                fs::remove_dir_all(dl_tmp).ok();
                ui::print_download_interrupted(&pkg_name);
                log_audit("syshub", &downloaded, "rolled_back",
                          Some(&e.to_string()), started.elapsed().as_millis() as u64);
                std::process::exit(1);
            }
        };
        total_bytes += bytes;

        // Ed25519 signature check — against the pubkey embedded in the
        // package's own manifest.toml (syshub core is always Strict).
        crate::trust::verify_zex_archive(&zex_path, crate::trust::SignatureVerificationMode::Strict)?;

        // Extract payload/* into /overlayer/syshub.new/  (merged tree)
        extract_zex_into(&zex_path, staging)
            .with_context(|| format!("extracting {pkg_name}"))?;

        downloaded.push(pkg_name);
    }

    overall.finish_and_clear();
    println!();

    // ── 7. Verify the merged syshub.new tree ──────────────────────────────────
    ui::print_phase("Verifying integrity");
    verify_libc_boundaries(staging)?;

    // ── 8. Remount syshub rw ───────────────────────────────────────────────────
    // Must happen BEFORE the swap step below, not after. `/overlayer/syshub`
    // is genuinely mounted read-only until this call — confirmed live: the
    // swap's own rename (and its EXDEV copy-fallback, which needs to CREATE
    // a new file in `/overlayer/syshub/bin/`) failed with "Permission
    // denied" every time while this remount was still ordered afterward.
    // Old reasoning here claimed rename "works on ro too because we're
    // swapping inside syshub.new → syshub, not within syshub" — that
    // conflates the RENAME SOURCE (staging, always writable) with the
    // RENAME DESTINATION (`/overlayer/syshub/bin/zex`), whose *containing
    // directory* is exactly what the ro mount protects; the source being
    // writable was never what mattered.
    remount(SYSHUB_PATH, true)?;

    // ── 9. Zex self-upgrade swap ───────────────────────────────────────────────
    // If syshub.toml shows a new zex version, swap the binary now that
    // syshub is actually writable.
    let old_zex_ver = local.packages.get("zex")
        .map(|v| val_str(v)).unwrap_or_else(|| "0".into());
    let new_zex_ver = remote.packages.get("zex")
        .map(|v| val_str(v)).unwrap_or_else(|| old_zex_ver.clone());

    let zex_swapped = match swap::maybe_swap_zex(staging, &old_zex_ver, &new_zex_ver) {
        Ok(swapped) => swapped,
        Err(e) => {
            // Swap failed after we'd already remounted rw — leaving the
            // base mounted rw on a hard error would silently drop the
            // "immutable" guarantee for however long until the next
            // upgrade attempt happens to fix it. Put it back before
            // propagating, matching how the later file-commit rollback
            // branch already remounts ro on its own failure path.
            remount(SYSHUB_PATH, false).ok();
            fs::remove_dir_all(staging).ok();
            fs::remove_dir_all(dl_tmp).ok();
            return Err(e).context("self-upgrade swap of zex binary");
        }
    };

    if zex_swapped {
        println!("  {G}✓{RST}  zex self-upgraded: {B}{old_zex_ver}{RST} → {G}{new_zex_ver}{RST}",
            G = ui::G, RST = ui::RST, B = ui::B);
    }

    // ── 10. Atomic overwrite: walk syshub.new → place onto syshub ─────────────
    ui::print_phase("Applying to immutable base");

    let mut tx = Transaction::new(Path::new(ROLLBACK_STAGE))
        .context("creating rollback transaction")?;
    let live = Path::new(SYSHUB_PATH);
    let mut commit_err: Option<anyhow::Error> = None;

    'apply: for entry in WalkDir::new(staging).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let rel       = entry.path().strip_prefix(staging).unwrap();
        let live_path = live.join(rel);

        if let Err(e) = tx.checkpoint(&live_path) {
            commit_err = Some(e);
            break 'apply;
        }
        if let Err(e) = swap::atomic_place(entry.path(), &live_path) {
            commit_err = Some(e);
            break 'apply;
        }
    }

    if let Some(err) = commit_err {
        // Rollback everything
        remount(SYSHUB_PATH, false).ok();
        tx.rollback().ok();
        swap::restore_bak().ok();   // put old zex back
        fs::remove_dir_all(staging).ok();
        fs::remove_dir_all(dl_tmp).ok();
        log_audit("syshub", &downloaded, "rolled_back",
                  Some(&err.to_string()), started.elapsed().as_millis() as u64);
        bail!("Syshub overwrite failed — fully rolled back: {err}");
    }

    // ── 11. Update manifest ───────────────────────────────────────────────────
    fs::write(LOCAL_MANIFEST, &remote_raw)
        .context("writing updated syshub.toml")?;
    ui::print_phase("Regenerating system manifest");

    // ── 12. Relock syshub ─────────────────────────────────────────────────────
    if let Err(e) = remount(SYSHUB_PATH, false) {
        eprintln!("  {Y}WARN: could not remount ro: {e}{RST}",
            Y = ui::Y, RST = ui::RST);
        eprintln!("  Run:  mount -o remount,ro {SYSHUB_PATH}");
    }

    // ── 13. Commit + cleanup ──────────────────────────────────────────────────
    tx.commit();
    swap::cleanup_bak();
    fs::remove_dir_all(staging).ok();
    fs::remove_dir_all(dl_tmp).ok();

    let elapsed  = started.elapsed().as_secs();
    let total_mb = total_bytes as f64 / 1_048_576.0;

    ui::print_syshub_done(downloaded.len(), total_mb, elapsed,
                          &remote.core_info.build_version);
    log_audit("syshub", &downloaded, "success",
              None, started.elapsed().as_millis() as u64);
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────────


fn is_pkg_pinned(name: &str) -> bool {
    const PINNED: &str = "/overlayer/zexlib/registry/pinned.toml";
    let Ok(raw) = std::fs::read_to_string(PINNED) else { return false };
    #[derive(serde::Deserialize, Default)]
    struct PF { #[serde(default)] pinned: Vec<Pin> }
    #[derive(serde::Deserialize)]
    struct Pin { name: String }
    toml::from_str::<PF>(&raw)
        .map(|f| f.pinned.iter().any(|p| p.name.eq_ignore_ascii_case(name)))
        .unwrap_or(false)
}

fn diff_packages(
    local:    &SyshubManifest,
    remote:   &SyshubManifest,
    base_url: &str,
) -> Vec<UpgradePkg> {
    let mut out = Vec::new();
    for (name, rv) in &remote.packages {
        if name == "provides" { continue; }
        let rv_s = val_str(rv);
        let lv_s = local.packages.get(name).map(val_str).unwrap_or_else(|| "0".into());
        if is_upgrade(&lv_s, &rv_s) {
            if is_pkg_pinned(name) {
                log::info!("Syshub package '{}' is pinned — skipping", name);
                continue;
            }
            let filename = format!("{}-{}.zex", name, rv_s);
            let url      = format!("{}/{}", base_url.trim_end_matches('/'), filename);
            out.push(UpgradePkg { name: name.clone(), old_ver: lv_s, new_ver: rv_s, filename, url });
        }
    }
    out
}

fn val_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        // Real syshub.toml entries are tables ([packages.zlib] with a
        // `version` field, size_bytes, depends, etc.), not plain strings —
        // stringifying the whole table here previously produced a garbled
        // "new version" (the debug-printed table itself) that broke both
        // the upgrade-vs-current version comparison (a real upgrade like
        // binutils 2.42->2.47 silently failed to register, since comparing
        // "2.42" against a whole table-blob string never looks like an
        // upgrade) and crashed the download progress bar (stray `{`/`}`
        // characters from the table blob broke indicatif's template
        // parser). Matches `cmd::update::diff::val_str`'s already-correct
        // handling of this same shape.
        toml::Value::Table(t) => t.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0").to_string(),
        other => other.to_string().trim_matches('"').to_string(),
    }
}

async fn online() -> bool {
    let Ok(client) = crate::http_client::build("zex-syshub/ping") else { return false };

    // There is no more zex-server / API backend behind archive.zainiumdynamics.tech
    // to ping (it was decommissioned — the domain now only serves static
    // package files via Cloudflare/R2) — a `/ping` attempt against it would
    // permanently 404, wasting a full network round-trip on every syshub
    // upgrade before falling through here anyway. Go straight to a generic
    // reachability probe.
    client.head("https://mirrors.edge.kernel.org/").send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn content_length(client: &reqwest::Client, url: &str) -> Option<u64> {
    let r = client.head(url).send().await.ok()?;
    r.headers().get(reqwest::header::CONTENT_LENGTH)?
        .to_str().ok()?.parse().ok()
}

async fn download_with_bar(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    bar: &indicatif::ProgressBar,
    overall: &indicatif::ProgressBar,
) -> Result<u64> {
    let resp = client.get(url).send().await?.error_for_status()?;
    if let Some(p) = dest.parent() { fs::create_dir_all(p)?; }
    let mut f   = std::io::BufWriter::new(fs::File::create(dest)?);
    let mut tot = 0u64;
    let mut s   = resp.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
        tot += chunk.len() as u64;
        use std::io::Write;
        f.write_all(&chunk)?;
        bar.set_position(tot);
        overall.inc(chunk.len() as u64);
    }
    bar.finish();
    Ok(tot)
}

/// Extract `payload/*` from a .zex (zexc / ZEX1) into `dest` root.
/// Multiple packages extract into the SAME dest → their trees merge naturally.
fn extract_zex_into(zex_path: &Path, dest: &Path) -> Result<()> {
    #[cfg(unix)] use std::os::unix::fs::symlink;

    let dec = crate::zex_codec::open_decoder(zex_path)?;
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

        if typ.is_dir() {
            fs::create_dir_all(&dst)?;
            continue;
        }
        if let Some(p) = dst.parent() { fs::create_dir_all(p)?; }

        if typ.is_file() {
            let mut out = fs::File::create(&dst)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))?;
                }
            }
        } else if typ.is_symlink() {
            if let Some(target) = entry.link_name()? {
                let _ = fs::remove_file(&dst);
                #[cfg(unix)] symlink(&target, &dst)?;
            }
        }
    }
    Ok(())
}

/// Reject any .zex payload that contains glibc-versioned shared objects.
fn verify_libc_boundaries(staging: &Path) -> Result<()> {
    const BAD: &[&str] = &[
        "libc.so.6", "libpthread.so.0", "libm.so.6",
        "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1",
    ];
    for e in WalkDir::new(staging).into_iter().filter_map(|e| e.ok()) {
        let n = e.file_name().to_string_lossy();
        for bad in BAD {
            if n.as_ref() == *bad {
                bail!(
                    "glibc artifact detected: {}\n\
                     Zainium packages must link against musl or relibc only.",
                    e.path().display()
                );
            }
        }
    }
    Ok(())
}

fn remount(path: &str, rw: bool) -> Result<()> {
    let flag = if rw { "remount,rw" } else { "remount,ro" };
    let st = std::process::Command::new("mount")
        .args(["-o", flag, path]).status()?;
    if !st.success() { bail!("mount -o {} {} failed", flag, path); }
    Ok(())
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
    // syshub upgrades used to only ever show up in their own
    // upgrade-audit.toml, invisible from the same place install/remove
    // operations are recorded.
    let _ = crate::cmd::install::history::record(
        crate::cmd::install::history::OperationType::Upgrade,
        pkgs.iter().map(|name| crate::cmd::install::history::PackageRecord {
            name: name.clone(),
            version: String::new(),
            format: "zex".to_string(),
        }).collect(),
        outcome == "success",
        err.map(str::to_string),
        ms,
    );
}
