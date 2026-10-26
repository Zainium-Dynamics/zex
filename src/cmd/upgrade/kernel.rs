//! kernel.rs — `elevate zex kernel`: the boot kernel and its quantra-ramfs.
//!
//! An installed system boots what Limine reads from the ESP (see esp.rs), so a kernel
//! never goes into the base: this writes it to the ESP. The kernel archive
//! (`kernel/x86_64/kernel.toml`, packages in `kernel/x86_64/packages/`) has the kernel
//! and the ramfs as separate packages. The kernel's modules are a syshub package (named
//! by the kernel entry's `modules` field) and go into the base like a syshub upgrade,
//! after asking.
//!
//! On the ESP, `linux-evl` + `quantra-ramfs.img` boot by default. An upgrade first
//! moves that pair to `linux-panic` + `quantra-ramfs-panic.img`, which the "Fallback
//! Kernel" menu entries boot, so the last working pair stays one menu choice away.
//! `kernel.toml` beside them records both pairs.
//!
//!   elevate zex kernel              what boots now, and what the archive has
//!   elevate zex kernel --u          upgrade the kernel and/or ramfs
//!   elevate zex kernel --rollback   boot the fallback pair by default again

use anyhow::{Context, Result, bail};
use indicatif::MultiProgress;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    esp::{self, Esp},
    syscore, ui,
    vercmp::is_upgrade,
};

const ZEX_SERVICES: &str = "/overlayer/syshub/engine/services/zex_services.toml";
const LOCAL_SYSHUB: &str = "/overlayer/syshub/engine/services/syshub.toml";
const STAGED_SYSHUB: &str = "engine/services/syshub.toml";
const DL_TMP: &str = "/overlayer/zexlib/tmp/kernel-dl";
const DEFAULT_INDEX: &str = "https://archive.zainiumdynamics.tech/kernel/x86_64/kernel.toml";
const DEFAULT_BASE: &str = "https://archive.zainiumdynamics.tech/kernel/x86_64/packages";
const LEDGER: &str = "kernel.toml";

const KERNEL: &str = "linux-evl";
const RAMFS: &str = "quantra-ramfs";

/// Each package's file on the ESP: (package, file that boots, fallback file).
/// The package's .zex carries the file at `payload/kernel/<file that boots>`.
const SLOTS: [(&str, &str, &str); 2] = [
    (KERNEL, "linux-evl", "linux-panic"),
    (RAMFS, "quantra-ramfs.img", "quantra-ramfs-panic.img"),
];

#[derive(Deserialize)]
struct Index {
    #[serde(default)]
    packages: HashMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct Services {
    #[serde(default)]
    mirrors: Vec<Mirror>,
    /// Optional `[kernel]` table: another kernel archive than the default.
    kernel: Option<Source>,
}

#[derive(Deserialize)]
struct Mirror {
    id: String,
    index_url: String,
    base_url: String,
    format: String,
    priority: u32,
}

#[derive(Deserialize)]
struct Source {
    index_url: String,
    base_url: String,
}

/// What is on the ESP: package -> version, for the pair that boots and the fallback.
#[derive(Default, Deserialize, Serialize)]
struct Ledger {
    #[serde(default)]
    current: BTreeMap<String, String>,
    #[serde(default)]
    fallback: BTreeMap<String, String>,
}

struct Pick {
    name: String,
    old: String,
    new: String,
    file: String,
    url: String,
}

struct Modules {
    name: String,
    version: String,
    file: String,
    url: String,
    entry: toml::Value,
}

// ── Commands ──────────────────────────────────────────────────────────────────

pub async fn status() -> Result<()> {
    crate::syshub_pending::ensure_available()?;
    let esp = Esp::mount()?;
    let ledger = read_ledger(&esp);
    let mut latest = BTreeMap::new();
    if syscore::online().await {
        let services = load_services()?;
        let (index_url, _) = kernel_source(&services);
        let client = crate::http_client::build("zex-kernel")?;
        if let Ok(index) = fetch_index(&client, &index_url).await {
            for (name, _, _) in SLOTS {
                if let Some(e) = index.packages.get(name) {
                    latest.insert(name.to_string(), syscore::val_str(e));
                }
            }
        }
    }
    ui::print_kernel_status(&ledger.current, &ledger.fallback, &latest);
    Ok(())
}

pub async fn upgrade() -> Result<()> {
    ui::print_kernel_header();
    crate::syshub_pending::ensure_available()?;
    if !syscore::online().await {
        ui::print_no_internet();
        std::process::exit(1);
    }
    let services = load_services()?;
    let (index_url, base_url) = kernel_source(&services);
    let client = crate::http_client::build("zex-kernel")?;
    let index = fetch_index(&client, &index_url).await?;

    let esp = Esp::mount()?;
    let mut ledger = read_ledger(&esp);

    let mut picks = Vec::new();
    for (name, _, _) in SLOTS {
        let Some(entry) = index.packages.get(name) else {
            continue;
        };
        let new = syscore::val_str(entry);
        let old = ledger
            .current
            .get(name)
            .cloned()
            .unwrap_or_else(|| "0".into());
        if is_upgrade(&old, &new) {
            let file = file_of(name, entry);
            picks.push(Pick {
                name: name.to_string(),
                url: format!("{}/{}", base_url.trim_end_matches('/'), file),
                file,
                old,
                new,
            });
        }
    }
    if picks.is_empty() {
        ui::print_kernel_uptodate(ledger.current.get(KERNEL).map(String::as_str));
        return Ok(());
    }
    let rows: Vec<(&str, &str, &str)> = picks
        .iter()
        .map(|p| (p.name.as_str(), p.old.as_str(), p.new.as_str()))
        .collect();
    ui::print_kernel_list(&rows);
    if !ui::ask_yes("Proceed with the kernel upgrade?") {
        ui::print_cancelled();
        return Ok(());
    }

    // the new kernel's drivers live in the base: ask before staging them
    let mut modules = None;
    if let Some(kernel) = picks.iter().find(|p| p.name == KERNEL)
        && let Some(name) = index.packages.get(KERNEL).and_then(|e| field(e, "modules"))
    {
        if ui::ask_yes(&format!(
            "Update the kernel modules ({name} {}) in the System Hub with this kernel?",
            kernel.new
        )) {
            modules = Some(find_modules(&client, &services, &name, &kernel.new).await?);
        } else {
            ui::print_kernel_without_modules(&kernel.new);
        }
    }

    // ── download and verify everything before anything changes ────────────────
    let dl = Path::new(DL_TMP);
    if dl.exists() {
        fs::remove_dir_all(dl)?;
    }
    fs::create_dir_all(dl)?;
    let mut jobs: Vec<(String, String, String)> = picks
        .iter()
        .map(|p| (p.name.clone(), p.url.clone(), p.file.clone()))
        .collect();
    if let Some(m) = &modules {
        jobs.push((m.name.clone(), m.url.clone(), m.file.clone()));
    }
    let mut sizes = Vec::new();
    for (_, url, _) in &jobs {
        sizes.push(syscore::content_length(&client, url).await.unwrap_or(0));
    }
    let mp = MultiProgress::new();
    let overall = ui::make_overall_bar(&mp, sizes.iter().sum());
    let mut zexes: HashMap<String, PathBuf> = HashMap::new();
    for ((name, url, file), size) in jobs.iter().zip(sizes) {
        let bar = ui::make_pkg_bar(&mp, size, name);
        let dest = dl.join(file);
        syscore::download_with_bar(&client, url, &dest, &bar, &overall)
            .await
            .with_context(|| format!("downloading {name}"))?;
        crate::trust::verify_zex_archive(&dest, crate::trust::SignatureVerificationMode::Strict)
            .with_context(|| format!("verifying {name}"))?;
        zexes.insert(name.clone(), dest);
    }
    overall.finish_and_clear();

    let mut boot_files: HashMap<String, PathBuf> = HashMap::new();
    for p in &picks {
        let (_, booted, _) = slot(&p.name);
        let out = dl.join(booted);
        extract_boot_file(&zexes[&p.name], booted, &out)?;
        boot_files.insert(p.name.clone(), out);
    }

    // ── modules into the base (applied at the next boot, before the GPU loads) ─
    let mut modules_txn = None;
    if let Some(m) = &modules {
        ui::start_phase("Staging the kernel modules");
        modules_txn = Some(stage_modules(m, &zexes[&m.name])?);
    }

    // ── the ESP: running pair becomes the fallback, then the new files go in ──
    ui::start_phase("Installing on the EFI partition");
    let dir = esp.kernel_dir();
    for (_, booted, fallback) in SLOTS {
        let cur = dir.join(booted);
        if cur.is_file() {
            esp::copy_synced(&cur, &dir.join(fallback))?;
        }
    }
    ledger.fallback = ledger.current.clone();
    for p in &picks {
        let (_, booted, _) = slot(&p.name);
        esp::copy_synced(&boot_files[&p.name], &dir.join(booted))?;
        ledger.current.insert(p.name.clone(), p.new.clone());
    }
    esp.fallback_entries_use(SLOTS[0].2, SLOTS[1].2)?;
    write_ledger(&esp, &ledger)?;
    drop(esp);
    fs::remove_dir_all(dl).ok();

    ui::print_kernel_done(
        ledger.current.get(KERNEL).map(String::as_str),
        modules_txn.as_deref(),
    );
    Ok(())
}

pub fn rollback() -> Result<()> {
    crate::syshub_pending::ensure_available()?;
    let esp = Esp::mount()?;
    let dir = esp.kernel_dir();
    for (_, _, fallback) in SLOTS {
        if !dir.join(fallback).is_file() {
            bail!("no fallback kernel on the EFI partition to go back to ({fallback} is missing)");
        }
    }
    for (_, booted, fallback) in SLOTS {
        swap(&dir.join(booted), &dir.join(fallback))?;
    }
    let mut ledger = read_ledger(&esp);
    std::mem::swap(&mut ledger.current, &mut ledger.fallback);
    esp.fallback_entries_use(SLOTS[0].2, SLOTS[1].2)?;
    write_ledger(&esp, &ledger)?;
    drop(esp);
    ui::print_kernel_rolled_back(ledger.current.get(KERNEL).map(String::as_str));
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn slot(name: &str) -> (&'static str, &'static str, &'static str) {
    SLOTS
        .into_iter()
        .find(|(n, _, _)| *n == name)
        .expect("picks only come from SLOTS")
}

fn field(v: &toml::Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_string)
}

fn file_of(name: &str, entry: &toml::Value) -> String {
    field(entry, "file").unwrap_or_else(|| format!("{name}-{}.zex", syscore::val_str(entry)))
}

fn load_services() -> Result<Services> {
    let raw = fs::read_to_string(ZEX_SERVICES).context("reading zex_services.toml")?;
    toml::from_str(&raw).context("parsing zex_services.toml")
}

fn kernel_source(services: &Services) -> (String, String) {
    match &services.kernel {
        Some(s) => (s.index_url.clone(), s.base_url.clone()),
        None => (DEFAULT_INDEX.into(), DEFAULT_BASE.into()),
    }
}

async fn fetch_index(client: &reqwest::Client, url: &str) -> Result<Index> {
    let raw = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()?
        .text()
        .await?;
    toml::from_str(&raw).with_context(|| format!("parsing {url}"))
}

/// The syshub package with the kernel's modules, which must be for exactly that kernel.
async fn find_modules(
    client: &reqwest::Client,
    services: &Services,
    name: &str,
    kernel_version: &str,
) -> Result<Modules> {
    let mirror = services
        .mirrors
        .iter()
        .filter(|m| m.id.contains("syshub") && m.format == "zex")
        .min_by_key(|m| m.priority)
        .context("No syshub mirror in zex_services.toml")?;
    let index = fetch_index(client, &mirror.index_url).await?;
    let Some(entry) = index.packages.get(name) else {
        bail!("{name} is not in the System Hub archive yet; nothing was changed");
    };
    let version = syscore::val_str(entry);
    if version != kernel_version {
        bail!(
            "the System Hub has {name} {version}, not {kernel_version} for this kernel; nothing was changed"
        );
    }
    let file = file_of(name, entry);
    Ok(Modules {
        name: name.to_string(),
        url: format!("{}/{}", mirror.base_url.trim_end_matches('/'), file),
        file,
        version,
        entry: entry.clone(),
    })
}

/// Pulls `payload/kernel/<booted>` out of a kernel-tier .zex.
fn extract_boot_file(zex: &Path, booted: &str, out: &Path) -> Result<()> {
    let want = format!("payload/kernel/{booted}");
    let dec = crate::zex_codec::open_decoder(zex)?;
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        if path == want && entry.header().entry_type().is_file() {
            let mut f =
                fs::File::create(out).with_context(|| format!("write {}", out.display()))?;
            std::io::copy(&mut entry, &mut f)?;
            f.sync_all()?;
            return Ok(());
        }
    }
    bail!("{} has no {want}", zex.display())
}

/// Adds the modules to the staged base upgrade (joining one already waiting) and
/// records their version in the staged syshub.toml.
fn stage_modules(m: &Modules, zex: &Path) -> Result<String> {
    let fresh = crate::syshub_pending::waiting().is_none();
    let root = crate::syshub_pending::begin_or_extend()?;
    let staged = (|| -> Result<String> {
        syscore::extract_zex_into(zex, &root).with_context(|| format!("extracting {}", m.name))?;
        let ledger = root.join(STAGED_SYSHUB);
        let text = match fs::read_to_string(&ledger) {
            Ok(t) => t,
            Err(_) => fs::read_to_string(LOCAL_SYSHUB).context("reading syshub.toml")?,
        };
        let mut doc: toml::Table = toml::from_str(&text).context("parsing syshub.toml")?;
        let packages = doc
            .entry("packages")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let Some(t) = packages.as_table_mut() {
            t.insert(m.name.clone(), m.entry.clone());
        }
        if let Some(parent) = ledger.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&ledger, toml::to_string(&doc)?).context("staging syshub.toml")?;
        crate::syshub_pending::commit(&format!("{}-{}", m.name, m.version))
    })();
    if staged.is_err() {
        if fresh {
            crate::syshub_pending::clear().ok();
        } else {
            crate::syshub_pending::relock();
        }
    }
    staged
}

fn read_ledger(esp: &Esp) -> Ledger {
    fs::read_to_string(esp.kernel_dir().join(LEDGER))
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

fn write_ledger(esp: &Esp, ledger: &Ledger) -> Result<()> {
    esp::write_synced(
        &esp.kernel_dir().join(LEDGER),
        toml::to_string(ledger)?.as_bytes(),
    )
}

fn swap(a: &Path, b: &Path) -> Result<()> {
    let tmp = a.with_file_name(format!(
        "{}.swap",
        a.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::rename(a, &tmp).with_context(|| format!("rename {}", a.display()))?;
    fs::rename(b, a).with_context(|| format!("rename {}", b.display()))?;
    fs::rename(&tmp, b).with_context(|| format!("rename {}", tmp.display()))
}
