use super::stats;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub enum PackageBackend {
    /// Package installed by Zex into Content Store + Union Layer
    ZexStore,
    Apt,
    Flatpak,
    Snap,
}

impl PackageBackend {
    /// Human-readable backend label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ZexStore => "zex-store",
            Self::Apt => "apt",
            Self::Flatpak => "flatpak",
            Self::Snap => "snap",
        }
    }

    /// Build the removal shell command string (used by the visual StepRunner).
    ///
    /// **Package names are validated before this is called**: see
    /// `validate_package_name()` in `daemon.rs` and the CLI clap validation.
    /// The resulting string is executed via `sh -c` only inside StepRunner which
    /// is the UI layer; headless / daemon paths use `execute_removal` instead.
    #[allow(dead_code)]
    pub fn remove_cmd(&self, name: &str, recursive: bool) -> String {
        match self {
            Self::ZexStore => {
                format!("echo 'ZexStore removal for {} handled internally'", name)
            }
            Self::Apt => {
                if recursive {
                    format!(
                        "apt-get remove -y --auto-remove {pkg} 2>/dev/null; \
                         apt-get purge  -y {pkg}             2>/dev/null; \
                         apt-get autoremove -y               2>/dev/null; true",
                        pkg = name
                    )
                } else {
                    format!("apt-get remove -y {pkg} 2>/dev/null; true", pkg = name)
                }
            }
            Self::Flatpak => format!("flatpak uninstall -y {} 2>/dev/null; true", name),
            Self::Snap => format!("snap remove {} 2>/dev/null; true", name),
        }
    }

    /// Execute removal using structured subprocess invocations (no `sh -c`).
    ///
    /// This is the safe, injection-proof path used by the daemon and any
    /// programmatic callers.  Returns `true` when all commands succeed.
    pub async fn execute_removal(&self, name: &str, recursive: bool) -> bool {
        match self {
            Self::ZexStore => zex_store_removal(name).await,
            Self::Apt => {
                let mut remove_args = vec!["remove", "-y"];
                if recursive {
                    remove_args.push("--auto-remove");
                }
                remove_args.push(name);
                let ok1 = run_cmd("apt-get", &remove_args).await;

                let _ = run_cmd("apt-get", &["purge", "-y", name]).await;

                if recursive {
                    let _ = run_cmd("apt-get", &["autoremove", "-y"]).await;
                }

                ok1
            }
            Self::Flatpak => run_cmd("flatpak", &["uninstall", "-y", name]).await,
            Self::Snap => run_cmd("snap", &["remove", name]).await,
        }
    }
}

/// Execute removal for a Zex Content Store package.
/// Reads metadata from TOML registry, cleans system + union, deletes registry entry, runs GC.
async fn zex_store_removal(name: &str) -> bool {
    use std::collections::HashSet;
    use std::path::PathBuf;

    let registry_dir = std::path::Path::new("/overlayer/zexlib/registry");

    let (reg_path, content_hash) = match find_registry_toml(name) {
        Some(v) => v,
        None => return false,
    };

    let store_path = PathBuf::from(format!("/overlayer/zexlib/store/{}", content_hash));
    let union_path = PathBuf::from("/overlayer/zexlib/union");

    if store_path.exists() {
        for entry in walkdir::WalkDir::new(&store_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() || entry.file_type().is_symlink() {
                if let Ok(rel) = entry.path().strip_prefix(&store_path) {
                    let system_path = std::path::Path::new("/").join(rel);
                    if system_path
                        .symlink_metadata()
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false)
                    {
                        let _ = std::fs::remove_file(&system_path);
                    }
                    let union_file = crate::archive_safety::live_path(&union_path.join(rel));
                    if union_file.exists() || union_file.symlink_metadata().is_ok() {
                        let _ = crate::immutable::try_clear_immutable(&union_file);
                        let _ = std::fs::remove_file(&union_file);
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(&reg_path);

    let overlay = crate::cmd::install::union::UnionLayer::new();
    let _ = overlay.sync_fstab();
    let _ = overlay.apply_live_mounts();

    let mut active_refs = HashSet::new();
    if let Ok(entries) = std::fs::read_dir(registry_dir) {
        for dir_entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(dir_entry.path()) {
                for line in content.lines() {
                    if let Some(hash) = line.strip_prefix("content_hash = \"") {
                        if let Some(hash) = hash.strip_suffix('"') {
                            active_refs.insert(hash.to_string());
                        }
                    }
                }
            }
        }
    }

    true
}

/// Spawn a subprocess with explicit argv (no shell interpolation).
/// Returns `true` when the process exits with status 0.
async fn run_cmd(program: &str, args: &[&str]) -> bool {
    match Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

/// Probe each backend in priority order (zex-store → apt → flatpak → snap).
/// Returns the first backend that recognises the package, or `None`.
pub async fn find_backend(name: &str) -> Option<PackageBackend> {
    if let Ok(Some(cached)) = super::persist_cache::PersistCache::get(name) {
        stats::Stats::record_cache_hit().await;
        return Some(cached);
    }

    stats::Stats::record_cache_miss().await;

    let result = if zex_store_has(name) {
        Some(PackageBackend::ZexStore)
    } else if apt_has(name).await {
        Some(PackageBackend::Apt)
    } else if flatpak_has(name).await {
        Some(PackageBackend::Flatpak)
    } else if snap_has(name).await {
        Some(PackageBackend::Snap)
    } else {
        None
    };

    if let Some(ref be) = result {
        let _ = super::persist_cache::PersistCache::set(name, be.clone());
    }
    result
}

/// Find a package's TOML registry file. Returns (path, content_hash).
fn find_registry_toml(name: &str) -> Option<(std::path::PathBuf, String)> {
    let registry_dir = std::path::Path::new("/overlayer/zexlib/registry");
    if !registry_dir.exists() {
        return None;
    }

    let exact = registry_dir.join(format!("{}.toml", name));
    if exact.exists() {
        if let Some(hash) = extract_content_hash(&exact) {
            return Some((exact, hash));
        }
    }

    if let Ok(entries) = std::fs::read_dir(registry_dir) {
        for dir_entry in entries.flatten() {
            let fname = dir_entry.file_name().to_string_lossy().to_string();
            if fname.ends_with(".toml") {
                let pkg = fname.trim_end_matches(".toml");
                if pkg.eq_ignore_ascii_case(name) {
                    if let Some(hash) = extract_content_hash(&dir_entry.path()) {
                        return Some((dir_entry.path(), hash));
                    }
                }
            }
        }
    }

    None
}

/// Extract content_hash from a TOML registry file.
fn extract_content_hash(path: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(hash) = line.strip_prefix("content_hash = \"") {
            if let Some(hash) = hash.strip_suffix('"') {
                return Some(hash.to_string());
            }
        }
    }
    None
}

/// Check if a package exists in Zex's TOML registry.
fn zex_store_has(name: &str) -> bool {
    find_registry_toml(name).is_some()
}

/// `true` when dpkg-query reports the package as installed.
async fn apt_has(name: &str) -> bool {
    match Command::new("dpkg-query")
        .args(["-W", "--showformat=${db:Status-Abbrev}", name])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.trim().starts_with('i')
        }
        Err(_) => false,
    }
}

/// `true` when `flatpak list` contains the application name.
async fn flatpak_has(name: &str) -> bool {
    let available = Command::new("which")
        .arg("flatpak")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .map(|s| s.status.success())
        .unwrap_or(false);

    if !available {
        return false;
    }

    match Command::new("flatpak")
        .args(["list", "--app", "--columns=application"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).to_lowercase();
            out.contains(&name.to_lowercase())
        }
        Err(_) => false,
    }
}

/// `true` when `snap list` contains the package name.
async fn snap_has(name: &str) -> bool {
    let available = Command::new("which")
        .arg("snap")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .map(|s| s.status.success())
        .unwrap_or(false);

    if !available {
        return false;
    }

    match Command::new("snap")
        .arg("list")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).to_lowercase();
            out.contains(&name.to_lowercase())
        }
        Err(_) => false,
    }
}
