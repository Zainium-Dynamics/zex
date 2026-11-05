//! Local package installer for ZEX.

use std::fs;
use std::path::{Path, PathBuf};

use crate::extract;

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}
#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe { geteuid() }
}

struct InstallOpts {
    target: PathBuf,
    root: PathBuf,
    dry_run: bool,
    force: bool,
    package_name: Option<String>,
}

/// Called from main.rs: `zex -i <file|dir> [--dry-run] [--root <path>] [-f]`
pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "Usage: elevate zex local-install <file|dir> [--dry-run] [--root <path>] [--force]"
                .into(),
        );
    }

    let opts = parse_opts(args)?;

    if !opts.target.exists() {
        return Err(format!("Path not found: {}", opts.target.display()));
    }

    #[cfg(unix)]
    if !opts.dry_run
        && opts.root == Path::new("/overlayer/zexlib/union")
        && unsafe { libc_geteuid() } != 0
    {
        return Err("Root privileges required for system install.\n   Run: elevate zex local-install <file>".into());
    }

    println!("  ▶ Target: {}", opts.target.display());
    println!("  ▶ Root:   {}", opts.root.display());
    if opts.dry_run {
        println!("  ▶ Mode:   DRY RUN (no changes will be made)");
    }
    if opts.force {
        println!("  ▶ Force:  ON (will overwrite existing files)");
    }
    println!();

    let install_dir = if opts.target.is_file() {
        let format = extract::detect_format(&opts.target)
            .map_err(|e| format!("Format detection failed: {}", e))?;
        println!("  ▶ Detected: {}", format);

        let stem = opts
            .target
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("pkg");
        let clean = stem.strip_suffix(".tar").unwrap_or(stem);
        let extract_dir =
            PathBuf::from("/overlayer/zexlib/tmp").join(format!("local_install_{}", clean));
        let _ = fs::remove_dir_all(&extract_dir);

        print!("  ▶ Extracting... ");
        let result = extract::extract(&opts.target, &extract_dir)
            .map_err(|e| format!("Extraction failed: {}", e))?;
        println!("✓ ({} files)", result.files_extracted);

        if !opts.dry_run {
            let staged_files: Vec<PathBuf> = walkdir::WalkDir::new(&extract_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .map(|e| e.path().to_path_buf())
                .collect();
            crate::cmd::install::elfpatch::patch_staged_elfs(&staged_files)
                .map_err(|e| format!("ELF patch failed: {}", e))?;
            crate::cmd::install::pcpatch::patch_staged_pkgconfig(
                &staged_files,
                crate::archive_safety::UNION_ROOT,
            )
            .map_err(|e| format!("pkg-config patch failed: {}", e))?;
            crate::cmd::install::shebangpatch::patch_staged_scripts(&staged_files)
                .map_err(|e| format!("shebang patch failed: {}", e))?;
        }

        extract_dir
    } else {
        opts.target.clone()
    };

    let pkg_name = opts.package_name.unwrap_or_else(|| {
        opts.target
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("local_pkg")
            .split('_')
            .next()
            .unwrap_or("local_pkg")
            .to_string()
    });

    println!("  ▶ Creating Transaction Snapshot...");
    create_transaction_snapshot(&pkg_name, "install", &opts.root)
        .map_err(|e| format!("Transaction failed: {}", e))?;

    let result = overlay_install(&install_dir, &opts.root, opts.dry_run, opts.force)?;

    if !opts.dry_run {
        println!("  ▶ Generating receipt...");
        generate_receipt(&pkg_name, &result.installed_paths)
            .map_err(|e| format!("Receipt error: {}", e))?;
        crate::triggers::note(&result.installed_paths);
        crate::triggers::flush();
    }

    if opts.target.is_file() {
        let _ = fs::remove_dir_all(&install_dir);
    }

    println!();
    if opts.dry_run {
        println!("  DRY RUN COMPLETE:");
        println!("    Would install: {} files", result.files_installed);
        println!(
            "    Would skip:    {} files (use -f to force)",
            result.files_skipped
        );
        println!();
        println!(
            "  To apply: elevate zex local-install {}",
            opts.target.display()
        );
    } else {
        println!(
            "  ✓ Installed {} files to {}",
            result.files_installed,
            opts.root.display()
        );
        if result.files_skipped > 0 {
            println!(
                "  ⚠ Skipped {} existing files (use -f to force)",
                result.files_skipped
            );
        }
    }

    Ok(())
}

fn parse_opts(args: &[String]) -> Result<InstallOpts, String> {
    let mut target: Option<PathBuf> = None;
    let mut root = PathBuf::from("/overlayer/zexlib/union");
    let mut dry_run = false;
    let mut force = false;
    let mut package_name = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--force" | "-f" => force = true,
            "--name" => {
                i += 1;
                if i < args.len() {
                    package_name = Some(args[i].clone());
                }
            }
            "--root" => {
                i += 1;
                if i >= args.len() {
                    return Err("--root requires a path argument".into());
                }
                root = PathBuf::from(&args[i]);
            }
            _ => {
                if target.is_none() && !args[i].starts_with('-') {
                    target = Some(PathBuf::from(&args[i]));
                }
            }
        }
        i += 1;
    }

    let target = target.ok_or("No target file or directory specified")?;
    Ok(InstallOpts {
        target,
        root,
        dry_run,
        force,
        package_name,
    })
}

pub struct InstallResultExtended {
    pub files_installed: usize,
    pub files_skipped: usize,
    #[allow(dead_code)]
    pub target_root: PathBuf,
    pub installed_paths: Vec<PathBuf>,
}

fn overlay_install(
    source_dir: &Path,
    root: &Path,
    dry_run: bool,
    force: bool,
) -> Result<InstallResultExtended, String> {
    let mut installed = 0usize;
    let mut skipped = 0usize;
    let mut paths = Vec::new();

    let manifest_path = source_dir.join("manifest.toml");
    let install_map: std::collections::HashMap<String, String> = if manifest_path.exists() {
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            #[derive(serde::Deserialize, Default)]
            struct Manifest {
                install: Option<InstallSection>,
            }
            #[derive(serde::Deserialize, Default)]
            struct InstallSection {
                #[serde(flatten)]
                paths: std::collections::HashMap<String, toml::Value>,
            }
            toml::from_str::<Manifest>(&raw)
                .ok()
                .and_then(|m| m.install)
                .map(|i| {
                    i.paths
                        .into_iter()
                        .filter(|(k, _)| !k.starts_with('_'))
                        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Default::default()
        }
    } else {
        Default::default()
    };

    let walk_base = if source_dir.join("payload").exists() {
        source_dir.join("payload")
    } else {
        source_dir.to_path_buf()
    };

    for entry in walkdir::WalkDir::new(&walk_base) {
        let entry = entry.map_err(|e| format!("Walk error: {}", e))?;
        let src_path = entry.path();
        let relative = src_path
            .strip_prefix(&walk_base)
            .map_err(|e| format!("Path error: {}", e))?;

        if relative.as_os_str().is_empty() {
            continue;
        }
        if relative.to_string_lossy() == "manifest.toml" {
            continue;
        }

        let rel_str = relative.to_string_lossy();
        let dest = if !install_map.is_empty() {
            let first = rel_str.split('/').next().unwrap_or("");
            if let Some(mapped_root) = install_map.get(first) {
                let remainder = rel_str
                    .strip_prefix(&format!("{first}/"))
                    .unwrap_or(&rel_str);
                PathBuf::from(mapped_root).join(remainder)
            } else {
                root.join(relative)
            }
        } else {
            root.join(relative)
        };
        let union_dest = dest;
        let dest = crate::archive_safety::live_path(&union_dest);

        if src_path.is_dir() {
            if dry_run {
            } else {
                let _ = fs::create_dir_all(&dest);
            }
            continue;
        }

        #[cfg(unix)]
        if src_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            let link_target =
                fs::read_link(src_path).map_err(|e| format!("Symlink read error: {}", e))?;
            let safe_target = crate::archive_safety::sanitize_link_target(relative, &link_target)
                .map_err(|e| format!("Unsafe symlink target: {e}"))?;

            if dry_run {
                println!(
                    "    [SYMLINK] {} → {}",
                    dest.display(),
                    safe_target.display()
                );
                installed += 1;
                continue;
            }

            if dest.exists() || dest.symlink_metadata().is_ok() {
                if !force {
                    println!("    [SKIP] {} (exists, use -f to force)", dest.display());
                    skipped += 1;
                    continue;
                }
                let _ = fs::remove_file(&dest);
            }

            if let Some(p) = dest.parent() {
                let _ = fs::create_dir_all(p);
            }
            std::os::unix::fs::symlink(&safe_target, &dest)
                .map_err(|e| format!("Symlink create error: {}", e))?;
            installed += 1;
            paths.push(union_dest);
            continue;
        }

        if dry_run {
            let action = if dest.exists() {
                "[OVERWRITE]"
            } else {
                "[NEW]      "
            };
            println!("    {} {}", action, dest.display());
            if dest.exists() && !force {
                skipped += 1;
            } else {
                installed += 1;
            }
            continue;
        }

        if dest.exists() && !force {
            println!("    [SKIP] {} (exists, use -f to force)", dest.display());
            skipped += 1;
            continue;
        }

        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("mkdir error: {}", e))?;
        }

        let tmp = dest.with_extension("_zex_tmp");
        fs::copy(src_path, &tmp).map_err(|e| format!("Copy error: {}", e))?;

        #[cfg(unix)]
        if is_executable_path(&dest) {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&tmp) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(&tmp, perms);
            }
        }

        fs::rename(&tmp, &dest).map_err(|e| format!("Rename error: {}", e))?;
        installed += 1;
        paths.push(union_dest);
    }

    Ok(InstallResultExtended {
        files_installed: installed,
        files_skipped: skipped,
        target_root: root.to_path_buf(),
        installed_paths: paths,
    })
}

fn is_executable_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/bin/") || s.contains("/sbin/") || s.contains("/libexec/") || s.contains("/games/")
}

fn create_transaction_snapshot(pkg: &str, op: &str, _root: &Path) -> Result<(), std::io::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let tx_id = format!("tx-{}", ts);
    let tx_dir = PathBuf::from(format!("/overlayer/zexlib/transactions/{}", tx_id));
    fs::create_dir_all(&tx_dir)?;

    let state_toml = format!(
        r#"transaction_id = "{}"
timestamp = "{}"
operation = "{}"
target_package = "{}"
backup_archive = "backup.tar.zst"
"#,
        tx_id, ts, op, pkg
    );
    fs::write(tx_dir.join("state.toml"), state_toml)?;

    let live_pkgs = PathBuf::from("/overlayer/zexlib/registry/packages.toml");
    if live_pkgs.exists() {
        fs::copy(&live_pkgs, tx_dir.join("packages.toml"))?;
    }

    let live_receipt = PathBuf::from(format!("/overlayer/zexlib/registry/installed/{}.toml", pkg));
    if live_receipt.exists() {
        fs::copy(&live_receipt, tx_dir.join(format!("{}.toml", pkg)))?;
    }

    Ok(())
}

fn generate_receipt(pkg: &str, paths: &[PathBuf]) -> Result<(), std::io::Error> {
    let mut bin = Vec::new();
    let mut lib = Vec::new();
    let mut etc = Vec::new();
    let mut share = Vec::new();
    let mut sbin = Vec::new();
    let mut others = Vec::new();

    for p in paths {
        let s = p.to_string_lossy().to_string();
        if s.contains("/bin/") {
            bin.push(s);
        } else if s.contains("/lib/") || s.contains("/lib64/") {
            lib.push(s);
        } else if s.contains("/etc/") {
            etc.push(s);
        } else if s.contains("/share/") {
            share.push(s);
        } else if s.contains("/sbin/") {
            sbin.push(s);
        } else {
            others.push(s);
        }
    }

    let receipt_dir = PathBuf::from("/overlayer/zexlib/registry/installed");
    fs::create_dir_all(&receipt_dir)?;

    let mut out = String::new();
    out.push_str("[package]\n");
    out.push_str(&format!("name = \"{}\"\n", pkg));
    out.push_str(&format!("display_name = \"{}\"\n", pkg));
    out.push_str("version = \"local\"\n");
    out.push_str("content_hash = \"local_override\"\n\n");

    out.push_str("[files]\n");

    fn format_arr(name: &str, arr: &[String]) -> String {
        if arr.is_empty() {
            return String::new();
        }
        let mut s = format!("{} = [\n", name);
        for item in arr {
            s.push_str(&format!("    \"{}\",\n", item));
        }
        s.push_str("]\n");
        s
    }

    out.push_str(&format_arr("bin", &bin));
    out.push_str(&format_arr("lib", &lib));
    out.push_str(&format_arr("etc", &etc));
    out.push_str(&format_arr("share", &share));
    out.push_str(&format_arr("sbin", &sbin));
    out.push_str(&format_arr("paths", &others));

    fs::write(receipt_dir.join(format!("{}.toml", pkg)), out)?;
    Ok(())
}
