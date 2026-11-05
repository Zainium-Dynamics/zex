//! swap.rs: Live binary swap for self-upgrading Zex.

use anyhow::{Context, Result, bail};
use std::{fs, path::Path};

const ZEX_LIVE: &str = "/overlayer/syshub/bin/zex";
const ZEX_BAK: &str = "/overlayer/syshub/bin/zex.bak";

/// Called by syscore after syshub.new is fully extracted and verified.
///
/// `new_syshub` is the staging root (`/overlayer/syshub.new`).
/// `old_zex_ver` / `new_zex_ver` come from the syshub.toml diff so we only
/// trigger a swap when zex itself actually changed.
///
/// Returns `Ok(true)` if a swap was performed, `Ok(false)` if no swap needed.
pub fn maybe_swap_zex(new_syshub: &Path, old_zex_ver: &str, new_zex_ver: &str) -> Result<bool> {
    if old_zex_ver == new_zex_ver {
        return Ok(false);
    }

    let new_bin = new_syshub.join("bin").join("zex");
    if !new_bin.exists() {
        return Ok(false);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&new_bin).context("reading metadata of syshub.new/bin/zex")?;
        if meta.mode() & 0o111 == 0 {
            bail!(
                "syshub.new/bin/zex is not executable (mode {:o}) — aborting swap",
                meta.mode()
            );
        }
    }

    if Path::new(ZEX_LIVE).exists() {
        atomic_place(Path::new(ZEX_LIVE), Path::new(ZEX_BAK))
            .context("renaming live zex to .bak")?;
    }

    match atomic_place(&new_bin, Path::new(ZEX_LIVE)) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(ZEX_LIVE, fs::Permissions::from_mode(0o755))
                    .context("chmod 755 on new zex binary")?;
            }
            Ok(true)
        }
        Err(e) => {
            if Path::new(ZEX_BAK).exists() {
                let _ = fs::rename(ZEX_BAK, ZEX_LIVE);
            }
            Err(e).context("renaming syshub.new/bin/zex to live path")
        }
    }
}

/// Delete the `.bak` after a fully successful upgrade.
/// Called at the very end of syscore::execute() after tx.commit().
pub fn cleanup_bak() {
    let _ = fs::remove_file(ZEX_BAK);
}

/// Restore `.bak` on rollback (called from rollback path in syscore).
pub fn restore_bak() -> Result<()> {
    if Path::new(ZEX_BAK).exists() {
        if Path::new(ZEX_LIVE).exists() {
            let _ = fs::remove_file(ZEX_LIVE);
        }
        fs::rename(ZEX_BAK, ZEX_LIVE).context("restoring zex from .bak during rollback")?;
    }
    Ok(())
}

/// Set executable permissions (chmod 755) on any path.
pub fn make_executable(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Generic atomic rename: used by syscore for non-zex files.
/// Tries rename first (atomic), falls back to copy+delete (cross-device).
pub fn atomic_place(src: &Path, dst: &Path) -> Result<()> {
    if let Some(p) = dst.parent() {
        fs::create_dir_all(p)?;
    }
    if fs::rename(src, dst).is_err() {
        fs::copy(src, dst)
            .with_context(|| format!("copy {} → {}", src.display(), dst.display()))?;
        let _ = fs::remove_file(src);
    }
    Ok(())
}

/// Same job as `atomic_place`, but for a symlink `src`: `fs::copy`
/// dereferences a symlink and copies whatever it points to, so
/// `atomic_place`'s own EXDEV fallback silently turns a symlink into a
/// regular-file copy of its target instead of recreating the link. This
/// only shows up cross-mount (same as `atomic_place`'s own EXDEV case),
/// which is why it went unnoticed: confirmed live that a real syshub
/// upgrade's commit step was skipping every symlink outright (a stricter
/// bug than the copy-vs-symlink mixup: the walk only ever looked at
/// regular files at all), and only didn't visibly break anything because
/// the affected symlinks (soname `.so` links) happened to still point at
/// the same target filename in the new version.
pub fn atomic_place_symlink(src: &Path, dst: &Path) -> Result<()> {
    let target = fs::read_link(src)
        .with_context(|| format!("reading symlink target of {}", src.display()))?;
    if let Some(p) = dst.parent() {
        fs::create_dir_all(p)?;
    }
    let _ = fs::remove_file(dst);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, dst)
        .with_context(|| format!("symlink {} → {}", dst.display(), target.display()))?;
    let _ = fs::remove_file(src);
    Ok(())
}
