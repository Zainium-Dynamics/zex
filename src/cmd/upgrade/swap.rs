//! swap.rs — Live binary swap for self-upgrading Zex.
//!
//! Problem: you cannot overwrite a running ELF on Linux (ETXTBSY).
//!
//! Solution: `fs::rename()` IS atomic on POSIX even for running binaries
//! because rename replaces the directory entry, not the inode — the kernel
//! keeps the old inode open as long as the process is alive, and the new
//! binary gets a fresh inode.
//!
//! Flow (called from syscore after syshub.new is verified):
//!   1. Detect whether zex version changed in the new syshub.toml
//!   2. Locate `syshub.new/bin/zex`
//!   3. Rename live `/overlayer/syshub/bin/zex` → `.bak` (keeps old inode alive)
//!   4. Rename `syshub.new/bin/zex` → `/overlayer/syshub/bin/zex`
//!   5. On any error: restore `.bak`
//!   6. After full upgrade success: delete `.bak`

use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

const ZEX_LIVE: &str    = "/overlayer/syshub/bin/zex";
const ZEX_BAK:  &str    = "/overlayer/syshub/bin/zex.bak";

/// Called by syscore after syshub.new is fully extracted and verified.
///
/// `new_syshub` is the staging root (`/overlayer/syshub.new`).
/// `old_zex_ver` / `new_zex_ver` come from the syshub.toml diff so we only
/// trigger a swap when zex itself actually changed.
///
/// Returns `Ok(true)` if a swap was performed, `Ok(false)` if no swap needed.
pub fn maybe_swap_zex(
    new_syshub:   &Path,
    old_zex_ver:  &str,
    new_zex_ver:  &str,
) -> Result<bool> {
    if old_zex_ver == new_zex_ver {
        return Ok(false); // zex version unchanged — nothing to do
    }

    let new_bin = new_syshub.join("bin").join("zex");
    if !new_bin.exists() {
        // syshub.new was built but contains no zex binary — skip swap,
        // let the normal file-by-file overwrite handle it.
        return Ok(false);
    }

    // Verify the new binary is executable before touching the live one.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&new_bin)
            .context("reading metadata of syshub.new/bin/zex")?;
        if meta.mode() & 0o111 == 0 {
            bail!(
                "syshub.new/bin/zex is not executable (mode {:o}) — aborting swap",
                meta.mode()
            );
        }
    }

    // 1. Back up the live binary (keeps the old inode open for currently
    //    running zex processes — they will finish normally on their old inode).
    if Path::new(ZEX_LIVE).exists() {
        fs::rename(ZEX_LIVE, ZEX_BAK)
            .context("renaming live zex to .bak")?;
    }

    // 2. Atomically place the new binary.
    match fs::rename(&new_bin, ZEX_LIVE) {
        Ok(_) => {
            // Ensure executable bit is set on the new binary.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(ZEX_LIVE, fs::Permissions::from_mode(0o755))
                    .context("chmod 755 on new zex binary")?;
            }
            Ok(true)
        }
        Err(e) => {
            // Swap failed — restore the backup so the system still has zex.
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
        fs::rename(ZEX_BAK, ZEX_LIVE)
            .context("restoring zex from .bak during rollback")?;
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

/// Generic atomic rename — used by syscore for non-zex files.
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
