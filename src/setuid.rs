//! Helpers that only work setuid root. Packages built by an unprivileged CI lose the bit
//! (libfuse, for one, only sets it when installed as root), so zex restores it for exactly
//! these paths after a transaction. Nothing outside this list is ever made setuid.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Paths relative to the syshub root.
pub const HELPERS: &[&str] = &[
    "bin/elev",
    "bin/elevate",
    "bin/fusermount3",
    "bin/fusermount",
    "bin/pkexec",
    "lib/polkit-1/polkit-agent-helper-1",
    "lib/security/unix_chkpwd",
];

/// The mode a staged base file must keep: extraction and staging drop setuid, and the base
/// cannot be changed after quantra-ramfs applies the upgrade.
pub fn staged_mode(rel: &str, mode: u32) -> u32 {
    if HELPERS.contains(&rel) { 0o4755 } else { mode }
}

/// Makes the helper at `path` root-owned 4755; untouched when already right (no copy-up).
pub fn restore(path: &Path) -> std::io::Result<bool> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => m,
        _ => return Ok(false),
    };
    if meta.uid() == 0 && meta.gid() == 0 && meta.mode() & 0o7777 == 0o4755 {
        return Ok(false);
    }
    std::os::unix::fs::chown(path, Some(0), Some(0))?;
    // chown clears setuid, so the mode goes last
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o4755))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::staged_mode;

    #[test]
    fn only_helpers_stay_setuid() {
        assert_eq!(staged_mode("lib/security/unix_chkpwd", 0o755), 0o4755);
        assert_eq!(staged_mode("bin/elevate", 0o755), 0o4755);
        assert_eq!(staged_mode("bin/ls", 0o755), 0o755);
    }
}
