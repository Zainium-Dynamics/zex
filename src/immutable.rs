//! Optional immutable flag (`FS_IOC_SETFLAGS`) for installed binaries.

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result};
use log::debug;

const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IOC_SETFLAGS: libc::c_ulong = 0x8008_6602;
const FS_IMMUTABLE_FL: i32 = 0x0000_0010;

/// Clear the immutable bit on `path` so it can be replaced; a no-op when unset or unsupported.
pub fn try_clear_immutable(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let file = File::open(path).with_context(|| format!("open for immutable: {}", path.display()))?;
    let fd = file.as_raw_fd();
    let mut flags: i32 = 0;
    if unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS as libc::c_int, &mut flags) } != 0
        || flags & FS_IMMUTABLE_FL == 0
    {
        return Ok(());
    }
    flags &= !FS_IMMUTABLE_FL;
    if unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS as libc::c_int, &mut flags) } != 0 {
        debug!(
            "clearing immutable flag on {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Set the immutable bit on `path` if it is a regular file under `bin/` or `sbin/`.
pub fn try_set_immutable(path: &Path) -> Result<()> {
    let s = path.to_string_lossy();
    if !(s.contains("/bin/") || s.contains("/sbin/")) {
        return Ok(());
    }

    if !path.is_file() {
        return Ok(());
    }

    let file = File::open(path).with_context(|| format!("open for immutable: {}", path.display()))?;
    let fd = file.as_raw_fd();
    let mut flags = FS_IMMUTABLE_FL;

    let rc = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS as libc::c_int, &mut flags) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        debug!(
            "FS_IOC_SETFLAGS skipped for {} (non-fatal): {err}",
            path.display()
        );
        return Ok(());
    }

    debug!("immutable flag set on {}", path.display());
    Ok(())
}