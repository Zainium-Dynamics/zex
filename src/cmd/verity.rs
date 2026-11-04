//! verity.rs — `elevate zex verity`: fs-verity for the userland, by the user's choice.
//!
//! quantra-ramfs seals the base and zaisys at every boot. The userland (union) is sealed
//! only when the user turns it on: a sealed file can be replaced but never written, and
//! some software updates its own files in place.
//!
//!   elevate zex verity                 is the userland sealed?
//!   elevate zex verity --union on      seal it now, and at every boot from now on
//!   elevate zex verity --union off     stop sealing it at boot (sealed files stay sealed
//!                                      until an upgrade or reinstall replaces them)

use anyhow::{Context, Result, bail};
use std::fs;
use std::os::fd::AsRawFd;
use std::path::Path;

const UNION: &str = "/overlayer/zexlib/union";
/// quantra-ramfs seals the union at boot while this exists (baseverity.rs, UNION_SWITCH).
const SWITCH: &str = "/overlayer/zexlib/seal-union";
/// Writable by design, never sealed (the same as quantra-ramfs).
const WRITABLE: [&str; 2] = ["etc", "var"];

const G: &str = "\x1b[92m";
const Y: &str = "\x1b[93m";
const D: &str = "\x1b[2m";
const R: &str = "\x1b[0m";

pub fn run(args: Vec<String>) -> Result<()> {
    let on = Path::new(SWITCH).exists();
    let Some(i) = args.iter().position(|a| a == "--union") else {
        let (sealed, open) = count_tree(Path::new(UNION));
        println!(
            "\n  Userland fs-verity: {}\n  {sealed} of {} files are sealed.\n  {D}(elevate zex verity --union on|off){R}\n",
            if on {
                format!("{G}on{R}, sealed at every boot")
            } else {
                format!("{Y}off{R}, only the base and zaisys are sealed")
            },
            sealed + open
        );
        return Ok(());
    };
    // SAFETY: geteuid(2) takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        bail!("root required: elevate zex verity --union on|off");
    }
    match args.get(i + 1).map(String::as_str) {
        Some("on") => {
            if !on {
                fs::write(SWITCH, b"").with_context(|| format!("creating {SWITCH}"))?;
            }
            let (sealed, already, failed) = seal_tree(Path::new(UNION))?;
            let total = sealed + already;
            let state = if on { "already on" } else { "on" };
            println!(
                "\n  {G}✓{R} Userland fs-verity {state}: {total} files sealed ({sealed} new).{}\n  {D}quantra-ramfs seals new userland files at every boot.{R}\n",
                if failed > 0 {
                    format!(" {Y}{failed} could not be sealed{R} (in use or not regular).")
                } else {
                    String::new()
                }
            );
        }
        Some("off") => {
            if on {
                fs::remove_file(SWITCH).with_context(|| format!("removing {SWITCH}"))?;
            }
            let (sealed, _) = count_tree(Path::new(UNION));
            let state = if on { "off" } else { "already off" };
            println!(
                "\n  {G}✓{R} Userland fs-verity {state}: new userland files are not sealed at boot.\n  {D}{sealed} files stay sealed until an upgrade or reinstall replaces them.{R}\n"
            );
        }
        _ => bail!("usage: elevate zex verity --union on|off"),
    }
    Ok(())
}

/// The regular files under `top` outside the writable trees.
fn files(top: &Path) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> {
    walkdir::WalkDir::new(top)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            e.depth() != 1 || !WRITABLE.iter().any(|w| e.file_name() == std::ffi::OsStr::new(w))
        })
}

/// (sealed, not sealed) regular files under `top`, without changing any.
fn count_tree(top: &Path) -> (usize, usize) {
    let (mut sealed, mut open) = (0, 0);
    for entry in files(top).flatten() {
        if entry.file_type().is_file() {
            if is_sealed(entry.path()) {
                sealed += 1;
            } else {
                open += 1;
            }
        }
    }
    (sealed, open)
}

/// FS_IOC_GETFLAGS: the file has FS_VERITY_FL.
fn is_sealed(path: &Path) -> bool {
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    const FS_VERITY_FL: libc::c_long = 0x0010_0000;
    let Ok(f) = fs::File::open(path) else {
        return false;
    };
    let mut flags: libc::c_long = 0;
    // SAFETY: `flags` is writable and outlives the call; the fd is open.
    let r = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) };
    r == 0 && flags & FS_VERITY_FL != 0
}

/// Seals every regular file under `top` except the writable trees: (sealed, already, failed).
fn seal_tree(top: &Path) -> Result<(usize, usize, usize)> {
    let (mut sealed, mut already, mut failed) = (0, 0, 0);
    for entry in files(top) {
        let Ok(entry) = entry else {
            failed += 1;
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        match enable(entry.path()) {
            Ok(true) => sealed += 1,
            Ok(false) => already += 1,
            Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                bail!("this filesystem has no fs-verity (tune2fs -O verity)")
            }
            Err(_) => failed += 1,
        }
    }
    Ok((sealed, already, failed))
}

/// struct fsverity_enable_arg (linux/fsverity.h), 128 bytes.
#[repr(C)]
struct EnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    sig_size: u32,
    reserved1: u32,
    sig_ptr: u64,
    reserved2: [u64; 11],
}

/// _IOW('f', 133, struct fsverity_enable_arg)
const FS_IOC_ENABLE_VERITY: libc::c_ulong = 0x4080_6685;

/// Ok(true) if sealed now, Ok(false) if it already was. SHA-256, 4096-byte blocks, no
/// salt: the same as quantra-ramfs, so both agree on every digest.
fn enable(path: &Path) -> std::io::Result<bool> {
    let f = fs::File::open(path)?;
    let arg = EnableArg {
        version: 1,
        hash_algorithm: 1,
        block_size: 4096,
        salt_size: 0,
        salt_ptr: 0,
        sig_size: 0,
        reserved1: 0,
        sig_ptr: 0,
        reserved2: [0; 11],
    };
    // SAFETY: `arg` is a valid fsverity_enable_arg that outlives the call; the fd is open.
    let r = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_ENABLE_VERITY as _, &arg) };
    if r == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EEXIST) {
        return Ok(false);
    }
    Err(e)
}

#[cfg(test)]
mod tests {
    #[test]
    fn enable_arg_is_128_bytes() {
        assert_eq!(std::mem::size_of::<super::EnableArg>(), 128);
    }
}
