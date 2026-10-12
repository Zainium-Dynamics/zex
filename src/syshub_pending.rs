//! Syshub upgrades are staged here and applied by quantra-ramfs at the next boot,
//! before the overlay is mounted, so base files always land in the base layer (never in zexlib).
//!
//! `/overlayer/.syshub-pending/` (installed disk only, root 0700, immutable while waiting):
//!   `root/<path>`  staged files        `manifest`  `f\tmode\tsha256\tpath` | `l\ttarget\tpath` | `d\tmode\tpath`
//!   `READY`        txn id, last write  `ROLLBACK`  undo the last applied upgrade at next boot

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub const PENDING: &str = "/overlayer/.syshub-pending";

/// Machine-owned files set by the installer or the user: an upgrade never replaces them.
/// New system accounts come from systemd-sysusers (sysusers.d), never from a shipped passwd.
pub const PROTECTED: &[&str] = &[
    "etc/passwd",
    "etc/shadow",
    "etc/group",
    "etc/gshadow",
    "etc/subuid",
    "etc/subgid",
    "etc/hostname",
    "etc/hosts",
    "etc/machine-id",
    "etc/localtime",
    "etc/locale.conf",
    "etc/vconsole.conf",
    "etc/greetd/config.toml",
    "share/cosmic/com.system76.CosmicComp/v1/xkb_config",
];

const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
const FS_IMMUTABLE_FL: libc::c_int = 0x10;

/// Live sessions have no pending area: their base is a read-only image.
pub fn ensure_available() -> Result<()> {
    if !Path::new(PENDING).is_dir() {
        bail!(
            "syshub upgrades need an installed Zainium system (live session: the base is a read-only image)"
        );
    }
    Ok(())
}

/// An upgrade already waiting for reboot, if any.
pub fn waiting() -> Option<String> {
    fs::read_to_string(Path::new(PENDING).join("READY")).ok().map(|s| s.trim().to_string())
}

/// Fresh staging root; any older staged upgrade is replaced (it is superseded by this one).
pub fn begin() -> Result<PathBuf> {
    ensure_available()?;
    clear()?;
    let root = Path::new(PENDING).join("root");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    Ok(root)
}

/// Write the manifest and READY, then lock everything until quantra-ramfs applies it.
pub fn commit(label: &str) -> Result<String> {
    let pending = Path::new(PENDING);
    let root = pending.join("root");
    for rel in PROTECTED {
        let p = root.join(rel);
        if fs::symlink_metadata(&p).is_ok() {
            fs::remove_file(&p).with_context(|| format!("drop protected {}", p.display()))?;
            log::info!("upgrade ships {rel}; kept this system's own copy");
        }
    }
    let mut lines = String::new();
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    paths.sort();
    for p in &paths {
        let rel = p.strip_prefix(&root).unwrap();
        let rel_s = rel.to_string_lossy();
        if rel_s.contains('\t') || rel_s.contains('\n') {
            bail!("unsupported file name in upgrade: {rel_s:?}");
        }
        let meta = fs::symlink_metadata(p)?;
        let mode = meta.permissions().mode() & 0o7777;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(p)?;
            lines.push_str(&format!("l\t{}\t{rel_s}\n", target.display()));
        } else if meta.is_dir() {
            lines.push_str(&format!("d\t{mode:o}\t{rel_s}\n"));
        } else if meta.is_file() {
            lines.push_str(&format!("f\t{mode:o}\t{}\t{rel_s}\n", sha256_file(p)?));
        }
    }
    if lines.is_empty() {
        bail!("nothing staged");
    }
    write_synced(&pending.join("manifest"), lines.as_bytes())?;

    let txn = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S"),
        label.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect::<String>()
    );
    write_synced(&pending.join("READY"), txn.as_bytes())?;
    lock(true);
    Ok(txn)
}

/// Ask quantra-ramfs to undo the last applied upgrade at the next boot.
pub fn request_rollback() -> Result<()> {
    ensure_available()?;
    set_immutable(Path::new(PENDING), false);
    write_synced(&Path::new(PENDING).join("ROLLBACK"), b"last\n")?;
    lock(true);
    Ok(())
}

/// Drop a staged upgrade that has not been applied yet.
pub fn clear() -> Result<()> {
    lock(false);
    let pending = Path::new(PENDING);
    for name in ["READY", "manifest", "root"] {
        let p = pending.join(name);
        if p.is_dir() {
            fs::remove_dir_all(&p).with_context(|| format!("remove {}", p.display()))?;
        } else if p.exists() {
            fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
        }
    }
    Ok(())
}

/// chattr ±i over the whole pending area; root can clear it, nothing else can touch it.
fn lock(on: bool) {
    let pending = Path::new(PENDING);
    let mut all = Vec::new();
    if !on {
        set_immutable(pending, false);
    }
    walk(pending, &mut all);
    if on {
        for p in &all {
            set_immutable(p, true);
        }
        set_immutable(pending, true);
    } else {
        for p in all.iter().rev() {
            set_immutable(p, false);
        }
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for d in rd.filter_map(|d| d.ok()) {
        let p = d.path();
        if fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false) {
            walk(&p, out);
        }
        out.push(p);
    }
}

fn set_immutable(path: &Path, on: bool) {
    let Ok(meta) = fs::symlink_metadata(path) else { return };
    if meta.file_type().is_symlink() {
        return;
    }
    let Ok(f) = File::open(path) else { return };
    let mut flags: libc::c_int = 0;
    // SAFETY: the fd stays open for both calls and flags is a valid int for the kernel.
    unsafe {
        if libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) != 0 {
            return;
        }
        let new = if on { flags | FS_IMMUTABLE_FL } else { flags & !FS_IMMUTABLE_FL };
        if new != flags {
            libc::ioctl(f.as_raw_fd(), FS_IOC_SETFLAGS as _, &new);
        }
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = File::create(path).with_context(|| format!("write {}", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
