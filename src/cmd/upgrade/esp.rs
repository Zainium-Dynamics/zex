//! esp.rs — Zainium's EFI system partition: the FAT partition Limine boots from.
//!
//! Limine reads only FAT, so the installer copies the kernel and quantra-ramfs from
//! zaisys onto the ESP (`overlayer/zaisys/kernel/`); that copy is what boots. This finds
//! it (already mounted, or any FAT partition carrying that directory and a limine.conf
//! naming this system's root) and mounts it for the length of a `zex kernel` run.

use anyhow::{Context, Result, bail};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where the booted kernel files live on the ESP.
pub const KERNEL_DIR: &str = "overlayer/zaisys/kernel";
const MOUNT_AT: &str = "/run/zex-esp";

pub struct Esp {
    pub root: PathBuf,
    mounted_here: bool,
}

impl Esp {
    pub fn mount() -> Result<Self> {
        let root_uuid = root_uuid();
        for (dir, fstype) in mounts() {
            if fstype == "vfat" && is_ours(Path::new(&dir), root_uuid.as_deref()) {
                return Ok(Esp {
                    root: dir.into(),
                    mounted_here: false,
                });
            }
        }
        fs::create_dir_all(MOUNT_AT).with_context(|| format!("create {MOUNT_AT}"))?;
        for dev in fat_partitions() {
            if !mount_vfat(&dev, MOUNT_AT) {
                continue;
            }
            if is_ours(Path::new(MOUNT_AT), root_uuid.as_deref()) {
                return Ok(Esp {
                    root: MOUNT_AT.into(),
                    mounted_here: true,
                });
            }
            unmount(MOUNT_AT);
        }
        bail!("Zainium's EFI partition (with {KERNEL_DIR}) was not found")
    }

    pub fn kernel_dir(&self) -> PathBuf {
        self.root.join(KERNEL_DIR)
    }

    /// Point the menu entries that boot `fallback_kernel` at `ramfs`, so the fallback
    /// kernel always starts with the ramfs that was packed for it.
    pub fn fallback_entries_use(&self, fallback_kernel: &str, ramfs: &str) -> Result<()> {
        let conf = self.root.join("limine.conf");
        let text = fs::read_to_string(&conf).with_context(|| format!("read {}", conf.display()))?;
        let want = format!("module_path: boot():/{KERNEL_DIR}/{ramfs}");
        let mut out = String::with_capacity(text.len());
        let mut in_fallback = false;
        let mut changed = false;
        for line in text.lines() {
            let t = line.trim_start();
            if line.starts_with('/') {
                in_fallback = false;
            }
            if let Some(path) = t.strip_prefix("path:") {
                in_fallback = path.trim().ends_with(&format!("/{fallback_kernel}"));
            }
            if in_fallback && t.starts_with("module_path:") && t != want {
                out.push_str(&line[..line.len() - t.len()]);
                out.push_str(&want);
                out.push('\n');
                changed = true;
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        if changed {
            write_synced(&conf, out.as_bytes())?;
        }
        Ok(())
    }
}

impl Drop for Esp {
    fn drop(&mut self) {
        if self.mounted_here {
            // SAFETY: sync(2) takes no arguments and cannot fail.
            unsafe { libc::sync() };
            unmount(MOUNT_AT);
        }
    }
}

/// Writes `data` beside `path` and renames it into place, so a cut-off write never
/// leaves a half-written file where the boot loader looks.
pub fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_file_name(format!(
        "{}.new",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let mut f = fs::File::create(&tmp).with_context(|| format!("write {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))
}

/// Same as [`write_synced`], from a file.
pub fn copy_synced(src: &Path, path: &Path) -> Result<()> {
    let tmp = path.with_file_name(format!(
        "{}.new",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        let mut from = fs::File::open(src).with_context(|| format!("open {}", src.display()))?;
        let mut to = fs::File::create(&tmp).with_context(|| format!("write {}", tmp.display()))?;
        std::io::copy(&mut from, &mut to)?;
        to.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))
}

fn is_ours(dir: &Path, root_uuid: Option<&str>) -> bool {
    if !dir.join(KERNEL_DIR).join("linux-evl").is_file() {
        return false;
    }
    let Ok(conf) = fs::read_to_string(dir.join("limine.conf")) else {
        return false;
    };
    // two Zainium installs on one machine: the one this system booted names its root
    root_uuid.is_none_or(|u| conf.contains(u))
}

fn root_uuid() -> Option<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("root=UUID="))
        .map(str::to_string)
}

/// (mount point, fs type) of every mount.
fn mounts() -> Vec<(String, String)> {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let _dev = f.next()?;
            Some((f.next()?.to_string(), f.next()?.to_string()))
        })
        .collect()
}

/// Partitions whose first sector is a FAT boot sector.
fn fat_partitions() -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir("/sys/class/block") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        if !e.path().join("partition").exists() {
            continue;
        }
        let dev = Path::new("/dev").join(e.file_name());
        let mut sector = [0u8; 512];
        let ok = fs::File::open(&dev)
            .and_then(|mut f| f.read_exact(&mut sector))
            .is_ok();
        let fat = ok
            && sector[510] == 0x55
            && sector[511] == 0xAA
            && (sector[54..57] == *b"FAT" || sector[82..87] == *b"FAT32");
        if fat {
            out.push(dev);
        }
    }
    out
}

fn mount_vfat(dev: &Path, target: &str) -> bool {
    let (Ok(src), Ok(dst), Ok(fstype)) = (
        CString::new(dev.as_os_str().as_encoded_bytes()),
        CString::new(target),
        CString::new("vfat"),
    ) else {
        return false;
    };
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    // SAFETY: all pointers are valid NUL-terminated strings for the duration of the call.
    unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        ) == 0
    }
}

fn unmount(target: &str) {
    let Ok(t) = CString::new(target) else { return };
    // SAFETY: `t` is a valid NUL-terminated path.
    unsafe {
        if libc::umount2(t.as_ptr(), 0) != 0 {
            libc::umount2(t.as_ptr(), libc::MNT_DETACH);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_entries_get_their_ramfs() {
        let dir = std::env::temp_dir().join(format!("zex-esp-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let conf = "timeout: 1\n\n/Zainium OS\n    path: boot():/overlayer/zaisys/kernel/linux-evl\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n\n/Zainium OS (Fallback Kernel)\n    path: boot():/overlayer/zaisys/kernel/linux-panic\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n";
        fs::write(dir.join("limine.conf"), conf).unwrap();
        let esp = Esp {
            root: dir.clone(),
            mounted_here: false,
        };
        esp.fallback_entries_use("linux-panic", "quantra-ramfs-panic.img")
            .unwrap();
        let out = fs::read_to_string(dir.join("limine.conf")).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert!(out.contains(
            "linux-evl\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n"
        ));
        assert!(out.contains(
            "linux-panic\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs-panic.img\n"
        ));
    }
}
