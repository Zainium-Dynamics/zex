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
/// The base's limine tool (the `limine` package), which writes the BIOS boot code.
const LIMINE_TOOL: &str = "/overlayer/syshub/bin/limine";
/// Where Limine's BIOS stage looks for limine-bios.sys (common/entry.s2.c).
const BIOS_STAGE3: [&str; 4] = [
    "boot/limine/limine-bios.sys",
    "boot/limine-bios.sys",
    "limine/limine-bios.sys",
    "limine-bios.sys",
];
const MOUNT_AT: &str = "/run/zex-esp";

pub struct Esp {
    pub root: PathBuf,
    /// The partition, for finding the disk the BIOS boot code goes on.
    dev: Option<PathBuf>,
    mounted_here: bool,
}

impl Esp {
    pub fn mount() -> Result<Self> {
        let root_uuid = root_uuid();
        for (dev, dir, fstype) in mounts() {
            if fstype == "vfat" && is_ours(Path::new(&dir), root_uuid.as_deref()) {
                return Ok(Esp {
                    root: dir.into(),
                    dev: Some(dev.into()),
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
                    dev: Some(dev),
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

    /// The whole disk the ESP is a partition of (`/dev/nvme0n1` for `/dev/nvme0n1p1`).
    pub fn disk(&self) -> Option<PathBuf> {
        let dev = fs::canonicalize(self.dev.as_ref()?).ok()?;
        let name = dev.file_name()?;
        let sys = Path::new("/sys/class/block").join(name);
        if !sys.join("partition").exists() {
            return None;
        }
        let parent = fs::canonicalize(&sys).ok()?.parent()?.file_name()?.to_owned();
        Some(Path::new("/dev").join(parent))
    }

    /// Puts a Limine release (the files of `limine-boot`'s `payload/limine/`) on the ESP:
    /// `BOOTX64.EFI` where UEFI firmware starts it, and `limine-bios.sys` wherever this
    /// ESP already has it, with the boot code written to the disk by the base's
    /// `limine` tool. BIOS boot breaks when that boot code and limine-bios.sys are from
    /// different releases, so limine-bios.sys is only replaced when the base's tool is
    /// the same release. Returns false when the BIOS part had to wait for that.
    pub fn install_limine(&self, files: &Path, version: &str) -> Result<bool> {
        let efi = files.join("BOOTX64.EFI");
        if efi.is_file() {
            let dir = self.root.join("EFI/BOOT");
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            copy_synced(&efi, &dir.join("BOOTX64.EFI"))?;
        }
        let bios = files.join("limine-bios.sys");
        let targets: Vec<PathBuf> = BIOS_STAGE3
            .iter()
            .map(|rel| self.root.join(rel))
            .filter(|p| p.is_file())
            .collect();
        if !bios.is_file() || targets.is_empty() {
            return Ok(true);
        }
        let release = version.split("-r").next().unwrap_or(version);
        let tool_release = std::process::Command::new(LIMINE_TOOL)
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|out| {
                out.lines()
                    .next()?
                    .strip_prefix("Limine ")
                    .map(|v| v.trim().to_string())
            });
        if tool_release.as_deref() != Some(release) {
            return Ok(false);
        }
        let disk = self
            .disk()
            .context("the disk of the EFI partition, for Limine's BIOS boot code")?;
        for dest in &targets {
            copy_synced(&bios, dest)?;
        }
        let status = std::process::Command::new(LIMINE_TOOL)
            .arg("bios-install")
            .arg(&disk)
            .stdout(std::process::Stdio::null())
            .status()
            .context("running limine bios-install")?;
        if !status.success() {
            bail!("limine bios-install {} failed", disk.display());
        }
        Ok(true)
    }

    /// The kernel file limine.conf boots by default: the first entry's `path:` under the
    /// kernel directory that is not the fallback kernel.
    pub fn booted_kernel(&self, fallback_kernel: &str) -> Option<String> {
        let text = fs::read_to_string(self.root.join("limine.conf")).ok()?;
        booted_kernel_in(&text, fallback_kernel)
    }

    /// Point the default menu entries that boot `old` at `new` (a kernel with another name).
    pub fn default_entries_use(&self, old: &str, new: &str) -> Result<()> {
        let conf = self.root.join("limine.conf");
        let text = fs::read_to_string(&conf).with_context(|| format!("read {}", conf.display()))?;
        let from = format!("boot():/{KERNEL_DIR}/{old}");
        let to = format!("boot():/{KERNEL_DIR}/{new}");
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            let t = line.trim_start();
            if t.strip_prefix("path:").is_some_and(|p| p.trim() == from) {
                out.push_str(&line[..line.len() - t.len()]);
                out.push_str(&format!("path: {to}"));
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
        write_synced(&conf, out.as_bytes())
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

fn booted_kernel_in(conf: &str, fallback_kernel: &str) -> Option<String> {
    let prefix = format!("boot():/{KERNEL_DIR}/");
    conf.lines()
        .filter_map(|l| l.trim_start().strip_prefix("path:"))
        .filter_map(|p| p.trim().strip_prefix(prefix.as_str()))
        .find(|name| *name != fallback_kernel && !name.contains('/'))
        .map(str::to_string)
}

fn is_ours(dir: &Path, root_uuid: Option<&str>) -> bool {
    // Zainium's ESP: the kernel directory with quantra-ramfs (the kernel's name may change)
    if !dir.join(KERNEL_DIR).join("quantra-ramfs.img").is_file() {
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

/// (device, mount point, fs type) of every mount.
fn mounts() -> Vec<(String, String, String)> {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let dev = f.next()?.to_string();
            Some((dev, f.next()?.to_string(), f.next()?.to_string()))
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
        let conf = "timeout: 1\n\n/Zainium OS\n    path: boot():/overlayer/zaisys/kernel/linux-zainium\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n\n/Zainium OS (Fallback Kernel)\n    path: boot():/overlayer/zaisys/kernel/linux-panic\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n";
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
            "linux-zainium\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n"
        ));
        assert!(out.contains(
            "linux-panic\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs-panic.img\n"
        ));
    }

    #[test]
    fn the_booted_kernel_comes_from_limine_conf_and_follows_a_rename() {
        let dir = std::env::temp_dir().join(format!("zex-esp-rename-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let conf = "timeout: 1\n\n/Zainium OS\n    path: boot():/overlayer/zaisys/kernel/linux-evl\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n\n/Zainium OS (Fallback Kernel)\n    path: boot():/overlayer/zaisys/kernel/linux-panic\n    module_path: boot():/overlayer/zaisys/kernel/quantra-ramfs.img\n";
        fs::write(dir.join("limine.conf"), conf).unwrap();
        let esp = Esp {
            root: dir.clone(),
            mounted_here: false,
        };
        assert_eq!(
            esp.booted_kernel("linux-panic").as_deref(),
            Some("linux-evl")
        );
        esp.default_entries_use("linux-evl", "linux-zainium")
            .unwrap();
        assert_eq!(
            esp.booted_kernel("linux-panic").as_deref(),
            Some("linux-zainium")
        );
        let out = fs::read_to_string(dir.join("limine.conf")).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert!(out.contains("path: boot():/overlayer/zaisys/kernel/linux-panic\n"));
        assert!(!out.contains("linux-evl"));
    }
}
