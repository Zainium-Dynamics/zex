//! Shared archive path sanitization for extract, install, and local-install.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Normalize and reject path traversal in archive-relative paths.
pub fn sanitize_archive_path(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => bail!("path traversal attempted: {:?}", path),
            _ => bail!("unsupported path component: {:?}", component),
        }
    }

    if out.as_os_str().is_empty() {
        bail!("empty path");
    }

    Ok(remap_usr_paths(out))
}

/// Rewrites a **symlink's** target — relative or absolute, possibly
/// containing `..` — into a target that is correct at the link's own
/// install location.
///
/// Not for hardlinks: use [`sanitize_archive_path`] on a hardlink's target
/// instead.
///
/// `owner_path` is the *raw, pre-remap* archive path of the symlink itself
/// (e.g. `"usr/bin/xbps-trigger"`). Relative targets are resolved against
/// its parent directory in the archive's *original* FHS namespace, because
/// that's the namespace the package author's path was written against
/// (Void's `xbps-triggers` ships `../../../usr/libexec/xbps-triggers`;
/// Void's and Chimera's `base-files` ship `/sbin -> usr/bin`). The resolved
/// path is remapped like any other archive path, then written **relative to
/// the link's own remapped directory**. A relative link resolves the same
/// way in the union, in the merged `/overlayer/syshub` view, in the base and
/// in a staged base upgrade, and it can point at a file another layer
/// provides. A union-absolute target only worked when the target was a
/// userland file, so a base package's links pointed into the userland.
///
/// A bare filename (a same-directory sibling such as `"sudo"`) is left as
/// is. Absolute targets in the real root (`/dev/null` unit masks, `/run`,
/// `/tmp`, `/home`, ...) or already in `/overlayer` are left as is; other
/// absolute targets (`/usr/lib/libfoo.so`) are remapped and made relative.
/// `..` beyond the archive root is clamped at the root, as a real path
/// resolution is at `/`, so a target can't climb out of the tree.
pub fn sanitize_link_target(owner_path: &Path, target: &Path) -> Result<PathBuf> {
    if target.as_os_str().is_empty() {
        bail!("empty link target");
    }

    const REAL_ROOT: &[&str] = &[
        "dev",
        "proc",
        "sys",
        "run",
        "tmp",
        "home",
        "root",
        "overlayer",
    ];

    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    if target.is_absolute() {
        let first = target.components().find_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        });
        if first.is_some_and(|f| REAL_ROOT.contains(&f.as_str())) {
            return Ok(target.to_path_buf());
        }
    } else if !target.to_string_lossy().contains('/') {
        // A bare filename with no directory component at all (e.g. "sudo", a
        // same-directory sibling) has nothing that needs remapping.
        return Ok(target.to_path_buf());
    } else {
        let base_dir = owner_path.parent().unwrap_or_else(|| Path::new(""));
        stack.extend(base_dir.components().filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            _ => None,
        }));
    }

    for component in target.components() {
        match component {
            Component::Normal(s) => stack.push(s.to_os_string()),
            Component::ParentDir => {
                stack.pop();
            }
            Component::CurDir | Component::RootDir => {}
            _ => bail!(
                "unsupported path component in link target: {}",
                target.display()
            ),
        }
    }

    if stack.is_empty() {
        bail!(
            "link target resolves to the archive root: {}",
            target.display()
        );
    }

    let resolved: PathBuf = stack.into_iter().collect();
    let remapped = remap_usr_paths(resolved);
    if remapped.as_os_str().is_empty() {
        bail!("empty link target after remap");
    }
    let owner = remap_usr_paths(owner_path.to_path_buf());
    let owner_dir = owner.parent().unwrap_or_else(|| Path::new(""));
    Ok(relative_from(owner_dir, &remapped))
}

/// The relative path that leads from directory `from` to `to` (both relative to one root).
fn relative_from(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for c in &to[common..] {
        out.push(c);
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Ensure `root.join(rel)` stays inside `root` after normalization.
pub fn safe_join_under(root: &Path, rel: &Path) -> Result<PathBuf> {
    let clean = sanitize_archive_path(rel)?;
    let dest = root.join(&clean);

    // `clean` is already guaranteed traversal-free by sanitize_archive_path
    // (any `..` component bails there), so this is defense-in-depth, not
    // the primary guarantee — and it must not depend on `dest`'s parent
    // directory already existing on disk. A file entry's parent dirs
    // aren't created until *after* this call returns (see unpack_tar), and
    // real archives can ship a file entry with no preceding directory
    // entry for its parent at all (confirmed live: curl-dev-8.21.0.zex's
    // `payload/include/curl/curl.h`). The old code canonicalized
    // `dest.parent()` and silently fell back to the raw, possibly-relative
    // `dest` when that lookup failed (nonexistent dir) — which then never
    // `starts_with` the always-absolute canonicalized `root`, a permanent
    // false positive that made every such real package fail to extract.
    // Joining `clean` onto the canonicalized root instead needs no
    // filesystem lookup and can't produce this mismatch.
    let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let dest_canon = root_canon.join(&clean);

    if !dest_canon.starts_with(&root_canon) {
        bail!(
            "path escapes output directory: {} (root: {})",
            dest.display(),
            root.display()
        );
    }
    Ok(dest)
}

/// Root directory handle for `openat2(RESOLVE_BENEATH)` confinement.
#[cfg(unix)]
pub struct ConfinedRoot {
    dir: File,
    root: PathBuf,
}

#[cfg(unix)]
impl ConfinedRoot {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).context("create extraction root")?;
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(root)
            .with_context(|| format!("open confined root {}", root.display()))?;
        Ok(Self {
            dir,
            root: root.to_path_buf(),
        })
    }

    pub fn write_file(&self, rel: &Path, reader: &mut dyn Read) -> Result<()> {
        let clean = sanitize_archive_path(rel)?;
        let mut file = openat2_beneath(self.dir.as_raw_fd(), &clean, &self.root, true)?;
        io::copy(reader, &mut file)
            .with_context(|| format!("writing confined file {}", clean.display()))?;
        file.sync_data().ok();
        Ok(())
    }
}

#[cfg(unix)]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(unix)]
const RESOLVE_BENEATH: u64 = 0x8;
#[cfg(unix)]
const RESOLVE_NO_SYMLINKS: u64 = 0x4;

#[cfg(unix)]
fn openat2_beneath(dirfd: RawFd, rel: &Path, root: &Path, truncate: bool) -> Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(rel.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("path contains NUL byte"))?;
    let how = OpenHow {
        flags: (libc::O_WRONLY | libc::O_CREAT | if truncate { libc::O_TRUNC } else { 0 }) as u64,
        mode: 0o644,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };

    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT2: libc::c_long = 437;
    #[cfg(not(target_arch = "x86_64"))]
    const SYS_OPENAT2: libc::c_long = libc::SYS_openat2;

    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dirfd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            let dest = safe_join_under(root, rel)?;
            return open_regular_file_for_write(&dest);
        }
        return Err(err.into());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

/// Open a regular file for writing with `O_NOFOLLOW` so a symlink at `path`
/// cannot be followed during extraction.
#[cfg(unix)]
pub fn open_regular_file_for_write(path: &Path) -> Result<File> {
    if let Ok(meta) = path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            bail!("refusing to write through symlink: {}", path.display());
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create parent directory for archive file")?;
    }

    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {} with O_NOFOLLOW", path.display()))
}

/// Copy archive entry bytes into a confined destination file.
#[cfg(unix)]
pub fn write_archive_file(path: &Path, reader: &mut dyn Read) -> Result<()> {
    let mut file = open_regular_file_for_write(path)?;
    io::copy(reader, &mut file)
        .with_context(|| format!("writing archive file {}", path.display()))?;
    file.sync_data().ok();
    Ok(())
}

#[cfg(not(unix))]
pub fn write_archive_file(path: &Path, reader: &mut dyn Read) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create parent directory for archive file")?;
    }
    let mut file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    io::copy(reader, &mut file)
        .with_context(|| format!("writing archive file {}", path.display()))?;
    Ok(())
}

/// Create a symlink only when the destination path is not already a symlink.
#[cfg(unix)]
pub fn create_sanitized_symlink(target: &Path, link_path: &Path) -> Result<()> {
    if link_path.symlink_metadata().is_ok() {
        fs::remove_file(link_path)
            .with_context(|| format!("remove existing path at {}", link_path.display()))?;
    }
    std::os::unix::fs::symlink(target, link_path)
        .with_context(|| format!("symlink {} -> {}", link_path.display(), target.display()))
}

/// Zainium union layer root — final install destination for userland packages.
pub const UNION_ROOT: &str = "/overlayer/zexlib/union";

/// The merged overlay whose upper layer is [`UNION_ROOT`].
pub const LIVE_ROOT: &str = "/overlayer/syshub";

/// Where a union path is written or removed: through the merged mount, so the overlay
/// sees the change at once (writing the upper layer behind its back stays invisible until reboot).
/// Reads of the userland-only view keep using the union path itself.
pub fn live_path(p: &Path) -> PathBuf {
    match p.strip_prefix(UNION_ROOT) {
        Ok(rel) if Path::new(LIVE_ROOT).is_dir() => Path::new(LIVE_ROOT).join(rel),
        _ => p.to_path_buf(),
    }
}

/// Remap FHS / Alpine / Void archive paths to **union-relative** layout.
///
/// Archive / config prefixes are rewritten so that when joined with
/// [`UNION_ROOT`] they land under `/overlayer/zexlib/union/...`:
///
/// | archive path              | relative after remap | absolute on disk              |
/// |---------------------------|----------------------|-------------------------------|
/// | `usr/bin/foo` / `/bin/x`  | `bin/foo`            | `…/union/bin/foo`             |
/// | `usr/sbin/bar`            | `sbin/bar`           | `…/union/sbin/bar`            |
/// | `usr/lib/…` / `lib64/…`   | `lib/…`              | `…/union/lib/…`               |
/// | `usr/share/…`             | `share/…`            | `…/union/share/…`             |
/// | `usr/etc/…` / `etc/…`     | `etc/…`              | `…/union/etc/…`               |
/// | `usr/include/…`           | `include/…`          | `…/union/include/…`           |
/// | other `usr/…`             | strip `usr/`         | under union                   |
///
/// Pure structural prefix rewrite — no package-name hardcoding.
pub fn remap_usr_paths(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    // Normalize: drop leading ./ and /
    let s = s.trim_start_matches("./").trim_start_matches('/');

    let mapped = if let Some(rest) = s.strip_prefix("usr/local/bin/") {
        format!("bin/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/local/sbin/") {
        format!("sbin/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/local/lib/") {
        format!("lib/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/local/share/") {
        format!("share/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/bin/") {
        format!("bin/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/sbin/") {
        format!("sbin/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/lib64/") {
        format!("lib/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/lib/") {
        format!("lib/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/share/") {
        format!("share/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/include/") {
        format!("include/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/etc/") {
        format!("etc/{rest}")
    } else if let Some(rest) = s.strip_prefix("usr/") {
        rest.to_string()
    } else if let Some(rest) = s.strip_prefix("bin/") {
        format!("bin/{rest}")
    } else if let Some(rest) = s.strip_prefix("sbin/") {
        format!("sbin/{rest}")
    } else if let Some(rest) = s.strip_prefix("lib64/") {
        format!("lib/{rest}")
    } else if let Some(rest) = s.strip_prefix("lib/") {
        format!("lib/{rest}")
    } else if let Some(rest) = s.strip_prefix("etc/") {
        format!("etc/{rest}")
    } else if let Some(rest) = s.strip_prefix("share/") {
        format!("share/{rest}")
    } else {
        s.to_string()
    };

    PathBuf::from(mapped)
}

/// Absolute install path under the union layer for an archive-relative path.
pub fn union_abs_path(archive_rel: &Path) -> Result<PathBuf> {
    let clean = sanitize_archive_path(archive_rel)?;
    Ok(Path::new(UNION_ROOT).join(clean))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_dir() {
        assert!(sanitize_archive_path(Path::new("../etc/passwd")).is_err());
    }

    #[test]
    fn remaps_usr_bin() {
        let p = sanitize_archive_path(Path::new("usr/bin/vim")).unwrap();
        assert_eq!(p, Path::new("bin/vim"));
        let abs = union_abs_path(Path::new("usr/bin/vim")).unwrap();
        assert_eq!(abs, Path::new("/overlayer/zexlib/union/bin/vim"));
    }

    #[test]
    fn link_target_allows_legitimate_relative_parent_dirs() {
        // Real Void package data: xbps-triggers ships a symlink whose
        // target is `../../../usr/libexec/xbps-triggers` — this used to be
        // rejected outright as "path traversal".
        let owner = Path::new("usr/bin/xbps-trigger");
        let target = Path::new("../../../usr/libexec/xbps-triggers");
        let resolved = sanitize_link_target(owner, target).unwrap();
        assert_eq!(resolved, Path::new("../libexec/xbps-triggers"));
    }

    #[test]
    fn link_target_clamps_excess_parent_dirs_at_root() {
        // Even more `..` than there are directories to climb must clamp at
        // the archive root, not error and not escape past it.
        let owner = Path::new("usr/bin/foo");
        let target = Path::new("../../../../../../etc/passwd");
        let resolved = sanitize_link_target(owner, target).unwrap();
        assert_eq!(resolved, Path::new("../etc/passwd"));
    }

    #[test]
    fn link_target_leaves_bare_filename_unchanged() {
        // A bare filename with no directory component at all has nothing
        // to remap — left exactly as-is (a plain same-directory sibling).
        let owner = Path::new("usr/bin/sudoedit");
        let target = Path::new("sudo");
        let resolved = sanitize_link_target(owner, target).unwrap();
        assert_eq!(resolved, Path::new("sudo"));
    }

    #[test]
    fn link_target_remaps_relative_multi_component_with_no_dotdot() {
        // Real Void/Chimera `base-files` data: a top-level usrmerge symlink
        // like "/sbin -> usr/bin" has *no* ".." at all, but "usr/bin" isn't
        // a real directory anywhere in our flattened union tree — it must
        // still be resolved + remapped, not left as a dangling literal
        // "usr/bin" string.
        let owner = Path::new("sbin");
        let target = Path::new("usr/bin");
        let resolved = sanitize_link_target(owner, target).unwrap();
        assert_eq!(resolved, Path::new("bin"));
    }

    #[test]
    fn link_target_remaps_absolute() {
        let owner = Path::new("usr/bin/foo");
        let target = Path::new("/usr/lib/libfoo.so");
        let resolved = sanitize_link_target(owner, target).unwrap();
        assert_eq!(resolved, Path::new("../lib/libfoo.so"));
    }

    #[test]
    fn link_target_stays_relative_inside_the_package() {
        // upower's unit enable link: must stay "../upower.service", not become
        // a union path (wrong for a base package, and through `payload/`).
        let owner = Path::new("lib/systemd/system/graphical.target.wants/upower.service");
        let target = Path::new("../upower.service");
        assert_eq!(sanitize_link_target(owner, target).unwrap(), target);
        let owner = Path::new("payload/lib/systemd/system/graphical.target.wants/upower.service");
        assert_eq!(sanitize_link_target(owner, target).unwrap(), target);
    }

    #[test]
    fn link_target_keeps_real_root_and_overlayer_paths() {
        let owner = Path::new("lib/systemd/system/foo.service");
        for t in ["/dev/null", "/run/foo", "/overlayer/syshub/lib/libfoo.so"] {
            assert_eq!(
                sanitize_link_target(owner, Path::new(t)).unwrap(),
                Path::new(t)
            );
        }
    }

    #[test]
    fn remaps_usr_lib_share_etc() {
        assert_eq!(
            sanitize_archive_path(Path::new("usr/lib/libfoo.so")).unwrap(),
            Path::new("lib/libfoo.so")
        );
        assert_eq!(
            sanitize_archive_path(Path::new("usr/share/man/man1/x.1")).unwrap(),
            Path::new("share/man/man1/x.1")
        );
        assert_eq!(
            sanitize_archive_path(Path::new("etc/foo.conf")).unwrap(),
            Path::new("etc/foo.conf")
        );
        assert_eq!(
            sanitize_archive_path(Path::new("lib64/ld-musl.so")).unwrap(),
            Path::new("lib/ld-musl.so")
        );
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlink_destination_for_file_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("real.txt");
        let link = dir.path().join("via-link.txt");
        fs::write(&real, b"secret").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = open_regular_file_for_write(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    #[cfg(unix)]
    fn writes_regular_file_with_o_nofollow() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("out.bin");
        let payload = b"hello zex";
        write_archive_file(&dest, &mut &payload[..]).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), payload);
    }
}
