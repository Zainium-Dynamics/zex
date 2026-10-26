//! Shared-library completeness for installed packages.
//!
//! A package can install "successfully" and still not run: wget2 shipped
//! `libwget.so.4.0.0` without the `libwget.so.4` link its binary loads, and its
//! manifest listed none of gpgme, libassuan or libgpg-error. Every program and
//! library a package installs is checked against what it links (ELF NEEDED):
//! missing SONAME links inside the package are added, and libraries nothing
//! provides are reported so the install can pull in the packages that do.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use oxipatch::elf::ElfFile;

/// Where Zainium's musl loader looks (`/overlayer/syshub/etc/ld-musl-x86_64.path`).
pub const LIB_DIRS: [&str; 3] = [
    "/overlayer/syshub/lib",
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib",
    "/overlayer/zexlib/union/lib",
];

/// Provided by musl itself; never looked up as packages.
const LIBC_NAMES: [&str; 3] = ["libc.so", "libc.musl-x86_64.so.1", "ld-musl-x86_64.so.1"];

fn is_elf(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() < 64 {
        return false;
    }
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == *b"\x7fELF"
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().into_owned())
}

/// Adds a `SONAME` link next to every staged shared library whose SONAME has no
/// file of that name (e.g. `libwget.so.4 -> libwget.so.4.0.0`); the links are
/// appended to `staged` so they are committed with the package.
pub fn add_soname_links(staged: &mut Vec<PathBuf>) {
    let present: HashSet<PathBuf> = staged.iter().cloned().collect();
    let mut added = Vec::new();
    for path in staged.iter() {
        if !is_elf(path) {
            continue;
        }
        let Some(soname) = ElfFile::open(path)
            .ok()
            .and_then(|f| f.soname().ok().flatten())
        else {
            continue;
        };
        let (Some(dir), Some(name)) = (path.parent(), file_name(path)) else {
            continue;
        };
        if soname == name || soname.contains('/') {
            continue;
        }
        let link = dir.join(&soname);
        if present.contains(&link) || link.symlink_metadata().is_ok() {
            continue;
        }
        if std::os::unix::fs::symlink(&name, &link).is_ok() {
            log::info!("added missing SONAME link {} -> {}", link.display(), name);
            added.push(link);
        }
    }
    staged.extend(added);
}

/// The loader directory that already has `soname`, if any.
pub fn system_dir_of(soname: &str) -> Option<&'static str> {
    LIB_DIRS
        .iter()
        .copied()
        .find(|d| Path::new(d).join(soname).exists())
}

fn on_system(soname: &str) -> bool {
    system_dir_of(soname).is_some()
}

/// Libraries the package's ELF files link against that neither the package
/// (by file name or SONAME) nor the system provides.
pub fn missing_libraries(staged: &[PathBuf]) -> Vec<String> {
    let mut provided: HashSet<String> = staged.iter().filter_map(|p| file_name(p)).collect();
    let mut needed = HashSet::new();
    for path in staged {
        if !is_elf(path) {
            continue;
        }
        let Ok(elf) = ElfFile::open(path) else {
            continue;
        };
        if let Ok(Some(soname)) = elf.soname() {
            provided.insert(soname);
        }
        // glibc programs and libraries load from glibc's own directory, which
        // its package fills; the musl libraries packages provide can't serve them
        if super::elfpatch::is_glibc_elf(&elf) {
            continue;
        }
        if let Ok(libs) = elf.needed_libs() {
            needed.extend(libs);
        }
    }
    let mut missing: Vec<String> = needed
        .into_iter()
        .filter(|lib| !LIBC_NAMES.contains(&lib.as_str()))
        .filter(|lib| !provided.contains(lib) && !on_system(lib))
        .collect();
    missing.sort();
    missing
}

/// Of `sonames`, the ones still not present on the system.
pub fn still_missing(sonames: &[String]) -> Vec<String> {
    let mut left: Vec<String> = sonames.iter().filter(|s| !on_system(s)).cloned().collect();
    left.sort();
    left.dedup();
    left
}

/// Requests to resolve for `soname`, best first: package names derived from the
/// library name (`libgpgme.so.45` -> gpgme, libgpgme, gpgme-libs, ...), so a
/// Zainium package of that name wins, then the `so:` capability every tier's
/// index can answer (Alpine/Chimera `so:` provides, Void `shlib-provides`,
/// Zainium `provides`), for libraries whose package is named differently.
pub fn provider_requests(soname: &str) -> Vec<String> {
    let base = soname.split(".so").next().unwrap_or(soname).to_lowercase();
    let stem = base.strip_prefix("lib").unwrap_or(&base).to_string();
    // libpcre2-8 -> pcre2, libgtk-3 -> gtk
    let unversioned = match stem.rsplit_once('-') {
        Some((head, tail)) if !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
            head.to_string()
        }
        _ => stem.clone(),
    };

    let mut out: Vec<String> = Vec::new();
    for name in [&stem, &unversioned] {
        for n in [
            name.clone(),
            format!("lib{name}"),
            format!("{name}-libs"),
            format!("lib{name}-libs"),
        ] {
            if !n.is_empty() && !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out.push(format!("so:{soname}"));
    out
}

/// Whether a resolved package really provides `soname`. Indexes that list
/// libraries (`so:` entries) must name this exact one, so a different major
/// version is never installed in its place; packages whose index lists no
/// libraries are accepted and checked on disk after installing.
pub fn provides_library(provides: &[String], soname: &str) -> bool {
    let wanted = soname.to_ascii_lowercase();
    let bare = |p: &str| {
        p.split(['=', '>', '<', '~'])
            .next()
            .unwrap_or(p)
            .trim()
            .to_ascii_lowercase()
    };
    let libs: Vec<String> = provides
        .iter()
        .map(|p| bare(p))
        .filter(|p| p.starts_with("so:") || p.contains(".so"))
        .collect();
    libs.is_empty()
        || libs
            .iter()
            .any(|p| p.strip_prefix("so:").unwrap_or(p) == wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_derived_from_the_library_name() {
        let r = provider_requests("libgpgme.so.45");
        assert_eq!(r[0], "gpgme");
        assert!(r.contains(&"libgpgme".to_string()));
        assert_eq!(r.last().unwrap(), "so:libgpgme.so.45");
        assert!(provider_requests("libgpg-error.so.0").contains(&"libgpg-error".to_string()));
        assert!(provider_requests("libpcre2-8.so.0").contains(&"pcre2".to_string()));
    }

    #[test]
    fn provides_library_rejects_other_major_versions() {
        assert!(provides_library(&[], "libfoo.so.1"));
        assert!(provides_library(&["foo".into()], "libfoo.so.1"));
        assert!(provides_library(
            &["so:libfoo.so.1=1.2".into()],
            "libfoo.so.1"
        ));
        assert!(!provides_library(
            &["so:libfoo.so.2=2.0".into()],
            "libfoo.so.1"
        ));
        assert!(provides_library(&["libfoo.so.1".into()], "libfoo.so.1"));
    }

    #[test]
    fn libc_is_never_missing() {
        assert!(LIBC_NAMES.contains(&"libc.musl-x86_64.so.1"));
    }

    #[test]
    fn soname_link_is_added_for_versioned_library() {
        let dir = tempfile::tempdir().unwrap();
        // any shared object with a SONAME different from its file name works; use a system one
        let candidates = [
            "/usr/lib64/libz.so.1",
            "/usr/lib/libz.so.1",
            "/lib/libz.so.1",
        ];
        let Some(src) = candidates.iter().map(Path::new).find(|p| p.exists()) else {
            return;
        };
        let real = std::fs::canonicalize(src).unwrap();
        let copy = dir.path().join(real.file_name().unwrap());
        std::fs::copy(&real, &copy).unwrap();
        let mut staged = vec![copy.clone()];
        add_soname_links(&mut staged);
        if file_name(&copy).as_deref() != Some("libz.so.1") {
            assert!(dir.path().join("libz.so.1").symlink_metadata().is_ok());
            assert_eq!(staged.len(), 2);
        }
    }
}
