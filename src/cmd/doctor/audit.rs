//! audit.rs: All health check functions for the doctor driver.

use anyhow::Result;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};
use walkdir::WalkDir;

use super::layout::*;
use crate::cmd::install::registry::PkgRecord;

#[derive(Debug, Default)]
pub struct AuditResult {
    pub dangling_symlinks: Vec<String>,
    pub broken_receipts: Vec<String>,
    pub libc_violations: Vec<LibcViolation>,
    pub syshub_ok: bool,
    pub syshub_total: usize,
    pub syshub_clean: usize,
    pub orphaned_packages: Vec<String>,
    pub orphaned_libs: Vec<String>,
    pub unsatisfied_deps: Vec<(String, String)>,
    pub missing_syshub_dirs: Vec<String>,
    pub missing_musl_files: Vec<String>,
    /// Empty when glibc isn't installed.
    pub missing_glibc_files: Vec<String>,
}

#[derive(Debug)]
pub struct LibcViolation {
    pub path: String,
    pub reason: String,
}

impl AuditResult {
    pub fn total_issues(&self) -> usize {
        self.dangling_symlinks.len()
            + self.broken_receipts.len()
            + self.libc_violations.len()
            + self.orphaned_packages.len()
            + self.orphaned_libs.len()
            + self.unsatisfied_deps.len()
            + self.missing_syshub_dirs.len()
            + self.missing_musl_files.len()
            + self.missing_glibc_files.len()
    }

    pub fn registry_ok(&self) -> bool {
        self.broken_receipts.is_empty()
    }

    pub fn deps_ok(&self) -> bool {
        self.unsatisfied_deps.is_empty()
    }

    pub fn fs_ok(&self) -> bool {
        self.dangling_symlinks.is_empty()
            && self.orphaned_libs.is_empty()
            && self.libc_violations.is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct SyshubManifest {
    packages: HashMap<String, toml::Value>,
}

pub fn run_full_audit() -> Result<AuditResult> {
    let mut r = AuditResult::default();

    let (syshub_pkgs, syshub_provides) = load_syshub(&mut r);

    let receipts = load_receipts(&mut r);

    let mut capabilities: HashSet<String> = HashSet::new();
    for rcpt in &receipts {
        capabilities.insert(rcpt.name.to_ascii_lowercase());
        for p in &rcpt.provides {
            capabilities.insert(p.to_ascii_lowercase());
        }
    }

    check_dangling_symlinks(SYSHUB, &mut r);
    check_dangling_symlinks(UNION, &mut r);

    check_deps(&receipts, &capabilities, &syshub_provides, &mut r);

    check_libc_boundaries(&mut r);

    check_syshub_dirs(&mut r);
    check_musl_sysroot(&mut r);
    check_glibc(&mut r);

    r.syshub_total = syshub_pkgs;
    r.syshub_clean = syshub_pkgs;
    r.syshub_ok = r.missing_syshub_dirs.is_empty() && r.missing_musl_files.is_empty();
    if r.syshub_ok {
        r.syshub_clean = r.syshub_total;
    }

    check_orphaned_packages(&receipts, &mut r);

    check_orphaned_libs(&receipts, &mut r);

    Ok(r)
}

fn load_syshub(_r: &mut AuditResult) -> (usize, HashSet<String>) {
    let mut provides = HashSet::new();
    let path = Path::new(SYSHUB_MANIFEST);
    if !path.exists() {
        return (0, provides);
    }
    let Ok(raw) = fs::read_to_string(path) else {
        return (0, provides);
    };
    let Ok(manifest) = toml::from_str::<SyshubManifest>(&raw) else {
        return (0, provides);
    };

    let count = manifest.packages.len();
    for (name, val) in &manifest.packages {
        provides.insert(name.to_ascii_lowercase());
        if let Some(arr) = val.as_table().and_then(|t| t.get("provides")) {
            if let Some(list) = arr.as_array() {
                for v in list {
                    if let Some(s) = v.as_str() {
                        provides.insert(s.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    (count, provides)
}

fn load_receipts(r: &mut AuditResult) -> Vec<PkgRecord> {
    let mut receipts = Vec::new();
    let dir = Path::new(INSTALLED_DIR);
    if !dir.exists() {
        return receipts;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return receipts;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "toml").unwrap_or(false) {
            match fs::read_to_string(&path)
                .ok()
                .and_then(|raw| toml::from_str::<PkgRecord>(&raw).ok())
            {
                Some(rcpt) => receipts.push(rcpt),
                None => {
                    r.broken_receipts.push(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    receipts
}

fn check_dangling_symlinks(base: &str, r: &mut AuditResult) {
    let p = Path::new(base);
    if !p.exists() {
        return;
    }
    for entry in WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_symlink()
            && !crate::archive_safety::live_path(path).exists()
            && !is_unit_link(path)
        {
            r.dangling_symlinks
                .push(path.to_string_lossy().into_owned());
        }
    }
}

/// A systemd unit link (an alias like `display-manager.service`, a `.wants/`
/// entry) whose target unit exists in a unit directory: systemd resolves it
/// by the target's name, so it is not dangling even when the relative path is.
fn is_unit_link(path: &Path) -> bool {
    let Ok(target) = fs::read_link(path) else {
        return false;
    };
    let Some(name) = target.file_name() else {
        return false;
    };
    path.components().any(|c| c.as_os_str() == "systemd")
        && SYSTEMD_UNIT_DIRS
            .iter()
            .any(|d| Path::new(d).join(name).exists())
}

fn check_deps(
    receipts: &[PkgRecord],
    caps: &HashSet<String>,
    syshub: &HashSet<String>,
    r: &mut AuditResult,
) {
    for rcpt in receipts {
        for dep in &rcpt.dependencies {
            let base = crate::cmd::install::apk::strip_constraint(dep);
            let d = base.to_ascii_lowercase();
            if !caps.contains(&d) && !syshub.contains(&d) {
                r.unsatisfied_deps.push((rcpt.name.clone(), dep.clone()));
            }
        }
    }
}

/// Scan union/lib and union/lib64 for any glibc-versioned .so files.
/// These should NOT exist: glibc lives only in its own directory
/// (union/x86_64-zainium-linux-gnu), never on musl's library path.
fn check_libc_boundaries(r: &mut AuditResult) {
    for lib_dir in [UNION_LIB, UNION_LIB64] {
        let p = Path::new(lib_dir);
        if !p.exists() {
            continue;
        }
        for entry in WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            for forbidden in GLIBC_FORBIDDEN_SO {
                if name == *forbidden {
                    r.libc_violations.push(LibcViolation {
                        path: entry.path().to_string_lossy().into_owned(),
                        reason: format!("glibc artifact '{}' found in userland", name),
                    });
                }
            }
        }
    }
}

fn check_syshub_dirs(r: &mut AuditResult) {
    for dir in SYSHUB_REQUIRED_DIRS {
        if !Path::new(dir).exists() {
            r.missing_syshub_dirs.push(dir.to_string());
        }
    }
}

fn check_musl_sysroot(r: &mut AuditResult) {
    if !Path::new(MUSL_SYSROOT_X86).exists() {
        r.missing_musl_files.push(MUSL_SYSROOT_X86.to_string());
        return;
    }
    for f in MUSL_CRITICAL {
        if !Path::new(f).exists() {
            r.missing_musl_files.push(f.to_string());
        }
    }
    let lgcc = Path::new(MUSL_LIB_X86).join("libgcc_s.so.1");
    if lgcc.exists() {}
}

/// glibc is optional; when its directory exists, its loader and libc must too.
fn check_glibc(r: &mut AuditResult) {
    if !Path::new(GLIBC_DIR).exists() {
        return;
    }
    for f in GLIBC_CRITICAL {
        if !Path::new(f).exists() {
            r.missing_glibc_files.push(f.to_string());
        }
    }
}

fn check_orphaned_packages(receipts: &[PkgRecord], r: &mut AuditResult) {
    for rcpt in receipts {
        if rcpt.installed_files.is_empty() {
            continue;
        }

        let all_gone = rcpt.installed_files.iter().all(|f| !Path::new(f).exists());
        if all_gone {
            r.orphaned_packages.push(rcpt.name.clone());
        }
    }
}

/// An orphaned lib is a .so file in union/lib or union/lib64 that is NOT
/// listed in any installed package's receipt.
fn check_orphaned_libs(receipts: &[PkgRecord], r: &mut AuditResult) {
    let mut registered_files: HashSet<String> = HashSet::new();
    for rcpt in receipts {
        for f in &rcpt.installed_files {
            registered_files.insert(f.clone());
        }
    }

    for lib_dir in [UNION_LIB, UNION_LIB64] {
        let p = Path::new(lib_dir);
        if !p.exists() {
            continue;
        }
        for entry in fs::read_dir(p).into_iter().flatten().flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !name.starts_with("lib") || !name.contains(".so") {
                continue;
            }
            let abs = path.to_string_lossy().into_owned();
            if !registered_files.contains(&abs) {
                r.orphaned_libs.push(abs);
            }
        }
    }
}
