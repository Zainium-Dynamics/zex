//! tests/harness.rs: Shared test utilities for all zex tests.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

/// A temporary overlayer filesystem tree for tests.
/// Dropped = cleaned up automatically.
pub struct TempOverlayer {
    pub root: tempfile::TempDir,
}

impl TempOverlayer {
    /// Create a complete mock overlayer layout.
    pub fn new() -> Self {
        let root = tempfile::TempDir::new().expect("failed to create tmpdir");
        let r = root.path();

        let dirs = [
            "overlayer/syshub/bin",
            "overlayer/syshub/lib",
            "overlayer/syshub/lib64",
            "overlayer/syshub/include",
            "overlayer/syshub/sbin",
            "overlayer/syshub/etc",
            "overlayer/syshub/share",
            "overlayer/syshub/drivers/system",
            "overlayer/syshub/engine/services",
            "overlayer/syshub/x86_64-zainium-linux-musl/bin",
            "overlayer/syshub/x86_64-zainium-linux-musl/lib",
            "overlayer/syshub/x86_64-zainium-linux-musl/include",
            "overlayer/zexlib/registry/installed",
            "overlayer/zexlib/registry/cache/tier1-zainium",
            "overlayer/zexlib/registry/cache/tier2-alpine",
            "overlayer/zexlib/registry/cache/tier3-void",
            "overlayer/zexlib/registry/cache/tier4-chimera",
            "overlayer/zexlib/union/bin",
            "overlayer/zexlib/union/lib",
            "overlayer/zexlib/union/share",
            "overlayer/zexlib/union/var/log",
            "overlayer/zexlib/transactions",
            "overlayer/zexlib/tmp",
            "overlayer/zaisys/kernel",
        ];
        for d in dirs {
            fs::create_dir_all(r.join(d)).unwrap();
        }

        fs::write(
            r.join("overlayer/syshub/engine/services/syshub.toml"),
            r#"[packages]
[packages.bash]
version = "5.2.37"
build_type = "dynamic"
libc_target = "musl"

[packages.coreutils]
version = "9.6"
build_type = "static"
libc_target = "relibc"
"#,
        )
        .unwrap();

        fs::write(
            r.join("overlayer/syshub/engine/services/zex_services.toml"),
            r#"[mirrors]
[mirrors.zainium-userland-zexlib]
url = "https://archive.zainiumdynamics.tech/userland/x86_64"
format = "zex"
tier = 1

[mirrors.alpine-main]
url = "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"
format = "apk"
tier = 2

[mirrors.void-musl-current]
url = "https://repo-default.voidlinux.org/current/musl"
format = "xbps"
tier = 3
"#,
        )
        .unwrap();

        fs::write(
            r.join("overlayer/zexlib/registry/packages.toml"),
            r#"[packages]
[packages.htop]
version = "3.4.0"
origin = "tier1-zainium"

[packages.ripgrep]
version = "14.1.1"
origin = "tier1-zainium"
"#,
        )
        .unwrap();

        TempOverlayer { root }
    }

    pub fn path(&self) -> &Path {
        self.root.path()
    }

    /// Full path from root: self.p("overlayer/syshub/bin") → /tmp/xxx/overlayer/syshub/bin
    pub fn p(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    /// Write an installed package receipt
    pub fn add_installed_receipt(&self, name: &str, version: &str, origin: &str) {
        let receipt = format!(
            r#"name = "{name}"
version = "{version}"
description = "Test package"
origin = "{origin}"
installed_at = "2026-06-27T00:00:00Z"
libc_target = "musl"
build_type = "dynamic"
license = "MIT"
maintainer = "test"

[remove]
files = ["/overlayer/zexlib/union/bin/{name}"]
symlinks = []
dirs = []
"#
        );
        fs::write(
            self.p(&format!("overlayer/zexlib/registry/installed/{name}.toml")),
            receipt,
        )
        .unwrap();

        let bin_path = self.p(&format!("overlayer/zexlib/union/bin/{name}"));
        fs::write(&bin_path, format!("#!/bin/sh\necho {name}\n")).unwrap();
    }

    /// Write a pinned.toml
    pub fn set_pinned(&self, toml_content: &str) {
        fs::write(
            self.p("overlayer/zexlib/registry/pinned.toml"),
            toml_content,
        )
        .unwrap();
    }

    /// Create a transaction directory with manifest
    pub fn add_transaction(&self, tx_id: &str, timestamp: &str) {
        let tx_dir = self.p(&format!("overlayer/zexlib/transactions/{tx_id}"));
        fs::create_dir_all(&tx_dir).unwrap();
        fs::write(
            tx_dir.join("manifest.toml"),
            format!(
                r#"id = "{tx_id}"
timestamp = "{timestamp}"
operation = "install"
packages = ["test-pkg"]
"#
            ),
        )
        .unwrap();
    }

    /// Add cache files to simulate download cache
    pub fn fill_cache(&self, tier: &str, size_bytes: usize) {
        let cache_dir = self.p(&format!("overlayer/zexlib/registry/cache/{tier}"));
        fs::create_dir_all(&cache_dir).unwrap();
        let data = vec![0u8; size_bytes];
        fs::write(cache_dir.join("cached-pkg-1.0.zex"), &data).unwrap();
    }

    /// Add temp files
    pub fn fill_tmp(&self, count: usize) {
        let tmp = self.p("overlayer/zexlib/tmp");
        for i in 0..count {
            fs::write(tmp.join(format!("tmpfile_{i}.dat")), &[0u8; 1024]).unwrap();
        }
    }
}

pub fn assert_file_exists(path: &Path) {
    assert!(path.exists(), "expected file to exist: {}", path.display());
}

pub fn assert_file_not_exists(path: &Path) {
    assert!(
        !path.exists(),
        "expected file NOT to exist: {}",
        path.display()
    );
}

pub fn assert_dir_exists(path: &Path) {
    assert!(
        path.is_dir(),
        "expected directory to exist: {}",
        path.display()
    );
}

pub fn assert_file_contains(path: &Path, needle: &str) {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    assert!(
        content.contains(needle),
        "file {} does not contain '{needle}'.\nContent:\n{content}",
        path.display()
    );
}

pub fn assert_toml_has_key(path: &Path, key: &str) {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let val: toml::Value = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("invalid TOML in {}: {e}", path.display()));
    let mut current = &val;
    for part in key.split('.') {
        current = current
            .get(part)
            .unwrap_or_else(|| panic!("key '{key}' not found in {}", path.display()));
    }
}

/// Build a minimal canonical `.zex` package (tar + zexc / ZEX1) in a tmpdir.
/// Includes `manifest.toml`, `signature.b3`, and `payload/` matching packer layout.
/// Returns the path to the created `.zex` file.
pub fn create_test_zex_package(name: &str, version: &str, tmpdir: &Path) -> PathBuf {
    let payload_rel = format!("payload/bin/{name}");
    let payload_bytes = format!("#!/bin/sh\necho '{name} v{version}'\n").into_bytes();

    let manifest_toml = format!(
        r#"[package]
name = "{name}"
version = "{version}"
description = "Test package: {name}"
license = "MIT"
maintainer = "Test <test@zainium.local>"

[install]
bin = "/overlayer/zexlib/union/bin"

[remove]
files = ["/overlayer/zexlib/union/bin/{name}"]
"#
    );

    let mut payload_hasher = blake3::Hasher::new();
    payload_hasher.update(payload_rel.as_bytes());
    payload_hasher.update(&payload_bytes);
    let payload_blake3 = payload_hasher.finalize().to_hex().to_string();

    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(manifest_toml.as_bytes());
    sig_hasher.update(payload_blake3.as_bytes());
    let sig_b3 = sig_hasher.finalize().to_hex().to_string();

    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        append_tar_bytes(&mut builder, "manifest.toml", manifest_toml.as_bytes());
        append_tar_bytes(&mut builder, "signature.b3", sig_b3.as_bytes());
        append_tar_bytes(&mut builder, &payload_rel, &payload_bytes);
        builder.finish().unwrap();
    }

    let zex_path = tmpdir.join(format!("{name}-{version}.zex"));
    let compressed = zex::zex_codec::compress(&tar_buf, 3).expect("zexc compress");
    fs::write(&zex_path, compressed).unwrap();
    zex_path
}

fn append_tar_bytes<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, data).unwrap();
}
