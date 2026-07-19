//! apk.rs — Native resolver for Alpine Linux (APK) and Chimera Linux
//! Parses APKINDEX.tar.gz directly into Zex package records.

use anyhow::{Context, Result};
use super::backend::{BackendConfig, MetadataManager, MirrorConfig, PackageFormat, PackageInfo, dynamic_metadata};

pub async fn resolve_apk(
    name: &str,
    client: &reqwest::Client,
    _config: &BackendConfig,
    mm: &MetadataManager,
    mirror: &MirrorConfig,
) -> Result<Option<PackageInfo>> {
    let mirror_name = mirror.id.clone();

    // Substitute {arch} placeholder in mirror URLs.
    #[cfg(target_arch = "x86_64")]  let arch = "x86_64";
    #[cfg(target_arch = "aarch64")] let arch = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = std::env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let arch = arch.to_string(); // bind lifetime

    let index_url = mirror.index_url.replace("{arch}", &arch);
    let base_url  = mirror.base_url.replace("{arch}", &arch);

    // Fetch APKINDEX.tar.gz
    let (bytes, _) = mm.fetch(&index_url, client, false).await?;

    // Unpack tar.gz in memory
    let decompressed = tokio::task::spawn_blocking(move || -> Result<String> {
        use std::io::Read;
        // APKINDEX.tar.gz is a concatenation of multiple gzip members
        // (signature tarball + index tarball) — a plain GzDecoder only
        // reads the first member and silently truncates before APKINDEX.
        let decoder = flate2::read::MultiGzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(decoder);
        let mut text = String::new();
        
        for file in archive.entries().context("Failed to read APKINDEX entries")? {
            let mut file = file.context("Failed to unwrap tar entry")?;
            if let Ok(path) = file.path() {
                if path.to_string_lossy() == "APKINDEX" {
                    file.read_to_string(&mut text).context("Failed to read APKINDEX text")?;
                    return Ok(text);
                }
            }
        }
        anyhow::bail!("APKINDEX not found in tarball")
    })
    .await
    .context("APKINDEX decompression task panicked")??;

    if let Some(rec) = find_record(&parse_all(&decompressed), name) {
        let (display_name, launch_cmd) = dynamic_metadata(&rec.name, Some(&rec.desc));

        // Filename/URL must use the *resolved* package name — for a
        // version-pinned dep ("vim-common=9.2.0747-r0") or a virtual
        // "provides" capability (e.g. "so:libncursesw.so.6"), that can
        // differ from the originally requested `name`.
        let filename = format!("{}-{}.apk", rec.name, rec.version);
        let url = format!("{}/{}", base_url.trim_end_matches('/'), filename);

        return Ok(Some(PackageInfo {
            name: rec.name.clone(),
            display_name,
            version: rec.version.clone(),
            source_mirror: Some(mirror_name),
            url,
            size: rec.size,
            launch_cmd,
            format: PackageFormat::Apk,
            filename,
            sha256: None,
            blake3: None,
            depends: rec.deps.clone(),
            provides: rec.provides.clone(),
            conflicts: rec.conflicts.clone(),
            requires_syshub: None,
            ..Default::default()
        }));
    }

    Ok(None)
}

struct ApkRecord {
    name: String,
    version: String,
    desc: String,
    size: u64,
    deps: Vec<String>,
    /// "Provides" tokens with any embedded version constraint stripped
    /// (e.g. "so:libc.musl-x86_64.so.1", "cmd:ldd").
    provides: Vec<String>,
    /// Genuine "cannot coexist with" conflicts — bare `!pkgname` entries
    /// in the `D:` field with no version operator at all. Alpine also
    /// uses *paired* `!pkg<V !pkg>V` entries to pin a subpackage to its
    /// parent's exact version (they're built and released together, so
    /// that's not a real conflict) — those are deliberately excluded.
    conflicts: Vec<String>,
}

/// Strips an embedded version constraint from a dependency/provides token.
/// APKINDEX tokens look like "vim-common=9.2.0747-r0", "so:libc.so.1>=1",
/// or plain "musl" — the resolvable identity is always the part before the
/// first constraint operator.
pub(crate) fn strip_constraint(tok: &str) -> &str {
    match tok.find(['=', '<', '>', '~']) {
        Some(i) => &tok[..i],
        None => tok,
    }
}

/// Version-constraint operator embedded in a dependency token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConstraintOp {
    Ge,
    Le,
    Gt,
    Lt,
    Eq,
    /// Alpine's "~=" fuzzy operator — same version prefix, not a strict order.
    Fuzzy,
}

/// Parses the version constraint embedded in a dependency/provides token,
/// if any — e.g. "vim-common=9.2.0747-r0" yields `(Eq, "9.2.0747-r0")`,
/// "so:libc.so.1>=1" yields `(Ge, "1")`; a plain "musl" (no operator)
/// yields `None`. Longer operators are checked before their single-char
/// prefixes so "libfoo>=1.2" isn't misread as "libfoo" `Gt` "=1.2".
pub(crate) fn parse_constraint(tok: &str) -> Option<(ConstraintOp, &str)> {
    for (marker, op) in [
        (">=", ConstraintOp::Ge),
        ("<=", ConstraintOp::Le),
        ("~=", ConstraintOp::Fuzzy),
        (">", ConstraintOp::Gt),
        ("<", ConstraintOp::Lt),
        ("=", ConstraintOp::Eq),
    ] {
        if let Some(i) = tok.find(marker) {
            return Some((op, &tok[i + marker.len()..]));
        }
    }
    None
}

/// Parses every package block out of a raw APKINDEX text in one pass.
fn parse_all(text: &str) -> Vec<ApkRecord> {
    let mut out = Vec::new();

    // We split by "\n\n" as each block is a package definition
    for block in text.split("\n\n") {
        let mut name = String::new();
        let mut version = String::new();
        let mut desc = String::new();
        let mut size = 0;
        let mut deps = Vec::new();
        let mut provides = Vec::new();
        let mut conflicts = Vec::new();

        for line in block.lines() {
            if line.len() < 2 {
                continue;
            }
            let (key, value) = line.split_at(2);
            match key {
                "P:" => name = value.to_owned(),
                "V:" => version = value.to_owned(),
                "T:" => desc = value.to_owned(),
                "S:" => size = value.parse().unwrap_or(0),
                "D:" => {
                    // Depends field: "D:!sudo so:libc.so.1 vim-common=9.2.0747-r0"
                    for d in value.split_whitespace() {
                        if let Some(pkg) = d.strip_prefix('!') {
                            // Bare "!pkg" (no operator) = real conflict.
                            // "!pkg<V" / "!pkg>V" pairs pin a subpackage
                            // to its parent's exact version — not a
                            // conflict, so those are dropped, not kept.
                            if !pkg.contains(['<', '>', '=', '~']) {
                                conflicts.push(pkg.to_string());
                            }
                            continue;
                        }
                        deps.push(d.to_string());
                    }
                }
                "p:" => {
                    // Provides field: "p:so:libc.so.1=1 cmd:ldd=1.2.4"
                    for p in value.split_whitespace() {
                        provides.push(strip_constraint(p).to_string());
                    }
                }
                _ => {}
            }
        }

        if !name.is_empty() && !version.is_empty() {
            out.push(ApkRecord { name, version, desc, size, deps, provides, conflicts });
        }
    }

    out
}

/// Resolves `target` against a package list two ways:
///   1. Direct package-name match (after stripping any version constraint).
///   2. Virtual "provides" match — e.g. "so:libncursesw.so.6" is satisfied
///      by whichever real package declares it in its `p:` field.
fn find_record<'a>(records: &'a [ApkRecord], target: &str) -> Option<&'a ApkRecord> {
    let target_base = strip_constraint(target);

    records.iter()
        .find(|r| r.name.eq_ignore_ascii_case(target_base))
        .or_else(|| {
            records.iter().find(|r| {
                r.provides.iter().any(|p| p.eq_ignore_ascii_case(target_base))
            })
        })
}
