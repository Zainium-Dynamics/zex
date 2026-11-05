//! xbps.rs: Native resolver for Void Linux

use super::backend::{
    BackendConfig, MetadataManager, MirrorConfig, PackageFormat, PackageInfo, dynamic_metadata,
};
use anyhow::{Context, Result};

/// Strips a version constraint from an XBPS dependency/provides token.
///
/// Two forms exist:
///   - Relational: "libarchive>=3.5.1_2", "foo<1.0", "foo=1.0": split at
///     the first operator.
///   - Exact pkgver pin with no operator at all: "xtools-minimal-0.70_1"
///     (full "name-version_revision"). Void version segments always start
///     with a digit, so split at the *last* '-' immediately followed by
///     a digit.
fn strip_constraint(tok: &str) -> &str {
    if let Some(i) = tok.find(['<', '>', '=']) {
        return &tok[..i];
    }
    let bytes = tok.as_bytes();
    let mut split_at = None;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            split_at = Some(i);
        }
    }
    match split_at {
        Some(i) => &tok[..i],
        None => tok,
    }
}

pub async fn resolve_xbps(
    name: &str,
    client: &reqwest::Client,
    _config: &BackendConfig,
    mm: &MetadataManager,
    mirror: &MirrorConfig,
) -> Result<Option<PackageInfo>> {
    let mirror_name = mirror.id.clone();

    #[cfg(target_arch = "x86_64")]
    let arch = "x86_64";
    #[cfg(target_arch = "aarch64")]
    let arch = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = std::env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let arch = arch.to_string();

    let index_url = mirror.index_url.replace("{arch}", &arch);
    let base_url = mirror.base_url.replace("{arch}", &arch);

    let (bytes, _) = mm
        .fetch(&index_url, client, super::installer::reinstalling())
        .await?;

    let mirror_id_for_pin = mirror.id.clone();
    let plist_dict = tokio::task::spawn_blocking(move || -> Result<plist::Dictionary> {
        use std::io::Read;
        let decoder = zstd::stream::read::Decoder::new(&bytes[..])
            .context("Failed to init zstd decoder for xbps repodata")?;

        let mut archive = tar::Archive::new(decoder);
        let mut plist_bytes = Vec::new();
        let mut meta_bytes = Vec::new();

        for file in archive
            .entries()
            .context("Failed to read xbps repodata tar entries")?
        {
            let mut file = file.context("Failed to unwrap tar entry")?;
            if let Ok(path) = file.path() {
                match path.to_string_lossy().as_ref() {
                    "index.plist" => {
                        file.read_to_end(&mut plist_bytes)
                            .context("Failed to read index.plist")?;
                    }
                    "index-meta.plist" => {
                        file.read_to_end(&mut meta_bytes)
                            .context("Failed to read index-meta.plist")?;
                    }
                    _ => {}
                }
            }
        }

        if !meta_bytes.is_empty() {
            if let Ok(meta_value) = plist::from_bytes::<plist::Value>(&meta_bytes) {
                if let Some(meta) = meta_value.as_dictionary() {
                    let pubkey_pem = meta.get("public-key").and_then(|v| v.as_data());
                    let signed_by = meta
                        .get("signature-by")
                        .and_then(|v| v.as_string())
                        .unwrap_or("unknown");
                    if let Some(pem) = pubkey_pem {
                        if let Err(e) =
                            super::native_sig::tofu_pin_void_key(&mirror_id_for_pin, pem, signed_by)
                        {
                            log::warn!(
                                "Void repo key pin check failed for '{mirror_id_for_pin}': {e}"
                            );
                        }
                    }
                }
            }
        }

        if plist_bytes.is_empty() {
            anyhow::bail!("index.plist not found in repodata archive");
        }
        let value: plist::Value =
            plist::from_bytes(&plist_bytes).context("Failed to parse index.plist")?;
        value
            .into_dictionary()
            .ok_or_else(|| anyhow::anyhow!("index.plist is not a dictionary"))
    })
    .await
    .context("XBPS repodata decompression task panicked")??;

    let target_lower = strip_constraint(name).to_ascii_lowercase();
    let wanted_lib = target_lower.strip_prefix("so:").map(str::to_string);

    for (pkg_key, metadata_val) in &plist_dict {
        let Some(meta) = metadata_val.as_dictionary() else {
            continue;
        };
        let matches = match &wanted_lib {
            Some(lib) => meta
                .get("shlib-provides")
                .and_then(|v| v.as_array())
                .is_some_and(|libs| {
                    libs.iter()
                        .any(|l| l.as_string().is_some_and(|l| l.eq_ignore_ascii_case(lib)))
                }),
            None => pkg_key.to_ascii_lowercase().eq(&target_lower),
        };
        if !matches {
            continue;
        }

        let pkgver = meta
            .get("pkgver")
            .and_then(|v| v.as_string())
            .unwrap_or(pkg_key);
        let version = pkgver
            .strip_prefix(&format!("{pkg_key}-"))
            .unwrap_or(pkgver)
            .to_string();
        let desc = meta
            .get("short_desc")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let size = meta
            .get("filename-size")
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0);
        let sha256 = meta
            .get("filename-sha256")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        let mut deps = Vec::new();
        if let Some(run_depends) = meta.get("run_depends").and_then(|v| v.as_array()) {
            for dep in run_depends {
                if let Some(d_str) = dep.as_string() {
                    deps.push(strip_constraint(d_str).to_string());
                }
            }
        }

        let mut provides = Vec::new();
        if let Some(prov_list) = meta.get("provides").and_then(|v| v.as_array()) {
            for p in prov_list {
                if let Some(p_str) = p.as_string() {
                    provides.push(strip_constraint(p_str).to_string());
                }
            }
        }
        if let Some(libs) = meta.get("shlib-provides").and_then(|v| v.as_array()) {
            provides.extend(
                libs.iter()
                    .filter_map(|l| l.as_string())
                    .map(|l| format!("so:{l}")),
            );
        }

        let arch = meta
            .get("architecture")
            .and_then(|v| v.as_string())
            .unwrap_or("x86_64");
        let filename = format!("{pkgver}.{arch}.xbps");
        let url = format!("{}/{}", base_url.trim_end_matches('/'), filename);
        let sig_url = Some(format!("{url}.sig2"));
        let (display_name, launch_cmd) = dynamic_metadata(pkg_key, Some(&desc));

        return Ok(Some(PackageInfo {
            name: pkg_key.clone(),
            display_name,
            version,
            source_mirror: Some(mirror_name),
            url,
            size,
            launch_cmd,
            format: PackageFormat::Xbps,
            filename,
            sha256,
            blake3: None,
            sig_url,
            depends: deps,
            provides,
            requires_syshub: None,
            ..Default::default()
        }));
    }

    Ok(None)
}
