use anyhow::{Context, Result};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use toml::Value as TomlValue;

use super::backend::{
    BackendConfig, MetadataManager, PackageFormat, PackageInfo, dynamic_metadata,
};

#[derive(Default, Debug, Clone)]
pub struct ZexIndexEntry {
    pub real_name:       String,
    pub version:         Option<String>,
    pub size:            Option<u64>,
    pub file:            Option<String>,
    pub blake3:          Option<String>,
    pub ed25519_sig:     Option<String>,   // "sig:ed25519:<hex>"
    pub depends:         Vec<String>,
    pub provides:        Vec<String>,
    pub requires_syshub: Option<String>,
    pub description:     Option<String>,
    pub license:         Option<String>,
    pub maintainer:      Option<String>,
    pub tags:            Vec<String>,
    pub build_type:      Option<String>,   // "static"|"dynamic"|"firmware"
    pub libc_target:     Option<String>,   // "relibc"|"musl"|"freestanding"
    pub edition:         Option<String>,   // package edition (e.g. Rust "2021")
}

#[derive(Debug, Clone)]
pub struct ZexIndex {
    entries:    HashMap<String, ZexIndexEntry>,
    capabilities: HashMap<String, String>,
    /// Base URL for downloading packages — filled in by fetch_index from mirror config.
    pub base_url: String,
}

impl ZexIndex {
    pub fn get(&self, name: &str) -> Option<&ZexIndexEntry> {
        let lower = name.trim().to_ascii_lowercase();
        if let Some(entry) = self.entries.get(&lower) {
            return Some(entry);
        }
        if let Some(pkg_name) = self.capabilities.get(&lower) {
            return self.entries.get(pkg_name);
        }
        None
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub async fn fetch_index(
    client: &reqwest::Client,
    config: &BackendConfig,
    mm: &MetadataManager,
) -> Result<ZexIndex> {
    // Find the Tier 1 Zainium native mirror from zex_services.toml mirrors list.
    // The mirror with id "zainium-userland-zexlib" carries the .toml ledger.
    let mirror = config
        .mirrors
        .iter()
        .find(|m| m.id == "zainium-userland-zexlib" && m.format == "zex")
        .or_else(|| config.mirrors.iter().find(|m| m.format == "zex"))
        .ok_or_else(|| anyhow::anyhow!(
            "No native Zainium (.zex) mirror configured in zex_services.toml"
        ))?;

    let index_url = &mirror.index_url;
    let base_url  = mirror.base_url.trim_end_matches('/').to_string();

    let (arc_bytes, _) = mm.fetch(index_url, client, false).await?;
    let bytes = arc_bytes.as_slice();
    let url_lower = index_url.trim().to_ascii_lowercase();

    // Parse TOML ledger (zex_ledger-x86_64.toml)
    if url_lower.ends_with(".toml") {
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("failed to decode zex index at {}", index_url))?;
        let value: TomlValue = toml::from_str(text)
            .with_context(|| format!("failed to parse zex index TOML at {}", index_url))?;
        let mut index = parse_index_toml(value)?;
        // Inject base_url so package_info_from_entry can build full download URLs.
        index.base_url = base_url;
        return Ok(index);
    }

    // JSON fallback
    if url_lower.ends_with(".json") {
        let value: JsonValue = serde_json::from_slice(bytes)
            .with_context(|| format!("failed to parse zex index JSON at {}", index_url))?;
        let mut index = parse_index_json(value)?;
        index.base_url = base_url;
        return Ok(index);
    }

    // Auto-detect: try TOML first
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(value) = toml::from_str::<TomlValue>(text) {
            if let Ok(mut index) = parse_index_toml(value) {
                index.base_url = base_url;
                return Ok(index);
            }
        }
    }

    let value: JsonValue = serde_json::from_slice(bytes)
        .with_context(|| format!("failed to parse zex index at {}", index_url))?;
    let mut index = parse_index_json(value)?;
    index.base_url = base_url;
    Ok(index)
}

pub async fn resolve_zex(
    name: &str,
    client: &reqwest::Client,
    config: &BackendConfig,
    mm: &MetadataManager,
) -> Result<Option<PackageInfo>> {
    let index = fetch_index(client, config, mm).await?;
    let Some(entry) = index.get(name) else {
        return Ok(None);
    };
    let info = package_info_from_entry(entry, &index.base_url)?;
    Ok(Some(info))
}

pub fn package_info_from_entry(
    entry: &ZexIndexEntry,
    base_url: &str,
) -> Result<PackageInfo> {
    let version = entry
        .version
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("zex index entry missing version for '{}'", entry.real_name)
        })?;

    let file = entry
        .file
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "zex index entry missing file path for '{}'",
                entry.real_name
            )
        })?;

    let url = if file.starts_with("http://") || file.starts_with("https://") {
        file.to_string()
    } else {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            file.trim_start_matches('/')
        )
    };

    let filename = url.split('/').last().unwrap_or("package.zex").to_owned();

    let (display_name, launch_cmd) = dynamic_metadata(&entry.real_name, None);
    let ed25519_sig  = entry.ed25519_sig.clone();
    let description  = entry.description.clone();
    let license      = entry.license.clone();
    let maintainer   = entry.maintainer.clone();
    let tags         = entry.tags.clone();
    let build_type   = entry.build_type.clone();
    let libc_target  = entry.libc_target.clone();
    let edition      = entry.edition.clone();

    Ok(PackageInfo {
        name: entry.real_name.clone(),
        display_name,
        version: version.to_string(),
        source_mirror: Some("zainium".to_string()),
        url,
        size: entry.size.unwrap_or(0),
        launch_cmd,
        format: PackageFormat::Zex,
        filename,
        sha256: None,
        sig_url: None,
        blake3: entry
            .blake3
            .as_ref()
            .filter(|v| !v.trim().is_empty())
            .cloned(),
        depends:      entry.depends.clone(),
        provides:     entry.provides.clone(),
        conflicts:    Vec::new(),
        description,
        license,
        maintainer,
        tags,
        build_type,
        libc_target,
        edition,
        ed25519_sig,
        requires_syshub: entry.requires_syshub.clone(),
    })
}

pub fn count_zex_packages(bytes: &[u8]) -> usize {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(value) = toml::from_str::<TomlValue>(text) {
            if let Ok(index) = parse_index_toml(value) {
                return index.len();
            }
        }
    }

    let value: JsonValue = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    match parse_index_json(value) {
        Ok(index) => index.len(),
        Err(_) => 0,
    }
}

fn parse_index_json(value: JsonValue) -> Result<ZexIndex> {
    let mut entries = HashMap::new();
    let mut capabilities = HashMap::new();

    match value {
        JsonValue::Array(list) => {
            for entry in list {
                if let Some(parsed) = parse_entry(None, &entry) {
                    entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                }
            }
        }
        JsonValue::Object(map) => {
            if let Some(packages) = map.get("packages") {
                match packages {
                    JsonValue::Array(list) => {
                        for entry in list {
                            if let Some(parsed) = parse_entry(None, entry) {
                                entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                            }
                        }
                    }
                    JsonValue::Object(obj) => {
                        for (name, entry) in obj {
                            if let Some(parsed) = parse_entry(Some(name), entry) {
                                entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                for (name, entry) in &map {
                    if let Some(parsed) = parse_entry(Some(name), entry) {
                        entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                    }
                }
            }
        }
        _ => {}
    }

    if entries.is_empty() {
        anyhow::bail!("zex index contains no packages")
    }

    for (name, entry) in &entries {
        for p in &entry.provides {
            capabilities.insert(p.to_lowercase(), name.clone());
        }
    }

    Ok(ZexIndex { entries, capabilities, base_url: String::new() })
}

fn parse_index_toml(value: TomlValue) -> Result<ZexIndex> {
    let mut entries = HashMap::new();
    let mut capabilities = HashMap::new();

    match value {
        TomlValue::Array(list) => {
            for entry in list {
                if let Some(parsed) = parse_entry_toml(None, &entry) {
                    entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                }
            }
        }
        TomlValue::Table(map) => {
            if let Some(packages) = map.get("packages") {
                match packages {
                    TomlValue::Array(list) => {
                        for entry in list {
                            if let Some(parsed) = parse_entry_toml(None, entry) {
                                entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                            }
                        }
                    }
                    TomlValue::Table(obj) => {
                        for (name, entry) in obj {
                            if let Some(parsed) = parse_entry_toml(Some(name), entry) {
                                entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                for (name, entry) in &map {
                    if let Some(parsed) = parse_entry_toml(Some(name), entry) {
                        entries.insert(parsed.real_name.to_ascii_lowercase(), parsed);
                    }
                }
            }
        }
        _ => {}
    }

    if entries.is_empty() {
        anyhow::bail!("zex index contains no packages")
    }

    for (name, entry) in &entries {
        for p in &entry.provides {
            capabilities.insert(p.to_lowercase(), name.clone());
        }
    }

    Ok(ZexIndex { entries, capabilities, base_url: String::new() })
}

fn parse_entry(name_hint: Option<&str>, value: &JsonValue) -> Option<ZexIndexEntry> {
    let obj = value.as_object()?;

    let real_name = pick_string(obj, &["real_name", "name", "id"])
        .or_else(|| name_hint.map(|n| n.to_string()))?;

    let version = pick_string(obj, &["version", "ver"]);
    let file = pick_string(obj, &["url", "path", "file", "filename", "artifact"]);
    let blake3 = pick_string(obj, &["blake3", "b3", "hash", "digest"]);
    let size = pick_u64(obj, &["size_bytes", "size", "bytes"]);
    let depends = parse_depends(
        obj.get("depends")
            .or_else(|| obj.get("dependencies"))
            .or_else(|| obj.get("pubgrub")),
    );
    let provides = parse_depends(obj.get("provides"));
    let requires_syshub = pick_string(obj, &["requires_syshub", "syshub", "base_os"]);

    let ed25519_sig     = pick_string_json(obj, &["ed25519_sig", "sig", "signature"]);
    let description     = pick_string_json(obj, &["description", "desc", "summary"]);
    let license         = pick_string_json(obj, &["license", "spdx"]);
    let maintainer      = pick_string_json(obj, &["maintainer", "author", "packager"]);
    let tags            = parse_depends_json(obj.get("tags").or_else(|| obj.get("keywords")));
    let build_type      = pick_string_json(obj, &["build_type", "link_type"]);
    let libc_target     = pick_string_json(obj, &["libc_target", "libc"]);
    let edition         = pick_string_json(obj, &["edition"]);

    Some(ZexIndexEntry {
        real_name,
        version,
        size,
        file,
        blake3,
        depends,
        provides,
        requires_syshub,
        ..Default::default()
    })
}

fn parse_entry_toml(name_hint: Option<&str>, value: &TomlValue) -> Option<ZexIndexEntry> {
    let obj = value.as_table()?;

    let real_name = pick_string_toml(obj, &["real_name", "name", "id"])
        .or_else(|| name_hint.map(|n| n.to_string()))?;

    let version = pick_string_toml(obj, &["version", "ver"]);
    let file = pick_string_toml(obj, &["url", "path", "file", "filename", "artifact"]);
    let blake3 = pick_string_toml(obj, &["blake3", "b3", "hash", "digest"]);
    let size = pick_u64_toml(obj, &["size_bytes", "size", "bytes"]);
    let depends = parse_depends_toml(
        obj.get("depends")
            .or_else(|| obj.get("dependencies"))
            .or_else(|| obj.get("pubgrub")),
    );
    let provides = parse_depends_toml(obj.get("provides"));
    let requires_syshub = pick_string_toml(obj, &["requires_syshub", "syshub", "base_os"]);

    // zex_ledger-x86_64.toml/syshub.toml are the only formats actually
    // published (see zex-server's ledger.rs) — no JSON index exists in
    // production, so this is the path that matters for these fields.
    let ed25519_sig  = pick_string_toml(obj, &["ed25519_sig", "sig", "signature"]);
    let description  = pick_string_toml(obj, &["description", "desc", "summary"]);
    let license      = pick_string_toml(obj, &["license", "spdx"]);
    let maintainer   = pick_string_toml(obj, &["maintainer", "author", "packager"]);
    let tags         = parse_depends_toml(obj.get("tags").or_else(|| obj.get("keywords")));
    let build_type   = pick_string_toml(obj, &["build_type", "link_type"]);
    let libc_target  = pick_string_toml(obj, &["libc_target", "libc"]);
    let edition      = pick_string_toml(obj, &["edition"]);

    Some(ZexIndexEntry {
        real_name,
        version,
        size,
        file,
        blake3,
        ed25519_sig,
        depends,
        provides,
        requires_syshub,
        description,
        license,
        maintainer,
        tags,
        build_type,
        libc_target,
        edition,
    })
}

fn pick_string(map: &serde_json::Map<String, JsonValue>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(JsonValue::String(s)) = map.get(*key) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn pick_u64(map: &serde_json::Map<String, JsonValue>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(value) = map.get(*key) {
            if let Some(n) = value.as_u64() {
                return Some(n);
            }
            if let Some(s) = value.as_str() {
                if let Ok(n) = s.trim().parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn parse_depends(value: Option<&JsonValue>) -> Vec<String> {
    let mut deps = Vec::new();
    let Some(value) = value else {
        return deps;
    };

    match value {
        JsonValue::Array(items) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    push_dep(&mut deps, s);
                } else if let Some(obj) = item.as_object() {
                    if let Some(name) = pick_string(obj, &["name", "real_name", "id"]) {
                        push_dep(&mut deps, &name);
                    } else if let Some(first) = obj.keys().next() {
                        push_dep(&mut deps, first);
                    }
                }
            }
        }
        JsonValue::Object(obj) => {
            for key in obj.keys() {
                push_dep(&mut deps, key);
            }
        }
        JsonValue::String(s) => {
            for part in s.split(',') {
                push_dep(&mut deps, part);
            }
        }
        _ => {}
    }

    deps
}

fn pick_string_toml(map: &toml::map::Map<String, TomlValue>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = map.get(*key) {
            if let TomlValue::String(s) = value {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn pick_u64_toml(map: &toml::map::Map<String, TomlValue>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(value) = map.get(*key) {
            match value {
                TomlValue::Integer(i) if *i >= 0 => return Some(*i as u64),
                TomlValue::String(s) => {
                    if let Ok(n) = s.trim().parse::<u64>() {
                        return Some(n);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn parse_depends_toml(value: Option<&TomlValue>) -> Vec<String> {
    let mut deps = Vec::new();
    let Some(value) = value else {
        return deps;
    };

    match value {
        TomlValue::Array(items) => {
            for item in items {
                match item {
                    TomlValue::String(s) => push_dep(&mut deps, s),
                    TomlValue::Table(obj) => {
                        if let Some(name) = pick_string_toml(obj, &["name", "real_name", "id"]) {
                            push_dep(&mut deps, &name);
                        } else if let Some(first) = obj.keys().next() {
                            push_dep(&mut deps, first);
                        }
                    }
                    _ => {}
                }
            }
        }
        TomlValue::Table(obj) => {
            for key in obj.keys() {
                push_dep(&mut deps, key);
            }
        }
        TomlValue::String(s) => {
            for part in s.split(',') {
                push_dep(&mut deps, part);
            }
        }
        _ => {}
    }

    deps
}

fn push_dep(out: &mut Vec<String>, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    // Strip version constraints like "foo >= 1.2" or "foo (>= 1.2)".
    let name = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    if name.is_empty() {
        return;
    }
    out.push(name.to_ascii_lowercase());
}

fn pick_string_json(map: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = map.get(*k) {
            if let Some(s) = v.as_str() { return Some(s.to_string()); }
            return Some(v.to_string());
        }
    }
    None
}

fn parse_depends_json(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(v) = value else {
        return Vec::new();
    };
    if let Some(arr) = v.as_array() {
        return arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
    }
    if let Some(s) = v.as_str() {
        return s.split_whitespace().map(|s| s.to_string()).collect();
    }
    Vec::new()
}
