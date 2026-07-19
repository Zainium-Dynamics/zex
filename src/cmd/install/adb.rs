//! adb.rs — Native decoder for apk-tools v3's "ADB" binary container format.
//!
//! Chimera Linux has migrated off the legacy Alpine `APKINDEX.tar.gz` /
//! gzip-tar `.apk` format onto this structured binary format (both its
//! index, `Packages.adb`, and individual `.apk` package files). This
//! module was written directly against apk-tools' own C sources
//! (`src/adb.c`, `src/adb.h`, `src/apk_adb.h`, `src/extract_v3.c` in the
//! upstream `alpinelinux/apk-tools` repo) — not reverse-engineered by
//! guesswork — so the field indices and block layout below match the
//! real format exactly.
//!
//! # Envelope
//! `"ADB."` (raw) | `"ADBd"` + raw deflate | `"ADBc"` + `{alg:u8,level:u8}` + body
//! (alg: 0=none, 1=deflate, 2=zstd)
//!
//! # Body
//! `file_header{magic:u32="ADB.", schema:u32}` then a sequence of
//! 8-byte-aligned **blocks**. Each block's leading `u32` packs the type
//! into its top 2 bits; type 3 ("EXT") means the real type/size follow in
//! an extended 16-byte header instead, for blocks too big for 30 bits.
//! Block type 0 = the object graph ("ADB block"), 1 = signature, 2 = a
//! file's raw data (schema `pckg` only, one block per non-inline file).
//!
//! # Object graph (block type 0)
//! `adb_hdr{compat_ver:u8, ver:u8, reserved:u16, root:adb_val_t}` followed
//! by a pool of values referenced by byte offset. Every `adb_val_t` is a
//! `u32`: top 4 bits = type tag, low 28 bits = either an inline small int
//! or a byte offset (from the start of this block) to the real data.
//! Objects/arrays are `[u32 count][u32 slot_1]..[u32 slot_{count-1}]`,
//! where `count` includes itself, so `count-1` real slots follow — for an
//! OBJECT, slot *i* is schema field *i* (1-based); for an ARRAY, slot *i*
//! is item *i*. Blobs are `[len-prefix][bytes]` with the prefix width
//! (1/2/4 bytes) chosen by the BLOB_8/16/32 tag.

use anyhow::{bail, Context, Result};

use super::backend::{BackendConfig, MetadataManager, MirrorConfig, PackageFormat, PackageInfo, dynamic_metadata};

// ── adb_val_t type tags (top 4 bits) ──────────────────────────────────────────
const TYPE_INT: u32 = 0x1;
const TYPE_INT32: u32 = 0x2;
const TYPE_INT64: u32 = 0x3;
const TYPE_BLOB8: u32 = 0x8;
const TYPE_BLOB16: u32 = 0x9;
const TYPE_BLOB32: u32 = 0xa;
const TYPE_ARRAY: u32 = 0xd;
const TYPE_OBJECT: u32 = 0xe;

fn val_type(v: u32) -> u32 { v >> 28 }
fn val_value(v: u32) -> u32 { v & 0x0fff_ffff }

// ── Schema field indices (from apk_adb.h — ADBI_* constants) ──────────────────
#[allow(dead_code)] // kept for schema completeness even where not all fields are read yet
mod field {
    // Dependency (schema_dependency): name / version / match-op
    pub const DEP_NAME: usize = 1;
    // Package info (schema_pkginfo)
    pub const PI_NAME: usize = 1;
    pub const PI_VERSION: usize = 2;
    pub const PI_DESCRIPTION: usize = 4;
    pub const PI_ARCH: usize = 5;
    pub const PI_INSTALLED_SIZE: usize = 12;
    pub const PI_FILE_SIZE: usize = 13;
    pub const PI_DEPENDS: usize = 15;
    pub const PI_PROVIDES: usize = 16;
    // ACL (schema_acl)
    pub const ACL_MODE: usize = 1;
    // File info (schema_file)
    pub const FI_NAME: usize = 1;
    pub const FI_ACL: usize = 2;
    pub const FI_SIZE: usize = 3;
    pub const FI_TARGET: usize = 6;
    // Directory info (schema_dir)
    pub const DI_NAME: usize = 1;
    pub const DI_ACL: usize = 2;
    pub const DI_FILES: usize = 3;
    // Package (schema_package, root object of a .apk file)
    pub const PKG_PKGINFO: usize = 1;
    pub const PKG_PATHS: usize = 2;
    // Index (schema_index, root object of Packages.adb)
    pub const NDX_PACKAGES: usize = 2;
}

const SCHEMA_INDEX: u32 = 0x78646e69; // "indx"
const SCHEMA_PACKAGE: u32 = 0x676b6370; // "pckg"

const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;
const S_IFBLK: u32 = 0o060000;
const S_IFCHR: u32 = 0o020000;
const S_IFIFO: u32 = 0o010000;

// ── Low-level byte access ─────────────────────────────────────────────────────

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn u64_at(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn read_int(buf: &[u8], v: u32) -> u64 {
    match val_type(v) {
        TYPE_INT => val_value(v) as u64,
        TYPE_INT32 => u32_at(buf, val_value(v) as usize).unwrap_or(0) as u64,
        TYPE_INT64 => u64_at(buf, val_value(v) as usize).unwrap_or(0),
        _ => 0,
    }
}

fn read_blob<'a>(buf: &'a [u8], v: u32) -> &'a [u8] {
    let off = val_value(v) as usize;
    match val_type(v) {
        TYPE_BLOB8 => {
            let Some(&len) = buf.get(off) else { return &[] };
            buf.get(off + 1..off + 1 + len as usize).unwrap_or(&[])
        }
        TYPE_BLOB16 => {
            let Some(len) = buf.get(off..off + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap())) else { return &[] };
            buf.get(off + 2..off + 2 + len as usize).unwrap_or(&[])
        }
        TYPE_BLOB32 => {
            let Some(len) = u32_at(buf, off) else { return &[] };
            buf.get(off + 4..off + 4 + len as usize).unwrap_or(&[])
        }
        _ => &[],
    }
}

/// A decoded OBJECT or ARRAY: a positional slot table into the block buffer.
struct ObjView<'a> {
    buf: &'a [u8],
    off: usize,
    num: usize, // total slots including the count slot itself
}

fn read_obj<'a>(buf: &'a [u8], v: u32) -> Option<ObjView<'a>> {
    match val_type(v) {
        TYPE_ARRAY | TYPE_OBJECT => {
            let off = val_value(v) as usize;
            let num = u32_at(buf, off)? as usize;
            if num == 0 { return None; }
            buf.get(off..off + num * 4)?; // bounds check the whole slot table
            Some(ObjView { buf, off, num })
        }
        _ => None,
    }
}

impl<'a> ObjView<'a> {
    fn val(&self, i: usize) -> u32 {
        if i >= self.num { return 0; } // 0 == ADB_NULL
        u32_at(self.buf, self.off + i * 4).unwrap_or(0)
    }
    fn int(&self, i: usize) -> u64 { read_int(self.buf, self.val(i)) }
    fn blob(&self, i: usize) -> &'a [u8] { read_blob(self.buf, self.val(i)) }
    fn string(&self, i: usize) -> String { String::from_utf8_lossy(self.blob(i)).into_owned() }
    fn obj(&self, i: usize) -> Option<ObjView<'a>> { read_obj(self.buf, self.val(i)) }
    /// Number of real array items (slot 0 is the count, not an item).
    fn arr_len(&self) -> usize { self.num.saturating_sub(1) }
}

fn read_root<'a>(block0: &'a [u8]) -> Result<ObjView<'a>> {
    if block0.len() < 8 { bail!("adb: block 0 too small for header"); }
    if block0[0] != 0 { bail!("adb: unsupported adb_compat_ver {}", block0[0]); }
    let root_val = u32_at(block0, 4).context("adb: truncated root value")?;
    read_obj(block0, root_val).ok_or_else(|| anyhow::anyhow!("adb: root is not an object"))
}

// ── Envelope (outer compression wrapper) ──────────────────────────────────────

pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 4 || &bytes[0..3] != b"ADB" {
        bail!("adb: not an ADB file (bad magic)");
    }
    match bytes[3] {
        b'.' => Ok(bytes.to_vec()),
        b'd' => deflate_decode(&bytes[4..]),
        b'c' => {
            if bytes.len() < 6 { bail!("adb: truncated compression header"); }
            let alg = bytes[4];
            let body = &bytes[6..];
            match alg {
                0 => Ok(body.to_vec()),
                1 => deflate_decode(body),
                2 => zstd::stream::decode_all(body).context("adb: zstd decompression failed"),
                other => bail!("adb: unsupported compression algorithm {other}"),
            }
        }
        other => bail!("adb: unrecognized envelope marker {other:#x}"),
    }
}

fn deflate_decode(body: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(body)
        .read_to_end(&mut out)
        .context("adb: deflate decompression failed")?;
    Ok(out)
}

// ── Block framing ─────────────────────────────────────────────────────────────

pub(crate) struct RawBlock<'a> {
    pub(crate) block_type: u32,
    pub(crate) payload: &'a [u8],
}

pub(crate) fn iter_blocks(body: &[u8]) -> Result<Vec<RawBlock<'_>>> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < 4 { bail!("adb: truncated block header"); }
        let type_size = u32_at(body, pos).unwrap();
        let top2 = type_size >> 30;
        let (block_type, hdr_len, raw_size): (u32, usize, u64) = if top2 == 3 {
            if body.len() - pos < 16 { bail!("adb: truncated extended block header"); }
            let btype = type_size & 0x3fff_ffff;
            let x_size = u64_at(body, pos + 8).context("adb: truncated ext block size")?;
            (btype, 16, x_size)
        } else {
            (top2, 4, (type_size & 0x3fff_ffff) as u64)
        };
        if (raw_size as usize) < hdr_len { bail!("adb: block size smaller than its own header"); }
        let payload_len = raw_size as usize - hdr_len;
        let payload_start = pos + hdr_len;
        let payload_end = payload_start.checked_add(payload_len)
            .filter(|&e| e <= body.len())
            .context("adb: block overruns buffer")?;
        blocks.push(RawBlock { block_type, payload: &body[payload_start..payload_end] });
        pos += (raw_size as usize).div_ceil(8) * 8;
    }
    Ok(blocks)
}

struct AdbFile {
    schema: u32,
    adb_block: Vec<u8>,
    data_blocks: Vec<Vec<u8>>,
}

fn parse(bytes: &[u8]) -> Result<AdbFile> {
    let decoded = decode_envelope(bytes)?;
    if decoded.len() < 8 { bail!("adb: truncated file header"); }
    let magic = u32_at(&decoded, 0).unwrap();
    if magic != 0x2e424441 { bail!("adb: bad file header magic"); }
    let schema = u32_at(&decoded, 4).unwrap();

    let mut adb_block = None;
    let mut data_blocks = Vec::new();
    for blk in iter_blocks(&decoded[8..])? {
        match blk.block_type {
            0 => adb_block = Some(blk.payload.to_vec()),
            2 => data_blocks.push(blk.payload.to_vec()),
            _ => {} // SIG (1) and anything unknown: not needed for our purposes
        }
    }
    let adb_block = adb_block.ok_or_else(|| anyhow::anyhow!("adb: missing object-graph block"))?;
    Ok(AdbFile { schema, adb_block, data_blocks })
}

// ── Package metadata (shared by index entries and standalone .apk files) ─────

#[derive(Debug, Clone, Default)]
pub struct AdbPkgInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub file_size: u64,
    pub depends: Vec<String>,
    pub provides: Vec<String>,
}

fn read_dep_names(arr: &ObjView) -> Vec<String> {
    (1..=arr.arr_len())
        .filter_map(|i| arr.obj(i))
        .map(|d| d.string(field::DEP_NAME))
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_pkginfo(info: &ObjView) -> AdbPkgInfo {
    let depends = info.obj(field::PI_DEPENDS).map(|a| read_dep_names(&a)).unwrap_or_default();
    let provides = info.obj(field::PI_PROVIDES).map(|a| read_dep_names(&a)).unwrap_or_default();
    AdbPkgInfo {
        name: info.string(field::PI_NAME),
        version: info.string(field::PI_VERSION),
        description: info.string(field::PI_DESCRIPTION),
        file_size: info.int(field::PI_FILE_SIZE),
        depends,
        provides,
    }
}

pub fn parse_index(bytes: &[u8]) -> Result<Vec<AdbPkgInfo>> {
    let file = parse(bytes)?;
    if file.schema != SCHEMA_INDEX {
        bail!("adb: expected index schema, got {:#x}", file.schema);
    }
    let root = read_root(&file.adb_block)?;
    let packages = root.obj(field::NDX_PACKAGES)
        .ok_or_else(|| anyhow::anyhow!("adb: index missing packages array"))?;
    Ok((1..=packages.arr_len())
        .filter_map(|i| packages.obj(i))
        .map(|pi| parse_pkginfo(&pi))
        .collect())
}

/// Resolves `target` against a parsed package list two ways: direct name
/// match (after stripping any version constraint), then falling back to a
/// "provides" match — mirrors apk.rs's resolution for the legacy format,
/// since Chimera dependency strings use the exact same conventions
/// (version-pinned names, `so:`/`cmd:` virtual capabilities).
fn find_record<'a>(records: &'a [AdbPkgInfo], target: &str) -> Option<&'a AdbPkgInfo> {
    let target_base = super::apk::strip_constraint(target);
    records.iter()
        .find(|r| r.name.eq_ignore_ascii_case(target_base))
        .or_else(|| records.iter().find(|r| {
            r.provides.iter().any(|p| super::apk::strip_constraint(p).eq_ignore_ascii_case(target_base))
        }))
}

// ── Public resolver (search + install use this) ───────────────────────────────

pub async fn resolve_adb(
    name: &str,
    client: &reqwest::Client,
    _config: &BackendConfig,
    mm: &MetadataManager,
    mirror: &MirrorConfig,
) -> Result<Option<PackageInfo>> {
    let mirror_name = mirror.id.clone();

    #[cfg(target_arch = "x86_64")]  let arch = "x86_64";
    #[cfg(target_arch = "aarch64")] let arch = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = std::env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let arch = arch.to_string();

    let index_url = mirror.index_url.replace("{arch}", &arch);
    let base_url = mirror.base_url.replace("{arch}", &arch);

    let (bytes, _) = mm.fetch(&index_url, client, false).await?;
    let records = tokio::task::spawn_blocking(move || parse_index(&bytes))
        .await
        .context("adb index parse task panicked")??;

    let Some(rec) = find_record(&records, name) else { return Ok(None) };
    let (display_name, launch_cmd) = dynamic_metadata(&rec.name, Some(&rec.description));
    let filename = format!("{}-{}.apk", rec.name, rec.version);
    let url = format!("{}/{}", base_url.trim_end_matches('/'), filename);

    Ok(Some(PackageInfo {
        name: rec.name.clone(),
        display_name,
        version: rec.version.clone(),
        source_mirror: Some(mirror_name),
        url,
        size: rec.file_size,
        launch_cmd,
        format: PackageFormat::Adb,
        filename,
        sha256: None,
        blake3: None,
        depends: rec.depends.clone(),
        provides: rec.provides.clone(),
        requires_syshub: None,
        ..Default::default()
    }))
}

// ── Package extraction (install driver uses this) ─────────────────────────────

pub struct ExtractedEntry {
    pub rel_path: String,
    pub mode: u32,
    pub content: Option<Vec<u8>>,
    pub link_target: Option<String>,
}

/// Walks a `.apk` package's path/file tree and pulls out every entry,
/// matching each regular file against its DATA block in file order —
/// exactly the algorithm `extract_v3.c`'s `apk_extract_v3_next_file` uses
/// upstream (metadata walk and data blocks are two interleaved streams
/// that must stay in lock-step).
pub fn extract_entries(bytes: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let file = parse(bytes)?;
    if file.schema != SCHEMA_PACKAGE {
        bail!("adb: expected package schema, got {:#x}", file.schema);
    }
    let root = read_root(&file.adb_block)?;
    let paths = root.obj(field::PKG_PATHS)
        .ok_or_else(|| anyhow::anyhow!("adb: package missing paths array"))?;

    let mut out = Vec::new();
    let mut data_blocks = file.data_blocks.iter();

    for pi in 1..=paths.arr_len() {
        let Some(dir) = paths.obj(pi) else { continue };
        let dir_name = dir.string(field::DI_NAME);
        let dir_mode = dir.obj(field::DI_ACL).map(|a| a.int(field::ACL_MODE) as u32).unwrap_or(0o755);
        if !dir_name.is_empty() {
            out.push(ExtractedEntry { rel_path: dir_name.clone(), mode: S_IFDIR | dir_mode, content: None, link_target: None });
        }
        let Some(files) = dir.obj(field::DI_FILES) else { continue };

        for fi in 1..=files.arr_len() {
            let Some(f) = files.obj(fi) else { continue };
            let fname = f.string(field::FI_NAME);
            let rel_path = if dir_name.is_empty() { fname } else { format!("{dir_name}/{fname}") };
            let file_mode = f.obj(field::FI_ACL).map(|a| a.int(field::ACL_MODE) as u32).unwrap_or(0o644);
            let size = f.int(field::FI_SIZE);
            let target = f.blob(field::FI_TARGET);

            if !target.is_empty() {
                if target.len() < 2 { bail!("adb: malformed target blob for '{rel_path}'"); }
                let mode_flag = u16::from_le_bytes([target[0], target[1]]) as u32;
                let rest = &target[2..];
                match mode_flag {
                    m if m == S_IFLNK || m == S_IFREG => {
                        // S_IFREG here means a hardlink (target = path of the
                        // already-extracted file to link to), not inline data.
                        out.push(ExtractedEntry {
                            rel_path,
                            mode: mode_flag | file_mode,
                            content: None,
                            link_target: Some(String::from_utf8_lossy(rest).into_owned()),
                        });
                    }
                    m if m == S_IFBLK || m == S_IFCHR || m == S_IFIFO => {
                        // Device/FIFO node — meaningless inside the union
                        // userland tree; skip, matching how xbps/apk device
                        // entries are already dropped elsewhere.
                    }
                    other => bail!("adb: unknown target mode {other:#o} for '{rel_path}'"),
                }
                continue;
            }

            if size == 0 {
                out.push(ExtractedEntry { rel_path, mode: S_IFREG | file_mode, content: Some(Vec::new()), link_target: None });
                continue;
            }

            let block = data_blocks.next()
                .ok_or_else(|| anyhow::anyhow!("adb: missing data block for '{rel_path}'"))?;
            if block.len() < 8 { bail!("adb: truncated data block header for '{rel_path}'"); }
            let path_idx = u32::from_le_bytes(block[0..4].try_into().unwrap());
            let file_idx = u32::from_le_bytes(block[4..8].try_into().unwrap());
            if path_idx as usize != pi || file_idx as usize != fi {
                bail!("adb: data block index mismatch for '{rel_path}' (expected {pi}/{fi}, got {path_idx}/{file_idx})");
            }
            let content = block[8..].to_vec();
            if content.len() as u64 != size {
                bail!("adb: data block size mismatch for '{rel_path}'");
            }
            out.push(ExtractedEntry { rel_path, mode: S_IFREG | file_mode, content: Some(content), link_target: None });
        }
    }
    Ok(out)
}
