//! Native `.zex` compression codec — wraps the `zexc` crate.
//!
//! Wire format: zexc stream with magic `ZEX1` containing a tar archive of:
//!   manifest.toml + signature.b3 + payload/
//!
//! APK (gzip) and XBPS (zstd/xz) use their own codecs; only native packages
//! go through this module.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use zexc::{compress as zexc_compress, decompress as zexc_decompress, CompressOptions, CompressionMode, StreamDecoder};

/// zexc frame magic (`ZEX1`).
pub const MAGIC: &[u8; 4] = b"ZEX1";

/// True when the first bytes look like a native zexc frame.
pub fn is_zex_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == MAGIC
}

/// Compress raw tar bytes into a `.zex` (zexc) frame.
///
/// `level` is clamped to 1..=22 (zexc range). Level 3 is the default for
/// development packs; 19 is appropriate for release packages.
pub fn compress(data: &[u8], level: i32) -> io::Result<Vec<u8>> {
    let level = level.clamp(1, 22) as u8;
    let opts = CompressOptions::default()
        .mode(CompressionMode::Balanced)
        .level(level);
    zexc_compress(data, &opts).map_err(|e| io::Error::other(e.to_string()))
}

/// One-shot decompress of a `.zex` (zexc) frame back to raw tar bytes.
pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    zexc_decompress(data).map_err(|e| io::Error::other(e.to_string()))
}

/// Streaming decoder over any `Read` source (file, cursor, network body).
pub fn stream_decoder<R: Read>(reader: R) -> StreamDecoder<R> {
    StreamDecoder::new(reader)
}

/// Open a path and return a streaming zexc decoder over it.
pub fn open_decoder(path: &Path) -> io::Result<StreamDecoder<File>> {
    let file = File::open(path)?;
    Ok(StreamDecoder::new(file))
}
