use crate::cmd::fmt::error::Result;
use crate::zex_codec;

/// Default zexc compression level. 19 is a strong/slow level appropriate
/// for distributable packages (we compress once, decompress many times).
pub const DEFAULT_LEVEL: i32 = 19;

/// Compress tar bytes into a native `.zex` (zexc / ZEX1) frame.
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    Ok(zex_codec::compress(data, level)?)
}

/// Decompress a native `.zex` (zexc / ZEX1) frame back to tar bytes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zex_codec::decompress(data)?)
}
