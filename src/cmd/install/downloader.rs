//! downloader.rs: Streaming HTTP downloader with live progress reporting.

use std::path::Path;
use std::time::Instant;

use bytes::Bytes;
use futures::StreamExt;
use indicatif::ProgressBar;
use tokio::io::{AsyncWriteExt, BufWriter};

use super::backend::{BackendConfig, DownloadStats};
use super::runtime::{self, LogLevel};

/// Typed download error: lets equip.rs choose the right UI message.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// The connection broke after at least one byte was received.
    #[error("network connection lost mid-download after {bytes_received} bytes")]
    NetworkLost { bytes_received: u64 },

    /// The server returned a non-200 status code.
    #[error("server returned HTTP {status}")]
    HttpError { status: u16 },

    /// Any other unexpected I/O or networking error.
    #[error("download failed: {0}")]
    Other(#[from] anyhow::Error),
}

const MAX_RETRIES: u32 = 3;

/// Downloads `url` to `dest` with **up to 3 retries** (exponential backoff).
///
/// Retry policy:
///   - Attempt 1: immediate
///   - Attempt 2: wait 500 ms
///   - Attempt 3: wait 1 000 ms
///   - Attempt 4: wait 2 000 ms: then give up
///
/// Only `NetworkLost` is retried; `HttpError` (4xx/5xx) and `Other` are
/// returned immediately because retrying won't fix a missing file or bad auth.
///
/// On failure the partially-written `dest` is always cleaned up.
pub async fn download(
    url: &str,
    dest: &Path,
    client: &reqwest::Client,
    config: &BackendConfig,
    pb: &ProgressBar,
) -> std::result::Result<DownloadStats, DownloadError> {
    let delays_ms: &[u64] = &[0, 500, 1_000, 2_000];

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = delays_ms[attempt as usize];
            pb.set_message(format!(
                "↩ Retry {}/{} (waiting {}ms)…",
                attempt,
                MAX_RETRIES - 1,
                delay
            ));
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            pb.set_position(0);
            pb.set_message("Downloading…");
        }

        match try_download(url, dest, client, pb).await {
            Ok(stats) => return Ok(stats),
            Err(DownloadError::NetworkLost { bytes_received }) => {
                let _ = tokio::fs::remove_file(dest).await;
                if attempt + 1 < MAX_RETRIES {
                    runtime::log_error_rate_limited(
                        config,
                        "download.network_lost",
                        &format!("network lost while downloading {}", url),
                        60,
                    );
                    log::warn!(
                        "Network lost after {} bytes (attempt {}/{}), retrying…",
                        bytes_received,
                        attempt + 1,
                        MAX_RETRIES
                    );
                    continue;
                }
                runtime::log_event(
                    config,
                    LogLevel::Error,
                    &format!("download permanently failed after retries for {}", url),
                );
                return Err(DownloadError::NetworkLost { bytes_received });
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(dest).await;
                runtime::log_event(
                    config,
                    LogLevel::Error,
                    &format!("non-retryable download failure for {}: {}", url, e),
                );
                return Err(e);
            }
        }
    }

    let _ = tokio::fs::remove_file(dest).await;
    Err(DownloadError::NetworkLost { bytes_received: 0 })
}

/// Inner implementation; separated so `download` can always clean up on error.
async fn try_download(
    url: &str,
    dest: &Path,
    client: &reqwest::Client,
    pb: &ProgressBar,
) -> std::result::Result<DownloadStats, DownloadError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| DownloadError::Other(anyhow::anyhow!("connection failed: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(DownloadError::HttpError {
            status: status.as_u16(),
        });
    }

    let total = response.content_length().unwrap_or(0);

    if total > 0 {
        pb.set_length(total);
    }

    let file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| DownloadError::Other(anyhow::anyhow!("cannot create temp file: {}", e)))?;

    let mut writer = BufWriter::with_capacity(128 * 1024, file);

    let mut stream = response.bytes_stream();
    let mut bytes_written = 0u64;
    let start = Instant::now();

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.map_err(|e| {
            if is_network_error(&e) {
                DownloadError::NetworkLost {
                    bytes_received: bytes_written,
                }
            } else {
                DownloadError::Other(anyhow::anyhow!("stream error: {}", e))
            }
        })?;

        writer
            .write_all(&chunk)
            .await
            .map_err(|e| DownloadError::Other(anyhow::anyhow!("disk write error: {}", e)))?;

        bytes_written += chunk.len() as u64;
        pb.set_position(bytes_written);
    }

    writer
        .flush()
        .await
        .map_err(|e| DownloadError::Other(anyhow::anyhow!("flush error: {}", e)))?;

    let duration = start.elapsed();
    let speed_mbps = if duration.as_secs_f64() > 0.0 {
        (bytes_written as f64 / 1_000_000.0) / duration.as_secs_f64()
    } else {
        0.0
    };

    pb.set_position(bytes_written);
    pb.finish_with_message(pb.message().to_string());

    Ok(DownloadStats {
        bytes: bytes_written,
        duration,
        speed_mbps,
    })
}

pub async fn download_to_vec_with_progress(
    client: &reqwest::Client,
    url: &str,
    pb: ProgressBar,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut request = client.get(url);

    let safe_name = url.replace(|c: char| !c.is_alphanumeric(), "_");
    let cache_dir = "/overlayer/syshub/var/cache/zex/equip";
    let cache_path = std::path::PathBuf::from(cache_dir).join(&safe_name);

    if let Ok(meta) = std::fs::metadata(&cache_path) {
        if let Ok(modified) = meta.modified() {
            let datetime: chrono::DateTime<chrono::Utc> = modified.into();
            request = request.header("If-Modified-Since", datetime.to_rfc2822());
        }
    }

    let response = request.send().await?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        pb.finish_and_clear();
        let data = std::fs::read(&cache_path)?;
        return Ok((data, false));
    }

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
    }

    let total = response.content_length().unwrap_or(0);
    if total > 0 {
        pb.set_length(total);
    }

    let mut stream = response.bytes_stream();
    let mut buffer = Vec::with_capacity(total as usize);
    let mut bytes_received = 0u64;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        buffer.extend_from_slice(&chunk);
        bytes_received += chunk.len() as u64;
        pb.set_position(bytes_received);
    }

    pb.finish_with_message(pb.message().to_string());
    Ok((buffer, true))
}

/// Returns true when a reqwest error looks like a mid-stream network failure
/// (as opposed to a malformed response or a deliberate HTTP error).
fn is_network_error(e: &reqwest::Error) -> bool {
    e.is_body() || e.is_connect() || e.is_timeout()
}
