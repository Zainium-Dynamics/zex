// zex/src/daemon.rs
//
// Daemon Mode: Long-Lived Background Service
// ──────────────────────────────────────────
//
// Listens on Unix socket: /var/run/zx.sock (or /run/user/{uid}/zx.sock)
//
// Benefits:
//   • Pre-loaded environment checks
//   • Warm cache from previous operations
//   • Single removal: 300ms → 50ms (IPC overhead instead of spawn)
//   • Multiple clients share single daemon (if desired)
//
// Protocol: Simple JSON over Unix socket
// Request:  {"cmd": "remove", "packages": ["firefox", "chromium"], "flags": {"recursive": true}}
// Response: {"ok": true, "freed_mb": 456.2} or {"ok": false, "err": "message"}
//
// Usage:
//   elevate zex remove daemon              # Start daemon
//   elevate zex remove --daemon-client remove firefox   # Use daemon

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const DAEMON_SOCKET: &str = "/var/run/zx.sock";

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonRequest {
    pub cmd: String,
    pub packages: Vec<String>,
    #[serde(default)]
    pub flags: DaemonFlags,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DaemonFlags {
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub yes: bool,
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freed_mb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Start daemon listening on Unix socket.
pub async fn start_daemon() -> Result<()> {
    // Ensure socket directory exists
    if let Some(parent) = Path::new(DAEMON_SOCKET).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove old socket if it exists
    if Path::new(DAEMON_SOCKET).exists() {
        std::fs::remove_file(DAEMON_SOCKET)?;
    }

    let listener = UnixListener::bind(DAEMON_SOCKET)?;
    eprintln!("✓ Daemon listening on {}", DAEMON_SOCKET);

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(handle_client(socket));
    }
}

/// Handle single client connection using newline-delimited JSON protocol.
///
/// Each request must be a single JSON object followed by a newline ('\n').
/// The response is a JSON object followed by a newline.
/// Maximum request size is 1 MiB — requests exceeding this are rejected.
async fn handle_client(socket: UnixStream) -> Result<()> {
    let (reader_half, mut writer_half) = socket.into_split();
    let reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read one newline-delimited JSON line (up to 1 MiB)
    const MAX_REQUEST_BYTES: usize = 1024 * 1024;
    reader
        .take(MAX_REQUEST_BYTES as u64)
        .read_line(&mut line)
        .await?;

    if line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<DaemonRequest>(line.trim()) {
        Ok(req) => handle_request(req).await,
        Err(e) => DaemonResponse {
            ok: false,
            freed_mb: None,
            err: Some(format!("Invalid request JSON: {}", e)),
        },
    };

    // Write response as a single newline-terminated JSON line
    let mut response_json = serde_json::to_string(&response)?;
    response_json.push('\n');
    writer_half.write_all(response_json.as_bytes()).await?;
    Ok(())
}

/// Process daemon request — delegates to the real removal engine.
async fn handle_request(req: DaemonRequest) -> DaemonResponse {
    match req.cmd.as_str() {
        "remove" => {
            if req.packages.is_empty() {
                return DaemonResponse {
                    ok: false,
                    freed_mb: None,
                    err: Some("No packages specified".to_string()),
                };
            }

            // Validate all package names before proceeding.
            for pkg in &req.packages {
                if let Err(e) = validate_package_name(pkg) {
                    return DaemonResponse {
                        ok: false,
                        freed_mb: None,
                        err: Some(format!("Invalid package name '{}': {}", pkg, e)),
                    };
                }
            }

            let opts = super::common::RunOpts {
                dry_run: false,
                force: false,
                quiet: true,
                recursive: req.flags.recursive,
                yes: true,
                verbose: req.flags.verbose,
            };

            // Run headless removal: detect backend and execute for each package.
            let mut total_freed = 0.0f64;
            let mut errors: Vec<String> = Vec::new();

            for pkg in &req.packages {
                match remove_headless(pkg, &opts).await {
                    Ok(freed) => total_freed += freed,
                    Err(e) => errors.push(format!("{pkg}: {e}")),
                }
            }

            if errors.is_empty() {
                DaemonResponse {
                    ok: true,
                    freed_mb: Some((total_freed * 10.0).round() / 10.0),
                    err: None,
                }
            } else {
                DaemonResponse {
                    ok: false,
                    freed_mb: Some((total_freed * 10.0).round() / 10.0),
                    err: Some(errors.join("; ")),
                }
            }
        }
        _ => DaemonResponse {
            ok: false,
            freed_mb: None,
            err: Some(format!("Unknown command: {}", req.cmd)),
        },
    }
}

/// Validate that a package name contains only safe characters.
/// Rejects shell metacharacters to prevent command injection.
fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow::anyhow!("package name is empty"));
    }
    if name.len() > 256 {
        return Err(anyhow::anyhow!("package name too long (max 256)"));
    }
    // Allow only characters valid in real package names across apt/flatpak/snap.
    let ok = name.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'.'
            || b == b'-'
            || b == b'_'
            || b == b'+'
            || b == b':'
            || b == b'@'
            || b == b'/'
    });
    if !ok {
        return Err(anyhow::anyhow!(
            "name contains invalid characters (only alphanumeric, ., -, _, +, :, @, / allowed)"
        ));
    }
    Ok(())
}

/// Remove a single package without any UI output — suitable for daemon mode.
/// Returns the amount of disk space freed in MB.
async fn remove_headless(name: &str, opts: &super::common::RunOpts) -> Result<f64> {
    use super::backend;
    use super::common::query_package;

    let pkg_backend = backend::find_backend(name)
        .await
        .ok_or_else(|| anyhow::anyhow!("package '{}' not found in any backend", name))?;

    let meta: Option<super::common::PackageMeta> = super::common::query_package(name).await;
    let size_mb = meta.as_ref().map(|m| m.size_mb).unwrap_or(0.0);
    let version = meta
        .as_ref()
        .map(|m| m.version.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Execute the removal using structured subprocess invocations (no sh -c).
    let success = pkg_backend.execute_removal(name, opts.recursive).await;

    if !success {
        return Err(anyhow::anyhow!("removal command failed for '{}'", name));
    }

    super::audit::log_removal(name, &version, pkg_backend.label(), size_mb, false).await;
    super::stats::Stats::record_removal(size_mb).await;

    Ok(size_mb)
}

/// Connect to daemon and send a newline-delimited JSON request, read response.
#[allow(dead_code)]
pub async fn daemon_client(req: DaemonRequest) -> Result<DaemonResponse> {
    use tokio::io::AsyncBufReadExt;
    let socket = UnixStream::connect(DAEMON_SOCKET).await?;
    let (reader_half, mut writer_half) = socket.into_split();

    // Send request as newline-terminated JSON
    let mut request_json = serde_json::to_string(&req)?;
    request_json.push('\n');
    writer_half.write_all(request_json.as_bytes()).await?;
    // Signal EOF to the server so it knows the request is complete
    writer_half.shutdown().await?;

    // Read one newline-terminated response line
    let mut reader = BufReader::new(reader_half);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;
    let response: DaemonResponse = serde_json::from_str(response_line.trim())?;
    Ok(response)
}
