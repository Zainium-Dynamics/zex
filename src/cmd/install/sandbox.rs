//! Post-install script execution with a minimal environment.

use std::path::Path;
use std::process::Command;

const BASH: &str = "/overlayer/syshub/bin/bash";

/// Run a package post-install script in an isolated minimal environment.
///
/// `action_arg` is `None` for Alpine's `.post-install` (run with no
/// arguments) and `Some("post-install")` for Void's single `INSTALL`
/// script, which is invoked once per lifecycle action via argv[1].
pub fn run_postinst(
    script_path: &Path,
    store_path: &Path,
    action_arg: Option<&str>,
) -> anyhow::Result<()> {
    if !script_path.exists() {
        return Ok(());
    }

    let bash = if Path::new(BASH).exists() {
        BASH
    } else {
        "bash"
    };

    let mut cmd = Command::new(bash);
    cmd.arg(script_path);
    if let Some(arg) = action_arg {
        cmd.arg(arg);
    }
    cmd.env_clear()
        .env(
            "PATH",
            "/overlayer/syshub/bin:/overlayer/zexlib/union/bin:/bin",
        )
        .env("HOME", "/root")
        .env("ZEX_STORE", store_path)
        .env("ZEX_ROOT", "/overlayer/zexlib/union");

    let mut cmd = crate::sandbox::wrap_postinst_command(cmd, store_path);
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("failed to execute post-install script: {e}"))?;

    if !status.success() {
        anyhow::bail!(
            "post-install script exited with status {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}
