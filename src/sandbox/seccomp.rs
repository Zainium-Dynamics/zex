//! Seccomp fallback: currently a no-op placeholder.

use anyhow::Result;

pub fn apply_postinst_filter() -> Result<()> {
    log::debug!("seccomp postinst filter not applied (Landlock primary)");
    Ok(())
}
