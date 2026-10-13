//! Seccomp fallback — currently a no-op placeholder.
//! Landlock is the primary confinement layer; elevate(1) provides the outer boundary.

use anyhow::Result;

pub fn apply_postinst_filter() -> Result<()> {
    log::debug!("seccomp postinst filter not applied (Landlock primary)");
    Ok(())
}
