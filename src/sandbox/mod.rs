//! In-process sandbox helpers for install/remove child processes.

#[cfg(target_os = "linux")]
mod landlock_rules;
#[cfg(target_os = "linux")]
mod seccomp;

use std::path::Path;

/// Apply sandbox restrictions in a child process (call from `Command::pre_exec`).
#[cfg(target_os = "linux")]
pub unsafe fn child_pre_exec(store_path: &Path) -> std::io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    if let Err(e) = landlock_rules::restrict_postinst(store_path) {
        log::debug!("Landlock sandbox unavailable (non-fatal): {e}");
        seccomp::apply_postinst_filter()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub unsafe fn child_pre_exec(_store_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Configure a `Command` to run a post-install script inside the sandbox.
pub fn wrap_postinst_command(
    mut cmd: std::process::Command,
    store_path: &Path,
) -> std::process::Command {
    let store = store_path.to_path_buf();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || {
                // SAFETY: called in single-threaded fork child before exec.
                child_pre_exec(&store)
            });
        }
    }
    let _ = store_path;
    cmd
}