//! preflight.rs — Pre-removal environment validation.
//! Checks Zainium-specific conditions — no apt/flatpak/snap.

use super::ui;

pub struct PreflightResult {
    pub root:            bool,
    pub registry_exists: bool,
    pub syshub_mounted:  bool,
    pub union_writable:  bool,
}

impl PreflightResult {
    pub fn is_ok(&self) -> bool {
        self.root && self.registry_exists && self.union_writable
    }

    pub fn report_fatal(&self) {
        if !self.root {
            ui::print_error("Root privileges required. Run with: elevate zex remove <package>");
        }
        if !self.registry_exists {
            ui::print_error(
                "Package registry not found at /overlayer/zexlib/registry/installed/\n\
                 Is the userland overlay mounted?"
            );
        }
        if !self.union_writable {
            ui::print_error(
                "Userland overlay /overlayer/zexlib/union is not writable.\n\
                 Check overlay mount status."
            );
        }
    }
}

pub fn validate() -> PreflightResult {
    PreflightResult {
        root: is_root(),
        registry_exists: std::path::Path::new(
            "/overlayer/zexlib/registry/installed"
        ).exists(),
        syshub_mounted: std::path::Path::new(
            "/overlayer/syshub/engine/services/syshub.toml"
        ).exists(),
        union_writable: is_writable("/overlayer/zexlib/union"),
    }
}

fn is_root() -> bool {
    #[cfg(unix)] { unsafe { libc::getuid() == 0 } }
    #[cfg(not(unix))] { true }
}

fn is_writable(path: &str) -> bool {
    let p = std::path::Path::new(path);
    if !p.exists() { return false; }
    let test = p.join(".zex_write_test");
    match std::fs::File::create(&test) {
        Ok(_) => { let _ = std::fs::remove_file(test); true }
        Err(_) => false,
    }
}
