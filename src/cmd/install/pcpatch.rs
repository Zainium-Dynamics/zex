//! pcpatch.rs — Rewrites pkg-config `.pc` file path variables for staged
//! userland packages.
//!
//! Alpine/Void `-dev` packages ship pkg-config `.pc` metadata with the
//! `prefix=`/`libdir=`/`includedir=` variables baked in at build time
//! against their own FHS layout (`prefix=/usr`) — none of which resolves
//! under Zainium's `/overlayer/zexlib/union/` install target. Even
//! packages substrate has already repackaged into a `.zex` container can
//! ship a WRONG rewrite: confirmed live against the real, production
//! `curl-dev-8.21.0.zex` — its `libcurl.pc` ships `prefix=/overlayer/syshub`
//! even though the package itself installs under
//! `/overlayer/zexlib/union` (per its own `manifest.toml`'s `[install]`
//! map). Substrate's own rewrite pass doesn't distinguish syshub-tier from
//! userland-union-tier targets, so this can't be trusted and has to be
//! corrected here, at install time, against the root the package is
//! actually landing under.
//!
//! Left unpatched, any tool invoking `pkg-config --cflags`/`--libs`
//! against a dependency gets headers/lib paths that don't exist on disk,
//! and compiling against that dependency fails outright.
//!
//! This is a plain-text rewrite, not an ELF concern — there's nothing for
//! `oxipatch` (an ELF patcher; see `elfpatch.rs`) to do here.
//!
//! Must run while `staged_files` are still under the temp stage directory
//! (same timing constraint as `elfpatch::patch_staged_elfs` — before
//! `ActivationPlan::commit()` and before
//! `crate::immutable::try_set_immutable` runs on the committed files).

use std::path::{Path, PathBuf};

/// Roots this rewrite recognizes and will always replace with the
/// package's real target root, regardless of which one shows up in a
/// given `.pc` — a raw distro package says `/usr`; a mis-rewritten
/// substrate repackage can say the wrong Zainium root entirely. Order
/// matters: `/usr/local` must be checked before the shorter `/usr` so it
/// isn't matched as a `/usr` prefix with `/local/...` left dangling.
const KNOWN_ROOTS: &[&str] = &[
    "/usr/local",
    "/usr",
    "/overlayer/syshub",
    "/overlayer/zexlib/union",
];

fn is_pc_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pc"))
        .unwrap_or(false)
}

/// Rewrite one `.pc` file's variable-definition lines in place.
///
/// Only touches `identifier=value` lines whose value is a literal
/// absolute path under a [`KNOWN_ROOTS`] entry — comments, the
/// `Name:`/`Version:`/`Libs:`/`Cflags:`/... metadata section, and
/// variable-interpolated values (`${prefix}/lib`) are left completely
/// untouched. Interpolated values don't need touching: fixing the
/// `prefix=` line alone already propagates through everything defined
/// relative to it, which is how the overwhelming majority of real `.pc`
/// files are written.
fn patch_one(path: &Path, target_root: &str) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(path)?;
    let mut changed = false;

    let rewritten: Vec<String> = content
        .lines()
        .map(|line| {
            let Some(eq) = line.find('=') else {
                return line.to_string();
            };
            let key = &line[..eq];
            if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return line.to_string();
            }
            let value = &line[eq + 1..];
            if value.starts_with('$') {
                return line.to_string();
            }
            for root in KNOWN_ROOTS {
                if let Some(rest) = value.strip_prefix(root) {
                    if rest.is_empty() || rest.starts_with('/') {
                        if value != format!("{target_root}{rest}") {
                            changed = true;
                        }
                        return format!("{key}={target_root}{rest}");
                    }
                }
            }
            line.to_string()
        })
        .collect();

    if changed {
        let mut out = rewritten.join("\n");
        if content.ends_with('\n') {
            out.push('\n');
        }
        std::fs::write(path, out)?;
    }
    Ok(())
}

/// Patch every staged `.pc` file's path variables in place.
///
/// `target_root` is the real base directory this package's files are
/// actually landing under (e.g. `/overlayer/zexlib/union` for a normal
/// userland install) — callers derive it from wherever they're actually
/// staging files, never from anything already inside the `.pc` file.
pub fn patch_staged_pkgconfig(staged_files: &[PathBuf], target_root: &str) -> anyhow::Result<()> {
    for path in staged_files {
        let is_regular = path
            .symlink_metadata()
            .map(|m| m.is_file())
            .unwrap_or(false);
        if !is_regular || !is_pc_file(path) {
            continue;
        }
        patch_one(path, target_root).map_err(|e| {
            anyhow::anyhow!("failed to patch pkg-config file '{}': {e}", path.display())
        })?;
    }
    Ok(())
}
