//! shebangpatch.rs: Rewrites `#!` interpreter lines in staged scripts.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SYSHUB_BIN: &str = "/overlayer/syshub/bin";
const UNION_BIN: &str = "/overlayer/zexlib/union/bin";

/// FHS bin/sbin roots a shebang interpreter path can start with: longest
/// prefixes first so `/usr/local/bin/` matches before the shorter
/// `/usr/bin/`-adjacent... actually these don't overlap as prefixes of
/// each other, order doesn't matter for correctness here, just listed by
/// how common each is.
const FHS_BIN_ROOTS: &[&str] = &[
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
];

fn is_script(head: &[u8]) -> bool {
    head.starts_with(b"#!")
}

/// Maps an FHS interpreter path (e.g. `/bin/sh`, `/usr/bin/env`) to its
/// real Zainium location. Prefers syshub if the binary is actually
/// present there: core interpreters (`sh`/`bash`/`env`/`python`/...) are
/// syshub-provided (confirmed: `bash` is one of syshub's own packages) —
/// falling back to the union tree for anything a T2/T3/T4 dependency
/// itself installed there instead. If neither exists yet (interpreter not
/// installed, or staged-but-not-yet-committed in this same transaction),
/// defaults to syshub: the common case for the core interpreters a
/// shebang almost always names. Returns `None` if `interp` isn't under a
/// recognized FHS bin root at all: nothing to rewrite.
fn rewrite_interpreter(interp: &str) -> Option<String> {
    let base_name = FHS_BIN_ROOTS
        .iter()
        .find_map(|root| interp.strip_prefix(root))?;
    if base_name.is_empty() {
        return None;
    }
    if let Some(found) = find_existing(base_name) {
        return Some(found);
    }
    if base_name == "sh" {
        for candidate in ["bash", "dash", "ash", "busybox"] {
            if let Some(found) = find_existing(candidate) {
                return Some(found);
            }
        }
    }
    Some(format!("{SYSHUB_BIN}/{base_name}"))
}

/// Returns the real path to `bin_name` if it exists under syshub (checked
/// first) or the union tree, `None` if it exists in neither.
fn find_existing(bin_name: &str) -> Option<String> {
    let syshub_path = format!("{SYSHUB_BIN}/{bin_name}");
    if Path::new(&syshub_path).exists() {
        return Some(syshub_path);
    }
    let union_path = format!("{UNION_BIN}/{bin_name}");
    if Path::new(&union_path).exists() {
        return Some(union_path);
    }
    None
}

/// Rewrite one file's shebang line in place, if it has one that needs it.
/// No-op on anything that isn't a `#!`-script, or whose interpreter path
/// isn't under a recognized FHS bin root, or whose shebang is already
/// correct.
pub fn patch_one(path: &Path) -> anyhow::Result<()> {
    let is_regular = path
        .symlink_metadata()
        .map(|m| m.is_file())
        .unwrap_or(false);
    if !is_regular {
        return Ok(());
    }

    let mut head = [0u8; 4096];
    let n = {
        let mut f = std::fs::File::open(path)?;
        f.read(&mut head)?
    };
    let head = &head[..n];
    if !is_script(head) {
        return Ok(());
    }
    let Some(nl) = head.iter().position(|&b| b == b'\n') else {
        return Ok(());
    };
    let Ok(first_line) = std::str::from_utf8(&head[..nl]) else {
        return Ok(());
    };

    let rest = &first_line[2..];
    let (interp, args) = rest
        .trim_start()
        .split_once(' ')
        .unwrap_or((rest.trim_start(), ""));

    let Some(new_interp) = rewrite_interpreter(interp) else {
        return Ok(());
    };

    let new_shebang = if args.is_empty() {
        format!("#!{new_interp}")
    } else {
        format!("#!{new_interp} {args}")
    };
    if new_shebang == first_line {
        return Ok(());
    }

    let full = std::fs::read(path)?;
    let old_nl = full.iter().position(|&b| b == b'\n').unwrap_or(full.len());
    let mut out = new_shebang.into_bytes();
    out.push(b'\n');
    out.extend_from_slice(&full[(old_nl + 1).min(full.len())..]);

    let mut out_f = std::fs::File::create(path)?;
    out_f.write_all(&out)?;
    Ok(())
}

/// Patch every staged script's shebang line in place.
pub fn patch_staged_scripts(staged_files: &[PathBuf]) -> anyhow::Result<()> {
    for path in staged_files {
        patch_one(path).map_err(|e| {
            anyhow::anyhow!("failed to patch shebang for '{}': {e}", path.display())
        })?;
    }
    Ok(())
}
