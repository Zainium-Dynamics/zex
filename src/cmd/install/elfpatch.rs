//! elfpatch.rs — Rewrites ELF `PT_INTERP`/`RPATH` for staged binaries.
//!
//! Alpine (`.apk`), Void (`.xbps`), and Chimera (`.adb`) packages are built
//! against their own distro's FHS layout: their binaries carry
//! `PT_INTERP` pointing at `/lib/ld-musl-x86_64.so.1` and `RPATH`/`RUNPATH`
//! entries under `/usr/lib`. Neither resolves under Zainium's
//! `/overlayer/` tree, so without rewriting, these packages install but
//! their binaries can't actually run.
//!
//! Called unconditionally by `installer.rs`, regardless of container
//! format — NOT just for raw `.apk`/`.xbps`/`.adb`. A `.zex` container
//! does not by itself mean "already built against `/overlayer/`": a
//! foreign package substrate has repackaged INTO a `.zex` container
//! (confirmed live: the real `curl-dev-8.21.0.zex`, which ships
//! `native = false` in its own manifest.toml) still carries whatever the
//! source distro built it against unless something rewrites it. Only a
//! genuinely T1-native `.zex` is already correct, and this pass is a
//! no-op against one — [`patch_one`] only rewrites entries it recognizes
//! as FHS paths and otherwise just appends the fallback RPATH entries if
//! they're missing.
//!
//! Built on [`oxipatch`], a from-scratch, tested patchelf-equivalent
//! library (not reimplemented here — see `next.md`/`plan.md` for why).
//!
//! Must run while `staged_files` are still under the temp stage directory
//! (before `ActivationPlan::commit()` and before
//! `crate::immutable::try_set_immutable` runs on the committed files) —
//! patching after commit would mean mutating already-immutable, live
//! union files.

use std::io::Read;
use std::path::{Path, PathBuf};

use oxipatch::elf::ElfFile;

/// Canonical musl dynamic linker for this OS — confirmed against a real
/// syshub-toolchain-built binary (`readelf -l .../syshub/bin/curl`).
const ZEX_INTERP: &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";

/// Where zex-installed userland packages' shared libraries live.
const ZEX_LIB_RPATH: &str = "/overlayer/zexlib/union/lib";

/// Where syshub's own immutable-base libraries live. A T2/T3/T4
/// dependency whose files are already provided by syshub under a
/// different package name (e.g. Void's `ncurses-libs`, syshub's own
/// `ncurses`) is correctly skipped at install time rather than
/// duplicated into `ZEX_LIB_RPATH` — but that means a binary linking
/// against it (confirmed live: `tmux` needing `libncursesw.so.6`) can
/// only find it here. Without this, every such binary fails to load at
/// runtime with "No such file or directory" even though the library
/// genuinely exists on disk, just outside the one directory RPATH used
/// to search.
const SYSHUB_LIB_RPATH: &str = "/overlayer/syshub/lib";

/// glibc's own directory (the `glibc` package): its loader, libc and the
/// libraries built against it. Kept apart from musl's, never on musl's path.
pub const GLIBC_LIB_DIR: &str = "/overlayer/zexlib/union/x86_64-zainium-linux-gnu/lib";

/// glibc's loader and libc themselves, and every program or library linked
/// against glibc: started by glibc's loader (`ld-linux`) or needing
/// `libc.so.6`. These keep their loader and library path — musl's loader
/// can't run them and the musl libraries in syshub/union can't load into
/// them.
pub fn is_glibc_elf(f: &ElfFile) -> bool {
    let named_glibc = |n: &str| n == "libc.so.6" || n.starts_with("ld-linux");
    f.interpreter()
        .ok()
        .flatten()
        .is_some_and(|i| i.contains("/ld-linux"))
        || f.soname().ok().flatten().is_some_and(|s| named_glibc(&s))
        || f.needed_libs()
            .is_ok_and(|libs| libs.iter().any(|l| named_glibc(l)))
}

fn is_elf(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

fn is_fhs_lib_entry(entry: &str) -> bool {
    entry == "/usr/lib"
        || entry == "/lib"
        || entry == "/usr/lib64"
        || entry == "/lib64"
        || entry.starts_with("/usr/lib/")
        || entry.starts_with("/lib/")
        || entry.starts_with("/usr/lib64/")
        || entry.starts_with("/lib64/")
}

/// Rewrite RPATH/RUNPATH entries that point at FHS lib dirs to
/// [`ZEX_LIB_RPATH`], keep everything else (e.g. `$ORIGIN`-relative
/// entries, or an already-correct entry on a re-patch), dedup preserving
/// order, and guarantee [`ZEX_LIB_RPATH`] is present even if the binary
/// shipped no RPATH at all (it still needs to find co-installed libs in
/// the union tree).
fn rebuild_rpath(existing: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for entry in existing.split(':').filter(|e| !e.is_empty()) {
        let mapped = if is_fhs_lib_entry(entry) {
            ZEX_LIB_RPATH
        } else {
            entry
        };
        if !out.iter().any(|e| e == mapped) {
            out.push(mapped.to_string());
        }
    }
    if !out.iter().any(|e| e == ZEX_LIB_RPATH) {
        out.push(ZEX_LIB_RPATH.to_string());
    }
    if !out.iter().any(|e| e == SYSHUB_LIB_RPATH) {
        out.push(SYSHUB_LIB_RPATH.to_string());
    }
    out.join(":")
}

fn patch_one(path: &Path) -> anyhow::Result<()> {
    let mut f = ElfFile::open(path)?;

    let has_interp = f.interpreter()?.is_some();
    let has_needed = !f.needed_libs()?.is_empty();

    // A file with neither an interpreter nor any DT_NEEDED entries is
    // fully self-contained (a static-PIE executable, e.g. built by
    // musl-gcc -static-pie) — no dynamic linker ever runs for it, so
    // RPATH is genuinely unused regardless of what it's set to. Skip
    // patching entirely rather than just skipping set_interpreter:
    // confirmed live against a real Chimera package
    // (apk-tools-static-bin's apk.static) that growing the .dynamic
    // section to add an RPATH entry corrupted its self-relocation table
    // (DT_RELACOUNT) — the binary went from running fine unpatched to
    // segfaulting on every invocation, args or not, after only the RPATH
    // add. Ordinary shared objects (.so) also have no interpreter but do
    // have DT_NEEDED (their own transitive deps), so they still reach the
    // RPATH-rewrite step below unaffected — confirmed separately against
    // real Alpine .so deps (libcurl.so, libbrotlicommon.so).
    if !has_interp && !has_needed {
        return Ok(());
    }
    if is_glibc_elf(&f) {
        return Ok(());
    }

    let existing_rpath = f.rpath()?.unwrap_or_default();
    let new_rpath = rebuild_rpath(&existing_rpath);
    let rpath_unchanged = existing_rpath == new_rpath;

    // Only executables carry a PT_INTERP segment — plain shared objects
    // (.so, loaded by an already-running dynamic linker, not exec'd
    // directly) have none, and oxipatch errors if asked to set one where
    // none exists. Confirmed against real Alpine deps (e.g.
    // libbrotlicommon.so.1.2.0), not assumed.
    let interp_unchanged = if has_interp {
        f.interpreter()?.as_deref() == Some(ZEX_INTERP)
    } else {
        true
    };

    // Nothing to do — don't touch the file at all. This isn't just an
    // optimization: `elfpatch::patch_staged_elfs` now runs unconditionally
    // on every package, including genuinely T1-native binaries that were
    // previously never patched at all. Calling set_interpreter/set_rpath/
    // commit/write_in_place unconditionally would rewrite the .dynamic
    // section of every one of them even when the values wouldn't actually
    // change — exactly the operation category that corrupted a real
    // static-PIE binary's self-relocation table (see the comment above).
    // Skipping the write entirely when both are already correct means a
    // T1-native binary (or a re-patched T2/T3/T4 one) with no actual
    // change to make never risks that at all.
    if rpath_unchanged && interp_unchanged {
        return Ok(());
    }

    if has_interp && !interp_unchanged {
        f.set_interpreter(ZEX_INTERP)?;
    }
    if !rpath_unchanged {
        // force_rpath = true → legacy DT_RPATH, matching this OS's own
        // toolchain-built binaries (confirmed via readelf, not RUNPATH).
        f.set_rpath(&new_rpath, true)?;
    }

    f.commit()?;
    f.write_in_place()?;
    Ok(())
}

/// Patch every staged ELF file's interpreter and RPATH in place.
///
/// `staged_files` must still be under the temp stage directory (mutable,
/// pre-commit). Any failure is a hard error — an unpatched interpreter
/// means a broken package, not a best-effort concern.
pub fn patch_staged_elfs(staged_files: &[PathBuf]) -> anyhow::Result<()> {
    for path in staged_files {
        let is_regular = path
            .symlink_metadata()
            .map(|m| m.is_file())
            .unwrap_or(false);
        if !is_regular || !is_elf(path) {
            continue;
        }
        patch_one(path).map_err(|e| {
            anyhow::anyhow!(
                "failed to patch ELF interpreter/RPATH for '{}': {e}",
                path.display()
            )
        })?;
    }
    Ok(())
}
