//! layout.rs — Zainium filesystem layout constants.
//!
//! This is the single source of truth for every path the doctor checks.
//! Matches real on-disk layout from `ls /overlayer/syshub`:
//!   bin  doc  drivers  engine  etc  include  lib  lib64  libexec  sbin  share  var
//!   x86_64-linux-musl/   ← musl sysroot (bin, lib, include)
//!
//! relibc  → syshub/lib64/   (x86_64 dynamic linker, libc.so, ld-zainium-x86_64.so.2)
//!           syshub/lib/    (aarch64)
//!           syshub/bin/    (ldd symlink, zainium-relibc-gcc-* wrappers)
//!           syshub/include/ (relibc headers)
//!
//! musl    → syshub/x86_64-zainium-linux-musl/lib/    (libc.so, ld-musl-x86_64.so.1)
//!           syshub/x86_64-zainium-linux-musl/include/
//!           syshub/x86_64-zainium-linux-musl/bin/    (ldd only)
//!           syshub/bin/x86_64-zainium-linux-musl-gcc   (cross-compiler, and
//!             every other -gcc-*/binutils tool — all live directly under
//!             the general syshub/bin/, not under the sysroot)
//!           syshub/lib/libgcc_s.so.1  (also general syshub/lib/, not the sysroot)

// ── Base roots ────────────────────────────────────────────────────────────────
pub const SYSHUB:           &str = "/overlayer/syshub";
pub const UNION:            &str = "/overlayer/zexlib/union";
pub const INSTALLED_DIR:    &str = "/overlayer/zexlib/registry/installed";
pub const PACKAGES_TOML:    &str = "/overlayer/zexlib/registry/packages.toml";
pub const SYSHUB_MANIFEST:  &str = "/overlayer/syshub/engine/services/syshub.toml";
pub const ZAISYS_KERNEL:    &str = "/overlayer/zaisys/kernel";

// ── relibc install locations ──────────────────────────────────────────────────
/// relibc dynamic linker + libc.so — real dir is lib/, lib64 is a symlink → lib/
pub const RELIBC_LIB:       &str = "/overlayer/syshub/lib";
/// lib64 → lib symlink (checked as symlink, not a separate dir)
pub const RELIBC_LIB64_SYMLINK: &str = "/overlayer/syshub/lib64";
/// Critical relibc files — real location is lib/, lib64 is a symlink to lib/
pub const RELIBC_CRITICAL: &[&str] = &[
    "/overlayer/syshub/lib/libc.so",
    "/overlayer/syshub/lib/libc.so.2",
    "/overlayer/syshub/lib/ld-zainium-x86_64.so.2",
];
/// lib64 must exist as a symlink pointing to lib/
pub const RELIBC_LIB64_SYMLINK_TARGET: &str = "lib";

// ── musl install locations ────────────────────────────────────────────────────
/// musl sysroot root — real name is x86_64-zainium-linux-musl (verified from ls).
/// Layout (corrected against a real root — the previous version of this
/// comment had the cross-compiler/binutils/specs location wrong):
///   bin/   — ldd only. The cross-compiler (`x86_64-zainium-linux-musl-gcc`
///             and friends: `-g++`, `-gcc-16`, `-gcc-ar`, `-gcc-nm`,
///             `-gcc-ranlib`) and binutils (`x86_64-zainium-linux-musl-ar`,
///             `-as`, `-ld`, `-ld.bfd`, `-nm`, `-objcopy`, `-objdump`,
///             `-ranlib`, `-readelf`, `-strip`, `-size`, `-strings`,
///             `-addr2line`, `-c++`, `-c++filt`, `-elfedit`, `-gprof`) all
///             live directly under the general `syshub/bin/`, not here.
///   include/ — full musl + GCC C++ headers (c++/15.3.0/)
///   lib/   — libc.so, ld-musl-x86_64.so.1, libc.a + the other static
///             libs (libm.a, libpthread.a, libcrypt.a, libdl.a, libresolv.a,
///             librt.a, libutil.a, libxnet.a), crt1.o/crti.o/crtn.o,
///             Scrt1.o, rcrt1.o. `libgcc_s.so.1` and any GCC specs file
///             are NOT here — `libgcc_s.so.1` lives in the general
///             `syshub/lib/`, and no `.specs` file exists in this build
///             at all.
pub const MUSL_SYSROOT_X86:   &str = "/overlayer/syshub/x86_64-zainium-linux-musl";
pub const MUSL_LIB_X86:       &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib";
pub const MUSL_BIN_X86:       &str = "/overlayer/syshub/x86_64-zainium-linux-musl/bin";

/// Critical files that MUST exist for a working musl toolchain — only the
/// libc itself lives inside the musl sysroot proper
/// (`x86_64-zainium-linux-musl/lib/`); the cross-compiler, binutils, and
/// libgcc all live directly under the general `syshub/bin/`/`syshub/lib/`,
/// not namespaced under the sysroot. Confirmed live against a real root:
/// the sysroot's own `bin/` contains only `ldd`, there is no `musl-gcc`
/// anywhere by that name (the real cross-compiler is
/// `x86_64-zainium-linux-musl-gcc`), and no `.specs` file exists in this
/// build at all — the previous list checked all three of these at the
/// wrong path (or a name that never existed), so a real, correctly-built
/// system permanently failed this check.
pub const MUSL_CRITICAL: &[&str] = &[
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib/libc.so",
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1",
    "/overlayer/syshub/lib/libgcc_s.so.1",
    "/overlayer/syshub/bin/x86_64-zainium-linux-musl-gcc",
];

// ── syshub layout — standard dirs that must exist ────────────────────────────
pub const SYSHUB_REQUIRED_DIRS: &[&str] = &[
    "/overlayer/syshub/bin",
    "/overlayer/syshub/sbin",
    "/overlayer/syshub/lib",
    "/overlayer/syshub/include",
    "/overlayer/syshub/share",
    "/overlayer/syshub/etc",
    "/overlayer/syshub/libexec",
    "/overlayer/syshub/drivers",
    "/overlayer/syshub/engine",
    "/overlayer/syshub/x86_64-zainium-linux-musl",
];

// ── libc boundary — forbidden glibc artifacts ─────────────────────────────────
/// .so files whose presence indicates a glibc-linked binary crept into the system
pub const GLIBC_FORBIDDEN_SO: &[&str] = &[
    "libc.so.6",
    "libpthread.so.0",
    "libm.so.6",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
    "libgcc_s.so.1",   // glibc's GCC runtime shim — forbidden
];

// ── userland scan dirs ─────────────────────────────────────────────────────────
pub const UNION_LIB:          &str = "/overlayer/zexlib/union/lib";
pub const UNION_LIB64:        &str = "/overlayer/zexlib/union/lib64";
pub const UNION_BIN:          &str = "/overlayer/zexlib/union/bin";
