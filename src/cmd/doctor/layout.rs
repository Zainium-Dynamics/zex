//! layout.rs — Zainium filesystem layout constants.
//!
//! This is the single source of truth for every path the doctor checks.
//! Matches the real on-disk layout of `/overlayer/syshub`:
//!   bin  drivers  engine  etc  include  lib  libexec  sbin  share  var
//!   x86_64-zainium-linux-musl/   ← musl (bin, lib, include)
//! There is no lib64.
//!
//! musl    → syshub/x86_64-zainium-linux-musl/lib/    (libc.so, ld-musl-x86_64.so.1)
//!           syshub/x86_64-zainium-linux-musl/include/
//!           syshub/x86_64-zainium-linux-musl/bin/    (ldd only)
//!           syshub/bin/x86_64-zainium-linux-musl-gcc   (the compiler and every
//!             other -gcc-*/binutils tool live directly under syshub/bin/)
//!           syshub/lib/libgcc_s.so.1  (also general syshub/lib/)
//!
//! glibc   → union/x86_64-zainium-linux-gnu/          (the `glibc` package, when
//!             installed: its loader, libraries, headers and tools in one directory,
//!             never on musl's library path)

// ── Base roots ────────────────────────────────────────────────────────────────
pub const SYSHUB: &str = "/overlayer/syshub";
pub const UNION: &str = "/overlayer/zexlib/union";
pub const INSTALLED_DIR: &str = "/overlayer/zexlib/registry/installed";
pub const PACKAGES_TOML: &str = "/overlayer/zexlib/registry/packages.toml";
pub const SYSHUB_MANIFEST: &str = "/overlayer/syshub/engine/services/syshub.toml";
pub const ZAISYS_KERNEL: &str = "/overlayer/zaisys/kernel";

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
pub const MUSL_SYSROOT_X86: &str = "/overlayer/syshub/x86_64-zainium-linux-musl";
pub const MUSL_LIB_X86: &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib";
pub const MUSL_BIN_X86: &str = "/overlayer/syshub/x86_64-zainium-linux-musl/bin";

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

// ── glibc ─────────────────────────────────────────────────────────────────────
/// glibc's own directory (the `glibc` package).
pub const GLIBC_DIR: &str = "/overlayer/zexlib/union/x86_64-zainium-linux-gnu";
/// What a working glibc install has.
pub const GLIBC_CRITICAL: &[&str] = &[
    "/overlayer/zexlib/union/x86_64-zainium-linux-gnu/lib/ld-linux-x86-64.so.2",
    "/overlayer/zexlib/union/x86_64-zainium-linux-gnu/lib/libc.so.6",
];

// ── libc boundary — forbidden glibc artifacts ─────────────────────────────────
/// glibc's files outside its own directory: on musl's library path they would
/// be found by musl programs and the musl toolchain
pub const GLIBC_FORBIDDEN_SO: &[&str] = &[
    "libc.so.6",
    "libpthread.so.0",
    "libm.so.6",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
];

// ── userland scan dirs ─────────────────────────────────────────────────────────
pub const UNION_LIB: &str = "/overlayer/zexlib/union/lib";
pub const UNION_LIB64: &str = "/overlayer/zexlib/union/lib64";
pub const UNION_BIN: &str = "/overlayer/zexlib/union/bin";

/// Where systemd looks units up by name; a unit link (an alias, a `.wants/`
/// entry) is resolved by its target's name, not as a path.
pub const SYSTEMD_UNIT_DIRS: &[&str] = &[
    "/overlayer/syshub/etc/systemd/system",
    "/overlayer/syshub/lib/systemd/system",
    "/overlayer/syshub/etc/systemd/user",
    "/overlayer/syshub/lib/systemd/user",
];
