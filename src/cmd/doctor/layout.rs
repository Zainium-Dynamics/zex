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
//! musl    → syshub/x86_64-linux-musl/lib/    (libc.so, ld-musl-x86_64.so.1)
//!           syshub/x86_64-linux-musl/include/
//!           syshub/x86_64-linux-musl/bin/    (ldd, zainium-musl-gcc-x86_64)
//!           syshub/bin/x86_64-zainium-linux-musl-gcc   (cross-compiler wrapper)
//!           syshub/bin/x86_64-zainium-linux-musl-g++
//!           syshub/lib/gcc/  (GCC internal libs for musl cross-compiler)

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
/// musl sysroot root — real name is x86_64-zainium-linux-musl (verified from ls)
/// Layout:
///   bin/   — ar, as, ld, ld.bfd, ldd→../lib/ld-musl-x86_64.so.1, musl-gcc,
///             nm, objcopy, objdump, ranlib, readelf, strip
///   include/ — full musl + GCC C++ headers (c++/15.3.0/)
///   lib/   — libc.so, ld-musl-x86_64.so.1→libc.so, libgcc_s.so.1,
///             libstdc++.so.6, crt*.o, Scrt1.o, rcrt1.o,
///             gcc/x86_64-zainium-linux-musl/15.3.0/ (GCC internals),
///             ldscripts/, musl-gcc.specs, zainium-musl-x86_64.specs
pub const MUSL_SYSROOT_X86:   &str = "/overlayer/syshub/x86_64-zainium-linux-musl";
pub const MUSL_LIB_X86:       &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib";
pub const MUSL_BIN_X86:       &str = "/overlayer/syshub/x86_64-zainium-linux-musl/bin";
pub const MUSL_SPECS_X86:     &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/zainium-musl-x86_64.specs";
pub const MUSL_GCC_LIB:       &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/gcc/x86_64-zainium-linux-musl";

/// Critical files that MUST exist inside the musl sysroot
pub const MUSL_CRITICAL: &[&str] = &[
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib/libc.so",
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1",
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib/libgcc_s.so.1",
    "/overlayer/syshub/x86_64-zainium-linux-musl/bin/musl-gcc",
    "/overlayer/syshub/x86_64-zainium-linux-musl/lib/zainium-musl-x86_64.specs",
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
