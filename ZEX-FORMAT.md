# ZEX Package Format Specification

Version: 1.0 — ZainiumOS 1.0

## Overview

A `.zex` file is a **tar archive compressed with zexc** containing
exactly two top-level entries: `manifest.toml` and `payload/`.

```
myapp-1.0.0.zex
├── manifest.toml
└── payload/
    ├── bin/
    │   └── myapp
    ├── lib/
    │   └── libmyapp.so
    └── share/
        └── man/man1/myapp.1
```

## Compression

| Field       | Value |
|-------------|-------|
| Algorithm   | **zexc** (native compressor, crate `zexc`) |
| Magic bytes | `5A 45 58 31` (`ZEX1`) |
| Level       | 3 (default), 19 (release) |
| Extension   | `.zex` only |
| Inner archive | tar containing `manifest.toml` + `signature.b3` + `payload/` |

> Note: Alpine `.apk` uses gzip and Void `.xbps` uses zstd/xz. Those are
> **compat** formats — only native Zainium packages use zexc.

## manifest.toml Schema

### [package] — required

```toml
[package]
name        = "myapp"          # string, required — lowercase, no spaces
version     = "1.0.0"          # string, required — any version scheme
description = "My application" # string, required — one line
license     = "MIT"            # string, required — SPDX identifier
maintainer  = "Name <email>"   # string, required

# Optional fields:
homepage    = "https://..."    # string
build_type  = "static"         # "static" | "dynamic" | "firmware"
libc_target = "musl"           # "musl" | "relibc" | "freestanding"
edition     = "stable"         # "stable" | "nightly" | "lts" | "testing"

# Cryptographic fields (required for repository upload):
ed25519_sig = "BASE64..."      # Ed25519 sig over blake3(payload/)
blake3      = "HEX64..."       # Blake3 hash of payload/ tree

# Dependencies:
depends  = ["libssl >= 3.0", "zlib"]
provides = ["openssl-compat"]  # virtual capabilities
tags     = ["network", "tls"]

requires_syshub = ">= 6.10"   # minimum syshub version
```

### [install] — required

Maps `payload/` subdirectories to absolute on-disk destinations.
All values MUST begin with `/overlayer/`.

```toml
[install]
bin   = "/overlayer/zexlib/union/bin"
lib   = "/overlayer/zexlib/union/lib"
share = "/overlayer/zexlib/union/share"
etc   = "/overlayer/zexlib/union/etc"
# Any key maps any payload/ subdir to any /overlayer/ path
```

### [remove] — required

Exact file list written by the installer. Shipped in the package
so the format is auditable. `zex remove` uses this verbatim.

```toml
[remove]
files    = ["/overlayer/zexlib/union/bin/myapp"]
symlinks = ["/overlayer/zexlib/union/bin/myapp-link"]
dirs     = ["/overlayer/zexlib/union/share/myapp"]
```

All paths MUST begin with `/overlayer/`. Path traversal (`../`) is rejected.

### [editions] — optional

```toml
[editions]
available = ["stable", "nightly"]
default   = "stable"
```

### [hooks] — optional

```toml
[hooks]
pre_install  = "payload/hooks/pre_install.sh"
post_install = "payload/hooks/post_install.sh"
pre_remove   = "payload/hooks/pre_remove.sh"
post_remove  = "payload/hooks/post_remove.sh"
```

Hook scripts must be relative paths under `payload/hooks/`.

## Payload Layout

```
payload/
├── bin/        → maps to [install].bin
├── lib/        → maps to [install].lib
├── share/      → maps to [install].share
├── etc/        → maps to [install].etc
└── hooks/      → hook scripts (not installed to disk)
```

The installer walks `payload/`, maps each file's leading component via
`[install]`, and writes the file to the mapped destination.

## Signing

### Key Hierarchy

```
Root signing key (offline, HSM)
  └─ Repository signing key (per-tier, yearly rotation)
       └─ Package ed25519_sig (per-package)
```

### Generating a keypair

```bash
zex fmt keygen [-o <output-dir>] [--force]
```

Writes `signing.key` (hex, 32 bytes — the **private** key, mode 0600) and
`trust.pub` (base64, 32 bytes — the **public** verifying key). Move
`signing.key` to the builder machine only, at
`/overlayer/syshub/etc/zex/signing.key`; ship `trust.pub` as part of every
Zainium OS image, at `/overlayer/syshub/engine/services/trust.pub`. Never
commit either to source control. Without a real keypair in place, `zex fmt
pack` silently falls back to a hardcoded, publicly-known dev key (logged as
a warning) — fine for local testing, never for a real release.

### Signing a Package (zex fmt)

```
blake3_hash = blake3(all files in payload/, sorted by path)
ed25519_sig = ed25519_sign(blake3_hash, repository_private_key)
```

Write `ed25519_sig` (base64) and `blake3` (hex) into `manifest.toml`.

> **Historical note (fixed 2026-07-19):** the signer implementation used to
> hash `blake3_hash` a second time before signing it, so the verifier's
> independently-recomputed digest could never match what was actually
> signed — every real `.zex` signature failed verification, regardless of
> key. This was never caught earlier because no real keypair had ever been
> deployed (the packer silently used an insecure dev-only fallback key
> instead). Fixed in `Signer128::sign()`; the scheme described above is
> what's actually implemented now, confirmed via a real pack→sign→verify
> round trip with a freshly generated keypair.

### Verification (zex install)

```
1. Extract manifest.toml from .zex
2. Recompute blake3(payload/) → verify == manifest.package.blake3
3. ed25519_verify(blake3_hash, manifest.package.ed25519_sig, public_key)
4. Verify sha256(full .zex) == ledger entry (from zex_ledger-x86_64.toml)
```

## Repository Ledger

The Zainium T1 repository serves a TOML ledger at:

```
https://archive.zainiumdynamics.tech/userland/x86_64/zex_ledger-x86_64.toml
```

```toml
[packages.ripgrep]
version  = "14.1.1"
file     = "ripgrep-14.1.1.zex"
sha256   = "abc123..."
blake3   = "def456..."
size     = 2_097_152
depends  = []
provides = ["rg"]
```

## Building a .zex Package

```bash
elevate zex fmt /path/to/package-src/
```

The `zex fmt` command:
1. Validates `manifest.toml` schema
2. Verifies all `[install]` paths are under `/overlayer/`
3. Verifies no glibc-linked ELFs in `payload/`
4. Computes `blake3(payload/)`
5. Signs with the repository key (requires key access)
6. Produces `<name>-<version>.zex`

## Constraints

| Field | Constraint |
|-------|-----------|
| Package name | `[a-z0-9][a-z0-9+._-]*`, max 128 chars |
| Version | Any printable ASCII, max 64 chars |
| Description | Single line, max 256 chars, UTF-8 |
| Install path | Must start with `/overlayer/`, no `../` |
| Remove paths | Must start with `/overlayer/`, no `../` |
| File count | ≤ 100,000 files per package |
| Total size | ≤ 10 GB uncompressed |
| Hook script | Max 64 KB, executed with `sh` |
