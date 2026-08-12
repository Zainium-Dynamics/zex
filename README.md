# zex

**The native package manager for Zainium OS.**

`zex` is a single BusyBox-style multicall binary that installs, removes,
updates, and audits packages across four package tiers — native Zainium
(`.zex`), Alpine Linux (`.apk`), Void Linux (`.xbps`), and Chimera Linux
(apk-tools v3 ADB binary containers, also `.apk`-named but a different
format). Every tier is verified against its real upstream signature scheme
before anything is installed.

- **Version:** 5.0.0
- **Language:** Rust 2024 edition
- **Target:** `x86_64-unknown-linux-musl` (pinned in `.cargo/config.toml`; no glibc anywhere in the toolchain)
- **License:** GPL-3.0, strict-only

## Status

Two-phase correctness + capability pass completed 2026-07-19. Build is
green, 502 tests pass. Full detail in [`REPORT.md`](./REPORT.md); short
verdict table in [`AUDIT-REPORT.md`](./AUDIT-REPORT.md). Not a universal
Linux package manager — this is Zainium OS's own package manager, with
compatibility shims that let it also consume three other distros' package
indices.

## Package tiers

| Tier | Distro | Format | Signature scheme |
|------|--------|--------|-------------------|
| T1 | Zainium (native) | `.zex` (tar + zexc compression) | Ed25519 + Blake3 |
| T2 | Alpine Linux | `.apk` (gzip-tar) | RSA-PKCS1v15 over the compressed control member |
| T3 | Void Linux (musl) | `.xbps` (zstd/xz-tar) | RSA-PKCS1v15-SHA256 over the whole file, TOFU-pinned key |
| T4 | Chimera Linux | `.apk` (apk-tools v3 ADB binary container — **not** gzip-tar) | RSA-PKCS1v15-SHA512 over the ADB signature block |

If a package exists in more than one tier, the tier with the lowest
priority number (as configured in `zex_services.toml`) wins. Dependencies
additionally prefer staying on the same mirror as the package that pulled
them in before falling back cross-tier.

## Building

```bash
# Native build (host libc)
cargo build --release

# Cross-compile for the Zainium musl target (on ZainiumOS)
CC=x86_64-zainium-linux-musl-gcc \
cargo build --target x86_64-zainium-linux-musl --release
```

Because `.cargo/config.toml` pins `target = "x86_64-unknown-linux-musl"`,
the release binary lands at
`target/x86_64-unknown-linux-musl/release/zex`, **not**
`target/release/zex`.

Full build/test/contribution details: [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Usage

```
zex <command> [options] [args]
```

Every command below is also available as `elevate zex <command>` for
operations that need root (installing, removing, upgrading), and has a
dedicated man page (`man zex-<command>`).

### Package management

```bash
# Install one or more packages
zex install ripgrep
zex install vim htop curl fd-find

# Preview what would be installed, no download/install
zex install neovim --dry-resolve

# Install from local cache only (no network)
zex install foo --cache-only

# Reproducible installs: pin an exact resolved graph, replay it elsewhere
zex install musl --lock-out musl.lock.toml
zex install --from-lock musl.lock.toml
zex install --verify-lock musl.lock.toml   # check for drift, install nothing

# Remove packages
zex remove ripgrep
zex remove vim htop --dry-run
zex remove foo --force   # skip reverse-dependency check

# Install a local package file directly
zex -i ./myapp-1.0.zex
```

### Updating

```bash
# Full system update: refresh indices, upgrade userland + syshub
zex update
zex update --yes           # skip confirmation prompt
zex update --uland-only    # userland packages only
zex update --syshub-only   # immutable base only

# Or drive each half directly
zex uland --u
zex syshub --u
```

`syshub` upgrades are crash-safe: every checkpoint is journaled to disk,
so an interrupted upgrade self-heals automatically the next time any
`zex` command runs.

### Inspecting the system

```bash
zex search "fuzzy finder"     # search all four tiers
zex depends ripgrep            # show the dependency tree
zex why libssl                 # show reverse dependencies
zex inspect ripgrep             # version, files, shared-lib deps, integrity
zex history                     # unified install/remove/upgrade timeline
zex history --package musl -n 5
zex doctor                      # audit registry, symlinks, glibc contamination
zex doctor --fix                # attempt automatic repair
```

### Pinning and rollback

```bash
zex pin gcc --reason "kernel ABI stability"
zex unpin gcc
zex pins                        # list all pinned packages

zex rollback --list
zex rollback tx-1719446400000
```

### Maintenance

```bash
zex sweep --dry-run             # preview cache/tmp cleanup
zex sweep --aggressive
zex -e ./myapp-1.0.zex -o ./out # extract a package archive to a directory
```

## Configuration

| File | Purpose |
|------|---------|
| `/overlayer/syshub/engine/services/zex_services.toml` | Mirror list, tier priorities, `signature_verification_mode` (`off`/`audit`/`strict`) |
| `/overlayer/syshub/engine/services/syshub.toml` | Immutable base package manifest |
| `/overlayer/zexlib/registry/installed/<name>.toml` | Per-package receipt — the authoritative record of what's installed |
| `/overlayer/zexlib/registry/packages.toml` | Derived master index, rebuildable from receipts via `zex doctor --fix` |

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — module structure, dispatch flow, dependency resolution, transaction model
- [`ZEX-FORMAT.md`](./ZEX-FORMAT.md) — the native `.zex` package format spec
- [`CHANGELOG.md`](./CHANGELOG.md) — release history
- [`REPORT.md`](./REPORT.md) — full engineering report, per-tier verification detail
- [`AUDIT-REPORT.md`](./AUDIT-REPORT.md) — short verdict summary
- `man/zex.1` and `man/zex-<command>.1` — full command reference (`man ./man/zex.1`)

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for build requirements, test
commands, code style, and the PR checklist.

## License

GPL-3.0, strict-only. See the `Licence` field in `Cargo.toml`.
