# zex Architecture

## Overview

`zex` is the native package manager for Zainium OS. It is a **BusyBox-style
multicall binary**: a single ELF that contains every package-management
command. Command dispatch happens via `argv[1]` (or `argv[0]` through a
symlink) in `src/main.rs`.

```
/overlayer/syshub/bin/zex             ← single binary
/overlayer/syshub/bin/zex-install  → zex
/overlayer/syshub/bin/zex-remove   → zex
```

## Module Structure

Real line counts (`find src -name '*.rs' | xargs wc -l`), 143 files, ~25,600
lines total:

```
src/
├── main.rs           — multicall dispatcher + built-in commands
├── aliases.rs        — command name → driver resolution
├── extract.rs        — generic archive extraction (`zex -e`)
├── archive_safety.rs — path sanitization + FHS→union remapping (shared)
├── trust.rs          — Tier 1 Ed25519 trust anchor (verify-side)
├── local_install.rs  — `zex -i <local-file>` handler
├── pinning.rs         — pin/unpin/pins built-in
├── lib.rs             — library exports for tests
└── cmd/
    ├── install/    ~11,000 lines — resolver, downloader, installer, registry, native_sig, adb, lockfile
    ├── fmt/         ~3,170 lines — pack / verify / security-audit pipeline for .zex
    ├── upgrade/     ~2,890 lines — vercmp, syscore (syshub), userland (uland), swap, transaction
    ├── remove/      ~1,870 lines — preflight, single, parallel, daemon
    ├── doctor/        ~940 lines — layout audit + auto-fix
    ├── update/        ~765 lines — combined syshub+userland update orchestration
    ├── search/        ~735 lines — multi-tier search + probers
    ├── rollback/      ~510 lines — transaction restore
    ├── sweep/         ~480 lines — cache + tmp cleanup
    ├── inspect/       ~370 lines — installed-package inspection
    ├── depends/       ~285 lines — dependency tree
    ├── why/           ~160 lines — reverse dependency
    └── history/        ~90 lines — unified operation timeline (new)
```

## Dispatch Flow

```
$ elevate zex install vim

main.rs: argv = ["zex", "install", "vim"]
  → command = "install"
  → cmd::install::run(["install", "vim"]).await
    → infuse::run(["vim"], lock_out).await
      → resolver::resolve("vim", ...).await          — tries mirrors by priority
      → depends::resolve_dependencies(&info, ...)     — BFS, tier-affinity-aware
      → downloader::download(url, ...).await          — reqwest + rustls
      → installer::install(path, info, ...)            — extract, verify, commit
      → registry::register(record)                     — atomic TOML write + master-index sync
```

## Four-Tier Package Routing

zex resolves packages from four tiers, tried in **priority order** (lower
number = tried first), from `zex_services.toml`:

| Tier | Format | Mirror IDs (priority) | Signature scheme |
|------|--------|------------------------|-------------------|
| T1 | `.zex` (tar + zexc, magic `ZEX1`) | `zainium-core-stable-syshub` (1), `zainium-userland-zexlib` (2) | Ed25519 + Blake3 (`trust.rs`) |
| T2 | `.apk` (gzip-tar, apk-tools v2) | `alpine-main` (3), `alpine-community` (4) | RSA-PKCS1v15 over the **compressed** control member (SHA1/256/512, key named in the signature entry) |
| T3 | `.xbps` (zstd/xz-tar) | `void-musl-current` (5), `void-musl-nonfree` (6) | RSA-PKCS1v15-SHA256 over the whole file, detached `.sig2`, key TOFU-pinned per mirror from the repodata itself |
| T4 | `.apk` (apk-tools v3 **binary "ADB" container**, *not* gzip-tar) | `chimera-main` (7), `chimera-user` (8) | RSA-PKCS1v15-SHA512 over a schema+digest construction inside the ADB signature block |

If a package exists in more than one tier, the **lowest-priority-number**
tier wins for the package the user actually named. **Dependencies** of that
package additionally prefer staying on the *same mirror* the root package
came from (`resolver::resolve_preferring`) before falling back cross-tier —
see "Dependency Resolution" below.

All four schemes are real, independently-verified cryptography
(`src/cmd/install/native_sig.rs` for T2–T4, `src/trust.rs` for T1) — not
just HTTPS transport trust. Alpine's and Chimera's trust anchors are
embedded in the binary at compile time (`native_sig.rs::trust_keys/`);
Void's is pinned on first contact with each mirror and compared on every
subsequent fetch.

## Filesystem Layout

```
/overlayer/
├── syshub/                         ← immutable base (squashfs or bind-mount ro)
│   ├── bin/                        ← zex, bash, coreutils
│   ├── lib/, lib64/, include/, etc/, share/
│   ├── engine/services/            ← syshub.toml, zex_services.toml, trust.pub
│   └── etc/zex/signing.key         ← Tier 1 PRIVATE signing key (builder machines only)
├── zexlib/                         ← mutable userland (overlayfs upper)
│   ├── union/                      ← merged view: bin/ lib/ share/ etc/
│   ├── registry/
│   │   ├── installed/              ← <name>.toml per package — THE authoritative state
│   │   ├── packages.toml           ← derived master-index summary (see Registry Architecture)
│   │   ├── pinned.toml             ← pinned packages
│   │   ├── trust/void/<mirror>.pem ← TOFU-pinned Void repo keys
│   │   ├── upgrade-audit.toml      ← syshub/uland-specific audit trail
│   │   ├── remove-audit.toml       ← remove-specific audit trail
│   │   └── cache/                  ← per-mirror metadata cache
│   ├── transactions/               ← tx-<timestamp>/ rollback snapshots
│   └── tmp/                        ← staging: local_install_*, update-dl/, syshub-rollback/
└── zaisys/
    └── kernel/                     ← kernel modules, firmware
```

`/overlayer/zexlib/history.toml` — the unified cross-tier operation history
(see `zex history`). Originally kept outside `/overlayer` as
`/var/lib/zex/history.json`; moved under `zexlib` (and to TOML) for
consistency with every other piece of zex state.

## Registry Architecture: Authoritative vs. Derived

Exactly one thing is authoritative: the `PkgRecord` files under
`registry/installed/*.toml` (`registry::load_all()`). Everything else is a
**derived** view, kept for other commands' convenience, and must always be
fully regeneratable from that source alone:

- `packages.toml` (master index) — flattened summary for `uland --u`,
  `doctor`, `search`, `rollback`. Kept in sync incrementally on every
  install/remove. If it drifts (deleted, corrupted, a bug skipped a sync),
  `registry::rebuild_master_index()` regenerates it **from scratch** —
  `zex doctor --fix` calls this, not the narrower `prune_master_index`
  (which only removes stale entries and can't add back a package that's
  genuinely installed but missing from the index).
- Search caches, telemetry dashboards, etc. — same rule.

## Dependency Resolution

The real, live resolver is a **BFS** over `depends` tokens
(`src/cmd/install/depends.rs`), not PubGrub — `pubgrub_resolver.rs` exists
in the tree but is **dead code**, never called from anywhere. This is
deliberate: Alpine/Void/Chimera repos are rolling-release (one version per
package, no history), so PubGrub's SAT-style "choose among candidate
versions" model has no real choice-space to search here.

What the BFS actually does, per dependency token:

1. **Tier affinity** — try resolving from the *same mirror* the root
   package came from first (`resolver::resolve_preferring`); only fall
   back to the normal all-mirrors-by-priority search if that mirror
   doesn't have it, and surface a visible warning when it does fall back.
2. **Version-constraint checking** — parse the real operator
   (`>=`,`<=`,`>`,`<`,`=`,`~=`) out of tokens like `libfoo>=2.0` and check
   the resolved candidate's actual version against it (structural
   comparison, no hardcoded prerelease keyword list), for both
   newly-resolved and already-installed dependencies.
3. **Conflict checking** — Alpine's `!pkgname` bidirectional
   incompatibility declarations, checked against everything already
   installed and everything else in the same install batch.
4. **Topological sort** by canonical resolved package name (not by the raw
   token string a package happened to reference it with — two different
   tokens, e.g. a version-pinned one and a bare one, can resolve to the
   same real package).

The whole plan (root + every dependency, download size, conflicts,
version violations, cross-tier fallbacks) is computed **before** any
download begins, and surfaced to the user before committing to the
install.

## Transactions, Rollback, and Crash Recovery

Two related but distinct mechanisms:

- **In-process rollback** (`cmd::install::transaction`,
  `cmd::upgrade::transaction`): every mutating step is checkpointed before
  it runs; if a *later* step in the same run fails, all checkpoints are
  restored in reverse order. This is what protects a normal failed install
  or upgrade.
- **Crash recovery** (`cmd::upgrade::transaction::Transaction::recover_stale`,
  added for syshub upgrades): checkpoints are also journaled to disk as
  they happen (not just held in memory), with a `STATE` marker flipped to
  `"committed"` as the *first* action of a successful commit, before any
  cleanup. If the process itself is killed (SIGKILL, power loss, OOM)
  between a checkpoint and commit/rollback, the in-memory `Transaction`
  value is lost — but the on-disk journal isn't. The *next* `zex syshub`
  invocation calls `recover_stale()` first, which finds any leftover
  `rollback-<pid>` directory still marked `"in_progress"` and replays its
  journal to restore full consistency, before doing anything else.

## Reproducible / Verifiable Installs

`zex install` supports three lockfile flags (`src/cmd/install/lockfile.rs`):

- `--lock-out <path>` — after a successful single-package install, writes
  the exact resolved root + dependency graph (real URLs, versions, source
  mirrors, hashes) as a TOML lockfile.
- `--from-lock <path>` — installs exactly what a lockfile pins, bypassing
  live dependency resolution entirely (so upstream index drift since
  generation can't change the result), through the same
  download→verify→install pipeline every other install path uses.
- `--verify-lock <path>` — compares a lockfile's pinned packages against
  the real `registry/installed/*.toml` (not the derived master index) and
  reports version/hash drift without installing anything.

## Unified History

`src/cmd/install/history.rs` records every install/remove/upgrade to
`/overlayer/zexlib/history.toml` (id, timestamp, operation, packages,
success, error, duration, user). `zex history [--package NAME] [-n COUNT]`
(`src/cmd/history/`) is the single place to see all of it together — it
complements, not replaces, the tier-specific audit files
(`upgrade-audit.toml`, `remove-audit.toml`) those subsystems already keep.

## Atomic Write Pattern

Every registry/journal file this codebase writes uses the same pattern:

```rust
let tmp = path.with_extension("toml.tmp");
fs::write(&tmp, data)?;      // write to .tmp
fs::rename(&tmp, &path)?;    // atomic rename — kernel guarantees atomicity
```

The crash-recovery journal additionally `fsync`s the temp file and its
parent directory before and after the rename, so the write survives a
power loss, not just a process crash.

## Security Model

### Privilege Model

All write operations require root, enforced by the `elevate(1)` suid
wrapper. `zex` itself never calls `setuid`.

### Path Safety

- Archive paths: `..` rejected, remapped structurally onto the union
  layout (`archive_safety::sanitize_archive_path`).
- Symlink targets: resolved relative to the archive's *original* FHS
  namespace (not the flattened union one), with `..` beyond the archive
  root clamped rather than allowed to escape — real packages routinely use
  multi-level `..` (Void's `xbps-triggers`) or self-referential usrmerge
  symlinks (`/bin -> usr/bin`) that a naive "reject any .." rule breaks.
- Hardlink targets use a different, simpler resolution than symlinks
  (`sanitize_archive_path`, staying relative to the staging tree) since
  they need an inode that already exists *right now*, not a lazily-resolved
  final path.

### Signature Verification Modes

`off` | `audit` | `strict` (config: `signature_verification_mode`,
default **`strict`**). Applies uniformly across all four tiers via
`installer::verify_signature`.
