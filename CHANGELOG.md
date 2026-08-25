# Changelog

All notable changes to **zex** (Zainium eXecutor & Package Manager) are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) principles.  
Versioning follows project releases (`Cargo.toml` package version).

---

## [5.0.1] — 2026-08-25

Everything in this release came out of live testing against the real
archive and a real syshub upgrade — not unit tests. Most of these bugs
never showed up any other way, since they only trigger against real
package content (a symlink in the payload, a `-dev` package's `.pc`
file, a script's shebang line) that synthetic test fixtures didn't
happen to include.

### Fixed

- **Packages with a symlink in them could never install.** The
  installer's own signature check hashed every payload entry's bytes,
  but a symlink has no body in the tar — it was silently hashed as
  empty instead of using the link target, so the recomputed hash never
  matched the real one. `zlib-dev` (ships `libz.so -> libz.so.1.3.2`)
  is what caught this. Matches how `trust.rs`'s own verifier already
  handled symlinks correctly — the installer had a second, separate
  copy of this logic that never got the same fix.
- **`.pc` files kept the wrong install prefix.** Alpine/Void `-dev`
  packages ship pkg-config metadata pointing at `/usr`; even packages
  already repackaged into our own `.zex` format sometimes carried the
  wrong Zainium prefix (`/overlayer/syshub` instead of
  `/overlayer/zexlib/union`). Any build tool using `pkg-config` against
  an installed dependency got paths that don't exist. New `pcpatch.rs`
  rewrites `prefix=`/`libdir=`/`includedir=` at install time.
- **Scripts with a `#!/bin/sh` or `#!/usr/bin/env ...` shebang failed
  to run at all.** Zainium has no `/bin` or `/usr/bin` — the kernel
  resolves a shebang path literally, so `exec()` just returned "No such
  file or directory". New `shebangpatch.rs` rewrites the interpreter
  path to wherever it actually lives (syshub first, then the union
  tree), and falls back from `sh` to `bash`/`dash`/`ash` if there's no
  literal `sh` binary — same substitution every real distro's own
  `/bin/sh` symlink already makes.
- ELF interpreter/RPATH patching, `.pc` patching, and shebang patching
  now all run on every installed package regardless of format. They
  used to be skipped for anything packaged as `.zex`, on the assumption
  that meant "already built correctly for Zainium" — true for a
  genuinely native package, false for a foreign package we've
  repackaged into a `.zex` container, which is exactly what was
  shipping broken `.pc` files above.
- Same three patches were missing entirely from the *upgrade* paths
  (`zex update`, `zex uland --u`). A fresh install got fixed up
  correctly; upgrading that same package to a newer version silently
  reintroduced the broken interpreter/RPATH/`.pc`/shebang all over
  again.
- ELF patching now checks whether the interpreter and RPATH actually
  need to change before touching the file at all, instead of
  unconditionally rewriting the `.dynamic` section. Doesn't matter for
  a foreign package that genuinely needs the rewrite, but it means a
  native binary that was already correct never gets its ELF structure
  touched for no reason.
- `zex -e`/`--extract` refused to extract some perfectly valid
  archives with "path escapes output directory" — the safety check
  canonicalized a directory that didn't exist yet, and silently fell
  back to comparing an absolute path against a relative one, which
  can never match.
- Chimera (T4) packages upgraded through `zex uland --u` lost their
  executable bit on regular files. The same bug had already been fixed
  for a fresh install; this was a second, separate copy of the
  extraction code that never got the fix.
- `zex syshub --u` could fail to replace its own binary during a
  self-upgrade. Two separate bugs: the swap ran before syshub was
  remounted read-write, so it was trying to write into a still-
  read-only filesystem; and the rename it used doesn't work across
  the syshub mount boundary, unlike the regular file-copy step a few
  lines later which already had a fallback for exactly that.
- Void packages were labelled `[T2-ALP]` and Alpine packages
  `[T3-VOD]` in upgrade output — backwards.
- Downloads in `zex update`, `zex uland --u`, and `zex syshub --u`
  never retried on a dropped connection; one hiccup failed the whole
  transaction. `zex install` already retried three times with
  backoff — the upgrade paths now do the same.
- Downloading multiple packages during an upgrade processed them in
  fixed pairs — if one finished early, its slot sat idle until its
  pair-mate finished instead of picking up the next package. Now a
  finished slot picks up whatever's next immediately.
- The per-package progress bar computed a label with the package name
  but never actually put it in the template for a real (non-spinner)
  download, so the name never showed up.
- The userland upgrade summary printed a made-up "userland version"
  number that didn't correspond to anything real — every package has
  its own version, there's no single combined one.
- Upgrade failure messages only printed the outermost error, hiding
  what actually went wrong underneath.

---

## [5.0.0] — 2026-07-10

### Summary

Major format, install-path, and CLI consistency release. Native `.zex` packages now use the **zexc** compressor end-to-end; foreign packages (Alpine APK, Void XBPS) remap FHS paths onto the Zainium union layer; upgrade is exposed only as **`uland`** and **`syshub`**. Full automated test suite is green.

---

### Added

- **`zexc` dependency** (`Cargo.toml`) — native lossless compressor, features `std` + `simd`.
- **`src/zex_codec.rs`** — shared pack/unpack API for `.zex` frames:
  - `compress` / `decompress`
  - `open_decoder` / `stream_decoder`
  - magic check `ZEX1` (`is_zex_magic`)
- **`PackageFormat::Zex`** in `extract.rs` — distinct from generic `TarZst` (Void/generic zstd).
- **`archive_safety::UNION_ROOT`** (`/overlayer/zexlib/union`) and **`union_abs_path()`**.
- Expanded **FHS → union remapping** for foreign packages (`usr/bin`, `usr/lib`, `usr/share`, `etc`, `lib64`, …).
- Unit tests for union absolute path mapping and lib/share/etc remaps.
- Dev-deps for integration crypto tests: `rand_core`, `blake3`, `ed25519-dalek`, `sha2`, `tar`.

---

### Changed

#### Native `.zex` format (breaking for old packages)

| Before | After |
|--------|--------|
| Often treated as `tar` + **zstd** | **zexc** frame (magic **`ZEX1`**) wrapping tar |
| Packer / verifier / many extractors used `zstd` | All `.zex` I/O goes through **`zex_codec` / zexc** |
| Docs mixed zstd magic `28 B5 2F FD` with “zexc” | `ZEX-FORMAT.md` documents **`ZEX1`** only for `.zex` |

Inner tar layout (unchanged structure):

```
manifest.toml
signature.b3
payload/...
```

#### Integrity (`signature.b3`)

- Packer, verifier, and install extractor now use the **same** hash:
  1. `payload_blake3 = Blake3(sorted archive_path ‖ file_bytes …)`
  2. `signature.b3 = Blake3(manifest.toml_bytes ‖ payload_blake3_hex)`
- Payload files sorted by path before hashing (deterministic).

#### Install / upgrade extract paths

- `zex install` for **Apk / Xbps**: archive paths remapped, then committed under  
  `/overlayer/zexlib/union/…`
- `zex uland --u` APK/XBPS extract: remapping applied (previously wrote raw `usr/bin/...` under union).
- Absolute symlink targets `/usr/bin/…` → `/overlayer/zexlib/union/bin/…`.

#### Upgrade CLI (product rule)

Upgrade is **exactly two user-facing commands** — no bare `zex upgrade`:

```bash
elevate zex uland --u      # userland (T1–T4)
elevate zex syshub --u     # immutable syshub core
```

- `aliases.rs`: removed `"upgrade"` route; kept `syshub` + `uland`.
- `main.rs`: dispatches only `syshub` | `uland`.
- Man page `zex-upgrade.1` updated accordingly.

#### Version comparison

- Pure **structural** compare: numeric parts, then raw suffix lexicographic.
- **No** hardcoded `alpha` / `beta` / `rc` / `git` keyword policy.
- `update/vercmp` and `upgrade/vercmp` aligned.

#### Package formats (policy)

Supported only:

| Format | Extension | Compression |
|--------|-----------|-------------|
| Native | `.zex` | zexc (`ZEX1`) + tar |
| Alpine / Chimera | `.apk` | gzip + tar |
| Void | `.xbps` | zstd (+ xz where needed) + tar |

Explicitly **not** supported: Debian `.deb`, Fedora/RHEL `.rpm`, Arch pacman packages.

#### Tests / harness

- Test packages built with **zexc** + correct `signature.b3` / `manifest.toml`.
- Magic check expects `ZEX1` (not zstd).
- Alias tests expect `syshub` / `uland` only.
- PubGrub FakeRegistry updated for pubgrub 0.2 `Box<dyn Error>` + `Range` API.
- Brittle `/bin/` assertions fixed to mean host FHS (`/usr/`), not union `…/bin`.

---

### Removed

- Dead **RPM / CPIO** extraction (~180 lines) from `installer.rs`.
- Dead **`extract_deb`** stub.
- Bare **`zex upgrade`** user command / alias.
- Misleading mirror score field name `deb_rtt_ms` → `rtt_ms` (not Debian-related).

---

### Fixed

| Issue | Fix |
|-------|-----|
| Project did not compile (`zexc` unresolved) | Added crate + `mod zex_codec` in lib **and** binary |
| Pack with zstd / unpack with zexc mismatch | Single zexc path everywhere for `.zex` |
| `signature.b3` always fail on install | Aligned hash algorithm across pack/verify/install |
| Uland APK/XBPS installed under `union/usr/bin` | Sanitize + remap before write |
| Missing `upgrade` alias broke tests inconsistently with product (uland/syshub only) | Product rule: only uland + syshub |
| PubGrub tests failed to compile on 0.2 | Error + Range API fixes |
| Diamond dependency stress test invalid graph | Correct mid-node diamond fixture |

---

### Security

- Path confinement retained (`archive_safety`, openat2 / O_NOFOLLOW where available).
- Ed25519 + Blake3 trust path remains (`trust.rs` + `zex fmt`).
- Dead RPM parser surface area removed (less untested attack surface).
- No new hardcoded secrets; packing still blocks credential patterns via secrets scan.

---

### Migration notes (breaking)

1. **Rebuild all Tier-1 `.zex` packages** with current `zex fmt` (zexc).  
   Old tar.zst `.zex` files will **not** decompress with the new decoder.
2. Ensure hosts have trust material at  
   `/overlayer/syshub/engine/services/trust.pub` when signature mode is `strict`.
3. Scripts that called `zex upgrade` must call `zex uland --u` or `zex syshub --u`.
4. Any external tooling that assumed zstd magic on `.zex` must switch to **`ZEX1`**.

---

### Verification

```bash
cargo check          # OK
cargo test           # all suites green (0 failed)
```

Approximate automated coverage after this release: **480+** tests across lib + integration suites.

---

## [5.0.0-pre] — 2026-07-04 (prior security pass)

Earlier remediation (documented in historical `report.md`):

- TLS SPKI pinning for primary archive host
- Landlock postinst sandbox hooks
- Ed25519 verification wired into install path
- Immutable bit on installed binaries
- SPDX SBOM at pack time
- Overflow checks enabled in release profile
- Overlay mount ownership clarified vs Quantra init

---

## Unreleased — 2026-07-19 engineering pass

Two-phase strengthening pass covering every tier (Alpine, Void, Chimera,
native Zainium): closing correctness gaps (Phase 1) then adding
differentiating capabilities beyond mainstream package managers (Phase 2).
502 tests passing (lib + integration), up from ~415 at the last recorded
count.

### Added

**Phase 1 — correctness**
- Multi-package atomic transactions with batch snapshot/rollback
  (`cmd::install::transaction`).
- Real conflict/replaces model: Alpine's `!pkgname` bidirectional
  incompatibility declarations, checked against the installed set and the
  current install batch (`depends::check_conflicts`).
- Post-install hook/script execution, sandboxed (`sandbox::run_postinst`),
  for both Alpine's `.post-install` and Void's `INSTALL` script styles —
  previously captured and silently discarded.
- Real version-constraint solving: dependency tokens like `libfoo>=2.0` are
  now parsed for their real operator and checked against the resolved
  candidate's actual version (`depends::check_version_constraint`),
  covering both freshly-resolved and already-installed dependencies.
- **Real native signature verification for every tier** (`native_sig.rs`):
  Alpine (RSA-PKCS1v15 over the compressed control member), Void (detached
  `.sig2`, RSA-PKCS1v15-SHA256, TOFU-pinned per-mirror key from the
  repodata itself), Chimera (RSA-PKCS1v15-SHA512 over the ADB signature
  block's schema+digest construction). All three schemes were reverse
  engineered from the real upstream C sources and confirmed byte-for-byte
  against live packages before being implemented.
- `zex fmt keygen` — generates a real Ed25519 keypair for Tier 1 signing
  (previously no tooling existed to do this at all).

**Phase 2 — differentiating capabilities**
- Crash-safe atomic syshub upgrades: `Transaction` now journals every
  checkpoint to disk (not just in-memory) and `recover_stale()` self-heals
  a killed/power-lost mid-upgrade on the next run.
- Reproducible/verifiable installs: `zex install --lock-out/--from-lock/--verify-lock`.
- Tier-affinity dependency resolution: `resolver::resolve_preferring`
  makes a dependency prefer the root package's own mirror before falling
  back cross-tier, with a visible warning on fallback.
- `zex history [--package NAME] [-n COUNT]` — a previously-built but never
  wired-up unified history module now actually records installs, removes,
  and upgrades, with a command to query it.
- `registry::rebuild_master_index()` — full from-scratch regeneration of
  `packages.toml`, used by `zex doctor --fix` (previously that path could
  only prune stale entries, never restore a missing one).

### Fixed

- **Tier 1 `.zex` signature verification never actually worked.**
  `Signer128::sign()` re-hashed an already-computed digest before signing
  (`packer.rs` passes `payload_blake3.as_bytes()`, which the signer hashed
  *again*), so `verifier::verify_signature`'s independently-recomputed
  digest could never match. Every real signed `.zex` package would have
  failed verification, regardless of key. Confirmed via a real
  pack→sign→verify round trip with a freshly generated keypair.
- Symlink/hardlink extraction path-traversal handling: an overly-strict
  "reject any `..`" rule broke legitimate multi-level-`..` targets (Void's
  `xbps-triggers`); a missing self-referential-symlink check meant real
  usrmerge packages (`base-files` on both Void and Chimera) collided with
  themselves during extraction; hardlinks and symlinks were incorrectly
  resolved with the same logic despite needing different semantics;
  duplicate archive entries remapping to the same union destination caused
  a double-`rename()` crash on commit. All four were real, live-reproduced
  bugs, not theoretical.
- `zex update`'s "no internet" check only ever pinged Zainium's own
  archive host with no fallback, so it reported no connectivity even when
  Alpine/Void/Chimera mirrors were perfectly reachable (same bug already
  fixed in `uland`, missed here and in `syshub`'s `online()` — now fixed
  in both).
- `zex update`'s `.zex` extraction (`apply.rs::extract_into`) had **no path
  sanitization at all** — no `..` rejection, no symlink-target validation
  — unlike every other extractor in the codebase. Now uses the same
  `archive_safety` primitives everywhere else does.
- `zex update`'s registry patching used fragile raw-TOML-text string
  surgery that could corrupt an unrelated line; replaced with
  `registry::update_version` (already used elsewhere) plus deletion of a
  redundant, equally fragile master-index patcher.
- Cross-tier dependency resolution bugs (busybox/xbps/base-files silently
  resolving from a different tier than the package that needed them) —
  root-caused to raw priority-ordering with no tier-affinity concept; see
  the tier-affinity feature above.
- A pinned dependency's installed-but-versioned token (e.g.
  `vim-common=9.2.0747-r0`) never matched the installed-set at all
  (exact-string comparison against raw tokens with embedded versions),
  causing needless re-resolves and wrong topological install ordering for
  any package with pinned/versioned deps — extremely common in Alpine.

See `report.md`/`REPORT.md` for the full historical engineering trail and
`ARCHITECTURE.md` for the current, corrected architecture description.

---

## Format reference (canonical)

See **`ZEX-FORMAT.md`** for the authoritative `.zex` layout.

```
package-1.0.0.zex          # zexc frame, magic ZEX1
└── tar
    ├── manifest.toml
    ├── signature.b3
    └── payload/
        ├── bin/
        ├── lib/
        └── …
```

Signing:

```
payload_blake3 = Blake3(sorted payload paths + bytes)
ed25519_sig    = sign(payload_blake3)   # in manifest
signature.b3   = Blake3(manifest.toml || payload_blake3)
```
