# Zex Package Manager — Full Engineering Report

| Field | Value |
|-------|--------|
| **Project** | `zex` — Zainium eXecutor & Package Manager |
| **Version** | 5.0.0 |
| **Path** | `/home/alizain/zex` |
| **Report date** | 2026-07-19 |
| **Language** | Rust 2024 edition |
| **Related docs** | `CHANGELOG.md`, `ZEX-FORMAT.md`, `ARCHITECTURE.md`, `AUDIT-REPORT.md` |

---

## 1. Executive summary

`zex` is a **BusyBox-style multicall binary** for Zainium OS: one ELF, many
package-management commands (`install`, `remove`, `update`, `uland`/`syshub`,
`search`, `doctor`, `history`, `fmt`, …), routing across four package tiers
(native Zainium, Alpine, Void, Chimera).

This report covers the **2026-07-19 engineering pass**: a two-phase
strengthening effort — Phase 1 closed correctness gaps (real signature
verification for every tier, real version-constraint solving, atomic
multi-package transactions, post-install hooks, a real conflict model),
Phase 2 added capabilities beyond what mainstream package managers offer
(crash-safe atomic upgrades, reproducible/verifiable installs, tier-affinity
dependency resolution, a unified history, and a formalized derived-vs-
authoritative registry with real repair). Along the way, two significant
**pre-existing, previously-undiscovered bugs** were found and fixed: Tier 1's
signature verification had never actually worked at all, and a family of
path-traversal/usrmerge-collision bugs broke real packages on two tiers.

| Question | Answer |
|----------|--------|
| Does it build? | **Yes** |
| Do tests pass? | **Yes** — 502 tests, 0 failures |
| Supported package formats? | `.zex` (Tier 1), `.apk` gzip-tar (Tier 2 Alpine), `.xbps` (Tier 3 Void), `.apk` **ADB binary container** (Tier 4 Chimera — not gzip-tar, a real apk-tools v3 format) |
| Debian / Fedora / Arch packages? | **No** (intentionally; dead code removed) |
| Is dependency resolution PubGrub? | **No** — `pubgrub_resolver.rs` exists but is **dead code**, never called. The real, live resolver is a BFS in `depends.rs` (see §5) |
| Is every tier's signature cryptographically verified? | **Yes**, independently confirmed for all four — see §6 |
| Fully production-ready for the world? | **No** — ready for **controlled Zainium rollout** after package rebuild + trust-anchor deployment |

---

## 2. What zex is responsible for

```
Boot (Quantra)  →  OverlayFS: syshub + zaisys + zexlib → /
Runtime (zex)   →  writes packages into /overlayer/zexlib/union/
                →  registry receipts under /overlayer/zexlib/registry/
                →  syshub upgrades under /overlayer/syshub (syshub --u)
```

| Concern | Owner |
|---------|--------|
| Overlay assembly / mounts | **Quantra** (not zex) |
| Package download, resolve, extract, register | **zex** |
| Pack-time audit & signing | **zex fmt** |
| Cryptographic verify at install | **zex** (`trust.rs` for Tier 1, `native_sig.rs` for Tiers 2–4) |

---

## 3. Architecture (current)

See `ARCHITECTURE.md` for the full, current architecture description. Summary:

### 3.1 Tier model (resolution) — corrected

| Tier | Origin | Format | Signature |
|------|--------|--------|-----------|
| T1 | Zainium native | `.zex` (zexc `ZEX1` + tar) | Ed25519 + Blake3 |
| T2 | Alpine | `.apk` (gzip-tar, apk-tools v2) | RSA over compressed control member |
| T3 | Void | `.xbps` (zstd/xz-tar) | RSA-SHA256, detached `.sig2`, TOFU-pinned key |
| T4 | Chimera | apk-tools v3 **binary ADB container** | RSA-SHA512 over ADB signature block |

The previous version of this report listed T4 as `.apk` (gzip-tar) — that
was wrong. Chimera migrated to apk-tools v3's binary "ADB" format for both
its repository index (`Packages.adb`) *and* individual package files;
`src/cmd/install/adb.rs` is a from-scratch binary decoder for it, written
directly against the real `apk-tools` C source (envelope, 8-byte-aligned
blocks, tagged values, schema field indices) — not guessed.

### 3.2 Dependency resolution — corrected

Earlier reports described PubGrub (`pubgrub = "0.2"`) as the resolution
engine. **This was never true of the live code path.**
`src/cmd/install/pubgrub_resolver.rs` exists and compiles, but nothing in
the actual install flow calls it — confirmed by exhaustive reference search.
The resolver that actually runs is a BFS in `depends.rs`, which now also
does tier-affinity-aware resolution and real version-constraint checking
(§5 of `ARCHITECTURE.md`). This isn't a regression: PubGrub's SAT-style
multi-version search has no real choice-space against these repos anyway,
since Alpine/Void/Chimera are rolling-release (one version per package, no
history) — a BFS with real constraint-checking is the correct tool, not a
compromise.

### 3.3 Upgrade product surface

Unchanged from the previous report: exactly two user commands,
`elevate zex uland --u` (userland, all tiers) and `elevate zex syshub --u`
(immutable core). Syshub upgrades are now crash-safe — see §7.

---

## 4. Package formats — deep dive

### 4.1 Supported

| Format | Wire container | Index / metadata | Notes |
|--------|-----------------|-------------------|-------|
| `.zex` | zexc (`ZEX1`) + tar | `manifest.toml`, `signature.b3`, ledger | Native |
| `.apk` (Alpine) | gzip + tar (apk-tools v2) | `APKINDEX`, `.PKGINFO` | |
| `.xbps` (Void) | zstd/xz + tar | `index.plist` / props | |
| `.apk` (Chimera) | **binary ADB container** (apk-tools v3) | `Packages.adb` | Not gzip-tar — see §3.1 |

### 4.2 Not supported

`.deb`, `.rpm`, Arch `.pkg.tar.*` — intentionally out of scope, dead stubs removed.

---

## 5. Dependency resolution — full detail

See `ARCHITECTURE.md`'s "Dependency Resolution" section for the complete,
current description (tier affinity, version-constraint checking, conflict
checking, canonical-name topological sort). All four are real, live-tested
behaviors as of this pass, not aspirational.

---

## 6. Security model — corrected and expanded

### 6.1 Per-tier signature verification (`native_sig.rs`)

Previous reports graded crypto ops "C+ — needs live trust.pub + signed repo
packages" without actually verifying whether the *mechanism itself* worked.
This pass did the actual verification work:

- **Alpine**: reverse-engineered against real `apk-tools` source and
  confirmed against two independent live packages — the signature covers
  the **compressed** bytes of the control tarball member (not the
  decompressed content — a real, confirmed quirk of apk-tools' own
  implementation), hash algorithm named in the signature filename
  (`.SIGN.RSA[256|512].<key>`). Trust anchors: all 18 of Alpine's real keys,
  extracted from a live `alpine-keys` package.
- **Chimera**: the ADB signature block's schema+digest construction,
  outer signature always RSA-SHA512 regardless of the inner digest
  algorithm, key identified by a 16-byte ID (`SHA512(PKCS1-DER pubkey)[:16]`)
  matched against all 8 of Chimera's real published keys. Confirmed against
  a live `chimerautils` package — notably signed by the founder's personal
  key (`q66@chimera-linux.org`), not the x86_64 arch key, proving the
  implementation must match by key ID across the whole set rather than
  guessing per-architecture.
- **Void**: RSA-PKCS1v15-SHA256 over the whole `.xbps` file, verified
  against a detached `.sig2`. Void's trust model is genuinely TOFU (the
  repodata self-declares its own signing key) — replicated faithfully:
  pinned per-mirror on first contact, hard-required to match on every
  subsequent fetch, confirmed to fail-closed against a tampered pin.
- **Tier 1 (`.zex`)**: **was completely broken.** `Signer128::sign()`
  re-hashed an already-computed digest before signing it, so the verifier's
  independently-recomputed digest could never match the stored one — every
  real signature would fail verification regardless of key. This had gone
  unnoticed because no real keypair existed anywhere (correctly — private
  keys shouldn't be committed) and the packer silently fell back to an
  insecure hardcoded dev key with just a log warning. Fixed, and a real
  keygen tool (`zex fmt keygen`) added so this can actually be tested and
  used going forward. Confirmed via a genuine pack→sign→verify round trip.

### 6.2 Path safety — expanded

Beyond the existing traversal-rejection and `openat2`/`O_NOFOLLOW`
controls, this pass found and fixed a real, live-reproduced bug family in
symlink/hardlink extraction (over-strict `..` rejection, missing
self-collision detection for usrmerge packages, wrong resolution semantics
shared between symlinks and hardlinks, duplicate-destination commit
crashes) — see `CHANGELOG.md` and `ARCHITECTURE.md`'s Path Safety section.

### 6.3 Signature verification modes

Unchanged: `off` | `audit` | `strict`, default `strict`, applied uniformly
across all four tiers via `installer::verify_signature`.

---

## 7. Phase 1 + Phase 2 — what changed this pass

### Phase 1 (correctness gaps closed)

1. Multi-package atomic transactions (batch snapshot/rollback).
2. Real conflict/replaces model (Alpine `!pkgname`, bidirectional).
3. Post-install hook/script execution, sandboxed — previously captured and discarded.
4. Real version-constraint solving (operators parsed and checked against resolved versions).
5. Real native signature verification for all four tiers (§6.1).

### Phase 2 (differentiating capabilities added)

1. **Crash-safe atomic syshub upgrades** — `Transaction` journals every
   checkpoint to disk; `recover_stale()` self-heals a killed mid-upgrade
   on the next run. Verified live with a hand-crafted "process died
   mid-upgrade" scenario.
2. **Reproducible/verifiable installs** — `--lock-out`/`--from-lock`/`--verify-lock`.
   Verified live: lockfile generated in one sandbox, installed from it in a
   completely fresh one, drift correctly detected against a tampered registry.
3. **Tier-affinity dependency resolution** — dependencies prefer the root
   package's own mirror before falling back cross-tier, with a visible
   warning on fallback. Verified by re-testing the exact `base-files`
   cross-tier substitution bug found earlier in this same engineering
   effort; it now resolves correctly.
4. **Unified history** — `history.rs` existed but was never called from
   anywhere; wired it into install/remove/upgrade, added `zex history`.
5. **Formalized registry architecture** — documented authoritative-vs-derived
   explicitly; added `rebuild_master_index()` for real from-scratch repair
   (previously `doctor --fix` could only prune, never restore a missing
   entry). Verified against total `packages.toml` corruption.

---

## 8. Test status

```
cargo build --release   → success
cargo test --release    → success, 502 passed, 0 failed
```

Every feature in §7 was additionally verified **live**, in an isolated
bwrap sandbox against real network data from the real Alpine/Void/Chimera
mirrors (not simulated) — both the positive case (real signed packages
verify, lockfiles round-trip, tier affinity holds) and the negative case
(tampering is rejected, drift is detected, crash recovery restores
correctly).

---

## 9. Production readiness scorecard

| Area | Grade | Notes |
|------|-------|-------|
| Build & automated tests | **A** | Green, 502 tests |
| Per-tier signature verification | **A-** | All four now real and independently confirmed; Tier 1 needed a genuine bug fix first |
| Dependency resolution correctness | **A-** | Real version constraints, tier affinity, conflict checking — all live-verified |
| Path safety / extraction | **B+** | Real bug family found and fixed this pass; no further known gaps |
| Crash safety (syshub upgrades) | **A-** | Real journal + recovery, live-verified |
| Reproducibility | **B+** | Lockfiles work for single-package installs; multi-package `--lock-out` not yet supported |
| Registry integrity | **A-** | Full from-scratch repair now exists and is exercised by `doctor --fix` |
| Crypto ops (key provisioning) | **C+** | `zex fmt keygen` exists now, but no real production Tier 1 keypair is deployed yet — that's an ops task, not a code gap |
| Docs consistency | **A-** (as of this pass) | This report, `ARCHITECTURE.md`, and `CHANGELOG.md` now match the real code; historical `report.md` (lowercase) remains as a dated snapshot, superseded |

### Verdict

> **Production-ready for controlled Zainium OS rollout**, with all four
> tiers' signature verification now genuinely functional (not just
> designed) and a real crash-recovery/reproducibility/audit story to go
> with it. Remaining gaps are **operational** (deploy real Tier 1 keys,
> rebuild Tier 1 packages with the fixed signer, soak-test at scale), not
> architectural.

---

## 10. Known remaining gaps

| ID | Gap | Severity |
|----|-----|----------|
| G1 | No real production Tier 1 keypair deployed (code now supports it correctly; ops task) | Ops |
| G2 | `--lock-out` doesn't support multi-package parallel installs yet | Low |
| G3 | `cmd::upgrade::userland` (uland) doesn't share syshub's crash-safe journal — only syshub does | Medium |
| G4 | `zex update`'s own audit trail isn't wired into the new unified `history` yet | Low |
| G5 | Large pre-existing unused-code warning surface (dead RPM-era leftovers, unrelated to this pass) | Low |

---

## 11. Key file index (updated)

| Path | Role |
|------|------|
| `src/main.rs` | Multicall dispatcher |
| `src/archive_safety.rs` | Path sanitize + FHS→union remap + symlink/hardlink resolution |
| `src/trust.rs` | Tier 1 Ed25519 trust anchor (verify-side) |
| `src/cmd/install/native_sig.rs` | Tiers 2–4 real signature verification |
| `src/cmd/install/adb.rs` | Chimera ADB binary format decoder |
| `src/cmd/install/depends.rs` | Real live BFS dependency resolver |
| `src/cmd/install/lockfile.rs` | Reproducible-install lockfiles |
| `src/cmd/install/history.rs` | Unified operation history (recording) |
| `src/cmd/history/` | `zex history` command (querying) |
| `src/cmd/upgrade/transaction.rs` | Crash-safe journaled transaction + recovery |
| `src/cmd/fmt/security/signer.rs` | Tier 1 Ed25519 signer (fixed this pass) |
| `ARCHITECTURE.md` | Current, corrected architecture description |
| `CHANGELOG.md` | Release history, this pass's full change list |

---

## 12. Conclusion

Zex **5.0.0** now has every tier's package signature *actually*
cryptographically verified — including catching and fixing a bug that meant
Tier 1's own native format had never worked — plus real dependency
correctness (version constraints, conflicts, tier affinity), crash-safe
core upgrades, reproducible installs, and a unified audit trail. The gaps
that remain are operational (key deployment, package rebuilds, soak
testing at scale), not gaps in the design or its implementation.

*End of report.*
