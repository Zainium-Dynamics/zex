# plan.md — Wire `oxipatch` into `zex`, verify against real `Test-zairoot`

Final, execution-ready version of `next.md` §4. Supersedes the informal
notes there for this specific piece of work.

## Context

Alpine/Void/Chimera-sourced packages (`PackageFormat::Apk`/`Xbps`/`Adb`)
ship binaries whose `PT_INTERP`/`RPATH` point at host FHS paths — neither
resolves under Zainium's `/overlayer/` layout, so those packages install
but don't run. `oxipatch` (pushed to
`https://gitlab.com/alizain.arch/oxipatch.git`, confirmed reachable,
`master` @ `5a7e3ea3f219bf05ccfb126cd67fddcca1527aa0`) is a complete,
tested patchelf-equivalent Rust library built to fix exactly this. `T1`
(`.zex`) packages are already built for `/overlayer/` and are excluded.

**Ground-truthed against a real binary already on this OS**, not guessed:
ran `readelf -l`/`-d` on `Test-zairoot/overlayer/syshub/bin/curl` (a real
binary built by this OS's own toolchain):
```
Requesting program interpreter: /overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1
Library rpath: [/overlayer/syshub/lib]
```
Confirms the interpreter path exactly matches what was already planned.
The RPATH target differs by design — syshub's own binaries point at
`/overlayer/syshub/lib` because that's *their* tree; zex-installed
userland packages live in `/overlayer/zexlib/union`, so they get
`/overlayer/zexlib/union/lib` instead. **Also confirms syshub's own
convention is legacy `DT_RPATH`, not `DT_RUNPATH`** — see the
`force_rpath` decision below, updated from the earlier draft to match.

## Part 1 — Implementation

### 1a. Dependency — `zex/Cargo.toml`

```toml
oxipatch = { git = "https://gitlab.com/alizain.arch/oxipatch.git", rev = "5a7e3ea3f219bf05ccfb126cd67fddcca1527aa0" }
```

Pinned `rev`, not floating on `master`, so `Cargo.toml` itself documents
the exact commit `zex` builds against.

### 1b. New module — `zex/src/cmd/install/elfpatch.rs`

Doc-comment style matches `native_sig.rs` (focused module, explains *why*).

```rust
pub fn patch_staged_elfs(staged_files: &[PathBuf]) -> anyhow::Result<()>
```

```rust
const ZEX_INTERP: &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";
const ZEX_LIB_RPATH: &str = "/overlayer/zexlib/union/lib";
```

Logic:
1. Skip anything that isn't a regular file (`symlink_metadata()?.is_file()`).
2. Read the first 4 bytes; skip anything that isn't
   `[0x7f, b'E', b'L', b'F']`.
3. For each real ELF file:
   - `let mut f = oxipatch::elf::ElfFile::open(path)?;`
   - **`f.set_interpreter(ZEX_INTERP)?;` only if `f.interpreter()?.is_some()`
     first** — corrected during live testing (see Part 2 below): plain
     shared objects (`.so`) have no `PT_INTERP` segment at all (only
     directly-executed binaries do), and oxipatch errors if asked to set
     one where none exists. Caught against a real Alpine dependency
     (`libbrotlicommon.so.1.2.0`), not assumed up front.
   - Rebuild RPATH (this part *does* run unconditionally, `.so` files have
     RPATH/RUNPATH too, for their own transitive deps): read `f.rpath()?.unwrap_or_default()`, split on `:`,
     map any entry that is (or starts with) `/usr/lib`, `/lib`, or
     `/usr/lib64` to `ZEX_LIB_RPATH`, keep other entries (e.g.
     `$ORIGIN`-relative, or already-`/overlayer/...` on a re-patch),
     dedup preserving order, push `ZEX_LIB_RPATH` if still absent (covers
     binaries shipping no RPATH at all). Join with `:`, call
     **`f.set_rpath(&new_rpath, true)?;`** — `force_rpath: true` sets
     legacy `DT_RPATH`, matching the real convention confirmed above on
     this OS's own binaries (not `DT_RUNPATH` — corrected from the
     earlier draft, which had guessed RUNPATH before this was checked
     against a real binary).
   - `f.commit()?; f.write_in_place()?;`
4. Any error is a hard failure, propagated via `?` — an unpatched
   interpreter is a broken package, not best-effort.

Register in `zex/src/cmd/install/mod.rs`: `pub mod elfpatch;` (alphabetical,
after `edition`).

### 1c. Call site — `zex/src/cmd/install/installer.rs`

Insert right after the existing `detect_launch_cmd` call (~line 221,
after the `stage_result` match resolves `Ok`, before Step 4's union-path
computation at ~line 223):

```rust
if info.format != PackageFormat::Zex {
    if let Err(e) = super::elfpatch::patch_staged_elfs(&staged_files) {
        cleanup_snapshot(&snapshot_dir);
        return Err(e);
    }
}
```

Correct insertion point because files are still mutable under
`store_path` here — `crate::immutable::try_set_immutable` only runs after
`plan.commit()` at Step 7, ~30 lines later. Patching after commit would
mean mutating already-immutable, already-live union files.
`detect_launch_cmd` only pattern-matches path strings, never touches file
contents, so call order relative to it doesn't matter.

## Part 2 — Verification against `/home/alizain/Test-zairoot`

Real end-to-end test, not just `cargo test` — per this project's standing
rule to prove fixes against real repo data. `Test-zairoot` is a copy of
this OS's root (`overlayer/syshub`, `overlayer/zaisys`, `overlayer/zexlib`
already present; `overlayer/zexlib/registry/installed/` currently empty —
nothing installed into this copy yet). `bwrap` is available on this host
(`/usr/bin/bwrap`).

### 2a. Build and place the binary

```bash
cd /home/alizain/zex
cargo build --release
cp target/release/zex /home/alizain/Test-zairoot/overlayer/syshub/bin/zex
```

`zex` is a native host build (glibc, this dev machine's own toolchain) —
that's fine and intentional for this test round. We are testing the
*install pipeline's* ELF-patching of the *packages it installs*, not
testing that `zex` itself is a cross-compiled Zainium/musl binary. Only
`/overlayer` gets shadowed by the sandbox (below), so `zex`'s own loader
resolution against the host's real `/lib64` is untouched and works
normally.

### 2b. Multicall symlinks

Per `main.rs`'s own documented layout ("Zex multicall binary dispatcher")
and the 11 driver names in `aliases.rs`:

```bash
cd /home/alizain/Test-zairoot/overlayer/syshub/bin
for cmd in install update remove upgrade search sweep rollback doctor depends why inspect; do
    ln -sf zex "zex-$cmd"
done
```

(Not load-bearing for `zex install` itself — every command in
`main.rs`'s dispatch table, including `install`, calls `cmd::*::run(...)`
in-process; the symlinks exist for external/driver-compat callers. Created
anyway to match the real production layout for a realistic test root.)

### 2c. Run inside `bwrap`, shadowing only `/overlayer`

`zex` hardcodes `/overlayer/zexlib/...` and `/overlayer/syshub/...` as
absolute paths throughout (`archive_safety::UNION_ROOT`, `installer.rs`'s
stage dir, etc.) — there is no `--root` override on the `install` driver
(only the separate `zex -i` local-install path has that flag). So testing
without touching the real host `/overlayer` means shadowing that one path
via a mount namespace, not passing a flag:

```bash
bwrap \
  --bind / / \
  --bind /home/alizain/Test-zairoot/overlayer /overlayer \
  --dev /dev \
  --proc /proc \
  --die-with-parent \
  /overlayer/syshub/bin/zex install <package-name>
```

`--bind / /` keeps the host's real filesystem (network, DNS, CA certs,
the host loader) visible everywhere except `/overlayer`, which gets
replaced by the `Test-zairoot` copy. Everything `zex install` writes
(`zexlib/tmp`, `zexlib/registry`, `zexlib/union`) lands in
`Test-zairoot/overlayer/...` on the real host filesystem, outside the
sandbox, inspectable afterward — nothing touches the real system
`/overlayer`.

### 2d. Test matrix — Tier 2 through Tier 4

Run the above for one real package from each non-T1 tier (skip T1/`.zex`
— already excluded from patching):
- **T2 — Alpine**: e.g. `bwrap ... zex install <alpine-pkg-with-a-binary-and-shared-lib>`
- **T3 — Void**: same, a real `.xbps` package
- **T4 — Chimera** (`.adb`): same, a real Chimera package

For each, after install completes:
1. **Inspect the committed binary directly**:
   ```bash
   readelf -l Test-zairoot/overlayer/zexlib/union/bin/<binary> | grep interpreter
   readelf -d Test-zairoot/overlayer/zexlib/union/bin/<binary> | grep -i rpath
   ```
   Confirm interpreter is the `ld-musl-x86_64.so.1` path and RPATH shows
   `/overlayer/zexlib/union/lib`.
2. **Actually execute it**, inside the same shadowed-`/overlayer` sandbox,
   to prove it's not just correct-looking headers:
   ```bash
   bwrap --bind / / --bind /home/alizain/Test-zairoot/overlayer /overlayer \
     --dev /dev --proc /proc --die-with-parent \
     /overlayer/zexlib/union/bin/<binary> --version
   ```
   (or whatever invocation proves the binary actually runs and can find
   its shared libs — this is the step that would catch an RPATH-vs-RUNPATH
   mistake or a missed transitive dependency, which header inspection
   alone would not).
3. Confirm a T1 `.zex` package installed the same way is untouched by
   `elfpatch` (its interpreter/RPATH unchanged from what was already
   baked in at build time) — sanity check that the `PackageFormat::Zex`
   skip guard works.

### 2e. Cleanup between runs

`Test-zairoot/overlayer/zexlib/registry/installed/` and
`.../zexlib/union/` accumulate state across test runs — clear
`zexlib/union/*` and `zexlib/registry/installed/*.toml` between package
tests if a clean-slate re-test is needed (don't touch `syshub/` or
`zaisys/`, those are the base rootfs copy, not zex-managed).

## Part 3 — Bugs found (and fixed) during live verification

Real `zex install curl` against `Test-zairoot` surfaced three pre-existing
bugs unrelated to oxipatch itself, all in `installer.rs`. Fixed here since
they were directly in the path being verified.

1. **Registry double-write.** `installer.rs` Step 5 had a second, manual
   TOML-write block (`reg_path`) writing an inferior duplicate receipt to
   `/overlayer/zexlib/registry/<name>.toml` (registry root), while
   `register_package()` (called one line earlier) already writes the real,
   complete receipt to `registry/installed/<name>.toml` correctly. The
   manual block's justifying comment described a "store hash dir as
   lowerdir" remount model that `union.rs` confirms doesn't exist in the
   current architecture (zex writes straight into the single
   `zexlib/union` upperdir; Quantra doesn't remount per-install) — stale
   leftover from an earlier design. **Deleted the dead block.** Also fixed
   the adjacent commit-failure rollback path, which referenced the now-gone
   `reg_path`: on a **fresh install** failure it now calls
   `registry::unregister()` to fully undo the registration written just
   before commit (previously left a phantom "installed" entry for a
   package whose files were never committed). On an **upgrade** failure,
   left as a `log::warn!` instead — reconstructing the pre-upgrade
   `PkgRecord` from `DbEntry` is a separate, real gap, not silently papered
   over.

2. **File-conflict pre-flight check was dead code.** `check_file_conflicts`/
   `preflight_conflict_check` existed, fully documented, but had zero call
   sites anywhere in the install flow — `grep` confirms. On top of being
   unwired, the function itself was broken even if called: it compared
   `staged_files` (temp-dir paths like `/overlayer/zexlib/tmp/zex-stage-*`)
   against the DB's `installed_files` (final union paths) — those could
   never match. **Fixed the signature to take `committed_files` (final
   union destinations) and wired it into `install()`** right after Step 4
   computes them, before Step 5 registration — true pre-flight, nothing
   touched yet if it aborts.

3. **Extended the conflict check to cover syshub, not just other zex
   packages.** The DB-only check has no way to see that a file already
   exists in the *immutable base OS image* — syshub isn't zex-registered.
   Confirmed live: `zex install curl` silently installed a second, Alpine
   copy of `curl`/`libcurl.so.4` into `zexlib/union`, which — since
   OverlayFS always serves the upperdir over the lowerdir — silently
   **shadowed** syshub's own `curl` with a different build, no warning.
   Added a second check: for each `committed_file`, does the equivalent
   path already exist under `/overlayer/syshub/`? If so, hard error
   (`ui::print_file_conflicts`, same UX as an inter-package conflict). No
   `--force` bypass added — none exists anywhere in the `install` CLI
   today, so a real conflict is unconditional until that flag exists.
   **One deliberate exception: `musl` itself.** Every T2/T3/T4 package
   transitively depends on musl, and syshub providing it is the *intended*
   design (the whole reason `elfpatch.rs` rewrites every binary's
   interpreter/RPATH to point at syshub's own `ld-musl-x86_64.so.1`) — not
   a surprising duplication. Without this exclusion, confirmed live, no
   T2/T3/T4 package could ever install (`zex install htop` failed on
   `musl` before the exclusion was added). Every *other* syshub/zexlib
   collision stays a hard error.

**Found but NOT fixed — flagged for later, separate subsystem:**
`zex remove curl` claims "Cleaning orphaned dependencies... 100%" but its
12 dependencies (`libcurl`, `zlib`, `brotli-libs`, etc.) were confirmed
still present in both `registry/installed/*.toml` and
`zexlib/union/lib/*` after the remove completed — the orphan-cleanup step
is cosmetic, doesn't actually run. This lives in `cmd::remove`, a
different driver than everything else in this plan; out of scope for
tonight, worth its own investigation.

4. **`extract_adb` (T4/Chimera) never applied file permissions — fixed.**
   Confirmed live: a real Chimera package (`apk-tools-static-bin`) landed
   as `-rw-r--r--`; `apk.static --version` inside the bwrap sandbox failed
   with `Permission denied` (not an ELF/oxipatch issue — the file simply
   wasn't executable). `ExtractedEntry.mode` was already read for
   `S_IFDIR`/`S_IFLNK` type bits in `extract_adb`'s match, but the regular-
   file branch (`_ => { fs::write(...) }`) never called
   `fs::set_permissions` with it — `extract_tar` (used for apk/xbps) always
   did this correctly via `entry.header().mode()`; `extract_adb` just
   never had the equivalent line. Added
   `fs::set_permissions(&dest_path, Permissions::from_mode(entry.mode & 0o7777))`
   after the write. T4-only bug — T2/T3 packages were never affected.

5. **elfpatch corrupted a real static-PIE binary — fixed by skipping it
   entirely.** After fix #4, `apk.static` (Chimera) landed executable but
   segfaulted on every invocation (`--version`, `--help`, no args — all
   exit 139). `readelf` showed it's a static-PIE musl build: a real
   `PT_DYNAMIC` segment with self-relocation data (`DT_RELACOUNT` =
   26828 entries) but **no `PT_INTERP`** and **no `DT_NEEDED`** (fully
   self-contained, zero external library deps). `elfpatch.rs` correctly
   skipped `set_interpreter` (no interp to set) but still ran the RPATH
   rewrite unconditionally, which grows the `.dynamic` section — that
   growth is the suspected corruption point: static-PIE startup code
   self-applies its relocation table using offsets baked in at build time,
   and oxipatch's append-only-growth strategy shifting anything nearby
   plausibly desyncs it. **Fix:** `elfpatch::patch_one` now checks both
   `interpreter()?.is_some()` and `!needed_libs()?.is_empty()` up front —
   if a file has *neither* (no interpreter to run it, no dependencies to
   resolve), skip patching it completely rather than just skipping the
   interpreter step. Ordinary `.so` files also lack `PT_INTERP` but do
   have `DT_NEEDED` (their own transitive deps), so they're unaffected —
   confirmed separately against real Alpine `.so` deps. This is a real
   oxipatch-side edge case (RPATH-add on a self-relocating static-PIE
   binary), not something to consider fixed upstream — flagging for
   oxipatch's own backlog is worth doing separately; the zex-side fix
   here is the correct, safe mitigation regardless (RPATH was always
   meaningless for a file with no dynamic linker to consult it).

6. **`is_in_syshub` was silently broken for every `so:`-prefixed soname
   dependency — fixed at the resolver, not with a package-name carve-out.**
   User caught this live: a real `musl` package (Alpine, `1.2.6-r2`)
   installed into `zexlib/union` even though syshub already provides musl
   at `x86_64-zainium-linux-musl` — meaning two different musl builds now
   coexist, with OverlayFS silently serving the Alpine one. My first
   response (§ item above, now reverted) was a `pkg_name == "musl"`
   exception in the conflict-check — the user correctly rejected this as
   not systematic and asked for the resolver itself to recognize
   syshub-provided deps and never queue them at all. Root cause, traced
   through three real bugs in `backend::is_in_syshub`
   (`depends.rs::dep_already_present` calls this to decide whether to even
   queue a dependency):
   - `SyshubManifest.provides` was declared as a **top-level** field
     (expecting `[provides]`), but the real `syshub.toml` nests it as
     `[packages.provides]` — the field never actually populated.
   - Nothing stripped the `so:` prefix Alpine/Void/Chimera use for
     library dependencies (`so:libc.musl-x86_64.so.1`), so even a working
     lookup would search for a package literally named
     `"so:libc.musl-x86_64.so.1"`.
   - Even with both fixed, that exact token still wouldn't match the
     manifest's generic `libc = "musl"` alias without normalizing away the
     architecture-specific musl soname suffix.
   Fixed all three: `PackagesSection` now uses `#[serde(flatten)]` so
   `provides` (a named field) and the flat `versions` map both populate
   correctly from the real nested shape; `normalize_dep_token` strips
   `so:` and collapses any `libc.musl-*` soname to `libc` before matching
   against `provides`/`versions`. Confirmed live: `musl` is no longer
   queued as a dependency at all for a fresh `htop`/`curl` install — the
   `check_file_conflicts` `musl` exception (item 3 above) was removed
   entirely as a result; the conflict check is uniform again, exactly as
   the user wanted, because musl now never reaches it in the first place.

7. **Tier priority reordered per user decision**: Void is now Tier 2
   (`zex_services.toml` priority 3/4), Alpine dropped to Tier 3 (priority
   5/6), Chimera stays Tier 4 (7/8) unchanged. Reasoning given: Alpine
   targets embedded/minimal use, Void targets power users, and Zainium
   positions itself as the more capable OS of the two — Void should be
   tried first. Only the numeric `priority` values (what actually drives
   resolution order) were changed; cosmetic origin-label strings elsewhere
   (`"tier2-alpine"`, `"tier3-void"` in `registry.rs`/`upgrade/userland.rs`)
   were deliberately left alone — renaming them touches on-disk registry
   `origin` field matching across multiple files, a real regression risk
   for a purely cosmetic inconsistency; flagged, not silently fixed.

8. **History moved from `/var/lib/zex/history.json` to
   `/overlayer/zexlib/history.toml`, and JSON → TOML.** Per user request:
   consistency with every other piece of zex state (receipts,
   `packages.toml`, transaction snapshots — all TOML, all under
   `zexlib`) rather than a lone JSON file living outside `/overlayer`
   entirely. `HistoryFile { entries: Vec<HistoryEntry> }` wraps the list
   since TOML has no bare-array root, serialized as `[[entry]]`. Also
   incidentally explains why this session's `zex history` showed "No
   history recorded yet" through most of testing: the old path was
   outside the bwrap sandbox's shadowed `/overlayer`, so every write
   attempt silently failed (permission denied against the real host,
   confirmed nothing leaked there) — moving it under `zexlib` also fixes
   that for any future sandboxed testing.

9. **`is_in_syshub` fix #6 alone wasn't enough — the manifest data file
   itself was malformed TOML, always failing to parse.** After deploying
   fix #6, `musl` was *still* being queued. Traced to the actual
   `syshub.toml` on disk: `libc = "musl"` (plain string) followed later by
   `libc.so.6 = "glibc"` and `libz.so`/`libz.so.1` — in TOML, an unquoted
   dot in a key is a path separator, so `libc.so.6` means "table `libc`,
   key `so.6`", which collides with the earlier plain string `libc` and is
   a hard parse error. Verified empirically with a standalone
   `toml::from_str` test against the real file — confirmed
   `toml::from_str::<SyshubManifest>` had *always* failed, silently,
   including before any of tonight's changes (`is_in_syshub` returning
   `false` for everything, always — a second, independent latent bug,
   coincidentally masked until now). Fixed by quoting the four
   dot-containing keys (`"libc.so.6"`, `"libm.so.6"`, `"libz.so"`,
   `"libz.so.1"`) so TOML treats them as literal string keys, not nested
   paths. Confirmed live: `musl` install-plan exclusion and the
   pre-existing (also previously-dead, same root cause)
   `infuse.rs` "locked inside the immutable Syshub" root-package check
   both work correctly now.

10. **`extract_xbps` assumed zstd unconditionally — real Void packages can
    be xz.** Surfaced while retesting after the above:
    `zex install figlet` (now resolving from Void, post-reorder) failed
    with zstd's own "Unknown frame descriptor" error. Downloaded the real
    package directly and ran `file` on it: genuinely XZ-compressed, not
    zstd (`figlet-2.2.5_6.x86_64-musl.xbps`). `ARCHITECTURE.md`'s own tier
    table already documented `.xbps` as "zstd/xz-tar" — the code just
    never actually branched on it. `extract_xbps` now peeks the first 6
    bytes and picks `xz2::read::XzDecoder` or `zstd::stream::read::Decoder`
    based on real magic bytes (XZ: `FD 37 7A 58 5A 00`, zstd:
    `28 B5 2F FD`), erroring clearly if neither matches, instead of
    guessing. `extract_apk` (Alpine) was **not** touched — `.apk` really
    is always gzip per apk-tools v2's actual spec, confirmed against
    `ARCHITECTURE.md`'s tier table, not the same class of bug.

## Part 4 — Full driver smoke test (against the fully-fixed binary)

Every driver run for real inside the bwrap sandbox against `Test-zairoot`,
post all fixes above:

| Driver | Result |
|---|---|
| `install` | ✓ T2 (Alpine `figlet`→then Void after reorder)/T3 (Void `kurly`)/T4 (Chimera `apk-tools-static-bin`), conflict detection, musl exclusion — all confirmed |
| `remove` | ✓ clean removal, files + registry entry gone |
| `search` | ✓ real live results across all 3 mirrored tiers |
| `doctor` | ✓ runs a real audit (flagged some `Test-zairoot`-copy-specific filesystem gaps — dangling symlinks, a few missing relibc/musl files — plausibly artifacts of how the copy was made, not chased further; `--fix` deliberately not run, since it could write to syshub) |
| `rollback` | ✓ per-package tx rollback fully restores files + registry (syshub-tx rollback not exercised — needs a real `syshub --u` first, too risky/infra-dependent to trigger just for this) |
| `sweep` | ✓ cache cleanup |
| `inspect` | ✓ correct file list, size, dependency info |
| `depends` | ✓ correctly labels `musl` as `[syshub]`/protected in the tree (minor cosmetic count mismatch in the summary line — "To be installed: 1" when nothing was actually pending — not chased, informational-only) |
| `why` | ✓ correct reverse-dependency query |
| `pin`/`pins`/`unpin` | ✓ all three |
| `fmt` / `fmt keygen` | ✓ generates a real Ed25519 keypair |
| `history` | ✓ after moving it under `zexlib` (see item 8) and binding `/var/lib/zex` in the sandbox — writes and reads back correctly as TOML |
| `syshub`/`uland` (real upgrade) | **not exercised** — would need real infra at `archive.zainiumdynamics.tech` and is a much higher-blast-radius operation; deliberately left untested this session |

## Known gaps still open (found, not fixed — flagged for later)

- `zex remove`'s "Cleaning orphaned dependencies" step is cosmetic — confirmed
  live (Part 3, item 3) that dependencies are not actually removed. Separate
  subsystem (`cmd::remove`), needs its own investigation.
- `depends`'s summary counts (`Already installed`/`Syshub`/`To be installed`)
  don't always add up correctly — minor, display-only.
- Cosmetic tier-label strings (`"tier2-alpine"`, `"tier3-void"` in
  `registry.rs`/`upgrade/userland.rs`) still reflect the pre-reorder numbering
  even though the real `priority` values (which drive actual resolution) are
  now correct — not fixed, flagged as a maintainability nit, not a bug.

## Part 5 — The three flagged gaps, now fixed

All three verified live against `Test-zairoot` after fixing.

11. **`zex remove`'s orphan-cleanup was a fully cosmetic progress bar —
    now really removes orphans, cascading.** `cmd/remove/single.rs`'s
    `collect_safe_orphans` had the relationship backwards: it searched for
    packages that list the *target* (the thing being removed) as their own
    dependency — i.e. reverse-dependents — which is almost always empty for
    a leaf package like `curl`, not "what does curl depend on that's now
    unused." Worse, even if it had found anything, the result only ever
    fed a display line (`ui::print_removing_item`); the actual deletion
    loops iterated `to_remove` alone, never touching whatever
    `collect_safe_orphans` returned. Rewrote it to do the real check:
    take the removed package's own `dependencies` tokens, find which
    *other* installed packages satisfy them (matching both plain name and
    the package's own `provides` list — receipts mix plain
    `"pkgname=version"` and virtual `"so:soname"` tokens, confirmed
    against real receipts), then keep only the ones nothing else installed
    still needs. Iterates to a fixed point so removal cascades (removing
    `jq` orphans `oniguruma`; if `oniguruma` had its own now-unused dep,
    that would cascade too). Wired the result into the real file/receipt/
    master-index deletion loops, not just the display list. Confirmed
    live: `zex remove jq` → `oniguruma` (jq's only real, non-syshub
    dependency) is listed **and** genuinely deleted — files gone, receipt
    gone, `packages.toml` updated, "Packages removed: 2".
12. **`depends`'s summary math didn't subtract the syshub-protected
    count.** `missing = total_unique - installed_count` never subtracted
    `syshub_count`, so every syshub-provided dependency (e.g. `musl`) got
    double-counted as both "Syshub (protected)" and "To be installed" in
    the same summary. Fixed to subtract the union of installed ∪
    syshub-protected from the total (not a naive double-subtraction, in
    case a package is ever both). Confirmed live: `zex depends kurly` now
    shows `Total: 2, Already installed: 1, Syshub (protected): 1` with no
    phantom "To be installed" line.
13. **Tier-label strings renamed to match the reordered priorities.**
    `registry.rs::derive_origin` now emits `tier2-void`/`tier3-alpine`
    (was `tier2-alpine`/`tier3-void`) for newly-registered packages;
    `tier4-chimera`/`tier1-zainium` unchanged. Verified this doesn't touch
    upgrade-routing behavior first: `upgrade/userland.rs::match_mirror`
    matches on the distro-name substring too
    (`o.contains("alpine")`/`"void"`/`"chimera"`), not just the tier-number
    substring, so the rename only changes the label, not routing. Updated
    the now-stale doc comments alongside it. **Deliberately left the
    dozens of `tests/*.rs` fixtures using these exact strings unchanged**
    — they use `"tier2-alpine"` etc. purely as arbitrary, internally-
    consistent opaque test labels unrelated to real tier-priority-number
    correctness; renaming them would be pure churn with no behavior
    change and no test currently asserts anything about the number itself.
    Confirmed live: a fresh Void install's `packages.toml` entry now reads
    `origin = "tier2-void"`.

`fmt` was explicitly excluded from this pass — user is rebuilding it as a
standalone tool separately, to be wired back in later.
