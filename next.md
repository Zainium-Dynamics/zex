# next.md — zex ↔ quantra integration: what's left to build

Working notes for tomorrow. Covers: partial rollback in `zex`, auto service
pickup by `quantra`, the syshub-immutability invariant, and the ELF-patch
module `zex` needs of its own (separate from `zex-env`).

---

## 1. Partial rollback in `zex`

**Already implemented** (`zex/src/cmd/rollback/transaction.rs`):

- `rollback_userland(tx_id)` — this is *already* per-package/per-transaction,
  i.e. already "partial" in the sense that matters: it reads the package's
  receipt (`registry/installed/<pkg>.toml` → `PkgRecord.installed_files`),
  deletes exactly those files/symlinks/dirs from `zexlib/union/`, restores
  the pre-op `packages.toml` + `<pkg>.toml` snapshots, and re-extracts
  `backup.tar.zst` if the tx was an upgrade/remove. One `tx-<id>` = one
  package's install/upgrade/remove, reversed surgically.
- `rollback_syshub(tx_id)` — same idea for a `syshub-<id>` tx: remount
  `/overlayer/syshub` rw, extract `syshub-backup.tar.zst` over it, restore
  `syshub.toml`, remount ro. **This is the only code path anywhere that is
  allowed to write to syshub** (see §3).
- Dispatch is by tx-id prefix (`"syshub-"` vs plain) in
  `rollback/main.rs::run()`.

**Not implemented yet — this is the gap:**

- A **full reset** command (what `quantra-ramfs/ARCHITECTURE.md` currently
  only documents as a manual `rm -rf /overlayer/zexlib/union/*`). That's not
  safe to expose as a raw shell instruction — it needs to be a real `zex`
  subcommand that:
  1. Iterates every `registry/installed/*.toml` receipt (not just one tx)
     and removes every listed file/symlink/dir from `zexlib/union/`.
  2. Truncates `packages.toml` back to empty (or to a "factory" snapshot if
     one exists).
  3. Clears `pinned.toml`.
  4. Leaves `transactions/` and `tmp/` cache alone (or offers `--purge-cache`
     as a separate flag — don't conflate reset with `zex sweep`).
  5. Emits a summary (packages removed, bytes freed) same as
     `rollback_userland` does today via `ui::print_uland_success`.
- Proposed name: `zex rollback --full` (reuses the existing `rollback`
  verb/module) or a new top-level `zex reset` — pick one, don't add both.
  Leaning `zex rollback --full` since it's the same mental model (undo to a
  known-good state) and keeps the command count at 11.
- Needs a confirmation prompt (`--yes` to skip) since it's destructive across
  *all* packages, unlike today's single-tx rollback.

---

## 2. Auto-registration with `quantra` when `zex` installs something

**Already implemented, just needs to be wired up:**

- `quantra/src/services/manager.rs::add_and_start_transient(service)` — can
  register + start a brand-new service at runtime, no reboot needed.
- `quantra/src/services/manager.rs::reload_named_service(name)` — sends
  `reload_signal` (default `SIGHUP`) or runs `reload_command` for an
  already-running service.
- `quantra-ctl` already exposes `Reload { service }` as a CLI verb
  (`quantra-ctl/src/main.rs:93`) that maps to `ControlCommand::Reload`.
- Service unit discovery at boot:
  `parser::parse_services_with_enabled_filter(cfg.services_dir, cfg.enabled_dir)`
  (`manager.rs:468`) scans `/overlayer/syshub/etc/quantra-system/services/*.toml`.

**The actual gap:** none of this fires automatically when `zex install`
drops a new `services/<name>.toml` into that directory mid-session. Today
the user would have to manually run `quantra-ctl reload <service>` or
reboot. To make "install → it just runs" true:

- After a successful install/upgrade whose receipt includes a path under
  `.../etc/quantra-system/services/`, `zex` should shell out to (or IPC into)
  `quantra-ctl` and call the equivalent of `add_and_start_transient` for any
  *new* unit, or `Reload` for an existing one being upgraded.
- Decide the transport: `quantra-ctl` already talks to `quantra` over some
  control channel (check `quantra/src/ctl/main.rs` for the socket/IPC
  mechanism) — `zex` should reuse that same channel rather than shelling out
  to the `quantra-ctl` binary if a library entry point exists.
- This should be best-effort and non-fatal: if `quantra` isn't reachable
  (e.g. running inside a chroot/build sandbox, not live boot), `zex install`
  must still succeed — just skip the notify step and log it.

---

## 3. Syshub immutability — hard invariant, not a convention

**Rule:** nothing except `zex`'s own two code paths may ever write to
`/overlayer/syshub/`:

1. `zex syshub --u` (upgrade) — three-rename swap
   (`syshub.new` → rename over `syshub`), documented in `zex/ARCHITECTURE.md`
   §"Syshub Upgrade Swap".
2. `zex rollback <syshub-tx-id>` — brief `remount rw` → restore from
   `syshub-backup.tar.zst` → `remount ro`
   (`rollback/transaction.rs::rollback_syshub`).

Everything else — every ordinary `zex install/remove/upgrade` of a userland
package, every config edit a running service makes, every log write — goes
through the OverlayFS `upperdir` (`zexlib/union`), **never** through a direct
write to the `syshub` lowerdir. This already falls out naturally from the
mount being read-only (`quantra-ramfs/src/overlay.rs` mounts syshub as
lowerdir, which OverlayFS never writes to directly — COW always lands in
upperdir).

**What to double check / harden tomorrow:**

- Confirm the *physical* `/zairoot/overlayer/syshub` partition/mount is
  actually mounted read-only at the block/mount level (not just "nothing in
  our code writes there") — otherwise a root process outside `zex` could
  still `mount -o remount,rw` it. `quantra-ramfs/src/verity.rs` (dm-verity)
  is the real backstop here: if syshub sits on a verity-protected device,
  writes aren't just discouraged, they're **impossible** without breaking
  the root hash. Verify verity is actually wired to the syshub partition,
  not just implemented as a module.
- `rollback_syshub`'s `remount(SYSHUB_PATH, true/false)` shells out to
  `mount -o remount,rw|ro` — confirm this is gated so *only* the `zex`
  syshub-rollback code path can invoke it (i.e. no other command in `zex`,
  and nothing in `quantra`, ever calls this remount helper).
- Nothing outside `zex/src/cmd/rollback/transaction.rs` and the syshub
  upgrade-swap code should reference `SYSHUB_PATH` as a write target — worth
  a quick grep across `zex/src/` and `quantra/src/` to confirm no other
  module writes under `/overlayer/syshub/` (reads are fine and expected
  everywhere).

---

## 4. ELF patching for `zex` — use `oxipatch`, do not reimplement

**Superseded plan below.** The original idea here was to hand-write a fresh
patchelf-equivalent inside `zex`. Don't — `oxipatch`
(`/run/media/alizain/ZAINIUM_DRIVE/zex-native/oxipatch`, workspace-local
crate, v0.1.0) is *already* a complete, from-scratch, full-parity Rust
reimplementation of patchelf: interpreter, `RPATH`/`RUNPATH` (including
`shrink-rpath` and `$ORIGIN`), `SONAME`, `NEEDED`, hash-table rebuild,
exec-stack, OS-ABI, symbol rename — ~71 tests green, clippy/fmt clean. `zex`
should depend on it as a library and call it, not re-derive byte-level ELF
surgery a second time. (`zex-env`'s `elffix.rs`/`linksafe.rs`/`scanlibs.rs`
stay untouched as personal `zexc` tooling — that decision is unaffected;
this is specifically about not *also* writing a second bespoke patcher
inside `zex` when a tested one already exists.)

**Prerequisite gap — resolved.** oxipatch used to live only on a removable
exFAT-like drive (`ZAINIUM_DRIVE`) with no git repository, so a path
dependency would've broken `zex`'s build whenever that drive was
unmounted. **Resolution: git dependency, not crates.io.** oxipatch now has
a real remote at `https://gitlab.com/alizain.arch/oxipatch.git` (confirmed
reachable, `master` branch). `zex/Cargo.toml` should depend on it as:
```
oxipatch = { git = "https://gitlab.com/alizain.arch/oxipatch.git" }
```
Pin to a specific `rev`/`tag` once oxipatch cuts a stable point (don't
float on `master` indefinitely — `Cargo.lock` will freeze the commit either
way, but an explicit `rev` makes intent visible in `Cargo.toml` itself).
No crates.io publish needed for `zex` to consume it.

**Where it plugs in:** `oxipatch::elf::ElfFile` (`open`/`set_interpreter`/
`set_rpath`/`add_rpath`/`commit`/`write_in_place`) called from
`zex/src/cmd/install/installer.rs::install()`, right after the
`extract_apk`/`extract_xbps`/`extract_adb` branches (installer.rs:203-207)
populate `staged_files`, and *before* the receipt/registry write. New thin
wrapper module `zex/src/cmd/install/elfpatch.rs` (mirrors the shape of
`native_sig.rs` — one focused file, not folded into `installer.rs`) that:
1. Filters `staged_files` down to actual ELF binaries/libraries (magic-byte
   check, not just extension) among the extracted set.
2. For each: `set_interpreter` to
   `/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1`,
   and rewrite `RPATH`/`RUNPATH` entries pointing at FHS paths
   (`/usr/lib`, `/lib`) to `/overlayer/zexlib/union/lib` — same rewrite
   rules `zex-env/src/elffix.rs`'s doc comment already specifies
   behaviorally (canonical interpreter path, leaked-host-path and FHS-path
   RPATH rules, `$ORIGIN` handling); oxipatch's `set_rpath`/`add_rpath`
   already handle the `$ORIGIN`-relative and force-rpath cases, no need to
   reimplement that part either.
3. Only runs for T2/T3/T4-sourced packages (`PackageFormat::Apk`/`Xbps`/
   `Adb`) per `zex/ARCHITECTURE.md` §"Four-Tier Package Routing" — T1
   `.zex` packages are already built against `/overlayer/` and must be
   skipped.
4. Errors here should fail the install (unlike the quantra-notify step in
   §2, a package with an unpatched interpreter is just broken, not
   best-effort) — surface via the same error path `installer.rs` already
   uses for extraction failures.
- Test the same way the rest of this project verifies tier-routing
  behavior: real Alpine/Void `.apk`/`.xbps` packages through the `bwrap`
  sandbox, confirming the patched binary actually executes under
  `/overlayer/` afterward (not just that oxipatch's own unit tests pass —
  those already do, they don't cover zex's specific path-rewrite rules).
