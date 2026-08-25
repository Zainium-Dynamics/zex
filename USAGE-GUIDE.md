# zex — internal usage guide

This is a practical reference for using `zex` day to day. It's meant for
people on the team who need to install, upgrade, and debug packages on a
Zainium box without going and reading the Rust source — the source stays
private, this doc is what stands in for it.

If you want to know *why* something works the way it does, or you're
changing the code, read `ARCHITECTURE.md` instead. This is about using
the tool, not building it.

## The basic idea

`zex` is one binary that answers to a bunch of different command names
(`zex install`, `zex-install`, `elevate zex install` — all the same
thing). It pulls packages from four places:

- **T1 — Zainium native (`.zex`)** — our own packages, signed with
  Ed25519, hashed with Blake3. This is where syshub itself lives too.
- **T2 — Void Linux (`.xbps`)**
- **T3 — Alpine Linux (`.apk`)**
- **T4 — Chimera Linux** (a different binary container, also confusingly
  named `.apk`)

If a name exists in more than one tier, whichever tier has the lowest
priority number in `zex_services.toml` wins. When zex pulls in a
dependency for something you asked for, it tries to stay on that same
tier first — it won't quietly swap in an Alpine build of a library for
something that otherwise came from Void.

Two places things get installed:

- `/overlayer/syshub/` — the immutable base. Mounted read-only most of
  the time; `zex syshub --u` remounts it read-write for the duration of
  an upgrade and puts it back to read-only when it's done, even on
  failure.
- `/overlayer/zexlib/union/` — everything else (T2/T3/T4 packages and
  userland `.zex` packages).

## Commands

Anything that writes to disk needs `elevate` in front of it.

### Installing and removing

```bash
elevate zex install ripgrep
elevate zex install vim htop curl fd-find     # multiple at once, installed in parallel

zex install neovim --dry-resolve              # show what would happen, don't touch anything
elevate zex install foo --cache-only          # only use what's already downloaded

elevate zex remove ripgrep
elevate zex remove foo --force                # skip the reverse-dependency check
zex remove vim htop --dry-run

elevate zex -i ./somepackage-1.0.zex          # install a local file directly, no network
```

If a dependency is something syshub already provides under a different
name (a common one: `coreutils` → we ship `userutils`), zex skips
installing it and tells you so instead of pulling in a redundant copy.
That list lives in `src/cmd/install/blocked.rs` — if you find another
case like this, that's where it gets added.

### Reproducible installs

```bash
elevate zex install somepkg --lock-out somepkg.lock.toml
elevate zex install --from-lock somepkg.lock.toml
zex install --verify-lock somepkg.lock.toml    # checks for drift, installs nothing
```

Useful for "make sure this box ends up with exactly the same dependency
graph as that other box."

### Updating and upgrading

```bash
elevate zex update                 # everything: refresh indices, upgrade both halves
elevate zex update --yes           # skip the confirmation prompt
elevate zex update --uland-only
elevate zex update --syshub-only

elevate zex uland --u              # just the userland half
elevate zex syshub --u             # just the immutable base
```

`zex syshub --u` is crash-safe — every step gets journaled to disk, so
if the process dies mid-upgrade (power loss, OOM kill, whatever), the
next `zex` invocation notices and finishes cleaning up on its own before
doing anything else. You don't have to do anything by hand.

If `zex` itself has a new version in the syshub package list, the
upgrade swaps its own binary out as part of the run — this is safe even
though zex is the thing running the upgrade, because the running process
keeps its old inode open until it exits.

### Looking things up

```bash
zex search "fuzzy finder"          # searches all four tiers at once
zex depends ripgrep                # dependency tree
zex why libssl                     # what depends on this
zex inspect ripgrep                # version, files, shared-lib deps, integrity status
zex history                        # every install/remove/upgrade, in order
zex history --package musl -n 5
```

### Health checks

```bash
zex doctor                         # checks the registry, dangling symlinks, glibc contamination
zex doctor --fix                   # tries to repair what it finds
```

Run `doctor --fix` if a package's files look like they've gone missing,
or something removed doesn't seem fully gone, or a symlink points at
nothing. It rebuilds the master package index from the individual
receipts if that's what's actually wrong.

### Pinning and rollback

```bash
zex pin gcc --reason "kernel ABI stability"
zex unpin gcc
zex pins                           # everything currently pinned

zex rollback --list
elevate zex rollback tx-1719446400000
```

A pinned package is skipped by upgrades until you unpin it. Every
transaction gets an ID you can roll back to individually.

### Cleanup

```bash
zex sweep --dry-run                # see what would be cleaned up
elevate zex sweep --aggressive

zex -e ./somepackage-1.0.zex -o ./extracted    # unpack a .zex without installing it
```

## Things that bite people

**A package that "installed successfully" but the binary won't run.**
Check `readelf -l <binary> | grep interpreter` — if it points at
`/lib/...` or anything not under `/overlayer/`, the ELF patch step
didn't run or didn't catch it. This should be automatic for every
install and upgrade now; if you see it happen, that's a real bug, not
expected behavior.

**A script fails with "No such file or directory" even though the file
is right there.** Check its first line (`head -1 thescript`). If it
says `#!/bin/sh` or `#!/usr/bin/env something`, that's the problem —
Zainium has no `/bin` or `/usr/bin`, so the kernel can't find the
interpreter the shebang names. zex rewrites these automatically on
install now, but it can only rewrite what it recognizes; if you hit a
shebang pattern that isn't `/bin/...`, `/sbin/...`, or `/usr/(local/)
bin|sbin/...`, it'll be left alone.

**`pkg-config` can't find a library that's clearly installed.** Check
the `.pc` file's `prefix=` line. Should read `/overlayer/zexlib/union`
for a normal dependency. If it says `/usr` or the wrong overlayer path,
that's the same class of bug as the shebang one above — same fix now
applies automatically, but flag it if you see a case that slipped
through.

**File conflict against "the base OS image."** Means the package you're
installing wants to write a file syshub already provides. If it's a
*dependency* being pulled in, zex is usually smart enough to skip just
those files and keep the rest. If it's the package you actually asked
for, you'll need `--force` (careful) or to just not install it — it's
probably redundant with what's already there.

**Downloads timing out or dropping mid-transfer.** zex retries this
automatically now (3 attempts, short backoff) for every download path —
install, update, and both upgrade commands. If it's still failing after
that, it's a real network problem, not something to debug in zex.

## Config files

| File | What it's for |
|------|----------------|
| `/overlayer/syshub/engine/services/zex_services.toml` | Mirror list, tier priorities, signature verification mode |
| `/overlayer/syshub/engine/services/syshub.toml` | What's actually in the immutable base right now |
| `/overlayer/zexlib/registry/installed/<name>.toml` | The receipt for one installed package — the actual source of truth |
| `/overlayer/zexlib/registry/packages.toml` | Derived index built from the receipts above; `zex doctor --fix` rebuilds it if it drifts |

## Testing changes before they ship

There's a sandboxed test environment at `Test-zairoot` that mirrors a
real Zainium install without touching the real machine — `bwrap` with
the overlayer tree bound in. Anything that touches package installation
or upgrades should get run through there against real packages from the
real mirrors before it's considered done. Synthetic test fixtures miss
things — most of the bugs in the 5.0.1 changelog entry only showed up
against real package content.
