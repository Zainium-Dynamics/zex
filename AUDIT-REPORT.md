# Zex Audit Report — pointer

This file previously held a short audit snapshot (2026-07-10). Updated
2026-07-19 after a two-phase correctness + capability strengthening pass —
see the canonical report for full detail.

**Canonical full report:** [`REPORT.md`](./REPORT.md)  
**Release history:** [`CHANGELOG.md`](./CHANGELOG.md)  
**Format specification:** [`ZEX-FORMAT.md`](./ZEX-FORMAT.md)  
**Architecture:** [`ARCHITECTURE.md`](./ARCHITECTURE.md)

Summary verdict:

| Item | Status |
|------|--------|
| Build / tests | Green — 502 tests |
| Formats | `.zex` (Tier 1), `.apk` gzip-tar (Tier 2 Alpine), `.xbps` (Tier 3 Void), `.apk` **ADB binary container** (Tier 4 Chimera — not gzip-tar) |
| Per-tier signature verification | **Real for all four** — Tier 1 was found broken (double-hashing bug) and fixed this pass; Tiers 2–4 independently confirmed against live packages |
| Dependency resolution | Real BFS with version-constraint checking, tier affinity, conflict checking (`depends.rs`) — **not** PubGrub, which exists in-tree but is dead code |
| Upgrade CLI | `uland` + `syshub` only; syshub upgrades are now crash-safe (journaled + self-healing) |
| Reproducibility | `zex install --lock-out/--from-lock/--verify-lock` |
| Audit trail | `zex history` — previously-unused module now wired up |
| Production | Controlled rollout with migration; not universal distro PM |
