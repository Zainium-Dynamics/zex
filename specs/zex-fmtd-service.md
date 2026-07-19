# zex-fmtd — Server/Website Backend Design (spec, not yet implemented)

Yeh doc batata hai ke `zex-fmt` (CLI tool, already implemented) ke upar
ek **daemon/service** kaise banega jo website/upload-page ke peeche
chale: user source submit kare -> daemon compile+scan kare -> reports +
`.zex` wapas de de. Maine isay implement nahi kiya (sirf design) kyun ke
arbitrary user-uploaded code ko compile/run karna **sandboxing/isolation
infra** maangta hai (VM/container per job, no network egress, resource
limits) jo is single CLI repo ke scope se bahar hai aur ghalat tarike se
implement karne par khud ek security hole ban sakta hai. Neeche jo design
hai woh production-safe pattern follow karta hai.

## High-level flow

```
[User uploads source.tar.gz via web form]
        │
        ▼
[zex-fmtd: POST /v1/submissions]
        │  - saves upload to /var/zex-fmtd/queue/<job-id>/
        │  - returns job-id immediately (202 Accepted)
        ▼
[Worker pool — each job runs in its OWN ephemeral container/VM]
        │  - no network egress except crates.io/apt mirror cache
        │  - read-only base image, job dir is the only writable mount
        │  - CPU/mem/time limits (e.g. 10 min wall clock, 2 vCPU, 4 GB)
        │  - runs: zex-fmt pack <src> -v <version> --locked
        ▼
[Artifacts copied OUT of the sandbox]
        │  - <name>_<version>.zex
        │  - <name>.toml            (install receipt)
        │  - <name>_<version>.zex.locked
        │  - <name>_<version>.zex.locked.review.md
        ▼
[zex-fmtd: GET /v1/submissions/<job-id>]
        - status: queued | running | passed | failed
        - on failed: exact tool that failed + why (cargo-audit advisory id,
          clippy lint, cppcheck finding, layout violation, etc.)
        - on passed: download links for the 4 artifacts above
```

## Why sandboxing is non-negotiable here

`zex-fmt pack` runs `cargo build`-adjacent tools (`cargo audit`,
`clippy`, `cppcheck`, etc.) against **untrusted, user-submitted source**.
Any of these can have build.rs / proc-macros / Makefiles that execute
arbitrary code at compile time. A web backend that runs this directly on
the host is a remote-code-execution service. Required isolation:

- One disposable container/microVM per submission (e.g. Firecracker,
  gVisor, or a fresh Docker container with `--network=none`,
  `--read-only`, a tmpfs work dir, and a non-root user).
- No outbound network from inside the sandbox except a pinned
  registry mirror (so `cargo audit`'s advisory DB and `cargo build`'s
  crate downloads still work without giving submitted code free
  internet access).
- Hard wall-clock + CPU + memory + disk-quota limits, enforced by the
  orchestrator, not by the tool itself.
- The sandbox is destroyed after artifacts are copied out — never
  reused for a second job.

## Suggested API surface

```
POST   /v1/submissions          multipart upload (source tarball) -> {job_id}
GET    /v1/submissions/:id      -> {status, report_json, artifact_urls[]}
GET    /v1/submissions/:id/zex          -> binary .zex
GET    /v1/submissions/:id/locked       -> .zex.locked (maintainer-auth required)
GET    /v1/submissions/:id/review.md    -> review checklist (maintainer-auth required)
POST   /v1/submissions/:id/review       -> maintainer-only: fill one of the 5 review slots
```

`/locked`, `/review.md`, and `POST /review` should require maintainer
authentication (not public) — that's the whole point of keeping
`.zex.locked` separate from the public `.zex`.

## What zex-fmt (this repo) already gives the daemon for free

Everything the daemon needs to *call* already exists as a library
function, not just a CLI:

- `zex_fmt::core::packer::pack(...)` — the daemon's worker can call this
  directly instead of shelling out to the `zex-fmt` binary, and get a
  structured `Result<PackResult, ZexError>` back.
- `zex_fmt::core::report::SecurityReport` — serializes straight to JSON
  for the `GET /v1/submissions/:id` response body.
- `zex_fmt::core::lock::LockedManifest::to_review_markdown()` — exactly
  what `GET /review.md` should return.

So the daemon itself can be a thin async wrapper (e.g. `axum` + a job
queue) around this library — no reimplementation of the audit logic
needed.
