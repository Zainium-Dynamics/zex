# Contributing to zex

## Build Requirements

```
Rust stable (≥ 1.82)        — cargo, rustc
Rust nightly                 — for fuzzing (cargo-fuzz)
musl cross-compiler          — x86_64-zainium-linux-musl-gcc (in syshub/bin)
ZainiumOS or compatible host — for integration testing
```

Install the nightly toolchain:
```bash
rustup toolchain install nightly
rustup target add x86_64-unknown-linux-musl  # for host cross-compile testing
```

## Build Commands

```bash
# Native build (host libc)
cargo build --release

# Cross-compile for Zainium musl target (on ZainiumOS)
CC=x86_64-zainium-linux-musl-gcc \
cargo build --target x86_64-zainium-linux-musl --release

# Cross-compile for relibc (requires nightly + custom target JSON)
cargo +nightly build \
  --target targets/x86_64-zainium-linux-relibc.json \
  -Z build-std=core,alloc,std \
  --release
```

## Testing

```bash
# All 502+ tests
cargo test

# Specific module
cargo test test_fs_mutations
cargo test test_install_driver
cargo test recover_stale
cargo test link_target

# With output (useful for debugging)
cargo test -- --nocapture

# Release mode (faster but harder to debug)
cargo test --release
```

### Fuzz Testing

```bash
cargo install cargo-fuzz

# Smoke test (60 seconds per target)
cargo +nightly fuzz run fuzz_manifest_parser -- -max_total_time=60
cargo +nightly fuzz run fuzz_receipt_parser  -- -max_total_time=60

# Full overnight run (72 hours)
cargo +nightly fuzz run fuzz_manifest_parser -- -max_total_time=259200
```

## Code Style

### ANSI Colour Palette

All terminal output uses the standard zex palette. Never use `colored`,
`termcolor`, or other crates — inline ANSI constants only:

```rust
const G:   &str = "\x1b[92m";  // green  — success, Zainium branding
const P:   &str = "\x1b[95m";  // purple — package names
const B:   &str = "\x1b[96m";  // blue   — versions, paths, numbers
const Y:   &str = "\x1b[93m";  // yellow — warnings
const R:   &str = "\x1b[91m";  // red    — errors
const DIM: &str = "\x1b[2m";   // dim    — secondary info
const BLD: &str = "\x1b[1m";   // bold   — headers
const RST: &str = "\x1b[0m";   // reset
```

### Error Handling

Use `anyhow` for all fallible functions. Never use `unwrap()` in production
code paths — use `.context("description")` or `bail!("message")`:

```rust
// Good
let raw = fs::read_to_string(&path)
    .with_context(|| format!("reading receipt: {}", path.display()))?;

// Bad
let raw = fs::read_to_string(&path).unwrap();
```

### Logging

Use `log::` macros (not `tracing::` — relibc compatible):
```rust
log::info!("Installing {}", pkg.name);
log::warn!("Package '{}' is pinned — skipping", name);
log::debug!("Blake3 verified for '{}'", name);
```

### No glibc

All code must compile and run against musl or relibc. Never use:
- `dlopen` / `dlsym` (use static linking)
- `pthread_atfork` (not available in relibc)
- `epoll_pwait2` (use `epoll_wait`)
- Any `glibc`-specific extension

### Driver Structure

Each driver command (`cmd/<name>/`) must have:
- `mod.rs` — declares all submodules, `pub use main::run`
- `main.rs` — `pub async fn run(raw_args: Vec<String>)` entry point
- `ui.rs` — all terminal output functions (zero printing elsewhere)

### Filesystem Writes

All registry writes MUST use the atomic tmp-rename pattern:

```rust
let tmp = path.with_extension("toml.tmp");
fs::write(&tmp, data).context("writing tmp")?;
fs::rename(&tmp, &path).context("committing")?;
```

### Path Safety

All paths from package manifests must be validated before use:
```rust
assert!(path.starts_with("/overlayer/"), "path escapes overlayer");
assert!(!path.contains("../"), "path traversal detected");
```

## Adding a New Command

1. Create `src/cmd/<name>/` with `mod.rs`, `main.rs`, `ui.rs`
2. Add `pub mod <name>;` to `src/cmd/mod.rs`
3. Add dispatch arm to `src/main.rs`
4. Add man page to `man/zex-<name>.1`
5. Add shell completion to `completions/`
6. Write at least 10 unit tests in `tests/test_drivers.rs`

## Pull Request Checklist

- [ ] `cargo fmt` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (all 502+ tests)
- [ ] New code has tests (minimum: 1 test per public function)
- [ ] No `unwrap()` in non-test code
- [ ] No `tracing::` (use `log::`)
- [ ] All file paths validated against `/overlayer/` prefix
- [ ] Man page updated if CLI changed
- [ ] ARCHITECTURE.md updated if structure changed

## Repository

```
https://github.com/zainiumdynamics/zex
```

Bug reports: GitHub Issues
Discussions: GitHub Discussions
Security issues: alizain.x404@gmail.com (PGP preferred)
