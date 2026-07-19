# zex fuzzing — cargo-fuzz setup

## Requirements

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Run a target (minimum 72h for thorough coverage)

```bash
# From zex/ root directory:

# Manifest parser (most critical — parses untrusted package data)
cargo +nightly fuzz run fuzz_manifest_parser -- -max_total_time=259200

# Archive extractor (path traversal prevention)
cargo +nightly fuzz run fuzz_zex_extractor -- -max_total_time=259200

# Alpine APKINDEX parser
cargo +nightly fuzz run fuzz_apkindex_parser -- -max_total_time=259200

# XBPS plist parser
cargo +nightly fuzz run fuzz_xbps_parser -- -max_total_time=259200

# Version comparison
cargo +nightly fuzz run fuzz_vercmp -- -max_total_time=259200

# Receipt parser (path escape prevention)
cargo +nightly fuzz run fuzz_receipt_parser -- -max_total_time=259200
```

## Run with AddressSanitizer (recommended)

```bash
RUSTFLAGS="-Z sanitizer=address" \
cargo +nightly fuzz run fuzz_manifest_parser \
  fuzz/corpus/fuzz_manifest_parser \
  -- -max_total_time=86400
```

## Using the seed corpus

All targets have seed corpora in `fuzz/corpus/<target_name>/`.
cargo-fuzz picks them up automatically.

To minimize a found corpus:
```bash
cargo +nightly fuzz cmin fuzz_manifest_parser
```

## Reproducing a crash

```bash
cargo +nightly fuzz run fuzz_manifest_parser fuzz/artifacts/fuzz_manifest_parser/crash-abc123
```

## Fuzz target invariants

| Target | Key Invariants |
|---|---|
| `fuzz_manifest_parser` | No panic; paths under /overlayer/; no path traversal; signature length sane |
| `fuzz_zex_extractor` | No panic; no path escape from output dir |
| `fuzz_apkindex_parser` | No panic; no null bytes in names; no path separators |
| `fuzz_xbps_parser` | No panic; no path separators in package names |
| `fuzz_vercmp` | No panic; reflexive; antisymmetric; transitive |
| `fuzz_receipt_parser` | No panic; paths under /overlayer/; no null bytes; no path traversal |

## CI integration

Add to `.github/workflows/ci.yml` for nightly fuzz runs:

```yaml
fuzz:
  runs-on: ubuntu-latest
  if: github.event_name == 'schedule'
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@nightly
    - run: cargo install cargo-fuzz
    - run: cargo +nightly fuzz run fuzz_manifest_parser -- -max_total_time=3600
    - run: cargo +nightly fuzz run fuzz_receipt_parser  -- -max_total_time=3600
    - run: cargo +nightly fuzz run fuzz_zex_extractor   -- -max_total_time=3600
```
