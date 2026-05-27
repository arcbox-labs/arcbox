# ArcBox VirtioFS Benchmark Suite

Standalone benchmark tool for measuring VirtioFS filesystem performance.
Covers both micro-benchmarks (raw I/O operations) and macro-benchmarks
(real-world workloads).

## Building

This crate is intentionally **not** part of the main workspace. Build it
directly:

```bash
cargo build --manifest-path tests/bench-virtiofs/Cargo.toml --release
```

## Usage

```bash
# List available benchmarks
cargo run --manifest-path tests/bench-virtiofs/Cargo.toml -- --list

# Run all benchmarks against VirtioFS mount at /arcbox
cargo run --manifest-path tests/bench-virtiofs/Cargo.toml --release -- \
    --all --platform arcbox-hv --target /arcbox

# Run a specific benchmark
cargo run --manifest-path tests/bench-virtiofs/Cargo.toml --release -- \
    --benchmark sequential_read --target /arcbox

# Output JSON for CI consumption
cargo run --manifest-path tests/bench-virtiofs/Cargo.toml --release -- \
    --all --format json --target /arcbox > results.json

# Compare with a baseline and fail on regression
cargo run --manifest-path tests/bench-virtiofs/Cargo.toml --release -- \
    --all --compare baseline.json --fail-on-regression --threshold 5

# Native baseline (run against a local directory)
cargo run --manifest-path tests/bench-virtiofs/Cargo.toml --release -- \
    --all --platform native --target /tmp/bench --format json > native.json
```

## Benchmarks

### Micro-benchmarks

| Name | Description | Metric |
|------|-------------|--------|
| `sequential_read` | 512 MB sequential read via `dd` | MB/s |
| `sequential_write` | 512 MB sequential write via `dd` | MB/s |
| `random_read_4k` | Random 4 KB reads (fio or Rust fallback) | IOPS |
| `metadata_stat` | `stat()` on 10k files in nested dirs | ops/s |
| `create_delete` | Create + delete 10k files | ops/s |
| `negative_lookup` | `stat()` on non-existent files (100k) | ops/s |

### Macro-benchmarks

| Name | Description | Metric |
|------|-------------|--------|
| `npm_install` | `npm install` of a small project | wall time |
| `git_clone` | Shallow clone of expressjs/express | wall time |
| `rm_rf` | `rm -rf` of a 5000-file directory tree | wall time |
| `find_recursive` | `find -name "*.ts"` over 2000 files | wall time |

## Performance Targets

These are the minimum acceptable performance levels as a percentage of
native macOS filesystem performance:

| Benchmark | Target |
|-----------|--------|
| `sequential_read` | 90% |
| `sequential_write` | 85% |
| `random_read_4k` | 80% |
| `metadata_stat` | 85% |
| `npm_install` | 90% |
| `rm_rf` | 90% |
| `negative_lookup` | 99% |

## CI Integration

The `--fail-on-regression` flag causes the tool to exit with status 1 if
any benchmark regresses beyond `--threshold` percent compared to the
`--compare` baseline file. This can be wired into CI to block merges
that hurt filesystem performance.

## Dependencies

Optional external tools for improved accuracy:

- `fio` -- Used for random I/O benchmarks when available.
- `npm` -- Required for `npm_install` macro-benchmark.
- `git` -- Required for `git_clone` macro-benchmark.
