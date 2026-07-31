# VirtioFS datapath — measured performance and known limits

As of boot assets **0.6.13** (kernel v0.0.22 with the `fuse-spin-wait` patch,
2026-08-01). Backend: VZ (Apple's virtio-fs device — the custom VirtioFS
serves only the HV backend and has **no** performance measurement yet).
Host: Apple Silicon, macOS 26.4. Bench: `tests/bench-virtiofs` run inside the
guest against the `/arcbox` share; driver: `tests/e2e/tests/bench_virtiofs.rs`
(isolated daemon, results in `target/bench-virtiofs/`). Full investigation
record: Linear CORE-48.

## Headline: the fuse-spin-wait patch (kernel#17)

Same-day, same-VM-shape A/B, container context, `--warmup 1 --iterations 3`:

| bench | stock 6.18.38 | + spin-wait | Δ |
|---|---|---|---|
| metadata_stat | 31.8k ops/s | **50.3k** | **+58%** |
| negative_lookup | 23.6k | **33.0k** | +40% |
| create_delete | 4.6k | **5.9k** | +28% |
| find_recursive | 18.3k | **21.6k** | +18% |
| rm_rf | 2505 ms | **2380 ms** | −5% |
| sequential_read | 3771 MB/s | 3637 MB/s | −3.5% (noise) |

Mechanism: on virtualized ARM64 every synchronous FUSE op paid a cross-vCPU
round trip — device-IRQ trap, then a reschedule-IPI trap (measured **1:1**
with the request IRQ), then two context switches. Two architectural facts
make this unfixable by scheduling policy: ARM64 has no `TIF_POLLING_NRFLAG`
(every wakeup sends a physical IPI), and all vCPUs share one LLC domain
(`wake_affine` never migrates the waiter onto the IRQ CPU — the bare-metal
assumption that within-LLC IPIs are cheap breaks under virtualization).

The fix (`kernel` repo, `patches/fuse-spin-wait.patch`): `request_wait_answer`
polls `FR_FINISHED` for ≤40µs before sleeping — KVM halt polling applied at
the FUSE wait point. Double-gated: only virtio-class transports
(`fc->iq.ops != &fuse_dev_fiq_ops`; classic `/dev/fuse` daemons keep stock
behavior) and only non-blocking opcodes (READ/WRITE/FLUSH/FSYNC/FSYNCDIR/
COPY_FILE_RANGE/SETLKW excluded — an ungated spin cost **−54%** sequential
read). Reference ceiling: `taskset` + IRQ-affinity pinning reaches 54.6k
stat ops/s; the patch reaches ~97% of it with zero affinity management.

## Competitor context (Colima, Apple virtio-fs, Ubuntu 6.8 guest)

Both sides run **Apple's** virtio-fs device — this comparison isolates the
guest kernel + context, not the FS server. Two same-day container-context
pairs (same musl bench binary, same flags):

| bench | ArcBox 0.6.13 | Colima | ratio |
|---|---|---|---|
| metadata_stat (2026-07-31) | 52.8k | 51.7k | 102% |
| metadata_stat (2026-08-01) | 49.8k | 77.0k | 65% |
| negative_lookup (08-01) | 34.5k | 36.8k | 94% |
| create_delete (08-01) | 5.5k | 7.6k | 72% |
| find_recursive (08-01) | 20.1k | 25.8k | 78% |
| random_read_4k, buffered (08-01) | 21.9k | 37.0k | 59% |
| rm_rf (08-01) | 2482 ms | 1732 ms | 1.43× slower |
| sequential_read (08-01) | 3392 MB/s | 4160 MB/s | 82% |
| sequential_write (08-01) | 1652 MB/s | 1964 MB/s | 84% |

**Read the spread, not one cell**: Colima's own container-context stat swung
51.7k → 77.0k across two days (its container tax also varied: −34% one day,
≈0 the next), while ArcBox held 30–32k stock and 50–53k patched across ten
boots. Pre-patch ArcBox lost every row at 39–84%; post-patch the hottest
metadata ops sit at parity-to-65% depending on Colima's day. Unmeasured:
OrbStack, Docker Desktop, and our own HV backend.

## What we've ruled out (each with a same-VM A/B)

- **Container / seccomp overhead (ours)**: ArcBox numbers are identical in
  and out of containers, and `seccomp=unconfined` changes nothing — the
  round-trip cost dominates. (Colima's container tax exists and varies.)
- **`dax=always`**: never active on VZ. The pid-1 mount table shows
  `rw,relatime` only — Apple's device exposes no DAX window, and the agent's
  "remounted with dax=always" log records intent, not outcome.
- **CPU mitigations / HZ / preemption**: identical between the two guests
  (spectre_v2 `CSV2, but not BHB`; both HZ=1000 + voluntary preemption).
- **Guest syscall/VFS path**: on tmpfs (no virtiofs) ArcBox is 6–28%
  *faster* than Colima — the gap lived entirely in the FUSE round trip.
- **Kernel-version regression**: inverted — 6.12.11 scored 12.6k stat
  (2.4× worse); the 6.18 bump was a large improvement.
- **Wake latency / placement knobs**: `idle=poll` ±0; `__wake_up_sync` +11%;
  best sched-feature toggle (`NO_TTWU_QUEUE`) +12%; 2-vCPU boot ±0. None
  approach the pinning ceiling (+82%) — hence the spin-wait design.
- **`PARAVIRT_TIME_ACCOUNTING`**: inert — VZ offers no ARM PV_TIME, the
  static key never enables.

## Measurement discipline (violating these produced wrong conclusions)

- **Same context**: container vs container, or shell vs shell — never mixed.
  The original "39%" figure compared our container against Colima's shell.
- **Same day, paired**: competitor numbers swing up to ~50% across days;
  ours drift ≤9%. Cross-day ratios are noise.
- **Native is not a denominator for metadata**: cache-hot APFS stat runs at
  605k ops/s; no FUSE transport approaches it. Use competitor guests as the
  bar. (The CLAUDE.md "File I/O >90% of native" target predates this.)
- **Only the in-process trio is ratio-safe**: `metadata_stat`,
  `create_delete`, `negative_lookup`. The others shell out to PATH tools,
  call macOS-only `purge`, or depend on the I/O engine — see
  `CONFOUNDED_RATIO_BENCHES` in the bench driver.
- **Pin the random-read engine** (`--random-read-engine`); fio results
  report under a different name so cross-engine joins are impossible.

## Known gaps / next steps

- `create_delete`, `rm_rf`, buffered `random_read_4k` still trail Colima —
  the first two are unlink/fsync-class round trips the spin does not fully
  cover; small buffered reads are `FUSE_READ` and deliberately excluded
  from the spin (an ungated spin regressed bulk reads −54%).
- Upstream track: adaptive grow/shrink budget (as in KVM halt polling)
  instead of the fixed 40µs, with the LLC/IPI-under-virtualization story as
  motivation. Reproducer material in CORE-48.
- Extend the bench driver to `ARCBOX_VM_BACKEND=hv` to get the first
  numbers for the custom VirtioFS (feeds RES-17 / Paper B).
- Fix the agent's misleading dax log (records intent, not outcome).
