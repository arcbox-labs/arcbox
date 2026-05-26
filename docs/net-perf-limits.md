# Network datapath — measured performance and known limits

As of `net-perf-mergeable-rx` tag (commit `eb45a46`, 2026-04-24). Host: Apple Silicon, macOS 26.0.1. Guest: Linux under HV backend. Bench: `iperf3` client on host against `networkstatic/iperf3` container in guest, port-forwarded.

## Headline numbers

| Direction | Single stream | `-P 4` | VZ reference |
|---|---|---|---|
| Host → VM | **22.7 Gbps** | (see below) | ~10 Gbps |
| VM → Host | **15.0 Gbps** | **19.1 Gbps** (0 retrans) | ~10 Gbps |

Single-stream exceeds Apple's native VZ virtio-net by ~2×. See `virt/arcbox-net-inject/src/inject.rs` — the inject thread uses `VIRTIO_NET_F_MRG_RXBUF` with a vectored `readv()` across up to 16 descriptors per syscall, so one GSO_TCPV4 frame fans out into 40+ MSS-sized segments on the guest.

## Known limitation: Host → VM collapses under multi-flow saturation

When multiple parallel Host → VM flows each try to push above ~5 Gbps at once, throughput collapses. One flow usually survives near full speed; the others drop to near-zero at the receiver. Measurement at `-P 2` with rate caps (`iperf3 -b`):

| Rate cap per flow | Receiver total | Per-flow status |
|---|---|---|
| `-b 500M` | 1.0 Gbps | both clean |
| `-b 2G` | 4.0 Gbps | both clean |
| `-b 4G` | 6.6 Gbps | 17% loss on one flow |
| `-b 6G` | 6.0 Gbps | one flow full, **other ≈ 0** |
| `-b 8G+` | ≈ 1 Gbps | one flow survives, rest drop |
| `-b 2G` with `-P 4` | 8.0 Gbps | all four clean |

Unbounded `-P 2/3/4` at line rate reproduces the collapse. The per-flow breaking point is roughly 4–5 Gbps each.

## What we've ruled out

- **Inject scheduler fairness.** Both the serial drain-per-conn and a round-robin across conns produce the same collapse under saturating load. The hot loop isn't starving conns.
- **RX ring capacity.** `QUEUE_NUM_MAX` is already 1024 (`virt/arcbox-vmm/src/device/mmio_state.rs:163`); bumping the inject-side caps didn't change the failure mode.
- **Inject CPU.** The host-side inject thread is nowhere near pegged during these tests.

## What we haven't checked yet

Three cheap guest-side experiments to run before considering structural changes (multi-queue virtio-net, new backend, etc.):

1. **Raise `QUEUE_NUM_MAX` from 1024 to 2048** and rerun `-P 2 -b 6G`. If the picture changes (both flows get data but still lossy), ring capacity/fairness is real. If unchanged, the bottleneck is deeper.
2. **Guest `ethtool -S` counters** (`rx_missed`, `rx_no_buffer`) + **`/proc/interrupts` CPU distribution** during `-P 2 -b 6G`. If all virtio-input IRQs land on one guest CPU, multi-queue is justified. If CPU distribution is fine, look elsewhere (GRO, softirq budget).
3. **Guest softirq %** during `-P 2 -b 4G`. If `%si` is pegged on one CPU, it's a NAPI-budget problem — try tuning `netdev_budget` / `netdev_budget_usecs` inside the guest before any structural work.

Pick the fix based on which of those three actually moves the needle. Multi-queue virtio-net is substantial (frontend, backend N threads, feature negotiation, flow hashing) and should not be speculated into.

## Diagnostic results (2026-04-24)

Ran all three. Short answer: **bottleneck is not guest-side**.

**Experiment 1 — `QUEUE_NUM_MAX` 1024 → 2048**: unchanged. `-P 2 -b 6G` still collapses to ~550 Kbps receiver. Ring size is not the cap.

**Experiment 2 — guest `ethtool` + `/proc/interrupts`**:

| Signal | Value |
|---|---|
| `ethtool -l eth0` combined queues | **1** (current = max, no multi-queue negotiated) |
| `ethtool -g eth0` RX/TX rings | 1024 / 1024 |
| `ethtool -S eth0` rx_drops after `-b 6G -t 20` | **0** (no loss at the NIC) |
| `ethtool -k eth0` GRO/TSO/LRO | all on |
| `/proc/interrupts` virtio1 | **7499 on CPU0, 0 on CPU1-3** (pinned) |

Interrupts pin to CPU0, but see experiment 3 — that CPU is not saturated.

**Experiment 3 — guest `mpstat` during `-P 2 -b 6G -t 20`** (steady state, iperf3 SUM ≈ 10.3 Gbps):

| CPU | %sys | %soft | %idle |
|---|---|---|---|
| 0 | 9.6 | 23.0 | **66.7** |
| 1 | 0 | 1.5 | 98.5 |
| 2 | 0 | 0 | 100 |
| 3 | 0 | 0 | 100 |

CPU0 has **65–70 % idle headroom** — NAPI/softirq is nowhere near saturated. Multi-queue would parallelize work CPU0 already handles comfortably. It is not the right fix.

### What this rules out

- **Ring capacity** (ruled out by exp 1)
- **Guest NIC drops** (ruled out by exp 2 — `rx_drops=0`)
- **Guest softirq CPU saturation** (ruled out by exp 3 — CPU0 at 25 % soft)
- **Multi-CPU parallelism** (ruled out by exp 3 — CPU0 has headroom)

### What this implicates

The host-side pipeline, not the guest. Candidates:

- **ACK-intercept path** in the tokio datapath loop (`try_fast_path_intercept` in `tcp_bridge.rs`) runs on a single tokio task. Each guest ACK frame does a HashMap lookup, a TCP flow update, a `stream.write` to the host socket, and an ACK-frame build — per ACK, sequentially across all flows. `tx_kicks = 660 k` during the 20 s test, so the datapath processed ~33 k ACKs/sec single-threaded.
- **Inject thread** sharing one CPU for N flows — but mpstat on the host wasn't captured; this is the next thing to measure.
- **Host-side flow-control interaction** with loopback TCP.

### Repeatability note

The 5-second `-P 2 -b 6G` run that showed "one flow 6 Gbps, other 275 Kbps" is a transient startup pattern. Over 20 seconds the flows converge to ~6 + 4.3 Gbps = ~10.3 Gbps aggregate. The *steady-state* cap is 10–12 Gbps combined, roughly half of the single-flow 22 Gbps. The pipeline isn't collapsing — it just doesn't scale beyond one flow's worth of throughput.

### Next step

Host-side profile, not guest-side structural work. Specifically, check inject-thread CPU on the host and profile `try_fast_path_intercept` during `-P 2 -b 6G`.

## Host-side profile (2026-04-24, follow-up)

Sampled the daemon with `/usr/bin/sample` during both `-t 30` runs. Results below are per-thread active samples (total − wait-state syscalls) out of ~12,400 samples per thread over 15 s. Single core = 100 %.

**P1 single-flow, receiver 29.5 Gbps:**

| Thread | Active | % core |
|---|---|---|
| hv-vcpu-0 | 10844 | 88 % |
| rx-inject | 1456 | 12 % |
| tokio-rt-worker (busy A) | 952 | 8 % |
| tokio-rt-worker (busy B) | 879 | 7 % |
| tokio-rt-worker (busy C) | 163 | 1 % |
| **Total active** | **14502** | **118 %** |

**P2 dual-flow `-b 6G`, receiver 10.9 Gbps:**

| Thread | Active | % core |
|---|---|---|
| hv-vcpu-0 | 8297 | 67 % |
| **rx-inject** | **4418** | **36 %** |
| hv-vcpu-1/2/3 | ~980 | 8 % combined |
| tokio-rt-worker (3 workers combined) | ~730 | 6 % combined |
| **Total active** | **~15000** | **121 %** |

Both runs burn **≈ 120 % of one core**. P1 delivers 29.5 Gbps with that budget; P2 delivers 10.9 Gbps. **Same CPU, 2.7× less throughput.** That rules out every hypothesis that starts with "we need more CPU cycles" — multi-queue, tokio restructuring, work-stealing — none of those add throughput when the budget isn't the constraint.

### What shifted between P1 and P2

- `hv-vcpu-0` dropped from 88 % to 67 %: guest is doing **less** work per second under P2 (fewer bytes moved, fewer TCP transitions).
- `rx-inject` **tripled** from 12 % to 36 %.
- Tokio workers stayed trivial (<10 % combined in both cases). **ACK intercept is not the bottleneck.**

### Where rx-inject's extra time went

Hot leaves under the rx-inject thread (active samples, leaves only):

| Function | P1 | P2 | factor |
|---|---|---|---|
| `readv` | 931 | 2277 | 2.4× |
| `hv_vcpus_exit` | 91 | 1176 | **13×** |
| `pthread_cond_signal` | 76 | 879 | 11× |
| `hv_gic_set_spi` | — | 133 | — |
| `Hv::Vm::set_spi` | — | 124 | — |
| `Hv::Vm::interrupt_cpus` | — | 105 | — |
| `Hv::Vcpu::interrupt` | — | 104 | — |

IRQ-delivery-related functions — `hv_vcpus_exit`, `hv_gic_set_spi`, `Hv::Vm::set_spi`, `Hv::Vm::interrupt_cpus`, `Hv::Vcpu::interrupt`, `pthread_cond_signal` — account for **~2500 samples** under P2 vs ~170 under P1. The inject thread is spending **~15× more time delivering interrupts into the guest** under dual-flow.

### Root cause

GSO RX-merge coalesces only within a single TCP flow. One flow of 29 Gbps fits into a few dozen giant 60 KB frames per millisecond — each inject cycle moves ~60 KB and fires one IRQ for the whole batch. Two flows at 5–6 Gbps each cannot cross-merge, so the frame count per unit throughput roughly doubles, and every extra frame carries the full IRQ-delivery cost (GIC SPI write, vCPU exit signal, pthread wakeup).

The cap at ≈ 10–12 Gbps combined is where the per-IRQ cost in `hv_vcpus_exit` + `hv_gic_set_spi` eats the remaining headroom.

### What this invalidates

- **Multi-queue virtio-net**: the guest has CPU headroom (exp 3 on the guest side showed 67 % idle on CPU0). Splitting onto more vCPUs doesn't reduce the *per-IRQ* host-side cost, which is where the hot leaves live.
- **Tokio restructuring / Phase D sync datapath**: tokio workers are trivially loaded in both cases. They are not the bottleneck.
- **Ring size**: already ruled out.

### What actually remains

- **`VIRTIO_F_EVENT_IDX` IRQ suppression.** We already write `avail_event` in `flush_interrupt` but then unconditionally fire: `// Unconditionally fire interrupt. EVENT_IDX suppression can be added later once the basic path is validated.` (`virt/arcbox-net-inject/src/inject.rs`). Consulting the guest's `used_event_idx` before firing lets us skip 50–90 % of IRQs when the guest is already polling. This directly attacks the hot leaves.
- **Longer `COALESCE_TIMEOUT`.** Currently 200 µs. Bumping to 500 µs or dynamically scaling under load trades tail latency for fewer IRQs. Easy knob.
- **Avoid the `pthread_cond_signal` hop.** The inject-thread → vCPU wakeup currently goes `set_interrupt_status + pthread_cond_signal`. If the vCPU is already running (`Hv::Vcpu::run`) we only need `hv_vcpus_exit`; the `pthread_cond_signal` is redundant and shows up at 879 samples in P2.

EVENT_IDX is the direct target of the signature and already scaffolded; it should be tried first.

## Reproducer

```bash
# Start a clean daemon.
arcbox daemon start

# Run an iperf3 server in a guest container.
docker run -d --rm --name iperf3-srv -p 5201:5201 networkstatic/iperf3 -s

# Headline tests.
iperf3 -c 127.0.0.1 -p 5201 -t 10                  # single stream (expect ≥20 Gbps)
iperf3 -c 127.0.0.1 -p 5201 -R -t 10               # VM→Host (expect ≥15 Gbps)
iperf3 -c 127.0.0.1 -p 5201 -R -P 4 -t 10          # VM→Host parallel (expect ≥15 Gbps sum)

# Collapse reproducer (each flow 6 Gbps — expect one survives, others drop).
iperf3 -c 127.0.0.1 -p 5201 -P 2 -b 6G -t 10

# Rate-limited works clean.
iperf3 -c 127.0.0.1 -p 5201 -P 4 -b 2G -t 10
```
