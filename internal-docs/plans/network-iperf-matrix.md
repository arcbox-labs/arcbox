# iperf3 throughput matrix e2e

`tests/e2e/tests/network_iperf.rs` — the programmatic counterpart to the
manual `docs/net-perf-limits.md` reproducer. `tests/e2e/AGENTS.md` states the
boot ladder proves liveness, not throughput, and that RX/TX regressions are
proven by hand; this turns that procedure into one command that records the
whole matrix to `RunMetrics`.

```
cargo test -p arcbox-e2e --test network_iperf -- --ignored --nocapture
```

Needs a host `iperf3` (`brew install iperf3`) and, in the guest, an iperf3
image (`networkstatic/iperf3`, override `ARCBOX_E2E_IPERF_IMAGE`).

## Matrix

A host-local `iperf3 -s` (killed on drop) the guest reaches at `10.0.2.1`
(gateway→loopback egress datapath):

- **netns**: default docker bridge (container datapath: eth0 → bridge → veth
  → container netns) vs `--net=host` (bare-guest datapath, no veth hop).
- **direction**: forward (guest→host **upload**) vs `-R` (host→guest
  **download**, the window-flow-control + retransmission path).
- **parallelism**: single stream vs `-P 4`.

Plus an **inbound** cell: an iperf3 server in a container with a published
ephemeral port, driven by the host iperf3 client — the reverse topology
through `InboundListenerManager`.

## Gating

Default gate is **liveness only** (`ARCBOX_E2E_IPERF_MIN_GBPS` defaults to 0):
a gated cell fails only if it errors/hangs or delivers literally zero.
Rationale: the project's stance is "no automated throughput target", and VZ
throughput is wildly run-to-run variable — an idle-VM freeze (ABX-420) drops
a 5 Gbps path to 0.4 Gbps with no code change (observed: `hostnet_download_p4`
5.58 Gbps one run, 0.45 the next). Every rate is recorded as a trend line;
set `ARCBOX_E2E_IPERF_MIN_GBPS` on a quiet machine for a real regression gate.

## Findings (2026-07-20)

Two robust findings, reproduced across every run (throughput absolute values
noisy, the *gaps* are not):

1. **Container (bridge) UPLOAD collapses.** Guest→host upload from a
   default-bridge container runs at ~5–150 Mbps single-stream while the same
   upload from a `--net=host` container runs at 0.5–3.3 Gbps — a 15–60×
   gap, present only on the upload direction through the veth hop (download
   through the bridge tracks bare-guest closely). None of the behavior tests
   caught this: 50 Mbps × 256 MiB ≈ 40 s, inside the workload suite's 180 s
   upload deadline. **Root cause not yet identified** (candidate: the guest
   forwards container→bridge→eth0 traffic as many 1460-byte segments without
   the GSO coalescing the bare-guest path gets, so the flow is frame-rate /
   effective-cwnd bound — needs guest-side `ss -i` / retransmit-counter
   instrumentation to confirm). Recorded + WARN-logged, not gated.

   A hypothesis that the WouldBlock→dup-ACK path (a spurious fast-retransmit
   collapsing cwnd) caused it was tested and **disproven** — a zero-window
   flow-control fix did not move the number — so no datapath change shipped
   for it. That remains the open investigation.

2. **Inbound port-forward fails a multi-connection application.** The first
   programmatic exercise of a published container port with iperf3 fails at
   iperf3's control-message exchange ("unable to receive control message …
   Socket is not connected"): the host TCP connect to the published port is
   accepted, but the relay does not carry iperf3's control + data connection
   set cleanly. Single-connection inbound (the workload plan's W6, still
   unimplemented) may differ; this is the first evidence the inbound relay
   has a real gap. Recorded + WARN-logged, not gated.

Both are candidates for dedicated investigation on a quiet machine; the test
is the standing reproducer and trend recorder for when they are fixed
(flip the cell to gated once healthy).
