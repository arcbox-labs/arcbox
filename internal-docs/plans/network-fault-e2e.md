# Network-fault E2E suite

Live-VM end-to-end tests that inject network faults and assert the guest
observes them correctly. Motivated by a field incident (2026-07-19): a
container `apk` download hung for 23+ minutes on a guest-side TCP flow that
stayed `ESTABLISHED` with empty queues after the daemon's upstream leg died —
the proxy neither propagated the death to the guest leg (no RST/FIN) nor
logged anything at the proxy layer (115 log lines in the window, all
heartbeats). No existing test exercises flow *lifetime* across host-side
faults; `egress_throughput` only measures the happy path.

## Principles

- **Real datapath only.** Every test boots a real VM via `DaemonHandle` and
  drives real containers through the real proxy/DNS-intercept path. No mocks —
  the incident lived precisely in the seams (guest TCP ↔ vsock/virtio ↔ daemon
  proxy ↔ host socket) that mocks erase.
- **Faults come from an in-test origin server, not from host mutation.** The
  e2e isolation contract (one data dir per daemon; never touch helper state,
  `/etc/resolver`, or host routes) stays intact for the default suite: the
  chaos origin runs inside the test process on localhost, so the "upstream"
  the proxy dials is ours to kill, stall, or reset. Host-global fault tests
  (route clobber, interface flap) are a separate exclusive tier.
- **Every fault has a deadline assertion.** The product property under test is
  *bounded failure*: after an upstream dies, the guest-side flow must observe
  an error within a deadline, and no zombie `ESTABLISHED` flow may remain.

## Tier 1 — chaos origin (default suite, parallel-safe)

Fixture: `ChaosOrigin` — a localhost TCP/HTTP server the container fetches
from through the proxy, with per-connection fault controls:

| Fault | Mechanism | Assertion (guest side) |
|---|---|---|
| `rst_mid_transfer` | `SO_LINGER=0` + close at byte N | read fails ≤ 2s; no zombie flow |
| `fin_half_close` | `shutdown(WR)` mid-body | EOF surfaces, connection drains |
| `silent_death` | `SIGSTOP` the origin (peer stops ACKing) | guest read errors ≤ proxy idle/keepalive deadline (**currently unbounded — this is the incident; test is `#[should_panic]`-documented until the proxy fix lands**) |
| `stall_then_resume` | pause N s < deadline, resume | transfer completes; no spurious reset |
| `connect_blackhole` | drop SYNs (listener closed, port firewalled in-process) | connect error ≤ deadline, not a hang |
| `slow_loris` | 1 byte/s body | backpressure holds; no daemon memory growth (ties into splicetcp egress-backpressure work) |

Flow shapes to cross with each fault: short request, multi-GB download,
idle-keepalive connection, 100 concurrent flows, inbound port-forward (host →
container), DNS-over-intercept lookups.

Zombie detection helper: `docker exec <c> netstat -tn` via the daemon's Docker
API; assert no `ESTABLISHED` flow to `198.18.0.0/15` whose counters are frozen
across two samples after the origin is gone.

## Tier 2 — daemon/VM lifecycle faults (default suite, serialized)

Reuses `daemon_failure.rs` patterns:

- daemon SIGKILL + restart with flows in flight → new flows work ≤ 10s,
  old flows error (not hang);
- VM pause/resume (balloon/idle path) with an idle-keepalive flow → flow
  survives or errors, never zombies;
- vsock flood during transfer (exercises the guest rx-budget patch end to
  end) → RPC latency bounded, no stall.

## Tier 3 — host-global faults (exclusive, nightly, self-hosted only)

These mutate host routing and MUST NOT run alongside anything (CI job takes a
runner-wide lock; locally behind `ARCBOX_E2E_HOST_CHAOS=1`):

- **route clobber replay**: add a competing `172.16/12` route via a scoped
  helper call, assert the reconciler repairs it ≤ deadline (today: no active
  watcher — `route_reconciler` is install-time-only with 5×2s retries; the
  incident window was 23 min), and host→container traffic recovers;
- **default-route flap**: toggle between two uplinks (the incident host has
  en0+en10 with the same gateway) → in-flight proxied flows must error ≤
  deadline, new flows must work immediately;
- **sleep/wake** (manual trigger): flows across a host sleep either resume or
  error — never zombie.

## Observability assertions (cross-cutting)

Each fault test also asserts the daemon *logged* a proxy-layer event for the
fault (target `arcbox_net`/proxy, level ≥ WARN). Today this fails for
`silent_death` — the incident produced zero proxy-layer lines — so the
logging gap is captured as a failing-by-design expectation alongside the
behavior gap.

## Where it runs

- Locally: `cargo test -p arcbox-e2e -- --ignored net_` (Tier 1–2), Tier 3
  behind the env gate.
- CI: Tier 1–2 in the self-hosted Apple Silicon runner job when
  `macos-runner-image-builder` lands; Tier 3 nightly on the same runner with
  the exclusive lock. GH-hosted runners stay excluded (no
  Virtualization.framework).

## Phasing

1. `ChaosOrigin` fixture + `rst_mid_transfer` + `silent_death` (the incident
   regression, expected-fail) + zombie detector. Smallest PR that would have
   caught the field bug.
2. Remaining Tier 1 faults × flow shapes; Tier 2.
3. Proxy fix (upstream keepalive/idle deadline → guest-leg RST + WARN log) —
   flips the expected-fail tests green; ships with them in one PR.
4. Tier 3 after the self-hosted runner exists.
