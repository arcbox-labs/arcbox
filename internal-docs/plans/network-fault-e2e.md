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

Only faults the in-process origin can produce **at the application layer**
belong here; anything that needs the packet path interrupted (dropped SYNs, a
peer that stops ACKing) is Tier 3, because the host kernel keeps ACKing for a
merely-idle in-process peer and a closed local port answers with RST rather
than dropping the SYN.

| Fault | Mechanism | Assertion (guest side) |
|---|---|---|
| `rst_mid_transfer` | `SO_LINGER=0` + close at byte N | read fails ≤ deadline; no zombie flow *(Phase 1, implemented)* |
| `fin_half_close` | `shutdown(WR)` mid-body | EOF surfaces, connection drains |
| `stall_then_resume` | pause N s < deadline, resume | transfer completes; no spurious reset |
| `slow_loris` | 1 byte/s body | backpressure holds; no daemon memory growth (ties into splicetcp egress-backpressure work) |

Flow shapes to cross with each fault: short request, multi-GB download,
idle-keepalive connection, 100 concurrent flows, inbound port-forward (host →
container).

Zombie detection helper: `docker exec <c> netstat -tn` via the daemon's Docker
API; assert no `ESTABLISHED` flow **to the chaos-origin destination the guest
actually dialed** (`10.0.2.1:<port>` for the gateway→loopback path, the same
destination `egress_throughput` uses) whose counters are frozen across two
samples after the origin is gone. Note `198.18.0.0/15` is *not* an ArcBox
address — it is the Surge/Clash Fake-IP convention (`common/AGENTS.md`); a flow
lands there only when the developer's host runs such a proxy, so keying the
detector on it would silently pass on a clean runner. (The 2026-07-19 field
capture showed a `198.18.x` zombie precisely because that host proxies through
Fake-IP; the ArcBox-owned leg is the `10.0.2.1` one.)

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
  error — never zombie;
- **silent upstream death** (the field incident, faithfully): with a flow in
  flight, interrupt its packet path — drop the upstream leg's packets via a
  scoped `pf`/route change so the peer stops being reachable without a
  FIN/RST. This is the real reproduction of the incident (the daemon's socket
  errors, e.g. `EHOSTUNREACH`/`ETIMEDOUT`); the guest leg must error ≤
  deadline, not zombie. Cannot be done in-process (Tier 1), which is why it
  lives here;
- **connect blackhole**: drop SYNs to a target so `connect(2)` never completes
  → connect error ≤ the proxy's connect deadline, not a hang. Also needs the
  firewall (a closed local port answers with RST, which is fast rejection, not
  a blackhole), so it is host-global, not Tier 1.

## Observability assertions (cross-cutting)

Tests for **abnormal** terminations assert the daemon *logged* a proxy-layer
event (target `arcbox_net`/proxy, level ≥ WARN): a peer RST, a silent upstream
death, a connect blackhole. This deliberately excludes normal traffic that
merely resembles a fault — a clean FIN half-close, a stall that resumes and
completes, a slow-but-successful transfer — because those are not proxy faults
and a WARN on them would be production log noise (and would make correct tests
fail). The silent-upstream-death case (Tier 3) is where this currently fails —
the field incident produced zero proxy-layer lines — so the logging gap is
captured as a failing-by-design expectation alongside the behavior gap, and
both flip green with the same proxy fix.

## Where it runs

- Locally: `cargo test -p arcbox-e2e -- --ignored net_` (Tier 1–2), Tier 3
  behind the env gate.
- CI: Tier 1–2 in the self-hosted Apple Silicon runner job when
  `macos-runner-image-builder` lands; Tier 3 nightly on the same runner with
  the exclusive lock. GH-hosted runners stay excluded (no
  Virtualization.framework).

## Phasing

1. **(implemented)** `ChaosOrigin` fixture + `rst_mid_transfer` bounded-failure
   test — the smallest real e2e that exercises upstream-death propagation on
   ArcBox's own datapath. The faithful silent-death regression is Tier 3
   (needs packet-path interruption), not here.
2. Remaining Tier 1 faults × flow shapes; the zombie-detection helper; Tier 2.
3. Tier 3, including the silent-upstream-death incident regression
   (expected-fail) — after the self-hosted runner exists.
4. Proxy fix (detect upstream-leg death/error → guest-leg RST + WARN log) —
   flips the Tier 3 expected-fail tests green; ships with them in one PR.
