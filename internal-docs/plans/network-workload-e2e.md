# Network-workload E2E suite

Companion to `network-fault-e2e.md`: that plan injects *faults*; this one
asserts the datapath under the realistic *workloads* a developer generates
every day — large pulls, uploads, dependency-install bursts, published ports,
DNS, container-to-container traffic. Today only the happy-path download
direction has any coverage (`egress_throughput`); everything else a developer
does daily is untested end to end.

## Principles

- **Locally runnable is the bar.** Every default-suite test runs on any Apple
  Silicon dev machine via `cargo test -p arcbox-e2e -- --ignored net_` with:
  no external network (in-process origins/sinks on localhost), no privileged
  helper, no vmnet, parallel-safe (isolated data dirs; only ephemeral host
  ports). CI wiring inherits the fault plan's "Where it runs" unchanged — the
  suite must not *depend* on it.
- **Real datapath only** (same as the fault plan). `docker exec`/`logs`/`cp`
  ride vsock, not eth0 (`app/arcbox-docker/src/proxy/connector.rs`), so they
  are the out-of-band control channel for in-guest assertions even when the
  network path under test is saturated or wedged.
- **Behavioral bounds, not absolute throughput.** Assertions are deadlines,
  zero-stall, latency-flatness ratios, and zombie-freedom; `RunMetrics`
  records the absolute numbers as trend lines, they are never pass/fail.
- **Workloads must be quiet.** The observability inverse of the fault plan:
  after every workload scenario, the daemon log must contain no proxy-layer
  ERROR, and a zombie sweep (the fault plan's detector, shared fixture) must
  come back empty. Faults assert loud logs; workloads assert quiet ones.

## Capability boundaries (source-verified 2026-07-19)

What the datapath actually supports, hence what is testable in the default
suite:

- **Published ports work helper-free in isolated mode.** The primary NIC is a
  socketpair-backed file-handle attachment created unconditionally
  (`virt/arcbox-vmm/src/vmm/darwin.rs`), and `InboundListenerManager` binds
  plain unprivileged sockets against it
  (`common/arcbox-proxy/src/inbound_relay.rs`). The vmnet "bridge NIC" +
  helper-installed `172.16/12` route is a separate mechanism for direct
  container-IP L3 routing only — out of scope here (fault plan Tier 3
  territory).
- **Ephemeral publish (`-p 127.0.0.1::80`) resolves guest-side.** Guest
  dockerd allocates the host port before `start` returns; ArcBox parses the
  inspect JSON and binds that exact port
  (`app/arcbox-docker/src/port_bindings.rs`,
  `app/arcbox-core/src/runtime.rs::resolve_bind_ip` — `127.0.0.1` bind IPs
  honored). `docker port` proxies the guest JSON verbatim. Never exercised by
  a test — W6 is that assertion.
- **UDP is a full per-flow proxy, not DNS-only.** Outbound non-DNS UDP gets a
  real host socket per 4-tuple with gateway→loopback translation and 60 s
  idle expiry (`common/arcbox-proxy/src/egress/udp.rs`); UDP publishing is
  supported inbound (`inbound_relay.rs` synthesizes L2 frames).
- **DNS:** containers query `10.0.2.1:53` directly (dockerd `daemon.json`,
  `guest/arcbox-agent/src/init.rs`), intercepted in-VMM by `DnsForwarder`
  sharing the host `DnsService` hosts table: `host.docker.internal` /
  `gateway.docker.internal` → gateway IP, dynamic `<name>.arcbox.local`
  registrations, NXDOMAIN for unregistered own-domain names, everything else
  forwarded to the host's resolv.conf upstreams (`virt/arcbox-net/src/dns.rs`).
  Own-domain behavior is fully local-testable; upstream forwarding is
  environment-dependent (external phase only).
- **Upload direction has no backpressure queue.** Guest→host payload writes
  that hit `WouldBlock` are silently dropped without ACK; recovery is the
  guest kernel's RTO retransmit
  (`common/splicetcp/src/tcp_bridge/fast_path.rs:91-104`). Download has a
  bounded-channel backpressure path (`common/splicetcp/src/direct_rx.rs`);
  upload has nothing. Accepted-by-design per the module docs, but W2 must pin
  the resulting behavior (eventual completion, no stall-forever) so a
  regression from "slow" to "stuck" is caught.
- **Container↔container traffic never leaves the guest kernel** (dockerd
  bridges/veth; the host only proxies the API calls). W10 is therefore a
  guest-kernel + dockerd regression test — exactly what the 6.18
  iptables-legacy migration needs standing coverage for — not a proxy test.

## The workload matrix

Shared fixture work (Phase 0): lift the blob server (`egress_throughput`) and
`ChaosOrigin` (`network_fault`) into `tests/e2e/src/net_fixtures.rs`; add a
`SlowSink` (raw-TCP byte-counting reader with a scriptable mid-stream pause),
a `UdpEcho`, a `published_host_port(data_dir, container, "80/tcp")` helper
(reads `docker port`), and the fault plan's zombie detector — one
implementation serving both suites. Scenarios within one test share a single
booted daemon and aggregate failures (the `run_downloads` pattern), because
boot time dominates.

| # | Workload (daily behavior) | Mechanism | Assertions |
|---|---|---|---|
| W1 | sustained download (big-file pull) | exists: `egress_throughput` | unchanged |
| W2 | sustained upload (push/POST) | `dd if=/dev/zero bs=1M count=256 \| nc 10.0.2.1 <port>` into `SlowSink`; variants: normal reader, reader pauses 5 s mid-stream | sink byte count exact; completion ≤ deadline in both variants — pause must slow it (RTO), never wedge it |
| W3 | concurrency burst (npm/cargo install shape) | 64 parallel 4 MB downloads inside one container + 8 containers × 8 flows | all complete; slowest ≤ 4× median (straggler bound); zombie sweep clean |
| W4 | connection churn (apk/git-HTTP shape) | 500 sequential GETs, fresh connection each | last-decile latency ≤ 3× first-decile (no per-flow leak/slowdown); no flow-table growth after |
| W5 | keepalive reuse | 100 pipelined requests on one connection (`printf … \| nc`; fixture speaks keep-alive) | all responses arrive, per-request latency flat |
| W6 | inbound publish TCP (dev serves a port) | `busybox httpd` + `-p 127.0.0.1::80`; discover port via `docker port` | (a) content correct from host `curl`; (b) 64 MB inbound download; (c) 32 concurrent host connections; (d) `docker stop` → host port stops accepting (listener lifecycle) |
| W7 | inbound publish UDP | `nc -u -l` echo in container, `-p 127.0.0.1::<p>/udp` | host datagrams echo back; port released on stop |
| W8 | UDP egress | container `nc -u 10.0.2.1 <port>` against `UdpEcho` | echo round-trip; after >60 s idle the flow re-establishes (expiry is invisible to the app) |
| W9 | DNS daily paths | in-container `nslookup` via vsock exec | `host.docker.internal` → gateway IP; named container resolves as `<name>.arcbox.local` from another container; unregistered `.arcbox.local` NXDOMAINs ≤ 2 s (bounded, not forwarded) |
| W10 | container↔container (compose shape) | user-defined network, `busybox httpd` server + client by service name and by IP | resolution + transfer work; regression net for guest bridge/iptables-legacy config (6.18) |
| W11 | registry round-trip (push+pull compound) | `registry:2` in-guest publishing ephemeral port; host CLI pushes alpine to `host.docker.internal:<port>`, pulls back | full-loop egress+inbound with real dockerd traffic. **Blocked**: guest dockerd needs `insecure-registries` for plain-HTTP non-loopback — requires an agent-side knob first; Phase 3 |
| W12 | long-lived idle flow across idle-shrink | keepalive flow held open past `ARCBOX_IDLE_TIMEOUT_SECS=20`, then reused | works or errors — never zombies (overlaps fault plan Tier 2; implement once, there) |
| W13 | parallel large downloads (multi-image-pull shape) | 8 × 64 MiB concurrent in the workbench | all complete ≤ deadline; straggler ≤ max(4×median, 10 s); throughput recorded; zombie sweep *(implemented)* |
| W14 | docker build (compound daily flow) | context with 8 MiB incompressible payload + RUN wget from the blob server; byte-exactness via in-build `RUN test $(wc -c)` | build succeeds ≤ deadline; built image runs; context and download byte-exact *(implemented)* |
| W15 | download integrity | known-pattern (`fill_pattern`) download piped through in-guest `sha256sum` | hash matches the server's hash of the exact bytes served — content, not just length *(implemented)* |
| W16 | upload integrity | container hashes a urandom payload it sends; host `spawn_hashing_sink` hashes what it receives | the two SHA-256s match — guards the direction the silent-data-loss bug hit *(implemented)* |

## External phase (env-gated, never default, still local)

`ARCBOX_E2E_EXTERNAL=1` (same spirit as `ARCBOX_E2E_EGRESS_URL`): real-tool
runs on a dev machine with internet — the tools whose hangs started all this:

- E1 `apk add` a real package (the 2026-07-19 incident's exact shape);
- E2 `git clone` a small public repo over smart HTTP;
- E3 `docker pull` a multi-layer image ≥ 500 MB (concurrent layer fetches);
- E4 HTTPS ≥ 100 MB download (TLS through the datapath).

Each with a hard deadline and the zombie sweep. Results are
environment-dependent by nature; these exist to be run manually when touching
the proxy, not to gate anything.

## First-run findings (2026-07-19, Phase 1 on master's datapath)

The initial local runs (with and without hot-path debug logging) failed all
five Phase-1 scenarios and pinned three datapath defects, all with **zero
proxy-layer WARN/ERROR lines** — the fault plan's observability gap
reproduced under plain workloads:

1. **Uploads silently lose data** (W2, both variants, both runs: 256 MiB
   arrived 1.3-3.2 MB short while the in-container client exited 0 — even
   against a reader draining at full speed). Mechanism, from
   `common/splicetcp/src/tcp_bridge/fast_path.rs`:
   - `is_new_data` accepts any segment whose *end* extends `last_ack`, so
     after a `WouldBlock` drop the next in-flight segment is written and
     `set_last_ack(seq_end)` **ACKs across the hole** — the guest never
     retransmits the dropped bytes (permanent gap, silently acknowledged);
   - `Ok(_n)` ignores short writes: partially written segments are ACKed in
     full, losing the unwritten tail;
   - FIN handling runs `close_fast_path` unconditionally, so a
     close-after-write client kills gap recovery even where it would work.
2. **Concurrent downloads wedge permanently, sequential ones degrade**
   (W3: 18 of 64 single-container flows and 5 of 64 across-containers flows
   died on a 60 s read timeout even with quiet logging; W4: sequential churn
   slowed to ~2 s/request — 120 of 500 requests inside the 240 s ceiling).
   The download
   direction sends with a hardcoded `window: 65535`, never reads the guest's
   advertised receive window, has no retransmission, and deliberately
   ignores pure ACKs — so a single guest-side window-overrun drop leaves a
   sequence gap no mechanism can fill; the guest dup-ACK storms (hundreds
   to ~1.1k per flow in the daemon log) until the client times out. The
   `guest-tx delivery counters` prove L2 delivery stayed lossless
   (`lossy_dropped=0`, `enobufs` events blocked-not-dropped), placing the
   loss at guest TCP window overrun.
3. **Hot-path debug logging is an observer effect**: `splicetcp=debug` logs
   every classified frame (~6k lines/s during a dup-ACK storm), distorting
   the datapath under measurement. The workload suite therefore runs the
   daemon at `info,arcbox_net=debug`.

**Resolved 2026-07-20** — the suite runs green end to end. Three product
fixes, each accepted by these scenarios:

1. Upload in-order ACK discipline (`last_ack` advances only over bytes
   actually written; dup-ACKs solicit guest fast retransmit; FIN defers
   past gaps) — W2 byte-exact.
2. Guest-window flow control **plus sender-side retransmission** (in-flight
   bytes buffered, window capped at 256 KiB, triple-dup-ACK fast retransmit,
   200 ms–2 s RTO, FIN retransmitted too). The deeper finding: the lossless
   L2 contract ends at guest `eth0` — the bridge→veth→container-netns
   backlog drops under burst (64 flows through one veth wedged 61/64;
   spread across 8 containers only 5/64), so the shim, as the download
   direction's sender-side TCP, must retransmit. Window gating alone made
   bursts *worse* by turning each drop into a full-window deadlock — W3.
3. Idle-datapath wakeups (connect-resolved waker + 20 ms poll tick while
   flows exist): a quiet loop only woke on guest frames or a 1 s tick, so
   every fresh connection paid up to a second twice (SYN-ACK, then first
   response bytes) — invisible under sustained transfer, ~2 s/request when
   sequential. Churn went from 127-of-500-in-240 s to 19 ms/request — W4.

The strict assertions stay as the permanent regression net; only the
observability WARNs from the original finding list remain future work
(loss-recovery events currently log at debug).

## Runtime budget

Default suite ≈ 4 test binaries (`network_workload` W2–W5, `network_inbound`
W6–W8, `network_dns` W9–W10, plus existing `egress_throughput`/
`network_fault`), one boot each ≈ 15–20 min serial on an M-series machine;
parallel-safe if run concurrently (distinct data dirs, ephemeral ports only).

## Phasing

1. Fixture lift (`net_fixtures.rs`; no behavior change to existing tests).
2. `network_workload.rs`: W2 upload (normal + paused-reader), W3 burst,
   W4 churn — pure in-process, no new capability questions, and W2 pins the
   datapath's weakest documented spot.
3. `network_inbound.rs` (W6–W8) + `network_dns.rs` (W9–W10) — W6 doubles as
   the missing e2e for ephemeral publish.
4. W5, W12 (with fault-plan Tier 2), W11 behind the insecure-registry knob,
   external phase E1–E4.
