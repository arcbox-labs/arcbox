# common/ — Shared Crates Agent Guidance

Scope: the pure, transport-agnostic crates under `common/`. Routing lives in
`common/arcbox-route/AGENTS.md` (authoritative — do not restate it here);
splicetcp internals live in `common/splicetcp/README.md`.
The crates below the net cluster — `arcbox-asset`, `arcbox-constants`,
`arcbox-error`, `arcbox-logging` — also live in `common/` but are **not** net
crates; the one hard rule below does not bind them. See "arcbox-asset &
distribution".

## The one hard rule

- **No VM / VirtIO / device / hypervisor dependency** in any `common/` net
  crate (`arcbox-packet`, `arcbox-datapath`, `arcbox-conntrack`, `arcbox-dns`,
  `arcbox-fakeip`, `arcbox-proxy`, `splicetcp`, `arcbox-xnu-net`). WHY: two
  independent consumers depend on that purity — the VM datapath
  (`virt/arcbox-net`, `virt/arcbox-net-virtio`) and the host-only proxy harness
  (`virt/arcbox-net/examples/tun_proxy.rs`, docs/surge-tun-proxy.md). Every
  change must serve **both**; adding a VM type here silently breaks the host
  harness. Most net-crate `lib.rs` headers restate this (arcbox-xnu-net's
  does not) — keep them true. The dependency half is checked mechanically
  by `cargo xtask check-layers` in CI (`linux-engine` job), for every
  `common/` crate, net or not: no direct edge into `virt/`, `engine/`,
  `computer/`, `app/` or `guest/`.

## arcbox-asset & distribution — invariants (net-purity rule does not apply)

- **Per-call unique temp name is load-bearing.** `download_and_verify` /
  `download_raw` (`arcbox-asset/src/download.rs`) stream to a private
  `{name}.{pid}.{seq}.tmp` sibling (`unique_temp_path`), hash the stream
  incrementally, then `rename` atomically. There is **no** cross-process lock,
  and several callers install into the same `~/.arcbox/runtime/bin`
  concurrently. Reverting to a fixed `dest.tmp` lets two writers truncate and
  interleave one file that *each writer's own stream hash still verifies* — a
  corrupt binary then gets renamed into place as "verified". Uniqueness makes
  each writer's temp private, so concurrent installs degrade to
  last-writer-wins with a genuinely verified file. The temp is removed on every
  error path — don't "simplify" that away, unique names otherwise accumulate.
  Regressions: `concurrent_downloads_of_same_dest_yield_verified_file`,
  `checksum_mismatch_removes_temp_file`.
- **The download module is feature-gated; plain `cargo test -p arcbox-asset`
  runs ZERO of those tests.** `download` is not in `default` (`Cargo.toml`).
  Run `cargo test -p arcbox-asset --features download`, or the regressions
  above are silently skipped.
- **tgz tools trust a sidecar, not the binary (ABX-413, open — tgz install
  integrity gap).** For `ArtifactFormat::Tgz` tools (`docker`,
  `docker-compose`) the `assets.lock` sha pins the **archive**, so `is_cached`
  and `validate_all` (`app/arcbox-docker-tools/src/manager.rs`) read a
  `{name}.sha256` sidecar and **never re-hash the extracted binary** — swap the
  installed binary while leaving the sidecar intact and `validate_all` passes.
  `ArtifactFormat::Binary` tools (`buildx`, …) ARE re-hashed against the file.
  Do not treat sidecar validation as tamper detection.
  - Wrong/corrupt docker binary that still passes `validate_all` →
    `shasum -a 256 ~/.arcbox/runtime/bin/docker` and
    `cat ~/.arcbox/runtime/bin/docker.sha256` → the sidecar (archive sha)
    matched while the binary did not; delete the sidecar to force a reinstall.
- **`arcbox-boot` is an EXTERNAL registry crate — do not patch it from this
  repo.** Pinned as `arcbox-boot = "0.5.1"` in the workspace `Cargo.toml`; it is
  not a path member. It still carries the fixed-temp-name bug and trusts the
  manifest bytes it parses (ABX-417, open — boot-manifest trust gap). The fix
  must land upstream and then be version-bumped here; a local edit has nowhere
  to go. (The `arcbox-boot` *binary* under `virt/arcbox-hypervisor/src/bin/` is
  an unrelated target that shares the name.)
- **`arcbox-constants/src/wire.rs` is the single source of truth** for
  `AGENT_PROTOCOL_VERSION` / `MIN_AGENT_PROTOCOL_VERSION` and the `MessageType`
  registry. Evolution rules (when to bump, how to add a message type, the
  roundtrip-test requirement) live in `rpc/AGENTS.md` — follow it, don't
  restate.

## arcbox-datapath — memory-safety landmines

- `LockFreeRing` is **SPSC only**; `MpmcRing` is the multi-producer/consumer
  variant (Vyukov bounded queue, `T: Copy`). WHY it matters: wiring a second
  producer/consumer onto `LockFreeRing` is **silent UB, not a slowdown** — no
  compile error (`unsafe Send/Sync` is bounded only on `T: Send`, which the u32
  indices used here satisfy). `PacketPool` uses
  `MpmcRing` deliberately for ABA safety (`src/pool.rs`).
- `PacketRef` **auto-frees on drop**. To hand a buffer to a ring by index, call
  `into_index()` (suppresses the free via `ManuallyDrop`); passing `.index()`
  without consuming the ref double-frees. `pool.get_mut(idx)` while any
  `PacketRef` for that index is live is caller-guaranteed **instant UB** — none
  of this is compiler-checked. `pool.free()` spin-retries because the MPMC ring
  can transiently report full; do not "fix" that into a bail.
- `LockFreeRing`/`MpmcRing` capacities round up to the next power of two
  (`next_power_of_two`). `PacketPool::new` does **not** — it keeps the caller's
  raw capacity (`.max(1)`); only its internal free-index ring rounds up.

## arcbox-conntrack — NAT engine cross-site invariants

- **Reverse-NAT key lockstep (extension checklist).** The reverse key
  `(dst_ip, external_ip, dst_port, nat_port, protocol)` is hand-built at THREE
  sites — two in `src/conntrack.rs` (`get_or_create` insert, `remove` delete)
  and one in `src/translate.rs` (`translate_inbound` builds the lookup key;
  `lookup_reverse` only does `self.reverse.get`, it builds no key).
  Change the tuple shape in one place and outbound still works while return
  traffic is silently `NatResult::Dropped` — a one-way-connectivity bug that is
  hard to localize. Change all three together.
- Hardcoded framing assumptions in `translate()`: L2 Ethernet at offset 0,
  EtherType at `[12..14]`, IPv4 (`0x0800`) only, TCP(6)/UDP(17) only —
  everything else is `PassThrough`/`Dropped`. UDP checksum `0` means "no
  checksum" and is deliberately skipped.
- `NatEngine::new` defaults the internal subnet to `192.168.64.0/24`. Callers on
  a different subnet MUST call `set_internal_network` or NAT silently no-ops.
- `PortAllocator::allocate` is a bare `fetch_add` mod range — it does **not**
  check conntrack for a live collision. Flag this before trusting it at high
  connection counts.
- Incremental RFC 1624 checksum updates live in `arcbox-packet::checksum`; the
  SIMD variants must equal the scalar path (`test_checksum_simd` asserts it).

## Guest-facing parsers (VM path)

- `translate()` (arcbox-conntrack) and `DnsQuery::parse` (arcbox-dns) consume
  arbitrary guest bytes on the VM datapath. The virt/AGENTS.md "Guest-controlled
  input" rule applies here: every guest-programmed value is arbitrary bits, all
  arithmetic on it must be checked, bounds verified before any slice. Any new
  field access needs the same length/overflow guards; tests must cover
  truncated and oversized inputs (including near-`u64::MAX`).

## arcbox-dns — hand-rolled byte layout

- Response builders write flag bytes at `[2]`/`[3]` and counts at `[6..12]`
  literally. `build_nxdomain`/SERVFAIL/NODATA MUST zero ANCOUNT/NSCOUNT/ARCOUNT,
  or EDNS(0) queries (ARCOUNT=1 in the request) get malformed responses.
- Only the first question is parsed (QDCOUNT ≥ 1); trailing OPT/EDNS ignored.
- This crate compiles for the guest musl target (`aarch64-unknown-linux-musl`).
  Keep it std-only (`std::net`); do not pull in host-only deps.

## arcbox-xnu-net — macOS batch DGRAM kernel landmines

It carries both halves of the datapath's guest socketpair I/O (ABX-313):
`GuestTx::flush` (`virt/arcbox-net/src/darwin/datapath_loop/guest_tx.rs`)
sends, `FdFrameSource::drain` (`common/splicetcp/src/frame_source.rs`)
receives. A semantics change here lands on both directions at once.

- `msghdr_x` must be **fully zeroed before every `recvmsg_x`** — older XNU
  kernels validate all fields, not just the ones we set (`src/ffi.rs`,
  `src/batch.rs` re-zeros per call). `recvmsg_x`/`sendmsg_x` are private-but-
  stable XNU symbols from `libsystem_kernel.dylib`.
- `MAX_BATCH = 256` matches the **default** `kern.ipc.maxrecvmsgx` /
  `maxsendmsgx`. These sysctls are tunable down and `cnt > max` returns
  **EINVAL** (a hard failure, not a short batch), so the crate reads both once
  per process and clamps every call itself
  (`BatchDgram::{send,recv}_capacity`). Callers no longer clamp — but a caller
  that pre-sizes buffers off `MAX_BATCH` will over-allocate on such a host.
- **An oversized datagram is truncated *silently* on recv.** XNU leaves
  `msg_flags` zeroed instead of raising `MSG_TRUNC` (measured macOS 26.4;
  `oversized_datagram_is_truncated_without_a_flag` pins it) and the discarded
  tail is not left queued. Slots are sized before the syscall and cannot grow,
  so every buffer must be at least the largest datagram the peer can send —
  this is why `MAX_FRAME_SIZE` stays 65535 in `frame_source.rs`.
- **A send that overruns the peer is a partial send, not an error.**
  `sendmsg_x` returns the accepted count and carries **no errno** once it
  accepted anything, so the caller must requeue `bufs[n..]` and learn *why* it
  blocked from a follow-up call. `GuestTx::flush` depends on this: it needs
  `EAGAIN` vs `ENOBUFS` for its blocked-state machine, so it hands the first
  refusal to a single `write(2)`. Regression:
  `partial_send_reports_accepted_count`.
- The fd must be `O_NONBLOCK`; `recv_batch` returns `WouldBlock` when idle and
  readiness reactors rely on that to clear readiness. A blocking fd wedges the
  reactor. A reactor must also drain **to** `WouldBlock` rather than stop at
  the first short batch — it clears readiness afterwards, so a datagram that
  arrived mid-drain would wait for an unrelated wakeup.

## arcbox-fakeip / arcbox-proxy — proxy awareness

- `proxy_detect` uses `scutil`/`ifconfig` probes that are **cfg-gated to
  macOS**; off macOS `detect()` silently falls back to env vars only.
- `198.18.0.0/15` (198.18.x / 198.19.x) is the **Surge/Clash** Fake-IP
  convention, not an ArcBox choice (`is_fake_ip`).
- The `dns_log` module is the seam that lets splicetcp recover the original
  hostname from a Fake-IP so TCP egress can tunnel **by name** (CONNECT /
  SOCKS5). Break it and by-name tunnelling regresses. Proxy internals →
  `common/splicetcp/README.md`.

## Debugging

- **Return traffic dropped, outbound fine** → check the three reverse-key sites
  are identical: `rg -n "ConnTrackKey::new" common/arcbox-conntrack/src`. Most
  likely a desynced reverse key or a missing `set_internal_network`.
- **NAT no-ops entirely / packets `PassThrough`** → verify EtherType is IPv4 and
  proto is TCP/UDP, and that the guest IP is inside the configured internal
  subnet (default `192.168.64.0/24`).
- **Batch recv fails with EINVAL on some hosts** → check `sysctl
  kern.ipc.maxrecvmsgx kern.ipc.maxsendmsgx`; a lowered cap below the per-call
  `cnt` is EINVAL. `BatchDgram` clamps to these itself, so an EINVAL here means
  the clamp was bypassed (a hand-rolled `recvmsg_x` call). Confirm the fd is
  `O_NONBLOCK`.
- **Guest-bound frames stop flowing while `guest-tx delivery counters` shows
  `queue_len` stuck non-zero** → the datapath queues on `send` and only writes
  on `flush`, so a missing `GuestTx::flush` in a new event-loop path strands
  everything it queued. `rg -n "guest_tx.flush" virt/arcbox-net/src/darwin` —
  the tail flush must also precede the `has_backlog` fast-path gate, or the
  gate reads "produced this iteration" as backpressure and starves the poll.
- **`tx_frames / tx_syscalls` sits at ~1 in the same log line** → batching is
  not engaging: either every flush sees a single queued frame (an event-loop
  path flushing too eagerly) or `sendmsg_x` is failing and every frame falls
  through to the single-write classifier.
- **Malformed DNS response for a client** → diff the flag/count bytes in the
  builder; confirm ANCOUNT/NSCOUNT/ARCOUNT are zeroed on the negative paths.
- **Sporadic memory corruption near the datapath** → look for a second
  writer/reader on a `LockFreeRing`, or a `get_mut`/`PacketRef` alias, or a
  buffer index handed to a ring without `into_index()`.

## Validation ladder (cheapest first)

1. `cargo test -p <crate>` — per-crate unit tests (every module has them).
2. Host-only end-to-end: the `tun_proxy` harness (Gate C, docs/surge-tun-proxy.md)
   exercises classifier + TcpBridge + proxy **without booting a VM**.
3. VM datapath: run through `virt/arcbox-net` / `virt/arcbox-net-virtio`.
4. Full-path throughput / regressions: iperf3 reproducer and measured caps in
   docs/net-perf-limits.md.

Because these crates are pure and have a host-only harness, a NAT/classifier/
proxy change is validatable on the host — far cheaper than the HV e2e ladder in
virt/AGENTS.md.

## Pointers (do not duplicate)

- Routing: `common/arcbox-route/AGENTS.md` (authoritative).
- splicetcp architecture: `common/splicetcp/README.md`.
- Perf numbers & throughput-collapse analysis: docs/net-perf-limits.md.
- Host tunnel proof: docs/surge-tun-proxy.md.
