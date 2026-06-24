# splicetcp

`splicetcp` is ArcBox's userspace TCP-termination and splice bridge. It sits on
the frame plane between an L2/L3 packet source and an egress dialer: it
classifies Ethernet frames, synthesizes the guest-facing TCP handshake, and then
promotes established flows to a fast path backed by a real host `TcpStream`.

It is intentionally **not** a full TCP/IP stack. The guest kernel still owns the
guest TCP state. `splicetcp` only gates outbound SYNs, creates the host-side
egress connection, mirrors the minimal sequence/ack state needed for frame
construction, and splices bytes between the guest frames and the host socket.

## Architecture

```text
packet source
  │
  ▼
FrameClassifier ── ARP / DHCP / DNS / UDP / ICMP ──▶ caller-owned handlers
  │
  ├─ gated TCP SYN ───────────────▶ TcpBridge::handle_outbound_syn
  │                                  │
  │                                  ▼
  │                                EgressResolver::resolve
  │                                  │
  │                                  ▼
  │                                EgressConn::Tcp
  │                                  │
  ▼                                  ▼
TCP data/ACK frames ◀──────────── TcpBridge fast path
```

The crate is split around a few seams:

- `classifier::FrameClassifier` is a pure Ethernet-frame demultiplexer. It owns
  no fd; callers feed frames via `classify_frame` and drain the resulting queues.
- `tcp_bridge::TcpBridge` performs SYN gating, handshake synthesis, and the
  promoted fast path.
- `egress::EgressResolver` is the policy/dial seam. The default resolver dials
  directly or through the system proxy; product code can inject its own router
  and outbound stack.
- `direct_rx::{ConnSink, PromotedConn}` lets callers take ownership of
  promoted host→guest reads instead of polling `TcpBridge::poll_fast_path`.
- `shim` adapts bare L3 links (`utun`, Network Extension packet flows) to the
  L2 classifier by adding/removing a synthetic Ethernet header.
- `utun` provides macOS helpers for the 4-byte AF header used by `utun` fds.

## Egress resolution

`TcpBridge` calls `EgressResolver::resolve` for every gated SYN and expects an
async `oneshot::Receiver<Option<EgressConn>>`. `FlowMeta` contains the 4-tuple
and, when a shared fake-IP DNS log is installed on the bridge, the recovered
destination domain.

Consumers typically wrap their router/outbound layer behind this trait:

1. classify a SYN,
2. map `FlowMeta` to routing metadata,
3. dial an outbound,
4. return `Some(EgressConn::Tcp(stream))` for a real fd that the bridge can
   splice.

For event-driven loops, wrap the resolver and notify the loop when the inner
receiver completes. The wake should be sent **after** forwarding the result so
the next `poll_handshakes` observes the completed dial immediately.

## Fast path and Tokio integration

Without a `ConnSink`, host→guest bytes are drained by
`TcpBridge::poll_fast_path`. This is simple and works in synchronous loops, but
the caller must keep polling while fast-path connections are active.

Enable the `tokio-frame-sink` feature to use
`direct_rx::TokioFrameConnSink` instead:

```rust,no_run
use splicetcp::direct_rx::TokioFrameConnSink;
use splicetcp::tcp_bridge::TcpBridge;

# let gateway_ip = std::net::Ipv4Addr::new(10, 0, 2, 2);
let mut bridge = TcpBridge::new(gateway_ip);
let (sink, mut frames) = TokioFrameConnSink::channel(1024);
bridge.set_conn_sink(sink);

// Await `frames.recv()` in the datapath loop and write each Ethernet frame to
// the guest-facing sink.
```

`TokioFrameConnSink` turns each accepted `PromotedConn` into a Tokio read task
and emits guest-bound Ethernet frames through a bounded `mpsc` channel. Channel
backpressure pauses socket reads instead of allowing unbounded buffering.

Important constraints:

- `send_conn` must be called from within a Tokio runtime; accepted connections
  are driven by `tokio::spawn`.
- The Tokio sink emits segmented, standard-MTU-style TCP data frames and does
  not support `TcpBridge::enable_large_frames()`.
- If the sink rejects a connection, `TcpBridge` keeps that connection on the
  fallback polling path.

When a promoted connection is owned by a `ConnSink` (`inline_owned = true`), the
bridge does not allocate the fallback 32 KiB per-connection read buffer. This
keeps the event-driven path from paying memory for a buffer it will never use.

## L3 tunnel shim

`FrameClassifier` and `TcpBridge` operate on Ethernet frames. Host tunnel links
such as macOS `utun` or iOS `NEPacketTunnelFlow` carry bare IP packets instead.
The `shim` module provides the adapter:

- `L3ToL2Source` wraps an L3 `FrameSource` and prepends a fixed synthetic
  Ethernet header before classification.
- `synthetic_l2_header` plus `l3_to_l2` provide the same conversion for
  callback/push based sources that have no pollable fd.
- `l2_to_l3` strips the synthetic Ethernet header from guest-bound frames and
  drops ARP or non-IPv4 frames that have no L3 representation.

The shim currently accepts IPv4 only. IPv6 and a complete IP stack are outside
the crate's scope.

## Memory and performance notes

- `FrameClassifier::new` uses a large packet pool suitable for the VM datapath.
  Memory-constrained consumers should use `with_pool_capacity`.
- `TcpBridge::enable_large_frames()` disables MSS segmentation for callers whose
  guest-facing transport can carry large frames. Do not enable it on standard
  MTU `utun`/packet-tunnel paths unless the entire write path is sized for those
  frames.
- For idle event-driven loops, rely on explicit wakes: dial completion from an
  `EgressResolver` wrapper, UDP/DNS handler wakes from the consumer, and
  `TokioFrameConnSink` for host→guest TCP readiness. A long backstop timer is
  fine as a missed-wake guard, but should not be the steady-state driver.

## Feature flags

- `tokio-frame-sink`: exposes `direct_rx::TokioFrameConnSink`, the Tokio-backed
  `ConnSink` for event-driven promoted host→guest reads.
