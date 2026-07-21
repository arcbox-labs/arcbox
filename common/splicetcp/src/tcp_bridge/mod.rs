//! TCP shim: hand-rolled handshake synthesizer + fast-path data plane.
//!
//! Replaces the smoltcp-based implementation entirely. The shim does the
//! minimum translation work a frame-to-socket bridge needs: generate our
//! own ISN, synthesize SYN-ACK / SYN / ACK frames for the 3-way, then
//! promote the connection to `FastPathConn` where host-socket bytes are
//! forwarded to/from the guest via TCP frames (or zero-copy inline via
//! the `arcbox-net-inject` thread when available).
//!
//! No congestion control, retransmission, reordering, or TIME_WAIT state
//! is implemented here — both endpoints (guest Linux kernel, host macOS
//! kernel) own their own TCP stacks end-to-end; any state machine work in
//! the middle would be duplication. Two sender-side disciplines make that
//! stance sound (2026-07-19, found by the network-workload e2e):
//!
//! - **Upload (guest→host)**: a segment is ACKed only for the bytes
//!   actually written, in order, to the host socket. Anything the socket
//!   didn't take (`WouldBlock`, short write) or that arrived beyond the
//!   contiguous cursor stays un-ACKed and the guest sees dup-ACKs — its
//!   own fast-retransmit/RTO machinery repairs the stream. ACKing past
//!   unwritten bytes is how uploads silently lost data.
//! - **Download (host→guest)**: the shim is the *sender-side* TCP for this
//!   direction, and the path beyond guest `eth0` (bridge → veth → container
//!   netns backlog) drops frames under burst like any real network — so it
//!   keeps the two sender duties a real stack cannot delegate: it never
//!   sends beyond the guest's advertised receive window (tracked from its
//!   ACKs, scaled by its SYN wscale, capped at [`HONORED_WINDOW_CAP`]),
//!   and it buffers in-flight bytes for retransmission (triple-dup-ACK
//!   fast retransmit, RTO backoff otherwise). Without these, one dropped
//!   frame wedged a flow forever and window overrun made that routine
//!   under concurrency.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant as StdInstant;

use tokio::sync::oneshot;

use arcbox_packet::checksum;

use crate::ethernet::ETH_HEADER_LEN;

const UNIX_DGRAM_MAX_FRAME_LEN: usize = 2048;
const TCP_IPV4_ETH_OVERHEAD: usize = ETH_HEADER_LEN + 20 + 20;
const FAST_PATH_GUEST_MSS: usize = UNIX_DGRAM_MAX_FRAME_LEN - TCP_IPV4_ETH_OVERHEAD;

/// Start of the inbound ephemeral port range.
const INBOUND_EPHEMERAL_START: u16 = 61000;
/// End of the inbound ephemeral port range (inclusive).
const INBOUND_EPHEMERAL_END: u16 = 65535;

/// Maximum concurrent in-progress handshakes. Prevents SYN-flood resource
/// exhaustion; excess SYNs are answered with RST.
const MAX_PENDING_SYNS: usize = 256;

/// Timeout for host-side `TcpStream::connect` during passive-open handshake.
const SYN_GATE_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Per-attempt delays for handshake frame retransmission (SYN-ACK or SYN).
/// Doubled each time — loopback / virtio paths are effectively lossless, so
/// this covers only the rare slow-guest case.
const HANDSHAKE_RETRANSMIT_DELAYS: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(200),
    std::time::Duration::from_millis(400),
    std::time::Duration::from_millis(800),
];

/// Maximum retransmit attempts before we abort the handshake (RST + evict).
const HANDSHAKE_MAX_RETRANSMITS: u8 = 3;

/// TTL for an in-progress handshake with no guest response. If the guest
/// never ACKs our SYN-ACK (or never SYN-ACKs our SYN), we abort and evict
/// after this much time total.
///
/// Must exceed `SYN_GATE_CONNECT_TIMEOUT_SECS` (5 s): the host connect —
/// including a proxy CONNECT/SOCKS handshake — is allowed the full connect
/// timeout, and a shorter TTL would abort slow-but-successful proxied
/// connects while they were still legitimately pending (ABX-431).
const HANDSHAKE_TOTAL_TTL: std::time::Duration = std::time::Duration::from_secs(7);

/// Idle deadline for a half-closed flow (guest sent FIN, host write side shut
/// but not yet EOF'd). The clock is refreshed on every host→guest byte, so an
/// actively streaming half-open never trips it; it only fires when the upstream
/// keeps its write side open with nothing to send — the FIN_WAIT2-leak the
/// non-inline half-close would otherwise hold forever. 120 s (2× Linux's
/// default `tcp_fin_timeout`) is generous enough not to truncate a slow but
/// live response while still bounding a hostile guest's accumulated entries.
const HALF_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Give-up deadline for a flow whose guest has gone silent while the shim is
/// actively soliciting a response — retransmitting unACKed data or a FIN, or
/// persist-probing a closed receive window. A live guest answers every
/// solicit (a retransmit elicits at least a dup-ACK; a persist probe elicits
/// a window-bearing ACK per RFC 793 §3.9), so five minutes of silence means
/// the guest endpoint is gone (container netns torn down, VM wedged) and the
/// entry would otherwise retransmit forever and leak its host fd plus up to
/// [`HONORED_WINDOW_CAP`] of retransmission buffer. Deliberately generous so
/// a paused-then-resumed VM (see `arcbox-vz` pause / sandbox checkpoint)
/// keeps its in-flight flows across any reasonable pause. Purely idle flows
/// (nothing in flight, window open) are never reaped — matching real TCP,
/// which keeps quiescent connections indefinitely.
const DEAD_FLOW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// TCP keepalive for the host-side (upstream) leg of every fast-path flow.
/// Without it a silently dead upstream — a default-route flap, a crashed
/// system proxy, a NAT timeout — never surfaces on the socket: reads stay
/// `WouldBlock` forever and the guest leg sits ESTABLISHED with empty queues
/// until the guest app gives up (observed in prod: `apk` hung 23+ minutes).
/// With keepalive the kernel probes an idle upstream and turns its death
/// into a read error, which `poll_fast_path` / the inline owners already
/// propagate as a guest RST. Idle 60 s + 4 probes × 15 s ⇒ a dead upstream
/// is detected within ~2 minutes of its last byte.
const UPSTREAM_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
const UPSTREAM_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const UPSTREAM_KEEPALIVE_RETRIES: u32 = 4;

/// Window scale we advertise to the guest. Shift by 7 = 128× scaling,
/// giving an effective receive window of 65535 × 128 = 8 MiB. Sufficient
/// for any VM→Host BDP on a local loopback link.
const SHIM_WSCALE: u8 = 7;

/// Upper bound on parked out-of-order upload bytes per flow, and on how far
/// past `last_ack` a parked segment may start. The [`SHIM_WSCALE`] window
/// invites the guest to keep up to 8 MiB in flight, so a single lost frame
/// can put megabytes of valid data behind a hole; parking is capped below
/// the full window to bound memory. Segments past either cap fall back to
/// drop-and-dup-ACK, which the guest repairs by retransmitting.
const OOO_REASSEMBLY_CAP: usize = 4 * 1024 * 1024;

/// Upper bound on the *number* of parked out-of-order segments per flow.
/// [`OOO_REASSEMBLY_CAP`] alone bounds only payload bytes, so a guest could
/// otherwise park millions of 1-byte segments — exhausting memory in
/// per-segment `Vec`/allocator overhead and driving quadratic insert/scan
/// work on the datapath thread. A real out-of-order burst is at most one
/// window's worth of MSS-sized segments accumulated over a sub-millisecond
/// local RTT (a few hundred); 4096 clears that by a wide margin while
/// capping the adversarial case. Segments past this fall back to
/// drop-and-dup-ACK like the byte cap.
const OOO_MAX_SEGMENTS: usize = 4096;

/// MSS we advertise in handshake frames to the guest. 1460 is the standard
/// Ethernet MSS (1500 MTU − 40 bytes IP+TCP). Host→guest large frames with
/// GSO are unaffected — MSS only bounds the *guest's* segment size.
const SHIM_MSS: u16 = 1460;

/// Floor for a peer-advertised MSS when sizing host→guest segments. 536 is the
/// IPv4 minimum (576-byte MTU − 40), so it is always safe to send; it also
/// guards against a missing or malformed MSS option collapsing segments to 0.
pub(crate) const TCP_MIN_MSS: u16 = 536;

/// Cap on the guest receive window the download path honors. Bounds both
/// the per-flow retransmission buffer and the burst a single flow can
/// inject toward the guest's bridge/veth backlog. 256 KiB sustains
/// multi-GB/s at sub-millisecond local RTTs.
pub(crate) const HONORED_WINDOW_CAP: u32 = 256 * 1024;

/// Initial retransmission timeout for unACKed download bytes; doubles per
/// retransmission up to [`MAX_RTO`]. Local RTTs are sub-millisecond, so
/// 200 ms only ever fires on actual loss, not reordering.
pub(crate) const INITIAL_RTO: std::time::Duration = std::time::Duration::from_millis(200);
pub(crate) const MAX_RTO: std::time::Duration = std::time::Duration::from_secs(2);

/// Delay before the first zero-window persist probe once the guest closes its
/// receive window with nothing in flight. After one probe byte is in flight the
/// RTO retransmit path (INITIAL_RTO→MAX_RTO backoff) keeps probing on its own.
pub(crate) const ZERO_WINDOW_PERSIST_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(200);

/// Fixed segment size the GSO/inline injection paths let the guest re-segment
/// at (the `gso_size` stamped by `arcbox-net-inject`'s `write_inline_headers`
/// and `inject_one_frame` — keep in sync). A flow whose peer advertised a
/// smaller MSS must NOT take the GSO path, or the guest re-segments at 1460 and
/// drops frames it can't forward onto its smaller link; such flows stay on the
/// non-GSO polling path where each segment is clamped to the exact peer MSS.
const GSO_SEGMENT_MSS: u16 = 1460;

/// Monotonically advancing ISN source. Stepped by a large odd constant
/// (Knuth multiplicative) for well-distributed values without a `rand`
/// dependency.
///
/// NOTE: this is *not* RFC 6528 secure. The sequence is deterministic and
/// predictable given any observed ISN. In the VMM context the attack
/// surface is limited to the co-resident guest, which already owns its
/// own stack, so the shim treats ISN unpredictability as a
/// non-requirement. If this code is ever reused outside that threat
/// model, replace the counter with an RFC 6528-compliant construction
/// (secret key + clock).
static ISN_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x51_3C_A4_E7);

pub(super) fn next_isn() -> u32 {
    ISN_COUNTER.fetch_add(0x9E37_79B9, std::sync::atomic::Ordering::Relaxed)
}

/// Full four-tuple key for deduplicating SYN gate entries and fast-path lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SynFlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

/// Role of a TCP connection whose handshake is being synthesized in-shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HandshakeRole {
    /// Guest sent SYN → we responded SYN-ACK → waiting for guest ACK.
    /// Used for outbound (guest-initiated) connections.
    PassiveOpen,
    /// We sent SYN → waiting for guest SYN-ACK.
    /// Used for inbound port-forward connections.
    ActiveOpen,
}

/// In-progress TCP handshake — tracked until the 3-way is complete, at
/// which point the connection is promoted to `FastPathConn`.
///
/// The struct holds only the fields the shim actually needs: the flow key,
/// peer options to mirror/record, the ISNs on both sides, and retransmit
/// bookkeeping. No send/recv buffers, no sliding window state, no
/// congestion control — those are the host and guest kernels' responsibility.
#[allow(dead_code)] // `flow_key` mirrors the HashMap key
pub(super) struct HandshakeConn {
    flow_key: SynFlowKey,
    role: HandshakeRole,
    /// Our chosen ISN. After handshake, `our_seq = our_isn + 1`.
    our_isn: u32,
    /// Peer's ISN. Known immediately for PassiveOpen (from guest SYN);
    /// for ActiveOpen, set when the guest's SYN-ACK arrives.
    peer_isn: u32,
    /// Host-side TCP stream. For PassiveOpen: populated once the async host
    /// connect completes. For ActiveOpen: set from the already-accepted
    /// stream at registration time.
    host_stream: Option<std::net::TcpStream>,
    /// Oneshot receiver for async host connect (PassiveOpen only).
    /// Consumed when connect resolves.
    connect_rx: Option<oneshot::Receiver<Option<crate::egress::EgressConn>>>,
    /// Peer's TCP options, mirrored in our SYN-ACK (PassiveOpen) or
    /// captured from their SYN-ACK (ActiveOpen).
    peer_wscale: Option<u8>,
    peer_sack: bool,
    peer_mss: u16,
    /// MAC addresses used when building frames to the guest.
    gw_mac: [u8; 6],
    guest_mac: [u8; 6],
    /// Retransmit bookkeeping for our handshake frame (SYN-ACK or SYN).
    retransmit_count: u8,
    last_sent: Option<StdInstant>,
    /// Saved frame bytes to re-emit on retransmit.
    saved_frame: Option<Vec<u8>>,
    /// When this handshake entry was created — for TTL enforcement.
    created: StdInstant,
}

/// The TCP shim. Owns handshake state, fast-path connection table, and
/// supporting configuration (gateway IP translation, proxy resolution,
/// per-connection MAC addresses).
pub struct TcpBridge {
    /// Next inbound ephemeral port to allocate (wraps within 61000-65535).
    next_ephemeral: u16,
    /// DNS resolution log for mapping IPs back to domain names (used by
    /// the proxy resolver).
    dns_log: Option<arcbox_fakeip::dns_log::DnsResolutionLog>,
    /// Egress resolver: decides + dials the upstream transport for each
    /// outbound SYN. Injectable so a consumer can replace the policy; the
    /// default reproduces the historical inline proxy-aware connect.
    egress: std::sync::Arc<dyn crate::egress::EgressResolver>,
    /// Gateway IP used by the guest. Connections targeting this IP are
    /// translated to `127.0.0.1` so they reach the host's loopback
    /// (enables `host.docker.internal` support).
    gateway_ip: Ipv4Addr,
    /// Fast-path connections bypassing any userspace TCP state machine.
    /// Keyed by (guest_src_ip, guest_src_port, dest_ip, dest_port).
    fast_path_conns: HashMap<SynFlowKey, FastPathConn>,
    /// Gateway MAC for constructing frames to the guest.
    fast_path_gateway_mac: [u8; 6],
    /// Guest MAC for constructing frames to the guest. Learned from inbound
    /// frames' source MAC; broadcast fallback until set.
    fast_path_guest_mac: Option<[u8; 6]>,
    /// When true, send entire read buffers as single large frames (up to 32KB).
    /// Enabled when the transport supports large frames (channel path, not socketpair).
    large_frames_enabled: bool,
    /// Maximum TCP payload bytes per host→guest fast-path frame when
    /// `large_frames_enabled` is false.
    fast_path_guest_mss: usize,
    /// Connection sink for sending promoted fast-path connections to the
    /// RX inject thread for inline (zero-copy) host→guest data transfer.
    conn_sink: Option<std::sync::Arc<dyn crate::direct_rx::ConnSink>>,
    /// Per-flow byte accounting sink: fired once per fast-path flow at teardown
    /// with its up/down totals. Injectable (like `egress`) so a consumer can
    /// account traffic the bridge spliced. `None` ⇒ no accounting.
    observer: Option<std::sync::Arc<dyn crate::egress::FlowObserver>>,
    /// TCP handshakes being synthesized. Each entry is promoted to
    /// `fast_path_conns` once the 3-way completes.
    handshake_conns: HashMap<SynFlowKey, HandshakeConn>,
    /// Notified when a pending handshake's async host connect resolves, so
    /// the datapath loop can emit the SYN-ACK immediately instead of
    /// waiting for the next guest frame or timer tick (an idle loop
    /// otherwise adds up to a full tick of connect latency).
    handshake_waker: Option<std::sync::Arc<tokio::sync::Notify>>,
    /// Silence deadline before a soliciting flow is declared dead
    /// ([`DEAD_FLOW_TIMEOUT`]; overridable in tests).
    dead_flow_timeout: std::time::Duration,
}

/// A TCP connection promoted to the fast path — bypasses any TCP state
/// machine entirely. The shim handles the handshake; data frames are
/// intercepted inline or polled from the host stream.
pub(super) struct FastPathConn {
    /// Host-side TCP stream (std blocking — used from the sync datapath loop).
    stream: std::net::TcpStream,
    /// Our SEQ number for frames sent TO guest. Shared atomic with the
    /// inject thread so ACKs emitted by `try_fast_path_intercept` always
    /// carry a SEQ matching the guest's rcv_nxt for this flow (the inject
    /// thread advances it when writing payload).
    our_seq: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Last ACK we sent to guest (= next SEQ we expect FROM guest).
    last_ack: u32,
    /// Shared atomic last_ack for inline inject thread synchronization.
    /// Updated by try_fast_path_intercept when guest ACKs arrive.
    last_ack_shared: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Remote IP as seen by the guest.
    remote_ip: Ipv4Addr,
    /// Guest IP.
    guest_ip: Ipv4Addr,
    /// Remote port as seen by the guest.
    remote_port: u16,
    /// Guest port.
    guest_port: u16,
    /// MSS the guest peer advertised for this flow (from its SYN / SYN-ACK).
    /// Bounds the host→guest segment size so emitted frames never exceed the
    /// path the guest can forward them over (e.g. a 1500-MTU docker bridge
    /// behind a 4000-MTU `eth0`). See `poll_fast_path`.
    peer_mss: u16,
    /// Window-scale shift the guest advertised in its SYN / SYN-ACK
    /// (0 when it offered none — scaling is then off per RFC 7323).
    guest_wscale: u8,
    /// Highest ACK the guest has sent for OUR stream. Shared with the
    /// inline inject thread — the "sent and acknowledged" cursor of
    /// download flow control.
    guest_acked: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Receive window from the guest's most recent ACK, already scaled by
    /// `guest_wscale`. Together with `guest_acked` it bounds host→guest
    /// in-flight bytes (see [`send_budget`]).
    guest_window: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Upload-path recovery counters (reported at flow close): segments
    /// the host socket wouldn't take, segments it took partially, and
    /// segments that arrived beyond the contiguous cursor. All three
    /// recover via guest retransmission; they quantify backpressure, not loss.
    up_would_block: u64,
    up_short_writes: u64,
    up_out_of_order: u64,
    /// Upload segments that arrived beyond the contiguous cursor, parked
    /// until the hole before them fills: `(guest_seq, payload)`, ordered by
    /// wrapping distance from `last_ack`. Parking turns one lost frame into
    /// one guest retransmission; dropping (the pre-2026-07 behavior) made
    /// recovery go-back-N across the whole 8 MiB advertised window, which
    /// collapsed docker-bridge uploads to tens of Mbit/s. A deque so the
    /// drain pops contiguous segments off the front in O(1); a real burst
    /// arrives in ascending order (append to back), so keeping it ordered is
    /// cheap. Bounded by [`OOO_REASSEMBLY_CAP`] and [`OOO_MAX_SEGMENTS`].
    ooo_segs: std::collections::VecDeque<(u32, Vec<u8>)>,
    /// Total payload bytes parked in `ooo_segs`; bounded by
    /// [`OOO_REASSEMBLY_CAP`].
    ooo_bytes: usize,
    /// OOO segments discarded because a reassembly cap was exceeded
    /// (recovered by guest retransmission, exactly as before parking existed).
    up_ooo_dropped: u64,
    /// True while the flow sits at a zero send budget — transition
    /// logging only, so a stuck window is visible in the daemon log
    /// without per-poll noise.
    window_stalled: bool,
    /// When the window first closed with nothing in flight, for the
    /// zero-window persist timer. `None` while the window is open. (The RTO
    /// `last_progress` clock can't be reused: it is reset every idle poll.)
    window_stalled_at: Option<StdInstant>,
    /// Sender-side retransmission buffer: every download byte from
    /// `retransmit_seq` (== the last drained `guest_acked`) up to `our_seq`,
    /// bounded by [`HONORED_WINDOW_CAP`]. Non-inline flows only.
    retransmit_buf: std::collections::VecDeque<u8>,
    /// Sequence number of `retransmit_buf[0]`.
    retransmit_seq: u32,
    /// Last time `guest_acked` advanced (RTO clock, armed while in flight).
    last_progress: StdInstant,
    /// Current retransmission timeout (backs off per retransmission).
    rto: std::time::Duration,
    /// Consecutive duplicate ACKs at the same `guest_acked` while data is
    /// in flight — three trigger fast retransmit.
    dup_acks: u8,
    /// Set by the intercept when the dup-ACK threshold fires; consumed by
    /// the next poll pass.
    fast_retransmit: bool,
    /// Sequence number of our FIN when `host_eof` (the FIN needs
    /// retransmission too — a lost FIN wedges the close the same way).
    fin_seq: Option<u32>,
    /// Download retransmissions performed (diagnostics, logged at close).
    retransmits: u64,
    /// Read buffer for host → guest data (reused across polls).
    read_buf: Vec<u8>,
    /// True if host stream has reached EOF.
    host_eof: bool,
    /// `Some(t)` once the guest half-closed (sent an in-order FIN) while the
    /// host side was still open: the poll path shuts the upstream's write side,
    /// keeps relaying host→guest until the host EOFs, then reaps once its own
    /// FIN is ACKed. Only set on the non-inline path (inline flows full-close).
    /// `t` is the FIN_WAIT2 clock — set at the FIN and refreshed on every
    /// host→guest byte; if it goes idle for [`HALF_CLOSE_TIMEOUT`] the entry is
    /// reaped so a peer that keeps its write side open forever (or a guest that
    /// silently drops FIN_WAIT2) can't leak the bridge entry and host fd.
    guest_fin_at: Option<StdInstant>,
    /// True if the socket has been cloned to the inline inject thread.
    /// poll_fast_path() skips connections with this flag — the inject
    /// thread reads directly from the cloned socket.
    inline_owned: bool,
    /// Guest→host (client→server) bytes forwarded on this flow.
    up_bytes: u64,
    /// Host→guest (server→client) bytes counted on the non-inline poll path.
    /// Inline flows count downstream in `down_shared` (poll_fast_path skips them).
    down_bytes: u64,
    /// Host→guest bytes counted by the inline inject thread, when `inline_owned`.
    down_shared: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Set by the inline sink owner when the host stream died mid-stream
    /// (error, not clean EOF) and the guest was RST-terminated;
    /// `poll_fast_path` reaps the entry. After a clean EOF the flag stays
    /// unset so the entry survives for the guest's close handshake. `Some`
    /// only when `inline_owned` (ABX-431).
    dead: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Last time any guest frame for this flow reached
    /// `try_fast_path_intercept` — the flow's sign of life. While the shim is
    /// soliciting a response (data/FIN in flight, or a closed window being
    /// persist-probed) and this goes stale past [`DEAD_FLOW_TIMEOUT`], the
    /// guest endpoint is gone and the flow is RST-reaped instead of
    /// retransmitting forever.
    last_guest_activity: StdInstant,
}

impl FastPathConn {
    /// Updates last_ack and syncs to the shared atomic (for inline inject thread).
    pub(super) fn set_last_ack(&mut self, ack: u32) {
        self.last_ack = ack;
        if let Some(ref shared) = self.last_ack_shared {
            shared.store(ack, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Parks an upload segment that arrived beyond the contiguous cursor
    /// (caller guarantees `seq` is strictly ahead of `last_ack`).
    /// Deduplicates same-seq arrivals and enforces [`OOO_REASSEMBLY_CAP`]
    /// on both total parked bytes and how far past the cursor a segment
    /// may start. Parking never ACKs: `last_ack` still advances only over
    /// bytes actually written to the host socket, in
    /// [`Self::drain_parked_segments`].
    pub(super) fn buffer_ooo_segment(&mut self, seq: u32, payload: &[u8]) {
        let base = self.last_ack;
        let rel = seq.wrapping_sub(base) as usize;
        let idx = self
            .ooo_segs
            .partition_point(|(s, _)| (s.wrapping_sub(base) as usize) < rel);
        let replaces_existing = matches!(self.ooo_segs.get(idx), Some((s, _)) if *s == seq);
        if rel.saturating_add(payload.len()) > OOO_REASSEMBLY_CAP
            || self.ooo_bytes.saturating_add(payload.len()) > OOO_REASSEMBLY_CAP
            // A new distinct segment past the count cap is dropped; an
            // in-place replacement of a parked seq does not grow the count.
            || (!replaces_existing && self.ooo_segs.len() >= OOO_MAX_SEGMENTS)
        {
            self.up_ooo_dropped += 1;
            return;
        }
        if replaces_existing {
            // Same start seq already parked: keep whichever is longer (a
            // retransmit may carry more data), never write the shorter twice.
            if self.ooo_segs[idx].1.len() >= payload.len() {
                return;
            }
            if let Some((_, old)) = self.ooo_segs.remove(idx) {
                self.ooo_bytes -= old.len();
            }
        }
        self.ooo_bytes += payload.len();
        self.ooo_segs.insert(idx, (seq, payload.to_vec()));
    }

    /// Writes parked out-of-order segments that the advanced `last_ack` now
    /// reaches, in sequence order, with the same partial-take semantics as
    /// the in-order path: the cursor advances only over bytes the host
    /// socket accepted. Stops at the first remaining hole, `WouldBlock`, or
    /// short take — whatever stays parked is re-driven by the guest's
    /// retransmission machinery (an arriving retransmit re-enters this
    /// drain). A hard write error propagates for the caller's RST teardown.
    pub(super) fn drain_parked_segments(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        while let Some(&(seq, ref data)) = self.ooo_segs.front() {
            let len = data.len();
            let seg_end = seq.wrapping_add(len as u32);
            let extends = seg_end.wrapping_sub(self.last_ack);
            if extends == 0 || extends >= 0x8000_0000 {
                // Fully at/behind the cursor: a retransmit landed in-order
                // first and already covered these bytes.
                if let Some((_, old)) = self.ooo_segs.pop_front() {
                    self.ooo_bytes -= old.len();
                }
                continue;
            }
            let overlap = self.last_ack.wrapping_sub(seq);
            if overlap >= 0x8000_0000 {
                break; // a hole still precedes the first parked segment
            }
            let start = overlap as usize;
            let take = match self.stream.write(&self.ooo_segs[0].1[start..]) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.up_would_block += 1;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    // Peer closed — drain at the TCP layer like the in-order
                    // path so the guest stops retransmitting.
                    self.set_last_ack(seg_end);
                    if let Some((_, old)) = self.ooo_segs.pop_front() {
                        self.ooo_bytes -= old.len();
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            self.up_bytes += take as u64;
            let new_ack = self.last_ack.wrapping_add(take as u32);
            self.set_last_ack(new_ack);
            if take < len - start {
                self.up_short_writes += 1;
                break; // remainder stays parked; overlap math resumes here
            }
            if let Some((_, old)) = self.ooo_segs.pop_front() {
                self.ooo_bytes -= old.len();
            }
        }
        Ok(())
    }
}

/// Bytes the shim may still send host→guest without exceeding the guest's
/// advertised receive window: `window − (sent − acked)`, wrap-safe.
///
/// The guest kernel guarantees buffering only inside this budget; staying
/// inside it (on a lossless local link) is what lets the shim carry no
/// retransmission machinery at all.
pub(crate) fn send_budget(our_seq: u32, guest_acked: u32, guest_window: u32) -> u32 {
    let in_flight = our_seq.wrapping_sub(guest_acked);
    if in_flight >= 0x8000_0000 {
        // Transiently stale snapshot ("acked ahead of sent") from racing
        // atomics — treat as nothing in flight rather than stalling.
        return guest_window;
    }
    guest_window.saturating_sub(in_flight)
}

impl TcpBridge {
    pub fn new(gateway_ip: Ipv4Addr) -> Self {
        Self {
            next_ephemeral: INBOUND_EPHEMERAL_START,
            dns_log: None,
            egress: std::sync::Arc::new(crate::egress::DefaultEgress::new(
                gateway_ip,
                None,
                SYN_GATE_CONNECT_TIMEOUT_SECS,
            )),
            gateway_ip,
            fast_path_conns: HashMap::new(),
            fast_path_gateway_mac: [0; 6],
            fast_path_guest_mac: None,
            large_frames_enabled: false,
            fast_path_guest_mss: FAST_PATH_GUEST_MSS,
            conn_sink: None,
            observer: None,
            handshake_conns: HashMap::new(),
            handshake_waker: None,
            dead_flow_timeout: DEAD_FLOW_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(super) fn set_dead_flow_timeout(&mut self, timeout: std::time::Duration) {
        self.dead_flow_timeout = timeout;
    }

    /// Installs a waker notified whenever an async host connect for a
    /// pending handshake resolves. Must be set from within a Tokio runtime
    /// context (`handle_outbound_syn` spawns the forwarding task).
    pub fn set_handshake_waker(&mut self, waker: std::sync::Arc<tokio::sync::Notify>) {
        self.handshake_waker = Some(waker);
    }

    /// Enables large frame mode (no MSS segmentation).
    /// Call when using the channel-based FrameSink path instead of socketpair.
    pub fn enable_large_frames(&mut self) {
        self.large_frames_enabled = true;
    }

    /// Sets the fast-path segmentation budget so each emitted IPv4 packet fits
    /// within `mtu` bytes. This preserves normal per-packet checksums and is the
    /// right mode for high-MTU L3 links such as host `utun` / Network Extension.
    pub fn set_fast_path_mtu(&mut self, mtu: usize) {
        self.fast_path_guest_mss = mtu
            .saturating_sub(20 + 20)
            .clamp(1, u16::MAX as usize - 20 - 20);
    }

    /// Attaches a connection sink for sending promoted fast-path connections
    /// to the RX inject thread for inline (zero-copy) host→guest transfer.
    pub fn set_conn_sink(&mut self, sink: std::sync::Arc<dyn crate::direct_rx::ConnSink>) {
        self.conn_sink = Some(sink);
    }

    /// Updates the MAC addresses used for fast-path frame construction.
    pub fn set_fast_path_macs(&mut self, gateway_mac: [u8; 6], guest_mac: [u8; 6]) {
        self.fast_path_gateway_mac = gateway_mac;
        self.fast_path_guest_mac = Some(guest_mac);
    }
}

mod fast_path;
mod handshake;
mod settings;

/// Returns true if the saved handshake frame is due for retransmit.
///
/// The retransmit delay schedule is indexed by `retransmit_count`; the
/// last-sent timestamp must have elapsed by at least that delay.
pub(super) fn should_retransmit(conn: &HandshakeConn, now: StdInstant) -> bool {
    let Some(last) = conn.last_sent else {
        return false;
    };
    let idx = usize::from(conn.retransmit_count).min(HANDSHAKE_RETRANSMIT_DELAYS.len() - 1);
    let delay = HANDSHAKE_RETRANSMIT_DELAYS[idx];
    now.duration_since(last) >= delay
}

/// Constructs an RST|ACK Ethernet frame in response to a SYN frame.
///
/// The RST has: seq=0, ack=syn_seq+1, flags=RST|ACK.
/// MAC addresses are swapped (gateway MAC as source, original source as dest).
/// IP addresses are swapped. Ports are swapped.
pub(super) fn build_rst_from_syn(syn_frame: &[u8], gateway_mac: [u8; 6]) -> Option<Vec<u8>> {
    let ip_start = ETH_HEADER_LEN;
    if syn_frame.len() < ip_start + 40 {
        return None;
    }

    let ihl = ((syn_frame[ip_start] & 0x0F) as usize) * 4;
    let l4_start = ip_start + ihl;
    if ihl < 20 || l4_start + 20 > syn_frame.len() {
        return None;
    }

    // Extract from original SYN.
    let src_mac = &syn_frame[6..12];
    let syn_src_ip = [
        syn_frame[ip_start + 12],
        syn_frame[ip_start + 13],
        syn_frame[ip_start + 14],
        syn_frame[ip_start + 15],
    ];
    let syn_dst_ip = [
        syn_frame[ip_start + 16],
        syn_frame[ip_start + 17],
        syn_frame[ip_start + 18],
        syn_frame[ip_start + 19],
    ];
    let syn_src_port = u16::from_be_bytes([syn_frame[l4_start], syn_frame[l4_start + 1]]);
    let syn_dst_port = u16::from_be_bytes([syn_frame[l4_start + 2], syn_frame[l4_start + 3]]);
    let syn_seq = u32::from_be_bytes([
        syn_frame[l4_start + 4],
        syn_frame[l4_start + 5],
        syn_frame[l4_start + 6],
        syn_frame[l4_start + 7],
    ]);

    // Build RST|ACK: ETH(14) + IP(20) + TCP(20) = 54 bytes.
    let mut frame = vec![0u8; ETH_HEADER_LEN + 40];

    // Ethernet header: dst=original src MAC, src=gateway MAC.
    frame[0..6].copy_from_slice(src_mac);
    frame[6..12].copy_from_slice(&gateway_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (swapped IPs).
    let ip = ETH_HEADER_LEN;
    frame[ip] = 0x45; // version=4, IHL=5
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes()); // total length
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 6; // TCP
    // src = original dst, dst = original src (we're the "server" responding).
    frame[ip + 12..ip + 16].copy_from_slice(&syn_dst_ip);
    frame[ip + 16..ip + 20].copy_from_slice(&syn_src_ip);
    // IP checksum.
    let ip_cksum = checksum::ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header (swapped ports).
    let tcp_start = ip + 20;
    frame[tcp_start..tcp_start + 2].copy_from_slice(&syn_dst_port.to_be_bytes()); // src port
    frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&syn_src_port.to_be_bytes()); // dst port
    // seq = 0
    frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&0u32.to_be_bytes());
    // ack = syn_seq + 1
    frame[tcp_start + 8..tcp_start + 12].copy_from_slice(&(syn_seq.wrapping_add(1)).to_be_bytes());
    frame[tcp_start + 12] = 0x50; // data offset = 5 (20 bytes)
    frame[tcp_start + 13] = 0x14; // RST|ACK
    frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&0u16.to_be_bytes()); // window = 0

    // TCP checksum.
    let tcp_cksum =
        checksum::tcp_checksum(syn_dst_ip, syn_src_ip, &frame[tcp_start..tcp_start + 20]);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    Some(frame)
}

#[cfg(test)]
mod tests;
