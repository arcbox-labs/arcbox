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
//! the middle would be duplication.

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
const HANDSHAKE_TOTAL_TTL: std::time::Duration = std::time::Duration::from_secs(3);

/// Window scale we advertise to the guest. Shift by 7 = 128× scaling,
/// giving an effective receive window of 65535 × 128 = 8 MiB. Sufficient
/// for any VM→Host BDP on a local loopback link.
const SHIM_WSCALE: u8 = 7;

/// MSS we advertise in handshake frames to the guest. 1460 is the standard
/// Ethernet MSS (1500 MTU − 40 bytes IP+TCP). Host→guest large frames with
/// GSO are unaffected — MSS only bounds the *guest's* segment size.
const SHIM_MSS: u16 = 1460;

/// Floor for a peer-advertised MSS when sizing host→guest segments. 536 is the
/// IPv4 minimum (576-byte MTU − 40), so it is always safe to send; it also
/// guards against a missing or malformed MSS option collapsing segments to 0.
const TCP_MIN_MSS: u16 = 536;

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
    /// Read buffer for host → guest data (reused across polls).
    read_buf: Vec<u8>,
    /// True if host stream has reached EOF.
    host_eof: bool,
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
}

impl FastPathConn {
    /// Updates last_ack and syncs to the shared atomic (for inline inject thread).
    pub(super) fn set_last_ack(&mut self, ack: u32) {
        self.last_ack = ack;
        if let Some(ref shared) = self.last_ack_shared {
            shared.store(ack, std::sync::atomic::Ordering::Relaxed);
        }
    }
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
        }
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
    if l4_start + 20 > syn_frame.len() {
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
