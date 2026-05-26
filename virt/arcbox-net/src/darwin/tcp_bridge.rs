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

use crate::ethernet::ETH_HEADER_LEN;
use crate::nat_engine::checksum;

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

fn next_isn() -> u32 {
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
enum HandshakeRole {
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
#[allow(dead_code)] // `flow_key` mirrors the HashMap key; `peer_mss` reserved for frame sizing
struct HandshakeConn {
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
    connect_rx: Option<oneshot::Receiver<Option<tokio::net::TcpStream>>>,
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
    dns_log: Option<super::dns_log::DnsResolutionLog>,
    /// Detected proxy environment on the host.
    proxy_env: Option<super::proxy_detect::ProxyEnvironment>,
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
    /// Connection sink for sending promoted fast-path connections to the
    /// RX inject thread for inline (zero-copy) host→guest data transfer.
    conn_sink: Option<std::sync::Arc<dyn crate::direct_rx::ConnSink>>,
    /// TCP handshakes being synthesized. Each entry is promoted to
    /// `fast_path_conns` once the 3-way completes.
    handshake_conns: HashMap<SynFlowKey, HandshakeConn>,
}

/// A TCP connection promoted to the fast path — bypasses any TCP state
/// machine entirely. The shim handles the handshake; data frames are
/// intercepted inline or polled from the host stream.
struct FastPathConn {
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
    /// Read buffer for host → guest data (reused across polls).
    read_buf: Vec<u8>,
    /// True if host stream has reached EOF.
    host_eof: bool,
    /// True if the socket has been cloned to the inline inject thread.
    /// poll_fast_path() skips connections with this flag — the inject
    /// thread reads directly from the cloned socket.
    inline_owned: bool,
}

impl FastPathConn {
    /// Updates last_ack and syncs to the shared atomic (for inline inject thread).
    fn set_last_ack(&mut self, ack: u32) {
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
            proxy_env: None,
            gateway_ip,
            fast_path_conns: HashMap::new(),
            fast_path_gateway_mac: [0; 6],
            fast_path_guest_mac: None,
            large_frames_enabled: false,
            conn_sink: None,
            handshake_conns: HashMap::new(),
        }
    }

    /// Enables large frame mode (no MSS segmentation).
    /// Call when using the channel-based FrameSink path instead of socketpair.
    pub fn enable_large_frames(&mut self) {
        self.large_frames_enabled = true;
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

    /// Checks if a TCP frame matches a fast-path connection.
    ///
    /// Called from the classifier's `drain_fast_path`. Returns
    /// `Some(ack_frame)` if the frame was handled (payload written to
    /// host stream, ACK generated), or `None` if not a fast-path match.
    pub fn try_fast_path_intercept(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < ETH_HEADER_LEN + 40 {
            return None; // Too short for ETH + IP + TCP minimum
        }

        let ip_start = ETH_HEADER_LEN;
        let protocol = frame[ip_start + 9];
        if protocol != 6 {
            return None; // Not TCP
        }

        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        if frame.len() < l4_start + 20 {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
        let flags = frame[l4_start + 13];

        let key = SynFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        let conn = self.fast_path_conns.get_mut(&key)?;

        let guest_seq = u32::from_be_bytes([
            frame[l4_start + 4],
            frame[l4_start + 5],
            frame[l4_start + 6],
            frame[l4_start + 7],
        ]);

        // FIN or RST → handle teardown ourselves.
        if flags & 0x04 != 0 {
            // RST: close host stream immediately, no response needed.
            tracing::debug!("Fast path: RST from guest {src_ip}:{src_port}→{dst_ip}:{dst_port}");
            self.fast_path_conns.remove(&key);
            return Some(Vec::new()); // Intercepted, no reply frame.
        }
        // Extract payload using IPv4 total_length to exclude Ethernet padding.
        // NOTE: FIN check is deferred until after payload write — RFC 793
        // allows FIN segments to carry data.
        let ip_total_len = u16::from_be_bytes([frame[ip_start + 2], frame[ip_start + 3]]) as usize;
        let ip_end = ip_start + ip_total_len;
        let tcp_data_offset = ((frame[l4_start + 12] >> 4) as usize) * 4;
        let payload_start = l4_start + tcp_data_offset;
        let payload_end = ip_end.min(frame.len());
        let payload_len = payload_end.saturating_sub(payload_start);

        // Write payload to host stream (if any). Handle retransmits by
        // only advancing `last_ack` when the segment extends previously
        // acknowledged data; re-writing already-ACKed bytes to the host
        // would corrupt the TLS stream on the peer side.
        if payload_len > 0 {
            use std::io::Write;
            let seq_end = guest_seq.wrapping_add(payload_len as u32);
            // seq_end > conn.last_ack (wrap-safe) means "segment carries
            // at least one new byte". Otherwise the entire segment is a
            // retransmit of data we already ACKed.
            let is_new_data = seq_end.wrapping_sub(conn.last_ack) > 0
                && seq_end.wrapping_sub(conn.last_ack) < 0x8000_0000;
            if is_new_data {
                let payload = &frame[payload_start..payload_start + payload_len];
                match conn.stream.write(payload) {
                    Ok(_n) => {
                        conn.set_last_ack(seq_end);
                        tracing::trace!(
                            "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} wrote {payload_len} bytes"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tracing::trace!(
                            "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} WouldBlock"
                        );
                        return Some(Vec::new());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                        // Peer closed; inject already relayed FIN. ACK at
                        // TCP layer so the guest stops retransmitting.
                        conn.set_last_ack(seq_end);
                        tracing::debug!(
                            "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} Broken pipe, draining {payload_len} bytes"
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Fast path TX write error: {e}");
                        self.fast_path_conns.remove(&key);
                        return None;
                    }
                }
            } else {
                // Duplicate/already-ACKed segment — skip write, re-ACK.
                tracing::trace!(
                    "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} retransmit (guest_seq={guest_seq}, last_ack={}, payload={payload_len})",
                    conn.last_ack
                );
            }
        }

        // FIN handling — after payload has been forwarded to host.
        if flags & 0x01 != 0 {
            tracing::debug!("Fast path: FIN from guest {src_ip}:{src_port}→{dst_ip}:{dst_port}");
            // FIN consumes 1 sequence number (in addition to any data bytes
            // already accounted for above).
            conn.set_last_ack(conn.last_ack.wrapping_add(1));
            let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
            let fin_ack = crate::ethernet::build_tcp_fin_frame(&crate::ethernet::TcpFrameParams {
                src_ip: conn.remote_ip,
                dst_ip: conn.guest_ip,
                src_port: conn.remote_port,
                dst_port: conn.guest_port,
                seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
                ack: conn.last_ack,
                window: 65535,
                src_mac: self.fast_path_gateway_mac,
                dst_mac: guest_mac,
            });
            self.fast_path_conns.remove(&key);
            return Some(fin_ack);
        }

        // Only ACK if the guest sent data — replying to a pure ACK
        // would create a dup-ACK loop that triggers fast retransmits on
        // the peer and tanks host→VM throughput.
        if payload_len == 0 {
            return Some(Vec::new());
        }

        let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
        let ack = crate::ethernet::build_tcp_ack_frame(&crate::ethernet::TcpFrameParams {
            src_ip: conn.remote_ip,
            dst_ip: conn.guest_ip,
            src_port: conn.remote_port,
            dst_port: conn.guest_port,
            seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
            ack: conn.last_ack,
            window: 65535,
            src_mac: self.fast_path_gateway_mac,
            dst_mac: guest_mac,
        });

        Some(ack)
    }

    /// Polls fast-path host streams for readable data and generates frames
    /// to inject into the guest.
    ///
    /// Returns frames to be written to the guest FD via `enqueue_or_write`.
    pub fn poll_fast_path(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut to_remove = Vec::new();
        let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
        let gw_mac = self.fast_path_gateway_mac;

        for (key, conn) in &mut self.fast_path_conns {
            if conn.host_eof || conn.inline_owned {
                continue;
            }

            use std::io::Read;
            match conn.stream.read(&mut conn.read_buf) {
                Ok(0) => {
                    // Host EOF — send FIN to guest.
                    conn.host_eof = true;
                    let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                    let fin =
                        crate::ethernet::build_tcp_fin_frame(&crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: seq_now,
                            ack: conn.last_ack,
                            window: 65535,
                            src_mac: gw_mac,
                            dst_mac: guest_mac,
                        });
                    // FIN consumes 1 SEQ.
                    conn.our_seq
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    frames.push(fin);
                    // Don't remove yet — keep the entry so the guest's FIN-ACK
                    // response is handled by try_fast_path_intercept (which will
                    // see the FIN flag and clean up).
                }
                Ok(n) => {
                    // Channel/inject path: send the entire read as one large
                    // frame (the inject thread's GSO hint lets the guest
                    // re-segment at MSS).
                    let data = &conn.read_buf[..n];
                    if self.large_frames_enabled {
                        let large = ETH_HEADER_LEN + 40 + data.len() > 1500;
                        let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                        let params = crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: seq_now,
                            ack: conn.last_ack,
                            window: 65535,
                            src_mac: gw_mac,
                            dst_mac: guest_mac,
                        };
                        let data_frame = if large {
                            crate::ethernet::build_tcp_data_frame_partial_csum(&params, data)
                        } else {
                            crate::ethernet::build_tcp_data_frame(&params, data)
                        };
                        conn.our_seq
                            .fetch_add(data.len() as u32, std::sync::atomic::Ordering::Relaxed);
                        frames.push(data_frame);
                    } else {
                        // Socketpair path: segment at FAST_PATH_GUEST_MSS.
                        let mut offset = 0;
                        while offset < data.len() {
                            let chunk_end = (offset + FAST_PATH_GUEST_MSS).min(data.len());
                            let chunk = &data[offset..chunk_end];
                            let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                            let data_frame = crate::ethernet::build_tcp_data_frame(
                                &crate::ethernet::TcpFrameParams {
                                    src_ip: conn.remote_ip,
                                    dst_ip: conn.guest_ip,
                                    src_port: conn.remote_port,
                                    dst_port: conn.guest_port,
                                    seq: seq_now,
                                    ack: conn.last_ack,
                                    window: 65535,
                                    src_mac: gw_mac,
                                    dst_mac: guest_mac,
                                },
                                chunk,
                            );
                            conn.our_seq.fetch_add(
                                chunk.len() as u32,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            frames.push(data_frame);
                            offset = chunk_end;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available — expected for non-blocking.
                }
                Err(e) => {
                    tracing::warn!(
                        "Fast path RX error {}:{} → {}:{}: {e}",
                        conn.remote_ip,
                        conn.remote_port,
                        conn.guest_ip,
                        conn.guest_port
                    );
                    to_remove.push(*key);
                }
            }
        }

        for key in to_remove {
            self.fast_path_conns.remove(&key);
        }

        frames
    }

    /// Promotes a connection to the fast path.
    ///
    /// Called when a shim handshake reaches ESTABLISHED and has a
    /// pre-connected host stream. The connection is moved into
    /// `fast_path_conns` and subsequent data bypasses handshake bookkeeping.
    pub fn promote_to_fast_path(
        &mut self,
        key: SynFlowKey,
        stream: std::net::TcpStream,
        our_seq: u32,
        last_ack: u32,
    ) {
        // Set non-blocking for polling in the event loop.
        stream.set_nonblocking(true).ok();
        stream.set_nodelay(true).ok();

        let last_ack_atomic = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(last_ack));
        let our_seq_atomic = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(our_seq));

        // Shim-synthesized handshakes know exact SEQ/ACK at promotion
        // time, so hand the cloned stream to the inject thread
        // immediately for zero-copy host→guest reads.
        let mut inline_owned = false;

        if let Some(ref sink) = self.conn_sink {
            match stream.try_clone() {
                Ok(cloned) => {
                    let gw_mac = self.fast_path_gateway_mac;
                    let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
                    let promoted = crate::direct_rx::PromotedConn {
                        stream: cloned,
                        remote_ip: key.dst_ip,
                        guest_ip: key.src_ip,
                        remote_port: key.dst_port,
                        guest_port: key.src_port,
                        our_seq: std::sync::Arc::clone(&our_seq_atomic),
                        last_ack: std::sync::Arc::clone(&last_ack_atomic),
                        gw_mac,
                        guest_mac,
                    };
                    if sink.send_conn(promoted) {
                        inline_owned = true;
                        tracing::info!(
                            "Fast path: promoted INLINE {}:{} → {}:{} (seq={our_seq}, ack={last_ack})",
                            key.src_ip,
                            key.src_port,
                            key.dst_ip,
                            key.dst_port,
                        );
                    } else {
                        tracing::warn!("Fast path: inline sink full, falling back to channel path");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Fast path: try_clone failed ({e}), falling back to channel path"
                    );
                }
            }
        } else {
            tracing::info!(
                "Fast path: promoted {}:{} → {}:{} (seq={our_seq}, ack={last_ack})",
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
            );
        }

        self.fast_path_conns.insert(
            key,
            FastPathConn {
                stream,
                our_seq: our_seq_atomic,
                last_ack,
                last_ack_shared: Some(std::sync::Arc::clone(&last_ack_atomic)),
                remote_ip: key.dst_ip,
                guest_ip: key.src_ip,
                remote_port: key.dst_port,
                guest_port: key.src_port,
                read_buf: vec![0u8; 32768],
                host_eof: false,
                inline_owned,
            },
        );
    }

    /// Returns the number of active fast-path connections.
    #[must_use]
    pub fn fast_path_count(&self) -> usize {
        self.fast_path_conns.len()
    }

    /// Returns the number of in-progress handshakes.
    #[must_use]
    pub fn handshake_count(&self) -> usize {
        self.handshake_conns.len()
    }

    /// Parses a TCP SYN frame and registers an in-shim `PassiveOpen`
    /// handshake: captures the guest ISN and options, generates our ISN,
    /// and spawns an async host connect. The SYN-ACK is emitted later by
    /// `poll_handshakes` once the connect resolves.
    ///
    /// Returns an RST frame if the SYN is rejected (capacity, malformed).
    /// Returns `None` on success — the handshake is now tracked.
    ///
    /// `gateway_mac` and `guest_mac` are the MAC addresses used on the
    /// guest's Ethernet link. The guest MAC is learned from the source MAC
    /// of inbound frames; if `guest_mac` is `None`, we use broadcast as a
    /// temporary fallback (first guest frame will correct it).
    pub fn handle_outbound_syn(
        &mut self,
        syn_frame: &[u8],
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
    ) -> Option<Vec<u8>> {
        // Parse the SYN frame: ETH(14) + IP(var) + TCP(var).
        let ip_start = ETH_HEADER_LEN;
        if syn_frame.len() < ip_start + 40 {
            return None;
        }
        let ihl = ((syn_frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        if l4_start + 20 > syn_frame.len() {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            syn_frame[ip_start + 12],
            syn_frame[ip_start + 13],
            syn_frame[ip_start + 14],
            syn_frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            syn_frame[ip_start + 16],
            syn_frame[ip_start + 17],
            syn_frame[ip_start + 18],
            syn_frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([syn_frame[l4_start], syn_frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([syn_frame[l4_start + 2], syn_frame[l4_start + 3]]);
        let flags = syn_frame[l4_start + 13];
        // Require SYN set, ACK clear.
        if flags & 0x12 != 0x02 {
            return None;
        }
        let guest_isn = u32::from_be_bytes([
            syn_frame[l4_start + 4],
            syn_frame[l4_start + 5],
            syn_frame[l4_start + 6],
            syn_frame[l4_start + 7],
        ]);

        let key = SynFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        // Retransmit of an existing handshake — same ISN means the guest
        // is re-sending the SYN because our SYN-ACK was lost. Drop
        // silently; poll_handshakes will handle the re-send.
        if let Some(existing) = self.handshake_conns.get(&key) {
            if existing.role == HandshakeRole::PassiveOpen && existing.peer_isn == guest_isn {
                tracing::debug!("Handshake shim: SYN retransmit dropped for {key:?}");
                return None;
            }
            // Different ISN = new connection attempt, evict stale entry.
            tracing::debug!("Handshake shim: ISN changed for {key:?}, replacing");
            self.handshake_conns.remove(&key);
        }

        // Capacity guard — send RST instead of silent drop.
        if self.handshake_conns.len() >= MAX_PENDING_SYNS {
            tracing::warn!("Handshake shim: capacity reached, RST for {key:?}");
            return build_rst_from_syn(syn_frame, gateway_mac);
        }

        // Parse peer options (MSS / WScale / SACK-perm).
        let opts = crate::ethernet::parse_tcp_syn_options(&syn_frame[l4_start..]);
        let peer_wscale = opts.wscale;
        let peer_sack = opts.sack_permitted;
        let peer_mss = opts.mss.unwrap_or(536);

        // Resolve connect target. Gateway IP → loopback for host.docker.internal.
        let target_ip = if dst_ip == self.gateway_ip {
            Ipv4Addr::LOCALHOST
        } else {
            dst_ip
        };
        let connect_addr =
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(target_ip, dst_port));

        // Spawn host connect. Result is delivered via oneshot.
        let (result_tx, result_rx) = oneshot::channel();
        tokio::spawn(async move {
            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(SYN_GATE_CONNECT_TIMEOUT_SECS),
                tokio::net::TcpStream::connect(connect_addr),
            )
            .await
            .ok()
            .and_then(Result::ok);
            let _ = result_tx.send(stream);
        });

        let our_isn = next_isn();
        self.handshake_conns.insert(
            key,
            HandshakeConn {
                flow_key: key,
                role: HandshakeRole::PassiveOpen,
                our_isn,
                peer_isn: guest_isn,
                host_stream: None,
                connect_rx: Some(result_rx),
                peer_wscale,
                peer_sack,
                peer_mss,
                gw_mac: gateway_mac,
                guest_mac,
                retransmit_count: 0,
                last_sent: None,
                saved_frame: None,
                created: StdInstant::now(),
            },
        );

        tracing::debug!(
            "Handshake shim: passive-open registered {key:?} our_isn={our_isn:08x} guest_isn={guest_isn:08x}"
        );
        None
    }

    /// Registers an inbound port-forward `ActiveOpen` handshake. We will
    /// emit a SYN toward the guest on the next `poll_handshakes`, then
    /// wait for the guest's SYN-ACK.
    ///
    /// Called from the datapath when `InboundListenerManager` accepts a
    /// new host connection.
    pub fn initiate_active_handshake(
        &mut self,
        flow_key: SynFlowKey,
        host_stream: std::net::TcpStream,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
    ) {
        host_stream.set_nonblocking(true).ok();
        host_stream.set_nodelay(true).ok();

        let our_isn = next_isn();
        // Evict any stale entry for the same four-tuple.
        self.handshake_conns.remove(&flow_key);

        self.handshake_conns.insert(
            flow_key,
            HandshakeConn {
                flow_key,
                role: HandshakeRole::ActiveOpen,
                our_isn,
                peer_isn: 0, // filled in when SYN-ACK arrives
                host_stream: Some(host_stream),
                connect_rx: None,
                peer_wscale: Some(SHIM_WSCALE),
                peer_sack: true,
                peer_mss: SHIM_MSS,
                gw_mac: gateway_mac,
                guest_mac,
                retransmit_count: 0,
                last_sent: None,
                saved_frame: None,
                created: StdInstant::now(),
            },
        );

        tracing::debug!(
            "Handshake shim: active-open registered {flow_key:?} our_isn={our_isn:08x}"
        );
    }

    /// Drives all in-progress handshakes: polls host connects, emits
    /// initial frames (SYN-ACK for passive, SYN for active), retransmits,
    /// and aborts after the TTL / retransmit limit.
    ///
    /// Returns frames to inject to the guest.
    pub fn poll_handshakes(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut to_abort: Vec<SynFlowKey> = Vec::new();
        let now = StdInstant::now();

        for (key, conn) in &mut self.handshake_conns {
            // Global TTL — abort stuck handshakes.
            if now.duration_since(conn.created) > HANDSHAKE_TOTAL_TTL {
                tracing::warn!("Handshake shim: TTL exceeded for {key:?}, aborting");
                to_abort.push(*key);
                continue;
            }

            match conn.role {
                HandshakeRole::PassiveOpen => {
                    // If host connect hasn't resolved, try to pick up the result.
                    if conn.host_stream.is_none() {
                        let Some(rx) = conn.connect_rx.as_mut() else {
                            // No stream, no pending connect — aborted.
                            to_abort.push(*key);
                            continue;
                        };
                        match rx.try_recv() {
                            Ok(Some(tokio_stream)) => match tokio_stream.into_std() {
                                Ok(std_stream) => {
                                    std_stream.set_nonblocking(true).ok();
                                    std_stream.set_nodelay(true).ok();
                                    conn.host_stream = Some(std_stream);
                                    conn.connect_rx = None;
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "Handshake shim: into_std failed for {key:?}: {e}"
                                    );
                                    to_abort.push(*key);
                                    continue;
                                }
                            },
                            Ok(None) => {
                                // Host connect refused / timed out. Emit
                                // RST|ACK toward the guest so the originating
                                // socket sees an immediate ECONNREFUSED
                                // instead of waiting for SYN retransmits.
                                tracing::debug!("Handshake shim: host connect failed for {key:?}");
                                let rst = crate::ethernet::build_tcp_rst_frame(
                                    &crate::ethernet::TcpFrameParams {
                                        src_ip: key.dst_ip,
                                        dst_ip: key.src_ip,
                                        src_port: key.dst_port,
                                        dst_port: key.src_port,
                                        seq: 0,
                                        ack: conn.peer_isn.wrapping_add(1),
                                        window: 0,
                                        src_mac: conn.gw_mac,
                                        dst_mac: conn.guest_mac,
                                    },
                                );
                                out.push(rst);
                                to_abort.push(*key);
                                continue;
                            }
                            Err(oneshot::error::TryRecvError::Empty) => {
                                continue; // still connecting
                            }
                            Err(oneshot::error::TryRecvError::Closed) => {
                                to_abort.push(*key);
                                continue;
                            }
                        }
                    }

                    // Host stream is ready. Emit SYN-ACK (first time) or
                    // retransmit based on timer.
                    if conn.saved_frame.is_none() {
                        let frame = crate::ethernet::build_tcp_syn_ack_frame(
                            &crate::ethernet::SynAckParams {
                                src_ip: key.dst_ip,
                                dst_ip: key.src_ip,
                                src_port: key.dst_port,
                                dst_port: key.src_port,
                                seq: conn.our_isn,
                                ack: conn.peer_isn.wrapping_add(1),
                                src_mac: conn.gw_mac,
                                dst_mac: conn.guest_mac,
                                mss: SHIM_MSS,
                                wscale: conn.peer_wscale.map(|_| SHIM_WSCALE),
                                sack_permitted: conn.peer_sack,
                            },
                        );
                        conn.saved_frame = Some(frame.clone());
                        conn.last_sent = Some(now);
                        out.push(frame);
                    } else if should_retransmit(conn, now) {
                        if conn.retransmit_count >= HANDSHAKE_MAX_RETRANSMITS {
                            to_abort.push(*key);
                            continue;
                        }
                        if let Some(ref frame) = conn.saved_frame {
                            out.push(frame.clone());
                            conn.retransmit_count += 1;
                            conn.last_sent = Some(now);
                        }
                    }
                }
                HandshakeRole::ActiveOpen => {
                    if conn.saved_frame.is_none() {
                        let frame =
                            crate::ethernet::build_tcp_syn_frame(&crate::ethernet::SynParams {
                                // We're sending from gateway → guest.
                                src_ip: key.dst_ip,
                                dst_ip: key.src_ip,
                                src_port: key.dst_port,
                                dst_port: key.src_port,
                                seq: conn.our_isn,
                                src_mac: conn.gw_mac,
                                dst_mac: conn.guest_mac,
                                mss: SHIM_MSS,
                                wscale: Some(SHIM_WSCALE),
                            });
                        conn.saved_frame = Some(frame.clone());
                        conn.last_sent = Some(now);
                        out.push(frame);
                    } else if should_retransmit(conn, now) {
                        if conn.retransmit_count >= HANDSHAKE_MAX_RETRANSMITS {
                            to_abort.push(*key);
                            continue;
                        }
                        if let Some(ref frame) = conn.saved_frame {
                            out.push(frame.clone());
                            conn.retransmit_count += 1;
                            conn.last_sent = Some(now);
                        }
                    }
                }
            }
        }

        for key in to_abort {
            self.handshake_conns.remove(&key);
        }

        out
    }

    /// Called when a TCP frame arrives that matches a pending handshake
    /// (keyed on `SynFlowKey`). For PassiveOpen: consumes the guest's ACK
    /// and promotes to `FastPathConn`. For ActiveOpen: consumes the
    /// guest's SYN-ACK, emits our final ACK, and promotes.
    ///
    /// Returns `Some(Vec<frame>)` if the frame was consumed by the shim
    /// (possibly emitting reply frames). Returns `None` if no matching
    /// handshake exists or the frame doesn't match the expected phase.
    pub fn try_complete_handshake(&mut self, frame: &[u8]) -> Option<Vec<Vec<u8>>> {
        let ip_start = ETH_HEADER_LEN;
        if frame.len() < ip_start + 40 {
            return None;
        }
        if frame[ip_start + 9] != 6 {
            return None;
        }
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        if l4_start + 20 > frame.len() {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
        let flags = frame[l4_start + 13];
        let seq = u32::from_be_bytes([
            frame[l4_start + 4],
            frame[l4_start + 5],
            frame[l4_start + 6],
            frame[l4_start + 7],
        ]);
        let ack = u32::from_be_bytes([
            frame[l4_start + 8],
            frame[l4_start + 9],
            frame[l4_start + 10],
            frame[l4_start + 11],
        ]);

        let key = SynFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        let conn = self.handshake_conns.get(&key)?;

        match conn.role {
            HandshakeRole::PassiveOpen => {
                // Expect ACK set, SYN clear, and RST/FIN both clear. Without
                // the RST/FIN check, RST|ACK (0x14) and FIN|ACK (0x11) would
                // pass the old `flags & 0x12 != 0x10` test and incorrectly
                // promote an already-aborted guest flow into the fast path.
                const SYN: u8 = 0x02;
                const ACK: u8 = 0x10;
                const RST: u8 = 0x04;
                const FIN: u8 = 0x01;
                if flags & (SYN | ACK) != ACK || flags & (RST | FIN) != 0 {
                    if flags & RST != 0 {
                        tracing::debug!("Handshake shim: RST during PassiveOpen for {key:?}");
                        self.handshake_conns.remove(&key);
                    }
                    return None;
                }
                // Guest is ACKing our SYN-ACK: ack should be our_isn + 1.
                if ack != conn.our_isn.wrapping_add(1) {
                    tracing::debug!(
                        "Handshake shim: passive ACK mismatch for {key:?} got ack={ack:08x} want={:08x}",
                        conn.our_isn.wrapping_add(1)
                    );
                    return None;
                }
                let conn = self.handshake_conns.remove(&key)?;
                let our_seq = conn.our_isn.wrapping_add(1);
                let last_ack = conn.peer_isn.wrapping_add(1);
                let Some(stream) = conn.host_stream else {
                    return Some(Vec::new());
                };
                self.promote_to_fast_path(key, stream, our_seq, last_ack);
                Some(Vec::new())
            }
            HandshakeRole::ActiveOpen => {
                // Expect SYN + ACK.
                if flags & 0x12 != 0x12 {
                    return None;
                }
                if ack != conn.our_isn.wrapping_add(1) {
                    tracing::debug!(
                        "Handshake shim: active SYN-ACK ack mismatch for {key:?} got ack={ack:08x} want={:08x}",
                        conn.our_isn.wrapping_add(1)
                    );
                    return None;
                }
                // Capture guest ISN from their SYN-ACK.
                let guest_isn = seq;
                // Mirror their options back so we can promote with sane state.
                let peer_opts = crate::ethernet::parse_tcp_syn_options(&frame[l4_start..]);

                let mut conn = self.handshake_conns.remove(&key)?;
                conn.peer_isn = guest_isn;
                if peer_opts.wscale.is_some() {
                    conn.peer_wscale = peer_opts.wscale;
                }
                if peer_opts.sack_permitted {
                    conn.peer_sack = true;
                }

                // Build ACK completing the handshake.
                let our_seq = conn.our_isn.wrapping_add(1);
                let last_ack = guest_isn.wrapping_add(1);
                let ack_frame =
                    crate::ethernet::build_tcp_ack_frame(&crate::ethernet::TcpFrameParams {
                        // Direction: gateway → guest.
                        src_ip: key.dst_ip,
                        dst_ip: key.src_ip,
                        src_port: key.dst_port,
                        dst_port: key.src_port,
                        seq: our_seq,
                        ack: last_ack,
                        window: 65535,
                        src_mac: conn.gw_mac,
                        dst_mac: conn.guest_mac,
                    });

                let Some(stream) = conn.host_stream else {
                    return Some(vec![ack_frame]);
                };
                self.promote_to_fast_path(key, stream, our_seq, last_ack);
                Some(vec![ack_frame])
            }
        }
    }

    /// Determines whether to connect via a proxy tunnel for the given destination.
    ///
    /// Returns `Some((proxy_authority, target_host, target_port, protocol))` if a
    /// proxy should be used, or `None` for direct connection. The proxy authority
    /// is a `"host:port"` string that `TcpStream::connect` can resolve (supports
    /// both IP addresses and hostnames like `proxy.corp.com`).
    #[allow(dead_code)] // reintegrated into handle_outbound_syn in a follow-up
    fn resolve_proxy_target(
        &self,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        domain: Option<&str>,
    ) -> Option<(String, String, u16, &'static str)> {
        let env = self.proxy_env.as_ref()?;

        // No proxy configured → always direct.
        if !env.has_usable_proxy() {
            return None;
        }

        // Check fake-ip BEFORE requiring a domain name. Fake-IP destinations
        // (198.18.0.0/15 from Surge/ClashX) always need proxy routing, even
        // if the DNS log hasn't recorded the domain yet (race between DNS
        // response and TCP SYN). Use the IP as fallback CONNECT target.
        let is_fake = env.is_fake_ip(dst_ip);

        // Resolve the host for the CONNECT/SOCKS5 tunnel target.
        // For fake-IP without domain, fall back to the IP string — the proxy
        // will resolve it on its end (Surge handles this correctly).
        let host = match domain {
            Some(d) => d.to_string(),
            None if is_fake => dst_ip.to_string(),
            None => return None,
        };

        // Check bypass list.
        if env.should_bypass(&host) {
            return None;
        }

        // Proxy fake-ip destinations and traffic when an explicit system proxy
        // is configured (corporate proxy environments).
        let need_proxy = is_fake
            || env.http_proxy.is_some()
            || env.https_proxy.is_some()
            || env.socks_proxy.is_some();
        if !need_proxy {
            return None;
        }

        // Prefer SOCKS5 (supports all protocols and avoids TLS issues),
        // then HTTPS proxy (HTTP CONNECT works on any port, not just 443),
        // then HTTP proxy as last resort.
        if let Some(ref socks) = env.socks_proxy {
            let authority = format!("{}:{}", socks.host, socks.port);
            return Some((authority, host, dst_port, "socks5"));
        }

        if let Some(ref https) = env.https_proxy {
            let authority = format!("{}:{}", https.host, https.port);
            return Some((authority, host, dst_port, "http-connect"));
        }

        if let Some(ref http) = env.http_proxy {
            let authority = format!("{}:{}", http.host, http.port);
            return Some((authority, host, dst_port, "http-connect"));
        }

        None
    }

    /// Configures proxy-aware connection support.
    ///
    /// When set, `handle_outbound_syn` uses the DNS log to resolve destination
    /// IPs to domain names and connect via system proxy (HTTP CONNECT / SOCKS5)
    /// when available. Without this, all connections use direct
    /// `TcpStream::connect`.
    pub fn set_proxy_awareness(
        &mut self,
        dns_log: super::dns_log::DnsResolutionLog,
        proxy_env: super::proxy_detect::ProxyEnvironment,
    ) {
        self.dns_log = Some(dns_log);
        self.proxy_env = Some(proxy_env);
    }

    /// Allocates the next inbound ephemeral port, wrapping at the end of
    /// the reserved 61000–65535 range.
    fn allocate_ephemeral(&mut self) -> u16 {
        let port = self.next_ephemeral;
        self.next_ephemeral = if self.next_ephemeral == INBOUND_EPHEMERAL_END {
            INBOUND_EPHEMERAL_START
        } else {
            self.next_ephemeral + 1
        };
        port
    }

    /// Registers an inbound port-forward connection as an ActiveOpen
    /// handshake. The SYN toward the guest is emitted on the next
    /// `poll_handshakes()` call.
    ///
    /// Called by the datapath when `InboundListenerManager` accepts a new
    /// host connection.
    pub fn initiate_inbound(
        &mut self,
        container_port: u16,
        stream: tokio::net::TcpStream,
        guest_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
    ) {
        let Ok(std_stream) = stream.into_std() else {
            tracing::warn!(
                "TCP bridge: inbound stream into_std() failed for guest:{container_port}"
            );
            return;
        };

        let eph_port = self.allocate_ephemeral();
        let flow_key = SynFlowKey {
            src_ip: guest_ip,
            src_port: container_port,
            dst_ip: gateway_ip,
            dst_port: eph_port,
        };

        let gw_mac = self.fast_path_gateway_mac;
        let gmac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
        self.initiate_active_handshake(flow_key, std_stream, gw_mac, gmac);

        tracing::debug!(
            "TCP bridge: inbound ActiveOpen registered gw:{eph_port} → guest:{container_port}"
        );
    }
}

/// Returns true if the saved handshake frame is due for retransmit.
///
/// The retransmit delay schedule is indexed by `retransmit_count`; the
/// last-sent timestamp must have elapsed by at least that delay.
fn should_retransmit(conn: &HandshakeConn, now: StdInstant) -> bool {
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
fn build_rst_from_syn(syn_frame: &[u8], gateway_mac: [u8; 6]) -> Option<Vec<u8>> {
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
mod tests {
    use super::*;
    use crate::ethernet::ETH_HEADER_LEN;

    const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 1);
    const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GUEST_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);

    // -------- Handshake synthesizer tests --------

    #[test]
    fn test_next_isn_distinct_values() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let isn = next_isn();
            assert!(seen.insert(isn), "next_isn produced duplicate {isn:08x}");
        }
    }

    /// Builds a synthetic guest SYN frame with the given options.
    fn make_guest_syn_frame(
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        options: &[u8],
    ) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let tcp_hdr_len = 20 + options.len();
        let ip_total = 20 + tcp_hdr_len;
        let mut frame = vec![0u8; ETH_HEADER_LEN + ip_total];
        // Eth: dst=GW_MAC, src=GUEST_MAC, IPv4.
        frame[0..6].copy_from_slice(&GW_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // IPv4.
        let ip = 14;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 16].copy_from_slice(&GUEST_IP.octets());
        frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
        // TCP.
        let tcp = 34;
        frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        frame[tcp + 12] = ((tcp_hdr_len / 4) as u8) << 4;
        frame[tcp + 13] = 0x02; // SYN
        frame[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
        frame[tcp + 20..tcp + 20 + options.len()].copy_from_slice(options);
        frame
    }

    /// Builds a guest ACK frame (pure ACK, no payload).
    fn make_guest_ack_frame(
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 40];
        frame[0..6].copy_from_slice(&GW_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = 14;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 16].copy_from_slice(&GUEST_IP.octets());
        frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
        let tcp = 34;
        frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
        frame[tcp + 12] = 0x50;
        frame[tcp + 13] = 0x10; // ACK
        frame
    }

    /// Builds a guest SYN-ACK frame (for ActiveOpen completion tests).
    fn make_guest_syn_ack_frame(
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut frame = make_guest_ack_frame(src_port, dst_ip, dst_port, seq, ack);
        let tcp = 34;
        frame[tcp + 13] = 0x12; // SYN | ACK
        frame
    }

    #[tokio::test]
    async fn handshake_passive_open_registers_and_emits_syn_ack() {
        // Spin up a local listener so the host connect succeeds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_port = addr.port();

        let mut bridge = TcpBridge::new(GW_IP);
        bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

        // Build a guest SYN with MSS + WScale + SACK-Permitted (12-byte options).
        let opts = &[
            2, 4, 0x05, 0xB4, // MSS = 1460
            3, 3, 8, // WScale = 8 (peer)
            4, 2, // SACK-Permitted
            1, 1, 1, // NOP padding to 12 bytes (4-aligned)
        ];
        // Target 127.0.0.1 directly via the non-gateway path.
        let syn = make_guest_syn_frame(40001, Ipv4Addr::LOCALHOST, server_port, 0xAAAA_AAAA, opts);

        // handle_outbound_syn returns None on success, Some(RST) on reject.
        let rst = bridge.handle_outbound_syn(&syn, GW_MAC, GUEST_MAC);
        assert!(rst.is_none());
        assert_eq!(bridge.handshake_count(), 1);

        // Accept the server-side connection so our tokio connect resolves.
        let (_accepted, _) = listener.accept().await.unwrap();
        // Give the tokio task time to deliver the stream.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Poll — should emit SYN-ACK.
        let out = bridge.poll_handshakes();
        assert_eq!(out.len(), 1, "expected one SYN-ACK frame");
        let syn_ack = &out[0];

        // Verify: flags=SYN|ACK, ack=guest_isn+1, correct options.
        let tcp = 34;
        assert_eq!(syn_ack[tcp + 13], 0x12);
        let ack = u32::from_be_bytes([
            syn_ack[tcp + 8],
            syn_ack[tcp + 9],
            syn_ack[tcp + 10],
            syn_ack[tcp + 11],
        ]);
        assert_eq!(ack, 0xAAAA_AAAAu32.wrapping_add(1));
        let parsed = crate::ethernet::parse_tcp_syn_options(&syn_ack[tcp..]);
        assert_eq!(parsed.mss, Some(SHIM_MSS));
        assert_eq!(parsed.wscale, Some(SHIM_WSCALE));
        assert!(parsed.sack_permitted);
    }

    #[tokio::test]
    async fn handshake_passive_open_completes_on_guest_ack() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_port = addr.port();

        let mut bridge = TcpBridge::new(GW_IP);
        bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

        let guest_isn = 0x1234_5678u32;
        let syn = make_guest_syn_frame(
            40002,
            Ipv4Addr::LOCALHOST,
            server_port,
            guest_isn,
            &[2, 4, 0x05, 0xB4],
        );
        assert!(
            bridge
                .handle_outbound_syn(&syn, GW_MAC, GUEST_MAC)
                .is_none()
        );

        let (_accepted, _) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let syn_ack = bridge.poll_handshakes();
        assert_eq!(syn_ack.len(), 1);
        let tcp = 34;
        let our_isn = u32::from_be_bytes([
            syn_ack[0][tcp + 4],
            syn_ack[0][tcp + 5],
            syn_ack[0][tcp + 6],
            syn_ack[0][tcp + 7],
        ]);

        // Guest completes the handshake.
        let guest_ack = make_guest_ack_frame(
            40002,
            Ipv4Addr::LOCALHOST,
            server_port,
            guest_isn.wrapping_add(1),
            our_isn.wrapping_add(1),
        );
        let result = bridge.try_complete_handshake(&guest_ack);
        assert!(result.is_some());

        // Now promoted to fast path; handshake entry gone.
        assert_eq!(bridge.handshake_count(), 0);
        assert_eq!(bridge.fast_path_count(), 1);
    }

    #[tokio::test]
    async fn handshake_active_open_emits_syn_and_completes() {
        // Pretend the host accepted a connection; wire up two loopback
        // streams so `initiate_active_handshake` has a valid stream.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        let host_stream = client.into_std().unwrap();

        let mut bridge = TcpBridge::new(GW_IP);
        bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

        let flow_key = SynFlowKey {
            src_ip: GUEST_IP,
            src_port: 8080,
            dst_ip: GW_IP,
            dst_port: 61500,
        };
        bridge.initiate_active_handshake(flow_key, host_stream, GW_MAC, GUEST_MAC);
        assert_eq!(bridge.handshake_count(), 1);

        // Poll emits our SYN toward the guest.
        let out = bridge.poll_handshakes();
        assert_eq!(out.len(), 1);
        let tcp = 34;
        assert_eq!(out[0][tcp + 13], 0x02, "expected pure SYN");
        let our_isn = u32::from_be_bytes([
            out[0][tcp + 4],
            out[0][tcp + 5],
            out[0][tcp + 6],
            out[0][tcp + 7],
        ]);

        // Guest responds with SYN-ACK.
        let guest_isn = 0xDEAD_BEEFu32;
        let syn_ack =
            make_guest_syn_ack_frame(8080, GW_IP, 61500, guest_isn, our_isn.wrapping_add(1));
        let reply = bridge.try_complete_handshake(&syn_ack);
        let reply = reply.expect("shim should accept SYN-ACK");
        assert_eq!(reply.len(), 1, "expected final ACK frame");
        assert_eq!(reply[0][tcp + 13], 0x10, "flags=ACK");

        assert_eq!(bridge.handshake_count(), 0);
        assert_eq!(bridge.fast_path_count(), 1);
    }

    #[tokio::test]
    async fn handshake_rejects_mismatched_ack() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut bridge = TcpBridge::new(GW_IP);
        bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

        let guest_isn = 7777;
        let syn = make_guest_syn_frame(
            40003,
            Ipv4Addr::LOCALHOST,
            addr.port(),
            guest_isn,
            &[2, 4, 0x05, 0xB4],
        );
        bridge.handle_outbound_syn(&syn, GW_MAC, GUEST_MAC);
        let (_accepted, _) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = bridge.poll_handshakes();

        // ACK with wrong ack number — shim must reject (return None) and
        // leave the handshake entry intact.
        let bad_ack = make_guest_ack_frame(
            40003,
            Ipv4Addr::LOCALHOST,
            addr.port(),
            guest_isn.wrapping_add(1),
            0xBAD_BAD,
        );
        let result = bridge.try_complete_handshake(&bad_ack);
        assert!(result.is_none());
        assert_eq!(bridge.handshake_count(), 1);
        assert_eq!(bridge.fast_path_count(), 0);
    }

    #[test]
    fn handshake_capacity_sends_rst() {
        let mut bridge = TcpBridge::new(GW_IP);
        // Fill to capacity with fake entries.
        for i in 0..MAX_PENDING_SYNS {
            let k = SynFlowKey {
                src_ip: GUEST_IP,
                src_port: 10000 + i as u16,
                dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                dst_port: 80,
            };
            bridge.handshake_conns.insert(
                k,
                HandshakeConn {
                    flow_key: k,
                    role: HandshakeRole::PassiveOpen,
                    our_isn: 0,
                    peer_isn: 0,
                    host_stream: None,
                    connect_rx: None,
                    peer_wscale: None,
                    peer_sack: false,
                    peer_mss: 1460,
                    gw_mac: GW_MAC,
                    guest_mac: GUEST_MAC,
                    retransmit_count: 0,
                    last_sent: None,
                    saved_frame: None,
                    created: StdInstant::now(),
                },
            );
        }
        let syn = make_guest_syn_frame(
            9999,
            Ipv4Addr::new(203, 0, 113, 1),
            80,
            0,
            &[2, 4, 0x05, 0xB4],
        );
        let rst = bridge.handle_outbound_syn(&syn, GW_MAC, GUEST_MAC);
        assert!(rst.is_some(), "capacity-exceeded must return RST");
        let rst = rst.unwrap();
        assert_eq!(rst[34 + 13], 0x14, "RST|ACK flags expected");
    }

    #[tokio::test]
    async fn poll_fast_path_segments_frames_for_unix_dgram_limit() {
        use tokio::io::AsyncWriteExt;

        let mut bridge = TcpBridge::new(GW_IP);
        bridge.set_fast_path_macs(GW_MAC, GUEST_MAC);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::net::TcpStream::connect(addr);
        let (client, accepted) = tokio::join!(connect, listener.accept());
        let client = client.unwrap();
        let (mut accepted, _) = accepted.unwrap();

        let key = SynFlowKey {
            src_ip: GUEST_IP,
            src_port: 12345,
            dst_ip: Ipv4Addr::new(198, 18, 30, 95),
            dst_port: 443,
        };
        bridge.promote_to_fast_path(key, client.into_std().unwrap(), 1, 1);

        let payload = vec![0xAB; FAST_PATH_GUEST_MSS * 2 + 128];
        accepted.write_all(&payload).await.unwrap();

        // Loopback TCP delivery from `write_all` to the peer's recv buffer
        // is asynchronous at the kernel level. On a slow/busy CI runner a
        // single immediate `poll_fast_path` can race the delivery and
        // observe zero bytes (non-blocking read returns WouldBlock). Poll
        // with a small backoff until we accumulate the full payload or
        // time out.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        loop {
            let batch = bridge.poll_fast_path();
            let had_new = !batch.is_empty();
            frames.extend(batch);
            let received: usize = frames
                .iter()
                .map(|f| f.len().saturating_sub(ETH_HEADER_LEN + 40))
                .sum();
            if received >= payload.len() || std::time::Instant::now() >= deadline {
                break;
            }
            if !had_new {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        assert!(
            frames.len() >= 3,
            "large host payload should be segmented into multiple guest frames (got {})",
            frames.len(),
        );
        assert!(
            frames
                .iter()
                .all(|frame| frame.len() <= UNIX_DGRAM_MAX_FRAME_LEN),
            "fast-path frames must respect the AF_UNIX/SOCK_DGRAM datagram limit"
        );
    }
}
