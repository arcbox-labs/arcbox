//! Ethernet frame classifier for the datapath.
//!
//! Demultiplexes inbound Ethernet frames by protocol. Frames are *fed* to
//! [`FrameClassifier::classify_frame`] — typically by an
//! [`FdFrameSource`](crate::frame_source::FdFrameSource) draining the guest
//! socketpair (VM) or a `utun` (host tunnel) — and routed:
//!
//! - **ARP** → [`ArpResponder`] — synthesizes the reply inline
//! - **TCP SYN** → gated for `TcpBridge::handle_outbound_syn`
//! - **TCP (non-SYN)** → queued for `drain_fast_path` / `drain_handshake`
//! - **DHCP** (UDP:67), **DNS** (UDP:53 to gateway), **UDP**, **ICMP** →
//!   stored in the `intercepted` queue for the datapath loop
//!
//! There is no userspace TCP state machine here. Connections are driven by
//! [`TcpBridge`](super::tcp_bridge) and the in-kernel guest stack; this
//! module is purely a demultiplexer.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;

use arcbox_datapath::FrameBuf;
use arcbox_datapath::pool::PacketPool;

use crate::ethernet::{ArpResponder, ETH_HEADER_LEN};

/// Default Ethernet MTU (excludes Ethernet header).
/// Used as fallback when VZ `setMaximumTransmissionUnit:` is unavailable.
#[cfg(test)]
const DEFAULT_ETHERNET_MTU: usize = 1500;

/// Enhanced MTU for VZ framework with `maximumTransmissionUnit` (macOS 13+).
/// Reduces frame count by ~2.7x vs 1500.
pub const ENHANCED_ETHERNET_MTU: usize = 4000;

/// Protocol numbers.
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// TCP SYN connection info extracted during frame classification.
///
/// SYN frames are held back (`gated_syns`) until the host connect
/// completes. The full frame is stored so it can be injected into
/// the rx_queue later.
#[derive(Debug, Clone)]
pub struct TcpSynInfo {
    pub dst_port: u16,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub syn_seq: u32,
    pub frame: Vec<u8>,
}

/// An intercepted frame from the guest destined for a non-TCP handler.
#[derive(Debug)]
pub struct InterceptedFrame {
    pub frame: FrameBuf,
    pub kind: InterceptedKind,
}

/// Classification of intercepted frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptedKind {
    /// DHCP packet (UDP dst port 67).
    Dhcp,
    /// DNS query (UDP dst port 53 to gateway IP).
    Dns,
    /// Other UDP traffic.
    Udp,
    /// ICMP traffic.
    Icmp,
}

/// Frame classifier.
///
/// Fed Ethernet frames via [`classify_frame`](Self::classify_frame), it
/// responds to ARP inline and routes TCP / UDP / ICMP into the appropriate
/// queues for downstream handlers. It owns no fd — the ingest source (see
/// [`FrameSource`](crate::frame_source::FrameSource)) is the caller's.
pub struct FrameClassifier {
    /// Gateway IP for DNS interception.
    gateway_ip: Ipv4Addr,
    /// Gateway MAC — captured at construction so ARP replies use it.
    gateway_mac: [u8; 6],
    /// TCP frames queued for downstream drains (fast-path intercept,
    /// handshake completion). Frames not matched by either drain are
    /// silently dropped on the next classifier iteration — there is no
    /// userspace TCP stack to consume them.
    rx_queue: VecDeque<FrameBuf>,
    /// Frames intercepted from the guest (DHCP, DNS, UDP, ICMP).
    intercepted: Vec<InterceptedFrame>,
    /// TCP SYN frames held for handoff to `TcpBridge::handle_outbound_syn`.
    gated_syns: Vec<TcpSynInfo>,
    /// ARP replies produced inline by `ArpResponder` during classification,
    /// drained by the datapath loop.
    pending_arp_replies: Vec<Vec<u8>>,
    /// ARP responder (gateway IP only).
    arp: ArpResponder,
    /// Pre-allocated packet pool for zero-alloc frame ownership.
    pool: Arc<PacketPool>,
    /// Negotiated MTU (excludes Ethernet header). Set at construction time
    /// based on whether the VZ `maximumTransmissionUnit` setter succeeded.
    #[allow(dead_code)]
    mtu: usize,
}

impl FrameClassifier {
    /// Default packet-pool capacity: 4096 buffers. Each buffer is
    /// `MAX_PACKET_SIZE` (64 KiB), so resident pool memory is ~256 MiB. This is
    /// acceptable for the VM datapath because:
    /// - One pool per VM (not per connection)
    /// - Idle pages are compressed by macOS memory compressor
    /// - Smaller pools increase heap fallback frequency, defeating the purpose
    /// - At ~300K frames/sec (10 Gbps / 4000 MTU), 4096 gives ~13 ms burst headroom
    ///
    /// Memory-constrained hosts (e.g. an iOS Network Extension) should construct
    /// with [`with_pool_capacity`](Self::with_pool_capacity) and a smaller count.
    ///
    /// Note: this is deliberately distinct from `arcbox_datapath::DEFAULT_POOL_CAPACITY`
    /// (8192) — it preserves the classifier's own historical pool size and is
    /// unrelated to the datapath ring/pool default. Pass *this* constant to
    /// [`with_pool_capacity`](Self::with_pool_capacity), not the `arcbox_datapath` one.
    pub const DEFAULT_POOL_CAPACITY: usize = 4096;

    /// Creates a new classifier with the
    /// [default pool capacity](Self::DEFAULT_POOL_CAPACITY).
    ///
    /// `mtu` should match the device's configured MTU. Use
    /// `ENHANCED_ETHERNET_MTU` (4000) when VZ `setMaximumTransmissionUnit:`
    /// succeeded, or 1500 otherwise.
    ///
    /// The gateway MAC (needed to synthesize ARP replies) is set later via
    /// [`set_gateway_mac`](Self::set_gateway_mac), once it is known.
    pub fn new(gateway_ip: Ipv4Addr, mtu: usize) -> Self {
        Self::with_pool_capacity(gateway_ip, mtu, Self::DEFAULT_POOL_CAPACITY)
    }

    /// Creates a classifier with an explicit packet-pool capacity (buffer count).
    ///
    /// Each pooled buffer is `MAX_PACKET_SIZE` (64 KiB), so resident pool memory
    /// is `pool_capacity * 64 KiB`. The default
    /// ([`DEFAULT_POOL_CAPACITY`](Self::DEFAULT_POOL_CAPACITY), 4096 ⇒ ~256 MiB)
    /// suits the VM datapath but is far too large for a memory-constrained host
    /// such as an iOS Network Extension (capped near 50 MiB) — pass a small count
    /// there (e.g. 256 ⇒ ~16 MiB).
    ///
    /// The pool only bounds burst headroom: once it is exhausted the classifier
    /// falls back to heap allocation, so a small pool trades throughput under
    /// bursts for a bounded footprint, never correctness. `pool_capacity` is
    /// clamped to a minimum of 1 by the pool.
    pub fn with_pool_capacity(gateway_ip: Ipv4Addr, mtu: usize, pool_capacity: usize) -> Self {
        // `PacketPool::new` is infallible in practice (it clamps capacity to ≥1);
        // `expect` documents the `Result` contract.
        let pool = Arc::new(PacketPool::new(pool_capacity).expect("packet pool allocation"));
        Self {
            gateway_ip,
            gateway_mac: [0; 6],
            rx_queue: VecDeque::new(),
            intercepted: Vec::new(),
            gated_syns: Vec::new(),
            pending_arp_replies: Vec::new(),
            arp: ArpResponder::new(gateway_ip, [0; 6]),
            pool,
            mtu,
        }
    }

    /// Sets the gateway MAC used by the inline ARP responder.
    pub fn set_gateway_mac(&mut self, mac: [u8; 6]) {
        self.gateway_mac = mac;
        self.arp = ArpResponder::new(self.gateway_ip, mac);
    }

    /// Drains pending ARP replies produced inline by the classifier.
    pub fn take_arp_replies(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.pending_arp_replies)
    }

    /// Clears any TCP frames left in the rx queue after the fast-path /
    /// handshake drains have run. These are frames that didn't match any
    /// active flow — they're silently dropped since there is no userspace
    /// TCP stack to process them. (A legitimate guest kernel will retransmit
    /// if needed.)
    pub fn clear_unmatched_rx(&mut self) {
        self.rx_queue.clear();
    }

    /// Takes all intercepted frames, leaving the internal buffer empty.
    pub fn take_intercepted(&mut self) -> Vec<InterceptedFrame> {
        std::mem::take(&mut self.intercepted)
    }

    /// Takes all gated TCP SYN frames, leaving the buffer empty.
    pub fn take_gated_syns(&mut self) -> Vec<TcpSynInfo> {
        std::mem::take(&mut self.gated_syns)
    }

    /// Filters fast-path TCP data frames from `rx_queue`.
    ///
    /// For each frame in `rx_queue`, calls `try_intercept` with a reference to
    /// the frame data. If the callback returns `Some(ack_frame)`, the frame is
    /// removed from the queue and the ACK is collected for injection to the guest.
    ///
    /// Frames that are not intercepted (callback returns `None`) remain in the
    /// queue for the handshake drain or eventual drop by `clear_unmatched_rx`.
    pub fn drain_fast_path(
        &mut self,
        mut try_intercept: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let mut ack_frames = Vec::new();

        // Filter in-place: remove intercepted frames via forward iteration.
        // VecDeque::remove(i) is O(n) but fast-path connections are few and
        // most frames pass through unintercepted, so removals are rare.
        let mut i = 0;
        while i < self.rx_queue.len() {
            if let Some(ack) = try_intercept(&self.rx_queue[i]) {
                if !ack.is_empty() {
                    ack_frames.push(ack);
                }
                self.rx_queue.remove(i);
                // Don't increment i — next element shifted into current slot.
            } else {
                i += 1;
            }
        }

        ack_frames
    }

    /// Filters handshake-completion frames from `rx_queue`.
    ///
    /// Parallel to [`drain_fast_path`] but for frames that complete an
    /// in-progress shim handshake (guest ACK → PassiveOpen completion, or
    /// guest SYN-ACK → ActiveOpen completion). The callback returns
    /// `Some(reply_frames)` if consumed (the final ACK for ActiveOpen, or
    /// empty for PassiveOpen); `None` to leave the frame in the queue.
    pub fn drain_handshake(
        &mut self,
        mut try_complete: impl FnMut(&[u8]) -> Option<Vec<Vec<u8>>>,
    ) -> Vec<Vec<u8>> {
        let mut reply_frames = Vec::new();

        let mut i = 0;
        while i < self.rx_queue.len() {
            if let Some(replies) = try_complete(&self.rx_queue[i]) {
                reply_frames.extend(replies);
                self.rx_queue.remove(i);
            } else {
                i += 1;
            }
        }

        reply_frames
    }

    /// Classifies a frame and routes it to the appropriate queue.
    ///
    /// The frame is a raw Ethernet frame borrowed from the ingest source (see
    /// [`FrameSource::drain`](crate::frame_source::FrameSource::drain)). Only
    /// the branches that retain a frame (TCP rx queue, intercepted UDP/ICMP,
    /// gated SYNs) copy it into a pooled [`FrameBuf`]; ARP and dropped frames
    /// never touch the pool. Also learns the guest MAC from the source address.
    pub fn classify_frame(&mut self, frame: &[u8], guest_mac: &mut Option<[u8; 6]>) {
        if frame.len() < ETH_HEADER_LEN {
            return;
        }

        // Learn guest MAC from source address.
        let src_mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
        learn_guest_mac(src_mac, guest_mac);

        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

        match ethertype {
            // ARP → inline responder (replies only for the gateway IP)
            0x0806 => {
                if let Some(reply) = self.arp.handle_arp(frame) {
                    self.pending_arp_replies.push(reply);
                }
            }
            // IPv4 → classify by protocol
            0x0800 => {
                self.classify_ipv4(frame);
            }
            // Everything else → drop
            _ => {
                tracing::debug!(
                    "Dropping frame with EtherType {:#06x}, len={}",
                    ethertype,
                    frame.len()
                );
            }
        }
    }

    /// Classifies an IPv4 frame by L4 protocol.
    fn classify_ipv4(&mut self, frame: &[u8]) {
        let ip_start = ETH_HEADER_LEN;
        if frame.len() < ip_start + 20 {
            return;
        }

        let protocol = frame[ip_start + 9];
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;

        match protocol {
            PROTO_TCP => {
                if l4_start + 14 <= frame.len() {
                    let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
                    let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
                    let flags = frame[l4_start + 13];
                    let dst_ip = Ipv4Addr::new(
                        frame[ip_start + 16],
                        frame[ip_start + 17],
                        frame[ip_start + 18],
                        frame[ip_start + 19],
                    );
                    let src_ip = Ipv4Addr::new(
                        frame[ip_start + 12],
                        frame[ip_start + 13],
                        frame[ip_start + 14],
                        frame[ip_start + 15],
                    );
                    tracing::debug!(
                        "TCP frame: {src_ip}:{src_port} → {dst_ip}:{dst_port} flags={flags:#04x} len={}",
                        frame.len()
                    );
                    // SYN without ACK = new outbound connection attempt — gate it.
                    if flags & 0x02 != 0 && flags & 0x10 == 0 {
                        let syn_seq = u32::from_be_bytes([
                            frame[l4_start + 4],
                            frame[l4_start + 5],
                            frame[l4_start + 6],
                            frame[l4_start + 7],
                        ]);
                        tracing::debug!(
                            "TCP SYN gated: {src_ip}:{src_port} → {dst_ip}:{dst_port} \
                             dst_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} frame_len={}",
                            frame[0],
                            frame[1],
                            frame[2],
                            frame[3],
                            frame[4],
                            frame[5],
                            frame.len(),
                        );
                        // SYN frames are rare (once per connection) — converting to
                        // Vec is negligible. TcpSynInfo.frame stays Vec<u8> because
                        // it's later injected back via inject_rx().
                        self.gated_syns.push(TcpSynInfo {
                            dst_port,
                            src_ip,
                            src_port,
                            dst_ip,
                            syn_seq,
                            frame: frame.to_vec(),
                        });
                        return;
                    }
                }
                // Retained for the fast-path / handshake drains: copy into a
                // pooled buffer the queue can own.
                let buf = FrameBuf::from_pool(&self.pool, frame);
                self.rx_queue.push_back(buf);
            }
            // UDP → check for DHCP/DNS interception
            PROTO_UDP => {
                if l4_start + 8 <= frame.len() {
                    let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
                    let dst_ip = Ipv4Addr::new(
                        frame[ip_start + 16],
                        frame[ip_start + 17],
                        frame[ip_start + 18],
                        frame[ip_start + 19],
                    );

                    let kind = if dst_port == 67 {
                        InterceptedKind::Dhcp
                    } else if dst_port == 53 && dst_ip == self.gateway_ip {
                        InterceptedKind::Dns
                    } else {
                        InterceptedKind::Udp
                    };

                    let buf = FrameBuf::from_pool(&self.pool, frame);
                    self.intercepted.push(InterceptedFrame { frame: buf, kind });
                }
            }
            // ICMP → intercept
            PROTO_ICMP => {
                let buf = FrameBuf::from_pool(&self.pool, frame);
                self.intercepted.push(InterceptedFrame {
                    frame: buf,
                    kind: InterceptedKind::Icmp,
                });
            }
            _ => {
                tracing::debug!("Dropping IPv4 protocol {}", protocol);
            }
        }
    }
}

/// Learns the guest MAC from a frame's source address.
fn learn_guest_mac(mac: [u8; 6], guest_mac: &mut Option<[u8; 6]>) {
    // Skip broadcast/multicast
    if mac[0] & 0x01 != 0 || mac == [0; 6] {
        return;
    }
    if guest_mac.is_none() {
        tracing::info!(
            "Learned guest MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
    }
    *guest_mac = Some(mac);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, RawFd};

    use crate::frame_source::{FdFrameSource, FrameSource};

    fn socketpair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use std::os::fd::OwnedFd;
        let mut fds: [i32; 2] = [0; 2];
        // SAFETY: valid pointer to 2-element array.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair() failed");
        // SAFETY: fds are valid file descriptors from socketpair.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn set_nonblocking(fd: RawFd) {
        // SAFETY: fcntl on a valid fd.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    /// Writes raw bytes to an FD.
    fn fd_write_raw(fd: RawFd, data: &[u8]) {
        // SAFETY: writing from valid buffer to valid fd.
        unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    }

    /// Builds a minimal ARP frame for testing.
    fn make_arp_frame() -> Vec<u8> {
        // Request: "Who has 192.168.64.1? Tell 192.168.64.2"
        let mut frame = vec![0u8; 42];
        let guest_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        // Ethernet: dst=broadcast, src=guest, type=ARP
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&guest_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        // ARP payload
        frame[14..16].copy_from_slice(&1u16.to_be_bytes()); // hw type = Ethernet
        frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // proto = IPv4
        frame[18] = 6; // hlen
        frame[19] = 4; // plen
        frame[20..22].copy_from_slice(&1u16.to_be_bytes()); // opcode = request
        frame[22..28].copy_from_slice(&guest_mac); // sender hw
        frame[28..32].copy_from_slice(&[192, 168, 64, 2]); // sender ip
        frame[32..38].copy_from_slice(&[0; 6]); // target hw (unknown)
        frame[38..42].copy_from_slice(&[192, 168, 64, 1]); // target ip = gateway
        frame
    }

    /// Builds a minimal TCP SYN frame for testing.
    fn make_tcp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 40];
        let guest_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        // Ethernet
        frame[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame[6..12].copy_from_slice(&guest_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header
        let ip = ETH_HEADER_LEN;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
        frame[ip + 9] = PROTO_TCP;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 168, 64, 2]);
        frame[ip + 16..ip + 20].copy_from_slice(&[1, 1, 1, 1]);
        frame
    }

    /// Builds a minimal UDP frame for testing.
    fn make_udp_frame(dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 28];
        let guest_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        frame[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame[6..12].copy_from_slice(&guest_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        let ip = ETH_HEADER_LEN;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&28u16.to_be_bytes());
        frame[ip + 9] = PROTO_UDP;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 168, 64, 2]);
        frame[ip + 16..ip + 20].copy_from_slice(&dst_ip);
        // UDP header
        let l4 = ip + 20;
        frame[l4..l4 + 2].copy_from_slice(&1234u16.to_be_bytes());
        frame[l4 + 2..l4 + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[l4 + 4..l4 + 6].copy_from_slice(&8u16.to_be_bytes());
        frame
    }

    /// Builds a minimal ICMP frame for testing.
    fn make_icmp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 28];
        let guest_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        frame[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame[6..12].copy_from_slice(&guest_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        let ip = ETH_HEADER_LEN;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&28u16.to_be_bytes());
        frame[ip + 9] = PROTO_ICMP;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 168, 64, 2]);
        frame[ip + 16..ip + 20].copy_from_slice(&[8, 8, 8, 8]);
        frame
    }

    #[test]
    fn classify_arp_generates_reply() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        device.set_gateway_mac([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01]);
        let mut guest_mac = None;

        device.classify_frame(&make_arp_frame(), &mut guest_mac);

        assert!(device.rx_queue.is_empty(), "ARP must not queue");
        assert_eq!(
            device.pending_arp_replies.len(),
            1,
            "ArpResponder should have produced a reply"
        );
    }

    #[test]
    fn classify_tcp_goes_to_rx_queue() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        device.classify_frame(&make_tcp_frame(), &mut guest_mac);

        assert_eq!(device.rx_queue.len(), 1);
        assert!(device.intercepted.is_empty());
    }

    #[test]
    fn small_pool_capacity_classifies_and_falls_back_to_heap() {
        // A memory-constrained classifier (e.g. an iOS Network Extension) built
        // with a tiny pool must still classify, and must not drop frames once the
        // pool is exhausted — the pool only bounds burst headroom, not
        // correctness.
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let cap = 4;
        let mut device = FrameClassifier::with_pool_capacity(gateway_ip, DEFAULT_ETHERNET_MTU, cap);
        let mut guest_mac = None;

        // Queue more frames than the pool holds (none are drained, so each holds
        // a buffer); every frame must still land in the rx queue.
        let n = cap + 2;
        for _ in 0..n {
            device.classify_frame(&make_tcp_frame(), &mut guest_mac);
        }
        assert_eq!(
            device.rx_queue.len(),
            n,
            "small pool must not drop frames past capacity (heap fallback)",
        );
    }

    #[test]
    fn classify_dhcp_intercepted() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        device.classify_frame(&make_udp_frame([255, 255, 255, 255], 67), &mut guest_mac);

        assert!(device.rx_queue.is_empty());
        assert_eq!(device.intercepted.len(), 1);
        assert_eq!(device.intercepted[0].kind, InterceptedKind::Dhcp);
    }

    #[test]
    fn classify_dns_to_gateway_intercepted() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        device.classify_frame(&make_udp_frame([192, 168, 64, 1], 53), &mut guest_mac);

        assert!(device.rx_queue.is_empty());
        assert_eq!(device.intercepted.len(), 1);
        assert_eq!(device.intercepted[0].kind, InterceptedKind::Dns);
    }

    #[test]
    fn classify_dns_to_external_is_udp() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        // DNS to 8.8.8.8 is regular UDP, not intercepted as DNS.
        device.classify_frame(&make_udp_frame([8, 8, 8, 8], 53), &mut guest_mac);

        assert!(device.rx_queue.is_empty());
        assert_eq!(device.intercepted.len(), 1);
        assert_eq!(device.intercepted[0].kind, InterceptedKind::Udp);
    }

    #[test]
    fn classify_icmp_intercepted() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        device.classify_frame(&make_icmp_frame(), &mut guest_mac);

        assert!(device.rx_queue.is_empty());
        assert_eq!(device.intercepted.len(), 1);
        assert_eq!(device.intercepted[0].kind, InterceptedKind::Icmp);
    }

    #[test]
    fn classify_regular_udp_intercepted() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        device.classify_frame(&make_udp_frame([1, 1, 1, 1], 443), &mut guest_mac);

        assert!(device.rx_queue.is_empty());
        assert_eq!(device.intercepted.len(), 1);
        assert_eq!(device.intercepted[0].kind, InterceptedKind::Udp);
    }

    #[test]
    fn fd_source_drain_reads_and_classifies() {
        use std::os::fd::AsRawFd;
        let (host_fd, guest_fd) = socketpair();
        set_nonblocking(host_fd.as_raw_fd());

        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        device.set_gateway_mac([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01]);
        let mut source = FdFrameSource::new(host_fd.as_raw_fd());
        let mut guest_mac = None;

        // Write an ARP request and an ICMP frame via the guest side.
        fd_write_raw(guest_fd.as_raw_fd(), &make_arp_frame());
        fd_write_raw(guest_fd.as_raw_fd(), &make_icmp_frame());

        // This is the exact ingest composition the datapath loop performs.
        source.drain(|frame| device.classify_frame(frame, &mut guest_mac));

        assert!(device.rx_queue.is_empty(), "ARP must not queue");
        assert_eq!(
            device.pending_arp_replies.len(),
            1,
            "ARP request should produce a reply"
        );
        assert_eq!(device.intercepted.len(), 1, "ICMP should be intercepted");
        assert!(guest_mac.is_some(), "Guest MAC should be learned");
    }

    #[test]
    fn learn_guest_mac_ignores_broadcast() {
        let mut mac = None;
        learn_guest_mac([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], &mut mac);
        assert!(mac.is_none());
    }

    #[test]
    fn learn_guest_mac_records_unicast() {
        let mut mac = None;
        learn_guest_mac([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE], &mut mac);
        assert_eq!(mac, Some([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));
    }

    #[test]
    fn classify_tcp_syn_is_gated() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        // Build a TCP SYN frame (flags = 0x02).
        let mut frame = make_tcp_frame();
        let ip = ETH_HEADER_LEN;
        let l4 = ip + 20;
        frame[l4 + 13] = 0x02; // SYN flag
        // Set src port = 12345, dst port = 443
        frame[l4..l4 + 2].copy_from_slice(&12345u16.to_be_bytes());
        frame[l4 + 2..l4 + 4].copy_from_slice(&443u16.to_be_bytes());
        // Set seq = 1000
        frame[l4 + 4..l4 + 8].copy_from_slice(&1000u32.to_be_bytes());

        device.classify_frame(&frame, &mut guest_mac);

        assert!(device.rx_queue.is_empty(), "SYN should NOT go to rx_queue");
        assert_eq!(device.gated_syns.len(), 1);
        assert_eq!(device.gated_syns[0].dst_port, 443);
        assert_eq!(device.gated_syns[0].src_port, 12345);
        assert_eq!(device.gated_syns[0].syn_seq, 1000);
        assert_eq!(device.gated_syns[0].dst_ip, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(device.gated_syns[0].src_ip, Ipv4Addr::new(192, 168, 64, 2));
    }

    #[test]
    fn classify_tcp_non_syn_goes_to_rx_queue() {
        let gateway_ip = Ipv4Addr::new(192, 168, 64, 1);
        let mut device = FrameClassifier::new(gateway_ip, DEFAULT_ETHERNET_MTU);
        let mut guest_mac = None;

        // Build a TCP ACK frame (flags = 0x10).
        let mut frame = make_tcp_frame();
        let ip = ETH_HEADER_LEN;
        let l4 = ip + 20;
        frame[l4 + 13] = 0x10; // ACK flag

        device.classify_frame(&frame, &mut guest_mac);

        assert_eq!(
            device.rx_queue.len(),
            1,
            "Non-SYN TCP should go to rx_queue"
        );
        assert!(device.gated_syns.is_empty());
    }
}
