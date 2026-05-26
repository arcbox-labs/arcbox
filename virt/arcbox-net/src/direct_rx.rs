//! Frame sink trait for host-to-guest frame injection.
//!
//! The datapath loop constructs Ethernet frames and sends them through
//! a [`FrameSink`]. The implementation (typically a crossbeam channel)
//! delivers them to the RX injection thread which writes to guest memory.

/// Sends raw Ethernet frames from the producer (datapath loop) to the
/// consumer (RX injection thread).
pub trait FrameSink: Send + Sync {
    /// Sends a frame. Returns `true` if accepted, `false` if full (frame
    /// dropped). The frame is a raw Ethernet frame WITHOUT the 12-byte
    /// virtio-net header (the injection thread adds that).
    fn send(&self, frame: Vec<u8>) -> bool;
}

/// [`FrameSink`] backed by a crossbeam bounded channel.
pub struct ChannelFrameSink {
    tx: crossbeam_channel::Sender<Vec<u8>>,
}

impl ChannelFrameSink {
    /// Creates a new channel-backed frame sink from the sending half.
    pub fn new(tx: crossbeam_channel::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl FrameSink for ChannelFrameSink {
    fn send(&self, frame: Vec<u8>) -> bool {
        self.tx.try_send(frame).is_ok()
    }
}

/// A TCP connection promoted to the inline inject path.
///
/// Carries everything the inject thread needs to construct
/// Ethernet/IP/TCP headers and read from the host socket. This struct
/// lives in `arcbox-net` (which does NOT depend on `arcbox-net-inject`)
/// so that the datapath / tcp_bridge can produce it without a reverse
/// dependency. The VMM layer implements [`ConnSink`] by converting
/// `PromotedConn` into `arcbox_net_inject::InlineConn`.
pub struct PromotedConn {
    /// Host-side TCP stream (non-blocking).
    pub stream: std::net::TcpStream,
    /// Remote IP as seen by the guest.
    pub remote_ip: std::net::Ipv4Addr,
    /// Guest IP.
    pub guest_ip: std::net::Ipv4Addr,
    /// Remote TCP port.
    pub remote_port: u16,
    /// Guest TCP port.
    pub guest_port: u16,
    /// Our SEQ number for frames sent TO guest (shared atomic so both
    /// the inject thread's writes and the fast-path intercept's ACK
    /// frames stay in sync).
    pub our_seq: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Last ACK from guest (shared with the datapath via atomic so the
    /// inject thread and fast-path intercept stay in sync).
    pub last_ack: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Gateway MAC for Ethernet source.
    pub gw_mac: [u8; 6],
    /// Guest MAC for Ethernet destination.
    pub guest_mac: [u8; 6],
}

/// Accepts promoted fast-path connections and delivers them to the RX
/// inject thread. Implemented in the VMM layer as a thin wrapper around
/// a crossbeam channel of `InlineConn`.
pub trait ConnSink: Send + Sync {
    /// Sends a promoted connection. Returns `true` if accepted, `false`
    /// if the channel is full (connection stays on the slow path).
    fn send_conn(&self, conn: PromotedConn) -> bool;
}
