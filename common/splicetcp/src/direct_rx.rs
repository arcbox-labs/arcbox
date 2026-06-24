//! Frame sink trait for host-to-guest frame injection.
//!
//! The datapath loop constructs Ethernet frames and sends them through
//! a [`FrameSink`]. The implementation (typically a crossbeam channel)
//! delivers them to the RX injection thread which writes to guest memory.

#[cfg(feature = "tokio-frame-sink")]
use std::sync::Arc;
#[cfg(feature = "tokio-frame-sink")]
use std::sync::atomic::Ordering;

#[cfg(feature = "tokio-frame-sink")]
use arcbox_packet::ethernet::{
    ETH_HEADER_LEN, TcpFrameParams, build_tcp_data_frame, build_tcp_fin_frame,
};
#[cfg(feature = "tokio-frame-sink")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "tokio-frame-sink")]
use tokio::sync::mpsc;

#[cfg(feature = "tokio-frame-sink")]
const UNIX_DGRAM_MAX_FRAME_LEN: usize = 2048;
#[cfg(feature = "tokio-frame-sink")]
const TCP_IPV4_ETH_OVERHEAD: usize = ETH_HEADER_LEN + 20 + 20;
#[cfg(feature = "tokio-frame-sink")]
const FAST_PATH_GUEST_MSS: usize = UNIX_DGRAM_MAX_FRAME_LEN - TCP_IPV4_ETH_OVERHEAD;

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
    /// Host→guest byte counter, present only when a flow observer is installed —
    /// `None` ⇒ no accounting and no per-connection allocation. The inline inject
    /// path reads the host socket outside the bridge's `poll_fast_path`, so this
    /// shared counter is how the bridge learns inline downstream totals at teardown.
    pub down_bytes: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
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

/// A [`ConnSink`] that turns promoted connections into Tokio-read tasks and
/// emits guest-bound Ethernet frames through a bounded channel.
///
/// This is the event-driven counterpart to `TcpBridge::poll_fast_path`: host-side
/// socket readability wakes the task, the task builds the same TCP data/FIN
/// frames the bridge would have built synchronously, and backpressure on the
/// channel pauses socket reads instead of growing memory without bound.
///
/// `send_conn` must be called from within a Tokio runtime because accepted
/// connections are driven by spawned read tasks. The emitted frames mirror the
/// configured guest MTU: by default it preserves the historical socketpair-safe
/// segmentation, and callers with a high-MTU link can use
/// [`channel_with_mtu`](Self::channel_with_mtu).
#[cfg(feature = "tokio-frame-sink")]
pub struct TokioFrameConnSink {
    tx: mpsc::Sender<Vec<u8>>,
    guest_mss: usize,
}

#[cfg(feature = "tokio-frame-sink")]
impl TokioFrameConnSink {
    /// Creates a sink from the sending half of a bounded frame channel.
    #[must_use]
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            guest_mss: FAST_PATH_GUEST_MSS,
        }
    }

    /// Creates a sink from the sending half of a bounded frame channel, segmenting
    /// host→guest data so each emitted IPv4 packet fits within `mtu` bytes.
    #[must_use]
    pub fn new_with_mtu(tx: mpsc::Sender<Vec<u8>>, mtu: usize) -> Self {
        Self {
            tx,
            guest_mss: guest_mss_for_mtu(mtu),
        }
    }

    /// Convenience constructor returning an `Arc<dyn ConnSink>` plus the receiving
    /// half that a datapath loop can await and write to its guest-facing sink.
    #[must_use]
    pub fn channel(capacity: usize) -> (Arc<dyn ConnSink>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Arc::new(Self::new(tx)), rx)
    }

    /// Convenience constructor equivalent to [`channel`](Self::channel), but with
    /// host→guest segmentation sized for a configured L3 MTU.
    #[must_use]
    pub fn channel_with_mtu(
        capacity: usize,
        mtu: usize,
    ) -> (Arc<dyn ConnSink>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Arc::new(Self::new_with_mtu(tx, mtu)), rx)
    }
}

#[cfg(feature = "tokio-frame-sink")]
impl ConnSink for TokioFrameConnSink {
    fn send_conn(&self, conn: PromotedConn) -> bool {
        let PromotedConn {
            stream,
            remote_ip,
            guest_ip,
            remote_port,
            guest_port,
            our_seq,
            last_ack,
            down_bytes,
            gw_mac,
            guest_mac,
        } = conn;
        let Ok(stream) = tokio::net::TcpStream::from_std(stream) else {
            return false;
        };
        let conn = AsyncPromotedConn {
            remote_ip,
            guest_ip,
            remote_port,
            guest_port,
            our_seq,
            last_ack,
            down_bytes,
            gw_mac,
            guest_mac,
            guest_mss: self.guest_mss,
        };
        tokio::spawn(read_promoted_conn(stream, conn, self.tx.clone()));
        true
    }
}

#[cfg(feature = "tokio-frame-sink")]
struct AsyncPromotedConn {
    remote_ip: std::net::Ipv4Addr,
    guest_ip: std::net::Ipv4Addr,
    remote_port: u16,
    guest_port: u16,
    our_seq: Arc<std::sync::atomic::AtomicU32>,
    last_ack: Arc<std::sync::atomic::AtomicU32>,
    down_bytes: Option<Arc<std::sync::atomic::AtomicU64>>,
    gw_mac: [u8; 6],
    guest_mac: [u8; 6],
    guest_mss: usize,
}

#[cfg(feature = "tokio-frame-sink")]
fn guest_mss_for_mtu(mtu: usize) -> usize {
    mtu.saturating_sub(20 + 20)
        .clamp(1, u16::MAX as usize - 20 - 20)
}

#[cfg(feature = "tokio-frame-sink")]
async fn read_promoted_conn(
    mut stream: tokio::net::TcpStream,
    conn: AsyncPromotedConn,
    frames: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                let seq_now = conn.our_seq.load(Ordering::Relaxed);
                let fin = build_tcp_fin_frame(&TcpFrameParams {
                    src_ip: conn.remote_ip,
                    dst_ip: conn.guest_ip,
                    src_port: conn.remote_port,
                    dst_port: conn.guest_port,
                    seq: seq_now,
                    ack: conn.last_ack.load(Ordering::Relaxed),
                    window: 65535,
                    src_mac: conn.gw_mac,
                    dst_mac: conn.guest_mac,
                });
                conn.our_seq.fetch_add(1, Ordering::Relaxed);
                let _ = frames.send(fin).await;
                return;
            }
            Ok(n) => {
                if let Some(c) = &conn.down_bytes {
                    c.fetch_add(n as u64, Ordering::Relaxed);
                }
                let data = &buf[..n];
                let mut offset = 0;
                while offset < data.len() {
                    let chunk_end = (offset + conn.guest_mss).min(data.len());
                    let chunk = &data[offset..chunk_end];
                    let seq_now = conn.our_seq.load(Ordering::Relaxed);
                    let frame = build_tcp_data_frame(
                        &TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: seq_now,
                            ack: conn.last_ack.load(Ordering::Relaxed),
                            window: 65535,
                            src_mac: conn.gw_mac,
                            dst_mac: conn.guest_mac,
                        },
                        chunk,
                    );
                    conn.our_seq
                        .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                    if frames.send(frame).await.is_err() {
                        return;
                    }
                    offset = chunk_end;
                }
            }
            Err(_) => return,
        }
    }
}

#[cfg(all(test, feature = "tokio-frame-sink"))]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, AtomicU64};

    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn tokio_frame_conn_sink_emits_data_frame_on_socket_readiness() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut upstream, accepted) = tokio::join!(async { client }, async {
            listener.accept().await.unwrap().0
        },);

        let (sink, mut rx) = TokioFrameConnSink::channel(4);
        let our_seq = Arc::new(AtomicU32::new(1000));
        let last_ack = Arc::new(AtomicU32::new(2000));
        let down = Arc::new(AtomicU64::new(0));
        let std_stream = accepted.into_std().unwrap();
        let accepted_conn = PromotedConn {
            stream: std_stream,
            remote_ip: std::net::Ipv4Addr::new(203, 0, 113, 10),
            guest_ip: std::net::Ipv4Addr::new(192, 168, 64, 2),
            remote_port: 443,
            guest_port: 50000,
            our_seq: our_seq.clone(),
            last_ack,
            down_bytes: Some(down.clone()),
            gw_mac: [0x02, 0, 0, 0, 0, 1],
            guest_mac: [0x02, 0, 0, 0, 0, 2],
        };
        assert!(sink.send_conn(accepted_conn));

        upstream.write_all(b"pong").await.unwrap();
        let frame = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("frame should be emitted by socket readiness")
            .expect("frame channel should stay open");

        assert_eq!(our_seq.load(Ordering::Relaxed), 1004);
        assert_eq!(
            down.load(Ordering::Relaxed),
            4,
            "inline downstream bytes counted into the shared counter"
        );
        let ip = ETH_HEADER_LEN;
        let tcp = ip + 20;
        assert_eq!(&frame[ip + 12..ip + 16], &[203, 0, 113, 10]);
        assert_eq!(&frame[ip + 16..ip + 20], &[192, 168, 64, 2]);
        assert_eq!(u16::from_be_bytes([frame[tcp], frame[tcp + 1]]), 443);
        assert_eq!(u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]), 50000);
        assert_eq!(&frame[tcp + 20..tcp + 24], b"pong");
    }

    #[tokio::test]
    async fn tokio_frame_conn_sink_segments_to_configured_mtu() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut upstream, accepted) = tokio::join!(async { client }, async {
            listener.accept().await.unwrap().0
        },);

        let (sink, mut rx) = TokioFrameConnSink::channel_with_mtu(4, 4000);
        let our_seq = Arc::new(AtomicU32::new(1000));
        let accepted_conn = PromotedConn {
            stream: accepted.into_std().unwrap(),
            remote_ip: std::net::Ipv4Addr::new(203, 0, 113, 10),
            guest_ip: std::net::Ipv4Addr::new(192, 168, 64, 2),
            remote_port: 443,
            guest_port: 50000,
            our_seq: our_seq.clone(),
            last_ack: Arc::new(AtomicU32::new(2000)),
            down_bytes: None,
            gw_mac: [0x02, 0, 0, 0, 0, 1],
            guest_mac: [0x02, 0, 0, 0, 0, 2],
        };
        assert!(sink.send_conn(accepted_conn));

        let payload = vec![0xAB; 5000];
        upstream.write_all(&payload).await.unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("first frame should be emitted")
            .expect("frame channel should stay open");
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("second frame should be emitted")
            .expect("frame channel should stay open");

        let first_ip_len =
            u16::from_be_bytes([first[ETH_HEADER_LEN + 2], first[ETH_HEADER_LEN + 3]]);
        let second_ip_len =
            u16::from_be_bytes([second[ETH_HEADER_LEN + 2], second[ETH_HEADER_LEN + 3]]);
        assert_eq!(first_ip_len, 4000);
        assert_eq!(second_ip_len, 1080);
        assert_eq!(our_seq.load(Ordering::Relaxed), 6000);
    }
}
