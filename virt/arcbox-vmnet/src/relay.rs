//! Pure L2 relay between a vmnet interface and a socketpair.
//!
//! When the `vmnet` feature is enabled, the bridge NIC uses vmnet.framework
//! directly instead of `VZNATNetworkDeviceAttachment`. This relay bridges
//! the vmnet read/write API with the socketpair fd that the
//! `VZFileHandleNetworkDeviceAttachment` consumes.
//!
//! All DHCP, DNS, and ARP processing is handled by vmnet itself — the relay
//! is a transparent L2 pipe.
//!
//! Two directions:
//! - **vmnet → guest**: event-driven. A `PACKETS_AVAILABLE` callback on the
//!   interface's dispatch queue drains `vmnet_read` to empty and writes each
//!   frame to the socketpair. No polling thread exists; an idle interface
//!   costs zero wakeups.
//! - **guest → vmnet**: async via `AsyncFd` on the socketpair.
//!
//! The callback context ([`ReadCtx`]) is owned by the handler block: the
//! block's copy helper takes an `Arc` reference and its dispose helper
//! releases it, so the context lives exactly as long as the framework's
//! block copy. Nothing frees it manually. The resulting reference cycle
//! (native interface → block → `ReadCtx` → `Arc<Vmnet>`) is broken by
//! `Vmnet::clear_event_callback`, called from both `Vmnet::stop` and this
//! relay's exit path.

use std::ffi::c_void;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use crate::ffi::{_Block_release, create_vmnet_event_block};
use crate::interface::Vmnet;

/// Maximum Ethernet frame size (jumbo frame capable).
const MAX_FRAME_SIZE: usize = 9216;

/// Context for the vmnet → guest event callback.
///
/// Shared with the dispatch queue through the handler block; every field
/// must stay safe to touch from an arbitrary dispatch thread.
struct ReadCtx {
    vmnet: Arc<Vmnet>,
    guest_fd: OwnedFd,
    /// Read buffer. Invocations are serialized on the interface's serial
    /// dispatch queue, so this lock is never contended — it exists to keep
    /// the shared-context mutation boring and safe.
    buf: Mutex<Vec<u8>>,
    /// Set when the socketpair peer is gone; later events return early.
    dead: AtomicBool,
    /// `PACKETS_AVAILABLE` invocations observed.
    events: AtomicU64,
    /// Frames delivered to the guest fd.
    frames: AtomicU64,
    /// Frames dropped on guest backpressure (EAGAIN / ENOBUFS).
    drops: AtomicU64,
}

impl ReadCtx {
    /// Drains all available vmnet packets to the guest socketpair.
    ///
    /// Draining to empty (`Ok(0)` = `VMNET_BUFFER_EXHAUSTED`) makes
    /// correctness independent of whether the framework's event is edge- or
    /// level-triggered: a spurious event costs one empty read.
    fn drain(&self) {
        if self.dead.load(Ordering::Relaxed) {
            return;
        }
        self.events.fetch_add(1, Ordering::Relaxed);
        let mut buf = self.buf.lock().expect("relay read buffer poisoned");
        loop {
            match self.vmnet.read_packet(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !self.forward_frame(&buf[..n]) {
                        self.dead.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Err(e) => {
                    // "interface not running" during stop is expected; any
                    // other error also has no retry path here — the next
                    // event re-enters.
                    tracing::trace!("vmnet read error: {e}");
                    break;
                }
            }
        }
    }

    /// Writes one frame to the guest fd. Returns `false` when the peer is
    /// gone (`EPIPE`), which ends the read path for good.
    fn forward_frame(&self, frame: &[u8]) -> bool {
        let fd = self.guest_fd.as_raw_fd();
        // Retry EINTR (a signal interrupted the write before any bytes were
        // sent); classify everything else.
        loop {
            // SAFETY: write to a valid socketpair fd with a valid buffer.
            let written = unsafe { libc::write(fd, frame.as_ptr().cast::<c_void>(), frame.len()) };
            if written >= 0 {
                self.frames.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::Interrupted => {}
                std::io::ErrorKind::BrokenPipe => return false,
                // WouldBlock (EAGAIN) or ENOBUFS: the guest RX ring is
                // momentarily full — drop this frame; the transport layer
                // retransmits.
                std::io::ErrorKind::WouldBlock => {
                    self.drops.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                _ if err.raw_os_error() == Some(libc::ENOBUFS) => {
                    self.drops.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                _ => {
                    // Unexpected but non-fatal.
                    tracing::debug!("vmnet→guest write error: {err}");
                    return true;
                }
            }
        }
    }
}

/// Event-callback trampoline: `ctx` is the `Arc<ReadCtx>` the block retains.
///
/// # Safety
///
/// Called by the block invoke on the interface's dispatch queue; `ctx` must
/// be an `Arc<ReadCtx>` pointer kept alive by the block's retain/release.
unsafe extern "C" fn on_packets_available(ctx: *const c_void) {
    // SAFETY: the block holds a strong count on this Arc (see retain below),
    // so the pointee is alive for the whole invocation.
    let ctx = unsafe { &*ctx.cast::<ReadCtx>() };
    ctx.drain();
}

/// Block copy helper target: takes one strong count on the context.
///
/// # Safety
///
/// `ctx` must originate from `Arc::as_ptr` on a live `Arc<ReadCtx>`.
unsafe extern "C" fn read_ctx_retain(ctx: *const c_void) {
    // SAFETY: per contract above; increment pairs with read_ctx_release.
    unsafe { Arc::increment_strong_count(ctx.cast::<ReadCtx>()) }
}

/// Block dispose helper target: releases the strong count taken on copy.
///
/// # Safety
///
/// `ctx` must hold a strong count previously taken by `read_ctx_retain`.
unsafe extern "C" fn read_ctx_release(ctx: *const c_void) {
    // SAFETY: per contract above; balances read_ctx_retain exactly once.
    unsafe { Arc::decrement_strong_count(ctx.cast::<ReadCtx>()) }
}

/// Bidirectional L2 relay between vmnet and a socketpair.
pub struct VmnetRelay {
    vmnet: Arc<Vmnet>,
    cancel: CancellationToken,
}

impl VmnetRelay {
    /// Creates a new relay.
    #[must_use]
    pub fn new(vmnet: Arc<Vmnet>, cancel: CancellationToken) -> Self {
        Self { vmnet, cancel }
    }

    /// Runs the relay until cancellation.
    ///
    /// `guest_fd` is one end of a `SOCK_DGRAM` socketpair. The other end is
    /// given to `VZFileHandleNetworkDeviceAttachment`.
    ///
    /// Registers the vmnet → guest event callback, then serves the
    /// guest → vmnet direction until cancelled or the peer closes, and
    /// finally unregisters the callback.
    ///
    /// # Errors
    ///
    /// Returns an error if the fd cannot be prepared, the event callback
    /// cannot be registered, or the `AsyncFd` cannot be created.
    pub async fn run(self, guest_fd: OwnedFd) -> std::io::Result<()> {
        // The fd MUST be non-blocking: `AsyncFd` requires it, and the event
        // handler's writes rely on EAGAIN/ENOBUFS surfacing as errors (guest
        // backpressure → drop) instead of blocking the vmnet dispatch queue.
        // `dup` shares the file status flags, so this covers the handler's
        // cloned fd too.
        let raw_fd = guest_fd.as_raw_fd();
        // SAFETY: fcntl F_GETFL/F_SETFL on a valid, owned fd.
        unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        // Clone the fd for the event handler (vmnet → guest direction).
        // SAFETY: dup is safe on a valid fd.
        let dup_fd = unsafe { libc::dup(raw_fd) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: dup_fd is a valid fd from dup().
        let reader_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_fd) };

        // Constructed before the callback registration on purpose: it is the
        // last fallible step, so once the callback is registered the only
        // exit is the loop below, whose tail always unregisters. An error
        // path between registration and the loop would strand the callback
        // (and the Vmnet it retains) until `Vmnet::stop`.
        let async_fd = AsyncFd::new(guest_fd)?;

        // vmnet → guest: event callback on the interface's dispatch queue.
        let ctx = Arc::new(ReadCtx {
            vmnet: Arc::clone(&self.vmnet),
            guest_fd: reader_fd,
            buf: Mutex::new(vec![0u8; MAX_FRAME_SIZE]),
            dead: AtomicBool::new(false),
            events: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        });
        // SAFETY: the trampolines above uphold the block's contract for an
        // `Arc<ReadCtx>` context; the copy into the heap block retains it.
        let block = unsafe {
            create_vmnet_event_block(
                Arc::as_ptr(&ctx).cast(),
                on_packets_available,
                read_ctx_retain,
                read_ctx_release,
            )
        };
        let registered = self.vmnet.set_event_callback(block);
        // Drop our block reference regardless: on success the framework
        // holds its own; on failure this disposes the block and releases
        // the context's extra count.
        // SAFETY: block is the live heap block created above.
        unsafe { _Block_release(block) };
        registered.map_err(std::io::Error::other)?;

        // guest → vmnet: async
        let vmnet_write = Arc::clone(&self.vmnet);
        let cancel_write = self.cancel.clone();
        let mut buf = vec![0u8; MAX_FRAME_SIZE];
        loop {
            tokio::select! {
                () = cancel_write.cancelled() => break,
                ready = async_fd.ready(Interest::READABLE) => {
                    let mut guard = match ready {
                        Ok(g) => g,
                        Err(e) => {
                            tracing::debug!("AsyncFd ready error: {e}");
                            break;
                        }
                    };

                    // Try to read from the socketpair.
                    let fd = async_fd.as_raw_fd();
                    // SAFETY: read from a valid socketpair fd with valid buffer.
                    let n = unsafe {
                        libc::read(
                            fd,
                            buf.as_mut_ptr().cast::<c_void>(),
                            buf.len(),
                        )
                    };

                    match n.cmp(&0) {
                        std::cmp::Ordering::Greater => {
                            if let Err(e) = vmnet_write.write_packet(&buf[..n as usize]) {
                                tracing::debug!("guest→vmnet write error: {e}");
                            }
                        }
                        std::cmp::Ordering::Equal => break, // Peer closed
                        std::cmp::Ordering::Less => {
                            let err = std::io::Error::last_os_error();
                            match err.kind() {
                                std::io::ErrorKind::WouldBlock => guard.clear_ready(),
                                // A signal interrupted the read before a
                                // frame arrived (EINTR): retry on the next
                                // iteration instead of tearing down the
                                // whole bridge-NIC relay.
                                std::io::ErrorKind::Interrupted => {}
                                _ => {
                                    tracing::debug!("guest→vmnet read error: {err}");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Unregister the read callback (idempotent with Vmnet::stop's own
        // clear). This releases the framework's block reference and with it
        // the ReadCtx, breaking the block → ctx → Arc<Vmnet> cycle.
        self.vmnet.clear_event_callback();
        tracing::debug!(
            events = ctx.events.load(Ordering::Relaxed),
            frames = ctx.frames.load(Ordering::Relaxed),
            drops = ctx.drops.load(Ordering::Relaxed),
            "vmnet relay stopped"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Weak;
    use std::time::{Duration, Instant};

    /// Test context collecting every frame the event callback drains.
    struct TestCtx {
        vmnet: Arc<Vmnet>,
        frames: Mutex<Vec<Vec<u8>>>,
    }

    impl TestCtx {
        fn drain(&self) {
            let mut buf = vec![0u8; MAX_FRAME_SIZE];
            while let Ok(n) = self.vmnet.read_packet(&mut buf) {
                if n == 0 {
                    break;
                }
                self.frames.lock().unwrap().push(buf[..n].to_vec());
            }
        }
    }

    /// # Safety
    /// `ctx` is an `Arc<TestCtx>` pointer kept alive by the block.
    unsafe extern "C" fn test_on_event(ctx: *const std::ffi::c_void) {
        // SAFETY: per the block's retain/release contract below.
        unsafe { &*ctx.cast::<TestCtx>() }.drain();
    }

    /// # Safety
    /// `ctx` must originate from `Arc::as_ptr` on a live `Arc<TestCtx>`.
    unsafe extern "C" fn test_retain(ctx: *const std::ffi::c_void) {
        // SAFETY: per contract above.
        unsafe { Arc::increment_strong_count(ctx.cast::<TestCtx>()) }
    }

    /// # Safety
    /// `ctx` must hold a strong count taken by `test_retain`.
    unsafe extern "C" fn test_release(ctx: *const std::ffi::c_void) {
        // SAFETY: per contract above.
        unsafe { Arc::decrement_strong_count(ctx.cast::<TestCtx>()) }
    }

    /// Builds a minimal DHCP DISCOVER as a raw Ethernet frame.
    fn build_dhcp_discover(mac: [u8; 6]) -> Vec<u8> {
        // BOOTP fixed part (236 bytes) + magic cookie + options.
        let mut bootp = vec![0u8; 236];
        bootp[0] = 1; // op = BOOTREQUEST
        bootp[1] = 1; // htype = Ethernet
        bootp[2] = 6; // hlen
        bootp[4..8].copy_from_slice(&0x2A2A_2A2Au32.to_be_bytes()); // xid
        bootp[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast flag
        bootp[28..34].copy_from_slice(&mac); // chaddr
        bootp.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // DHCP magic
        bootp.extend_from_slice(&[53, 1, 1]); // option: DHCP message type = DISCOVER
        bootp.push(255); // end option

        let udp_len = 8 + bootp.len();
        let ip_len = 20 + udp_len;

        let mut ip = vec![
            0x45, 0, // version/IHL, TOS
        ];
        ip.extend_from_slice(&u16::try_from(ip_len).unwrap().to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]); // id, flags/frag
        ip.extend_from_slice(&[64, 17, 0, 0]); // TTL, UDP, checksum placeholder
        ip.extend_from_slice(&[0, 0, 0, 0]); // src 0.0.0.0
        ip.extend_from_slice(&[255, 255, 255, 255]); // dst broadcast
        let sum = ip_header_checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());

        let mut udp = Vec::new();
        udp.extend_from_slice(&68u16.to_be_bytes()); // src port
        udp.extend_from_slice(&67u16.to_be_bytes()); // dst port
        udp.extend_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum 0 = disabled

        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xFF; 6]); // dst broadcast
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame.extend_from_slice(&bootp);
        frame
    }

    fn ip_header_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in header.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Returns true if `frame` is a UDP datagram from port 67 (a DHCP
    /// server reply — OFFER for our DISCOVER).
    fn is_dhcp_reply(frame: &[u8]) -> bool {
        frame.len() > 36
            && frame[12..14] == [0x08, 0x00]
            && frame[23] == 17
            && u16::from_be_bytes([frame[34], frame[35]]) == 67
    }

    /// Empirical pin of the event-callback semantics the relay depends on:
    /// registration delivers `PACKETS_AVAILABLE` when a packet arrives (a
    /// DHCP OFFER provoked from vmnet's built-in DHCP server), drain-to-empty
    /// collects it, and `clear_event_callback` releases the framework's
    /// block copy so the context is disposed rather than leaked.
    #[test]
    #[ignore = "requires macOS vmnet entitlements and root"]
    fn event_callback_delivers_dhcp_offer() {
        let vmnet = Arc::new(Vmnet::new_shared().expect("failed to create shared vmnet"));

        let ctx = Arc::new(TestCtx {
            vmnet: Arc::clone(&vmnet),
            frames: Mutex::new(Vec::new()),
        });
        let weak: Weak<TestCtx> = Arc::downgrade(&ctx);

        // SAFETY: trampolines uphold the block contract for Arc<TestCtx>.
        let block = unsafe {
            create_vmnet_event_block(
                Arc::as_ptr(&ctx).cast(),
                test_on_event,
                test_retain,
                test_release,
            )
        };
        vmnet
            .set_event_callback(block)
            .expect("event callback registration failed");
        // SAFETY: block is the live heap block created above.
        unsafe { _Block_release(block) };

        // Provoke a reply: vmnet's DHCP server answers a DISCOVER. Resend
        // periodically in case the first lands before the server is ready.
        let discover = build_dhcp_discover(vmnet.mac());
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut offered = false;
        while Instant::now() < deadline {
            vmnet
                .write_packet(&discover)
                .expect("write DISCOVER failed");
            std::thread::sleep(Duration::from_millis(200));
            if ctx.frames.lock().unwrap().iter().any(|f| is_dhcp_reply(f)) {
                offered = true;
                break;
            }
        }
        assert!(
            offered,
            "no DHCP reply delivered via event callback; frames seen: {}",
            ctx.frames.lock().unwrap().len()
        );

        // Unregister and drop our reference: the framework's dispose must
        // release the block-owned strong count, leaving the Weak dead.
        vmnet.clear_event_callback();
        drop(ctx);
        let deadline = Instant::now() + Duration::from_secs(2);
        while weak.upgrade().is_some() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            weak.upgrade().is_none(),
            "TestCtx leaked: block dispose never released the context"
        );

        vmnet.stop();
    }
}
