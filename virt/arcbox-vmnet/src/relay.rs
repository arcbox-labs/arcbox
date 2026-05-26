//! Pure L2 relay between a vmnet interface and a socketpair.
//!
//! When the `vmnet` feature is enabled, the bridge NIC uses vmnet.framework
//! directly instead of `VZNATNetworkDeviceAttachment`. This relay bridges
//! the vmnet read/write API (blocking) with the socketpair fd that the
//! `VZFileHandleNetworkDeviceAttachment` consumes.
//!
//! All DHCP, DNS, and ARP processing is handled by vmnet itself — the relay
//! is a transparent L2 pipe.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use crate::interface::Vmnet;

/// Maximum Ethernet frame size (jumbo frame capable).
const MAX_FRAME_SIZE: usize = 9216;

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
    /// Two directions:
    /// - **vmnet → guest**: dedicated blocking thread (vmnet read is blocking)
    /// - **guest → vmnet**: async via `AsyncFd` on the socketpair
    ///
    /// # Errors
    ///
    /// Returns an error if the `AsyncFd` cannot be created.
    pub async fn run(self, guest_fd: OwnedFd) -> std::io::Result<()> {
        // Clone the fd for the blocking thread (vmnet → guest direction).
        // SAFETY: dup is safe on a valid fd.
        let raw_fd = guest_fd.as_raw_fd();
        let dup_fd = unsafe { libc::dup(raw_fd) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: dup_fd is a valid fd from dup().
        let reader_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_fd) };

        let async_fd = AsyncFd::new(guest_fd)?;

        // vmnet → guest: blocking thread
        let vmnet_read = Arc::clone(&self.vmnet);
        let cancel_read = self.cancel.clone();
        let mut vmnet_to_guest = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; MAX_FRAME_SIZE];
            loop {
                if cancel_read.is_cancelled() {
                    break;
                }
                match vmnet_read.read_packet(&mut buf) {
                    Ok(0) => {
                        // No data available, brief yield.
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(n) => {
                        let fd = reader_fd.as_raw_fd();
                        // SAFETY: write to a valid socketpair fd with valid buffer.
                        let written =
                            unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), n) };
                        if written < 0 {
                            let err = std::io::Error::last_os_error();
                            match err.kind() {
                                std::io::ErrorKind::BrokenPipe => break,
                                // Non-blocking fd: backpressure from guest.
                                // Drop the packet and continue — the guest
                                // will retransmit at the transport layer.
                                std::io::ErrorKind::WouldBlock => {}
                                _ => tracing::debug!("vmnet→guest write error: {err}"),
                            }
                        }
                    }
                    Err(e) => {
                        if cancel_read.is_cancelled() {
                            break;
                        }
                        tracing::debug!("vmnet read error: {e}");
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }
        });

        // guest → vmnet: async
        let vmnet_write = Arc::clone(&self.vmnet);
        let cancel_write = self.cancel.clone();
        let guest_to_vmnet = async move {
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
                                buf.as_mut_ptr().cast::<libc::c_void>(),
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
                                if err.kind() == std::io::ErrorKind::WouldBlock {
                                    guard.clear_ready();
                                } else {
                                    tracing::debug!("guest→vmnet read error: {err}");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        };

        tokio::select! {
            () = self.cancel.cancelled() => {}
            _ = &mut vmnet_to_guest => {}
            () = guest_to_vmnet => {}
        }

        // Ensure the blocking thread exits regardless of which branch won.
        self.cancel.cancel();
        if let Err(e) = vmnet_to_guest.await {
            if e.is_panic() {
                tracing::error!("vmnet→guest blocking task panicked: {e}");
            } else {
                tracing::debug!("vmnet→guest blocking task join error: {e}");
            }
        }

        Ok(())
    }
}
