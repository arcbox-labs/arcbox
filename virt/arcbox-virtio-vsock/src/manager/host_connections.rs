use std::os::unix::io::{AsRawFd, RawFd};

use crate::VsockHostConnections;

use super::{
    RxOps, VSOCK_SHUTDOWN_F_BOTH, VSOCK_SHUTDOWN_F_RECEIVE, VSOCK_SHUTDOWN_F_SEND,
    VsockConnectionId, VsockConnectionManager,
};

impl VsockHostConnections for VsockConnectionManager {
    fn fd_for(&self, guest_port: u32, host_port: u32) -> Option<RawFd> {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        self.connections
            .get(&id)
            .filter(|c| c.connect)
            .map(|c| c.internal_fd.as_raw_fd())
    }

    fn mark_connected(&mut self, guest_port: u32, host_port: u32) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.connect = true;
            // The daemon may already have written request data into the
            // socketpair while the handshake was in flight; wake the
            // injection driver so it starts watching this fd now.
            self.ring_doorbell();
            tracing::info!("VsockConnectionManager: connection {:?} now Connected", id,);
        } else {
            tracing::warn!(
                "VsockConnectionManager: mark_connected for unknown connection \
                 guest_port={} host_port={}",
                guest_port,
                host_port,
            );
        }
    }

    fn remove_connection(&mut self, guest_port: u32, host_port: u32) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        self.remove(&id);
    }

    fn update_peer_credit(
        &mut self,
        guest_port: u32,
        host_port: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.update_peer_credit(buf_alloc, fwd_cnt);
        }
    }

    fn advance_fwd_cnt(&mut self, guest_port: u32, host_port: u32, bytes: u32) -> bool {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.advance_fwd_cnt(bytes);
            if conn.rx_queue.pending() {
                self.backend_rxq.push_back(id);
                self.ring_doorbell();
                return true;
            }
        }
        false
    }

    fn enqueue_credit_update(&mut self, guest_port: u32, host_port: u32) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.rx_queue.enqueue(RxOps::CREDIT_UPDATE);
            self.backend_rxq.push_back(id);
            self.ring_doorbell();
        }
    }

    fn handle_shutdown(&mut self, guest_port: u32, host_port: u32, flags: u32) {
        // Both bits set (or flags==0, which is spec-invalid but treated as
        // worst case) → full teardown, matching the default trait impl.
        if flags == 0 || flags & VSOCK_SHUTDOWN_F_BOTH == VSOCK_SHUTDOWN_F_BOTH {
            self.remove_connection(guest_port, host_port);
            return;
        }

        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if flags & VSOCK_SHUTDOWN_F_RECEIVE != 0 {
            if let Some(conn) = self.connections.get_mut(&id) {
                conn.mark_peer_no_recv();
            }
        }
        // `VSOCK_SHUTDOWN_F_SEND`: guest will not send any more data. Propagate
        // the half-close to the daemon-side fd by shutting down the write side
        // of the internal socketpair end — the daemon's `read(fds[0])` then
        // returns EOF. The reverse direction (daemon→guest writes) stays open
        // so the host can drain any in-flight bytes and finish the session.
        //
        // Without this, the daemon-side async fd stream never observes the
        // guest's half-close and `copy_bidirectional` stalls forever. This
        // manifests as `docker run <image>` (foreground attach) hanging after
        // the container exits: dockerd closes its end of attach, the guest
        // agent sends OP_SHUTDOWN F_SEND, but the daemon-side bridge never
        // learns about it and the Docker CLI waits indefinitely for EOF.
        if flags & VSOCK_SHUTDOWN_F_SEND != 0 {
            if let Some(conn) = self.connections.get(&id) {
                let fd = conn.internal_fd.as_raw_fd();
                // SAFETY: `fd` is borrowed from an `OwnedFd` held by the
                // connection map; it remains valid for the duration of this
                // call.
                let r = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
                if r != 0 {
                    let err = std::io::Error::last_os_error();
                    // ENOTCONN / EINVAL are benign — peer already tore down,
                    // or the write side was already shut (repeat F_SEND).
                    // Match the pattern used by the daemon-side shutdown in
                    // `rpc/arcbox-transport/src/vsock/stream.rs`.
                    if !matches!(err.raw_os_error(), Some(libc::ENOTCONN | libc::EINVAL)) {
                        tracing::warn!(
                            guest_port,
                            host_port,
                            "shutdown(internal_fd, SHUT_WR) for F_SEND failed: {}",
                            err,
                        );
                    }
                }
            }
        }
    }
}
