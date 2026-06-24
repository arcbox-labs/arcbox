//! `VirtioVsock` device — TX/RX queue handling, custom-VMM hot path, `VirtioDevice` impl.

mod rx_injection;
#[cfg(test)]
mod tests;
mod virtio_device;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{DeviceCtx, virtio_bindings};

use crate::addr::{HOST_CID, RESERVED_CID, VsockAddr, VsockHostConnections};
use crate::backend::VsockBackend;
use crate::connection::{ConnectionState, VsockConnection};
use crate::manager::VsockConnectionManager;
use crate::protocol::{VsockHeader, VsockOp};

/// Forwards `buf` to `fd` with partial-write + `EAGAIN` handling.
///
/// A single `libc::write` on a non-blocking socketpair can return short
/// (SO_SNDBUF full) or `EAGAIN` (buffer completely full). The previous
/// implementation dropped the tail in both cases, silently truncating
/// responses larger than the socket buffer (macOS default ~8 KiB). This
/// helper loops until all bytes are written, the peer closes the fd, or
/// the deadline expires. Returns the total number of bytes successfully
/// delivered.
///
/// Runs on the vCPU thread via the BSP's TX handler, so we cap the total
/// poll wait at a few milliseconds per call — enough to let the client
/// drain typical RPC responses, short enough that a slow consumer does
/// not stall the guest indefinitely. If the cap is hit we return a short
/// count; `advance_fwd_cnt` then reflects only what was delivered, and
/// the guest's credit accounting backs off naturally. See ABX-365.
fn write_all_with_backoff(fd: i32, buf: &[u8]) -> usize {
    const MAX_POLL_RETRIES: u32 = 16;
    const POLL_TIMEOUT_MS: libc::c_int = 2; // total worst case: 32 ms

    let mut offset = 0usize;
    let mut eagain_retries = 0u32;

    while offset < buf.len() {
        // SAFETY: fd is a valid connected socket from the manager;
        // `buf[offset..]` is a live slice for the remaining bytes.
        let ret = unsafe {
            libc::write(
                fd,
                buf[offset..].as_ptr().cast::<libc::c_void>(),
                buf.len() - offset,
            )
        };

        use std::cmp::Ordering;
        match ret.cmp(&0) {
            Ordering::Greater => {
                offset += ret as usize;
                eagain_retries = 0;
            }
            Ordering::Equal => {
                // Peer closed. Nothing more we can do.
                break;
            }
            Ordering::Less => {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                        if eagain_retries >= MAX_POLL_RETRIES {
                            tracing::warn!(
                                "Vsock: giving up after {MAX_POLL_RETRIES} EAGAIN retries at offset {offset}/{} on fd {fd}",
                                buf.len(),
                            );
                            break;
                        }
                        eagain_retries += 1;
                        // Wait for POLLOUT so the next write has a chance.
                        let mut pfd = libc::pollfd {
                            fd,
                            events: libc::POLLOUT,
                            revents: 0,
                        };
                        // SAFETY: single pollfd on the stack, count=1.
                        let _ = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
                    }
                    Some(libc::EINTR) => {}
                    _ => {
                        tracing::warn!("Vsock: write to fd {fd} failed at offset {offset}: {err}");
                        break;
                    }
                }
            }
        }
    }

    offset
}

/// Vsock device configuration.
#[derive(Debug, Clone)]
pub struct VsockConfig {
    /// Guest CID (Context Identifier).
    pub guest_cid: u64,
}

impl Default for VsockConfig {
    fn default() -> Self {
        Self {
            guest_cid: 3, // First available guest CID
        }
    }
}

/// `VirtIO` vsock device.
///
/// Enables socket communication between host (CID 2) and guest using
/// virtio transport.
pub struct VirtioVsock {
    config: VsockConfig,
    features: u64,
    acked_features: u64,
    /// Backend for host-side socket handling.
    backend: Option<Arc<Mutex<dyn VsockBackend>>>,
    /// Active connections.
    connections: RwLock<HashMap<(u32, u32), VsockConnection>>,
    /// Queue 0: RX (host -> guest).
    rx_queue: Option<VirtQueue>,
    /// Queue 1: TX (guest -> host).
    tx_queue: Option<VirtQueue>,
    /// Queue 2: Event (control events).
    event_queue: Option<VirtQueue>,
    /// Host-side connection fds keyed by guest port.
    /// Used by the guest-memory `process_queue` path to forward data
    /// between host sockets and guest vsock queues.
    host_connections: HashMap<u32, std::os::unix::io::RawFd>,
    /// Last processed avail index for TX queue (guest-memory path).
    last_avail_idx_tx: usize,
    /// Last processed avail index for RX queue (guest-memory path).
    last_avail_idx_rx: usize,
    /// Guest memory + IRQ context. Bound at registration time on the
    /// HV backend; remains `None` on the VZ backend (which does not use
    /// the custom-VMM `poll_rx_injection` path).
    ctx: Option<DeviceCtx>,
    /// Trait-object view of the host-side connection manager. Used by
    /// `process_queue` (TX path) so tests can supply a mock implementing
    /// `VsockHostConnections` without dragging in the concrete manager.
    conns: Option<Arc<Mutex<dyn VsockHostConnections>>>,
    /// Concrete view of the host-side connection manager. Required by
    /// `poll_rx_injection`, which calls non-trait methods (`backend_rxq`,
    /// `connections_with_pending_rx`, `get`/`get_mut`/`remove`,
    /// `enqueue_rw`/`enqueue_reset`, `peek`/`dequeue`/`pending` on
    /// `RxOps`, etc.). Always set alongside `conns` in production via
    /// `bind_connection_manager`; left `None` in unit-test contexts.
    conn_mgr: Option<Arc<Mutex<VsockConnectionManager>>>,
}

impl VirtioVsock {
    /// Feature: Stream socket.
    pub const FEATURE_STREAM: u64 = 1 << 0;
    /// Feature: Seqpacket socket.
    pub const FEATURE_SEQPACKET: u64 = 1 << 1;
    /// VirtIO version 1 compliance (required for modern MMIO transport).
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// Well-known CID for host.
    pub const HOST_CID: u64 = HOST_CID;
    /// Reserved CID.
    pub const RESERVED_CID: u64 = RESERVED_CID;

    /// Creates a new vsock device.
    #[must_use]
    pub fn new(config: VsockConfig) -> Self {
        Self {
            config,
            features: Self::FEATURE_STREAM
                | Self::FEATURE_VERSION_1
                | arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX,
            acked_features: 0,
            backend: None,
            connections: RwLock::new(HashMap::new()),
            rx_queue: None,
            tx_queue: None,
            event_queue: None,
            host_connections: HashMap::new(),
            last_avail_idx_tx: 0,
            last_avail_idx_rx: 0,
            ctx: None,
            conns: None,
            conn_mgr: None,
        }
    }

    /// Creates a vsock device with a backend.
    #[must_use]
    pub fn with_backend<B: VsockBackend + 'static>(config: VsockConfig, backend: B) -> Self {
        Self {
            config,
            features: Self::FEATURE_STREAM
                | Self::FEATURE_VERSION_1
                | arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX,
            acked_features: 0,
            backend: Some(Arc::new(Mutex::new(backend))),
            connections: RwLock::new(HashMap::new()),
            rx_queue: None,
            tx_queue: None,
            event_queue: None,
            host_connections: HashMap::new(),
            last_avail_idx_tx: 0,
            last_avail_idx_rx: 0,
            ctx: None,
            conns: None,
            conn_mgr: None,
        }
    }

    /// Sets the backend.
    pub fn set_backend<B: VsockBackend + 'static>(&mut self, backend: B) {
        self.backend = Some(Arc::new(Mutex::new(backend)));
    }

    /// Binds the device's `DeviceCtx` (guest memory + IRQ trigger).
    /// Required by the custom-VMM `poll_rx_injection` hot path.
    pub fn bind_ctx(&mut self, ctx: DeviceCtx) {
        self.ctx = Some(ctx);
    }

    /// Binds a trait-object view of the host-side connection manager.
    /// Required by `process_queue(1, ...)` (TX path). Tests set this
    /// directly with a mock; production callers use
    /// `bind_connection_manager` which also sets the concrete view.
    pub fn bind_connections(&mut self, conns: Arc<Mutex<dyn VsockHostConnections>>) {
        self.conns = Some(conns);
    }

    /// Binds the concrete `VsockConnectionManager`. Required by
    /// `poll_rx_injection`, which uses non-trait methods. Stores both
    /// the trait-object view (for `process_queue`) and the concrete
    /// view (for `poll_rx_injection`) — same `Arc`, two lenses.
    pub fn bind_connection_manager(&mut self, mgr: Arc<Mutex<VsockConnectionManager>>) {
        self.conns = Some(mgr.clone());
        self.conn_mgr = Some(mgr);
    }

    /// Returns a clone of the trait-object connection manager Arc.
    pub fn connections(&self) -> Option<Arc<Mutex<dyn VsockHostConnections>>> {
        self.conns.clone()
    }

    /// Returns the guest CID.
    #[must_use]
    pub const fn guest_cid(&self) -> u64 {
        self.config.guest_cid
    }

    /// Handles a connection request from guest.
    pub fn handle_connect(&self, src_port: u32, dst_port: u32) -> Result<()> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);
        let remote = VsockAddr::new(Self::HOST_CID, dst_port);

        let mut conn = VsockConnection::new(local, remote);
        conn.state = ConnectionState::Connecting;

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_connect(local)?;
            conn.state = ConnectionState::Connected;
        }

        self.connections
            .write()
            .unwrap()
            .insert((src_port, dst_port), conn);
        tracing::debug!(
            "Vsock connect: {}:{} -> {}:{}",
            self.config.guest_cid,
            src_port,
            Self::HOST_CID,
            dst_port
        );

        Ok(())
    }

    /// Handles data from guest.
    pub fn handle_send(&self, src_port: u32, dst_port: u32, data: &[u8]) -> Result<usize> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_send(local, data)
        } else {
            let mut conns = self.connections.write().unwrap();
            if let Some(conn) = conns.get_mut(&(src_port, dst_port)) {
                conn.enqueue_tx(data);
                Ok(data.len())
            } else {
                Err(VirtioError::InvalidOperation("Connection not found".into()))
            }
        }
    }

    /// Handles receive request from guest.
    pub fn handle_recv(&self, src_port: u32, dst_port: u32, buf: &mut [u8]) -> Result<usize> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_recv(local, buf)
        } else {
            let mut conns = self.connections.write().unwrap();
            if let Some(conn) = conns.get_mut(&(src_port, dst_port)) {
                let data = conn.dequeue_rx(buf.len());
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            } else {
                Err(VirtioError::InvalidOperation("Connection not found".into()))
            }
        }
    }

    /// Handles connection close from guest.
    pub fn handle_close(&self, src_port: u32, dst_port: u32) -> Result<()> {
        let local = VsockAddr::new(self.config.guest_cid, src_port);

        if let Some(ref backend) = self.backend {
            backend.lock().unwrap().on_close(local)?;
        }

        self.connections
            .write()
            .unwrap()
            .remove(&(src_port, dst_port));
        tracing::debug!("Vsock close: {}:{}", self.config.guest_cid, src_port);

        Ok(())
    }

    /// Returns the number of active connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    /// Returns a mutable reference to the TX queue.
    pub fn tx_queue_mut(&mut self) -> Option<&mut VirtQueue> {
        self.tx_queue.as_mut()
    }

    /// Returns a mutable reference to the RX queue.
    pub fn rx_queue_mut(&mut self) -> Option<&mut VirtQueue> {
        self.rx_queue.as_mut()
    }

    /// Handles a TX packet from the guest, forwarding data to host fds.
    fn handle_tx_packet_with_fds(
        &self,
        hdr: &VsockHeader,
        payload: &[u8],
        connections: Option<&mut dyn VsockHostConnections>,
    ) {
        // Copy packed fields to locals to avoid unaligned reference UB.
        let src_cid = { hdr.src_cid };
        let dst_cid = { hdr.dst_cid };
        let src_port = { hdr.src_port };
        let dst_port = { hdr.dst_port };
        let buf_alloc = { hdr.buf_alloc };
        let fwd_cnt = { hdr.fwd_cnt };
        let flags = { hdr.flags };

        match hdr.operation() {
            Some(VsockOp::Request) => {
                tracing::debug!(
                    "Vsock TX: OP_REQUEST src={}:{} dst={}:{}",
                    src_cid,
                    src_port,
                    dst_cid,
                    dst_port,
                );
            }
            Some(VsockOp::Response) => {
                // Guest accepted a host-initiated connection.
                // src_port = guest port, dst_port = host ephemeral port.
                tracing::info!(
                    "Vsock TX: OP_RESPONSE — connection established (guest_port={}, host_port={})",
                    src_port,
                    dst_port,
                );
                if let Some(conns) = connections {
                    conns.update_peer_credit(src_port, dst_port, buf_alloc, fwd_cnt);
                    conns.mark_connected(src_port, dst_port);
                }
            }
            Some(VsockOp::Rw) => {
                // Guest sends data. src_port = guest port, dst_port = host port.
                if let Some(conns) = connections {
                    conns.update_peer_credit(src_port, dst_port, buf_alloc, fwd_cnt);
                    if let Some(fd) = conns.fd_for(src_port, dst_port) {
                        if !payload.is_empty() {
                            let total = payload.len();
                            let forwarded = write_all_with_backoff(fd, payload);
                            if forwarded > 0 {
                                tracing::debug!(
                                    "Vsock TX: OP_RW guest_port={} host_port={} -> fd {fd}, {}/{} bytes",
                                    src_port,
                                    dst_port,
                                    forwarded,
                                    total,
                                );
                                // Advance fwd_cnt by the byte count we actually
                                // delivered to the host socket. If the write
                                // loop gave up due to sustained EAGAIN or a
                                // hard error, `forwarded` will be < total and
                                // guest credit accounting will reflect that
                                // (fewer acks → guest backs off).
                                #[allow(clippy::cast_possible_truncation)]
                                {
                                    conns.advance_fwd_cnt(src_port, dst_port, forwarded as u32);
                                }
                            }
                            if forwarded < total {
                                tracing::warn!(
                                    "Vsock TX: truncated write guest_port={} host_port={}: only {}/{} bytes forwarded (ABX-365)",
                                    src_port,
                                    dst_port,
                                    forwarded,
                                    total,
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Vsock TX: OP_RW no host fd for guest_port={} host_port={}",
                            src_port,
                            dst_port,
                        );
                    }
                }
            }
            Some(VsockOp::Shutdown) => {
                tracing::debug!(
                    "Vsock TX: OP_SHUTDOWN guest_port={} host_port={} flags=0x{:x}",
                    src_port,
                    dst_port,
                    flags,
                );
                if let Some(conns) = connections {
                    // Dispatch on the shutdown flags — a half-close (only
                    // F_RECEIVE or only F_SEND) should preserve the fd so
                    // either side can still drain in-flight data.
                    conns.handle_shutdown(src_port, dst_port, flags);
                }
            }
            Some(VsockOp::Rst) => {
                tracing::debug!(
                    "Vsock TX: OP_RST guest_port={} host_port={}",
                    src_port,
                    dst_port,
                );
                if let Some(conns) = connections {
                    conns.remove_connection(src_port, dst_port);
                }
            }
            Some(VsockOp::CreditUpdate) => {
                tracing::trace!(
                    "Vsock TX: OP_CREDIT_UPDATE guest_port={} host_port={} buf_alloc={} fwd_cnt={}",
                    src_port,
                    dst_port,
                    buf_alloc,
                    fwd_cnt,
                );
                if let Some(conns) = connections {
                    conns.update_peer_credit(src_port, dst_port, buf_alloc, fwd_cnt);
                }
            }
            Some(VsockOp::CreditRequest) => {
                tracing::trace!(
                    "Vsock TX: OP_CREDIT_REQUEST guest_port={} host_port={}",
                    src_port,
                    dst_port,
                );
                if let Some(conns) = connections {
                    conns.update_peer_credit(src_port, dst_port, buf_alloc, fwd_cnt);
                    conns.enqueue_credit_update(src_port, dst_port);
                }
            }
            _ => {}
        }
    }

    /// Registers a host-side fd for a guest vsock port.
    /// When the guest sends data to this port, it will be written to the fd.
    /// When the fd has data, it will be injected into the guest RX queue.
    pub fn add_host_connection(&mut self, guest_port: u32, fd: std::os::unix::io::RawFd) {
        tracing::info!("Vsock: host connection for guest port {guest_port} -> fd {fd}");
        self.host_connections.insert(guest_port, fd);
    }

    /// Process pending TX queue packets from guest.
    ///
    /// Pops available descriptors from the TX virtqueue, parses vsock headers,
    /// and dispatches each packet based on its operation code. Returns a list
    /// of completed descriptor heads and their written lengths, suitable for
    /// `push_used_batch()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TX queue is not ready or packet processing fails.
    pub fn process_tx_queue(&mut self, memory: &mut [u8]) -> Result<Vec<(u16, u32)>> {
        // Phase 1: Collect raw descriptor data from the TX queue.
        let mut raw_packets: Vec<(u16, Vec<u8>)> = Vec::new();

        {
            let queue = self
                .tx_queue
                .as_mut()
                .ok_or_else(|| VirtioError::NotReady("TX queue not ready".into()))?;

            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut data = Vec::new();

                for desc in chain {
                    if !desc.is_write_only() {
                        // Read-only buffers contain the guest-produced packet.
                        let start = desc.addr as usize;
                        let end = start + desc.len as usize;
                        if end <= memory.len() {
                            data.extend_from_slice(&memory[start..end]);
                        }
                    }
                }

                raw_packets.push((head_idx, data));
            }
        }

        // Phase 2: Parse and dispatch each packet.
        let mut completions = Vec::new();
        // Collect RX packets to inject after releasing the connections lock.
        let mut rx_inject: Vec<(VsockHeader, Vec<u8>)> = Vec::new();

        for (head_idx, data) in &raw_packets {
            if data.len() < VsockHeader::SIZE {
                tracing::warn!(
                    "Vsock TX: descriptor {} too short ({} bytes), skipping",
                    head_idx,
                    data.len()
                );
                completions.push((*head_idx, 0u32));
                continue;
            }

            let header = match VsockHeader::from_bytes(&data[..VsockHeader::SIZE]) {
                Some(h) => h,
                None => {
                    tracing::warn!(
                        "Vsock TX: failed to parse header for descriptor {}",
                        head_idx
                    );
                    completions.push((*head_idx, 0u32));
                    continue;
                }
            };

            let payload_len = { header.len } as usize;
            let payload = if payload_len > 0 && data.len() > VsockHeader::SIZE {
                let avail = data.len() - VsockHeader::SIZE;
                &data[VsockHeader::SIZE..VsockHeader::SIZE + payload_len.min(avail)]
            } else {
                &[] as &[u8]
            };

            let src_port = { header.src_port };
            let dst_port = { header.dst_port };

            match header.operation() {
                Some(VsockOp::Request) => {
                    tracing::debug!(
                        "Vsock TX: OP_REQUEST from port {} to port {}",
                        src_port,
                        dst_port
                    );
                    match self.handle_connect(src_port, dst_port) {
                        Ok(()) => {
                            // Build a RESPONSE header to inject into the RX queue.
                            let resp = VsockHeader::new(
                                VsockAddr::new(Self::HOST_CID, dst_port),
                                VsockAddr::new(self.config.guest_cid, src_port),
                                VsockOp::Response,
                            );
                            rx_inject.push((resp, Vec::new()));
                        }
                        Err(e) => {
                            tracing::warn!("Vsock TX: connect failed: {}", e);
                            // Send RST back to the guest.
                            let rst = VsockHeader::new(
                                VsockAddr::new(Self::HOST_CID, dst_port),
                                VsockAddr::new(self.config.guest_cid, src_port),
                                VsockOp::Rst,
                            );
                            rx_inject.push((rst, Vec::new()));
                        }
                    }
                }
                Some(VsockOp::Response) => {
                    // Guest acknowledging a host-initiated connection.
                    tracing::debug!(
                        "Vsock TX: OP_RESPONSE from port {} to port {}",
                        src_port,
                        dst_port
                    );
                    let mut conns = self.connections.write().unwrap();
                    if let Some(conn) = conns.get_mut(&(src_port, dst_port)) {
                        conn.state = ConnectionState::Connected;
                    }
                }
                Some(VsockOp::Rw) => {
                    tracing::trace!(
                        "Vsock TX: OP_RW {} bytes from port {} to port {}",
                        payload.len(),
                        src_port,
                        dst_port
                    );
                    if let Err(e) = self.handle_send(src_port, dst_port, payload) {
                        tracing::warn!("Vsock TX: send failed: {}", e);
                    }
                }
                Some(VsockOp::Shutdown) => {
                    tracing::debug!(
                        "Vsock TX: OP_SHUTDOWN from port {} to port {}",
                        src_port,
                        dst_port
                    );
                    if let Err(e) = self.handle_close(src_port, dst_port) {
                        tracing::warn!("Vsock TX: close failed: {}", e);
                    }
                    // Confirm with RST.
                    let rst = VsockHeader::new(
                        VsockAddr::new(Self::HOST_CID, dst_port),
                        VsockAddr::new(self.config.guest_cid, src_port),
                        VsockOp::Rst,
                    );
                    rx_inject.push((rst, Vec::new()));
                }
                Some(VsockOp::Rst) => {
                    tracing::debug!(
                        "Vsock TX: OP_RST from port {} to port {}",
                        src_port,
                        dst_port
                    );
                    let _ = self.handle_close(src_port, dst_port);
                }
                Some(VsockOp::CreditUpdate) => {
                    let buf_alloc = { header.buf_alloc };
                    let fwd_cnt = { header.fwd_cnt };
                    tracing::trace!(
                        "Vsock TX: OP_CREDIT_UPDATE port {} buf_alloc={} fwd_cnt={}",
                        src_port,
                        buf_alloc,
                        fwd_cnt
                    );
                    let mut conns = self.connections.write().unwrap();
                    if let Some(conn) = conns.get_mut(&(src_port, dst_port)) {
                        conn.update_peer_credit(buf_alloc, fwd_cnt);
                    }
                }
                Some(VsockOp::CreditRequest) => {
                    tracing::trace!(
                        "Vsock TX: OP_CREDIT_REQUEST from port {} to port {}",
                        src_port,
                        dst_port
                    );
                    // Respond with our credit state.
                    let conns = self.connections.read().unwrap();
                    if let Some(conn) = conns.get(&(src_port, dst_port)) {
                        let mut update = VsockHeader::new(
                            VsockAddr::new(Self::HOST_CID, dst_port),
                            VsockAddr::new(self.config.guest_cid, src_port),
                            VsockOp::CreditUpdate,
                        );
                        update.buf_alloc = conn.buf_alloc;
                        update.fwd_cnt = conn.fwd_cnt;
                        rx_inject.push((update, Vec::new()));
                    }
                }
                Some(VsockOp::Invalid) | None => {
                    let raw_op = { header.op };
                    tracing::warn!(
                        "Vsock TX: unknown/invalid op {} from port {}",
                        raw_op,
                        src_port
                    );
                }
            }

            completions.push((*head_idx, data.len() as u32));
        }

        // Phase 3: Inject any pending RX response packets.
        for (hdr, payload) in rx_inject {
            if let Err(e) = self.inject_rx_packet(&hdr, &payload, memory) {
                tracing::warn!("Vsock: failed to inject RX packet: {}", e);
            }
        }

        Ok(completions)
    }

    /// Process a specific virtqueue by index.
    ///
    /// Queue indices follow the VirtIO vsock specification:
    /// - 0: RX (host -> guest) — processed externally via `inject_rx_packet`
    /// - 1: TX (guest -> host) — dispatched here
    /// - 2: Event queue       — not yet implemented
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_queue(&mut self, queue_idx: u16, memory: &mut [u8]) -> Result<Vec<(u16, u32)>> {
        match queue_idx {
            1 => self.process_tx_queue(memory),
            _ => Ok(Vec::new()),
        }
    }

    /// Injects a response packet into the guest RX queue.
    ///
    /// Pops an available descriptor from the RX queue, writes the vsock header
    /// and optional payload into guest memory via the descriptor chain, then
    /// marks it as used. The MMIO/interrupt handler is responsible for
    /// signalling the guest after this call.
    ///
    /// # Errors
    ///
    /// Returns an error if the RX queue is not ready or no descriptors are
    /// available.
    pub fn inject_rx_packet(
        &mut self,
        header: &VsockHeader,
        data: &[u8],
        memory: &mut [u8],
    ) -> Result<()> {
        let queue = self
            .rx_queue
            .as_mut()
            .ok_or_else(|| VirtioError::NotReady("RX queue not ready".into()))?;

        let (head_idx, chain) = queue
            .pop_avail()
            .ok_or_else(|| VirtioError::InvalidQueue("No available RX descriptors".into()))?;

        let header_bytes = header.to_bytes();
        let total_len = header_bytes.len() + data.len();
        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(data);

        let mut written = 0usize;
        for desc in chain {
            if !desc.is_write_only() {
                continue;
            }
            let start = desc.addr as usize;
            let remaining = frame.len().saturating_sub(written);
            let to_write = remaining.min(desc.len as usize);
            if to_write == 0 {
                continue;
            }
            let end = start + to_write;
            if end > memory.len() {
                return Err(VirtioError::MemoryError(
                    "RX descriptor points outside guest memory".into(),
                ));
            }
            memory[start..end].copy_from_slice(&frame[written..written + to_write]);
            written += to_write;
        }

        queue.push_used(head_idx, written as u32);
        Ok(())
    }
}
