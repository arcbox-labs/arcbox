//! `VirtioVsock` device — TX/RX queue handling, custom-VMM hot path, `VirtioDevice` impl.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{DeviceCtx, QueueConfig, VirtioDevice, VirtioDeviceId, virtio_bindings};

use crate::addr::{HOST_CID, RESERVED_CID, VsockAddr, VsockHostConnections};
use crate::backend::{LoopbackBackend, VsockBackend};
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

    // =====================================================================
    // Custom-VMM RX-injection hot path
    // =====================================================================
    //
    // `poll_rx_injection` was previously `DeviceManager::poll_vsock_rx`.
    // It is the device side of the vsock RX loop the BSP vCPU drives
    // each iteration: peek host fds, drain the backend RX queue into
    // guest descriptors, and opportunistically process the TX queue.
    // Requires `bind_ctx` and `bind_connections` to have been called.

    /// Drives one round of vsock RX/TX maintenance:
    /// 1. Peek every connected host fd; on data → enqueue RW; on EOF →
    ///    enqueue RST.
    /// 2. Pop entries from the backend RX queue, build vsock packets
    ///    (REQUEST/RESPONSE/RW/SHUTDOWN/CREDIT_*), and write them into
    ///    available guest RX descriptors via `write_to_rx_descriptor`.
    /// 3. If `tx_qcfg` is supplied, drain the TX virtqueue via
    ///    `process_queue(1, ...)` so guest→host responses are picked up
    ///    on the same poll cycle.
    ///
    /// Returns `true` when anything was injected (caller fires
    /// INT_VRING). Returns `false` if the device isn't fully bound or
    /// nothing was pending.
    #[allow(clippy::too_many_lines)]
    pub fn poll_rx_injection(
        &mut self,
        rx_qcfg: &QueueConfig,
        tx_qcfg: Option<&QueueConfig>,
    ) -> bool {
        use std::os::fd::AsRawFd;

        use crate::manager::{RxOps, TX_BUFFER_SIZE};

        let Some(ctx) = self.ctx.clone() else {
            return false;
        };
        let Some(conns) = self.conn_mgr.clone() else {
            return false;
        };
        let mem_arc = ctx.mem.clone();
        let gpa_base_usize = mem_arc.gpa_base();
        let mem_len = mem_arc.len();

        let mut injected = false;

        // ------------------------------------------------------------------
        // Phase 1: peek every connected fd → enqueue RW or RST
        // ------------------------------------------------------------------
        {
            let connected_fds = conns
                .lock()
                .map(|mgr| mgr.connected_fds())
                .unwrap_or_default();

            // Log at INFO once per unique count change to avoid spam.
            static LAST_COUNT: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let count = connected_fds.len();
            if count != LAST_COUNT.swap(count, std::sync::atomic::Ordering::Relaxed) {
                tracing::info!("vsock Phase 1: {} connected fds", count);
            }

            for (conn_id, fd) in &connected_fds {
                let mut peek_buf = [0u8; 1];
                // SAFETY: `*fd` is owned by the connection manager and
                // stays live for the duration of this peek. `peek_buf` is
                // a valid mutable slice. MSG_DONTWAIT keeps it non-blocking.
                let n = unsafe {
                    libc::recv(
                        *fd,
                        peek_buf.as_mut_ptr().cast::<libc::c_void>(),
                        1,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                if n > 0 {
                    tracing::trace!(
                        "vsock Phase 1: data on fd {} for {:?} — enqueue RW",
                        fd,
                        conn_id,
                    );
                    if let Ok(mut mgr) = conns.lock() {
                        mgr.enqueue_rw(*conn_id);
                    }
                } else if n == 0 {
                    tracing::debug!(
                        "vsock Phase 1: EOF on fd {} for {:?} — enqueue RST",
                        fd,
                        conn_id,
                    );
                    if let Ok(mut mgr) = conns.lock() {
                        mgr.enqueue_reset(*conn_id);
                    }
                }
                // n < 0 with EAGAIN/EWOULDBLOCK = no data, skip.
            }
        }

        // ------------------------------------------------------------------
        // Phase 2: drain backend_rxq → fill RX descriptors
        // ------------------------------------------------------------------
        if !rx_qcfg.ready || rx_qcfg.size == 0 {
            return injected;
        }
        let Some(rx_desc) = (rx_qcfg.desc_addr as usize).checked_sub(gpa_base_usize) else {
            return injected;
        };
        let Some(rx_avail) = (rx_qcfg.avail_addr as usize).checked_sub(gpa_base_usize) else {
            return injected;
        };
        let Some(rx_used) = (rx_qcfg.used_addr as usize).checked_sub(gpa_base_usize) else {
            return injected;
        };
        let q_size = rx_qcfg.size as usize;

        // SAFETY: `mem_arc` was constructed from the VM-lifetime guest RAM
        // mmap. The slice we derive is short-lived (dropped before phase 3
        // re-derives its own slice) and used only by code that follows the
        // VirtIO descriptor-ownership discipline.
        let Some(guest_mem) = (unsafe { mem_arc.slice_mut(gpa_base_usize, mem_len) }) else {
            return injected;
        };

        if rx_avail + 4 > guest_mem.len() {
            return injected;
        }

        // Process backend_rxq: pop connections, fill RX descriptors. If we
        // run out of guest descriptors while backend_rxq still has entries,
        // we set `injected = true` so the caller raises INT_VRING — that
        // wakes the guest's rx_work, which refills descriptors, and the
        // next poll cycle drains the stalled entries.
        let mut rxq_starved = false;
        loop {
            let avail_idx =
                u16::from_le_bytes([guest_mem[rx_avail + 2], guest_mem[rx_avail + 3]]) as usize;
            let used_idx_off = rx_used + 2;
            let used_idx =
                u16::from_le_bytes([guest_mem[used_idx_off], guest_mem[used_idx_off + 1]]) as usize;

            if avail_idx == used_idx {
                if let Ok(mgr) = conns.lock() {
                    if !mgr.backend_rxq.is_empty() {
                        rxq_starved = true;
                    }
                }
                break;
            }

            let conn_id = {
                let Ok(mut mgr) = conns.lock() else {
                    break;
                };
                mgr.backend_rxq.pop_front()
            };
            let Some(conn_id) = conn_id else {
                break; // No pending connections.
            };

            // Build the packet for this connection's highest-priority op.
            let packet = {
                let Ok(mut mgr) = conns.lock() else {
                    break;
                };
                let Some(conn) = mgr.get_mut(&conn_id) else {
                    continue; // Connection removed while queued.
                };

                if conn.rx_queue.peek() == RxOps::RESET {
                    conn.rx_queue.dequeue();
                    let hdr = VsockHeader::new(
                        VsockAddr::host(conn_id.host_port),
                        VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                        VsockOp::Rst,
                    );
                    let pkt = hdr.to_bytes().to_vec();
                    mgr.remove(&conn_id);
                    pkt
                } else {
                    let op = conn.rx_queue.dequeue();
                    if op == 0 {
                        continue; // Spurious entry — no pending ops.
                    }

                    match op {
                        RxOps::REQUEST => {
                            let hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::Request,
                            );
                            tracing::debug!(
                                "Vsock RX: OP_REQUEST guest_port={} host_port={}",
                                conn_id.guest_port,
                                conn_id.host_port,
                            );
                            hdr.to_bytes().to_vec()
                        }
                        RxOps::RESPONSE => {
                            conn.connect = true;
                            let hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::Response,
                            );
                            tracing::debug!(
                                "Vsock RX: OP_RESPONSE guest_port={} host_port={}",
                                conn_id.guest_port,
                                conn_id.host_port,
                            );
                            hdr.to_bytes().to_vec()
                        }
                        RxOps::RW => {
                            if conn.peer_no_recv() {
                                // Peer half-closed its receive side. Drop the
                                // RW silently; the fd stays open so the peer's
                                // own sends still drain via the TX path.
                                tracing::trace!(
                                    "Vsock RX: skipping RW for half-closed conn guest_port={} host_port={}",
                                    conn_id.guest_port,
                                    conn_id.host_port,
                                );
                                continue;
                            }
                            if !conn.connect {
                                let hdr = VsockHeader::new(
                                    VsockAddr::host(conn_id.host_port),
                                    VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                    VsockOp::Rst,
                                );
                                mgr.remove(&conn_id);
                                hdr.to_bytes().to_vec()
                            } else {
                                let credit = conn.peer_avail_credit();
                                if credit == 0 {
                                    let mut hdr = VsockHeader::new(
                                        VsockAddr::host(conn_id.host_port),
                                        VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                        VsockOp::CreditRequest,
                                    );
                                    hdr.buf_alloc = TX_BUFFER_SIZE;
                                    hdr.fwd_cnt = conn.fwd_cnt.0;
                                    // Re-queue the RW so we retry once the peer
                                    // refreshes our view; mark the request as
                                    // pending so maybe_request_credit below
                                    // doesn't also enqueue a duplicate.
                                    conn.rx_queue.enqueue(RxOps::RW);
                                    conn.note_credit_request_sent();
                                    hdr.to_bytes().to_vec()
                                } else {
                                    let fd = conn.internal_fd.as_raw_fd();
                                    let max_read = credit.min(4096);
                                    let mut buf = vec![0u8; max_read];
                                    // SAFETY: `fd` is borrowed from
                                    // `conn.internal_fd`, live for the call.
                                    // `buf` is a valid mutable allocation.
                                    let n = unsafe {
                                        libc::read(
                                            fd,
                                            buf.as_mut_ptr().cast::<libc::c_void>(),
                                            max_read,
                                        )
                                    };
                                    if n <= 0 {
                                        if n == 0 {
                                            let mut hdr = VsockHeader::new(
                                                VsockAddr::host(conn_id.host_port),
                                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                                VsockOp::Shutdown,
                                            );
                                            hdr.flags = 3; // RCV | SEND
                                            hdr.buf_alloc = TX_BUFFER_SIZE;
                                            hdr.fwd_cnt = conn.fwd_cnt.0;
                                            hdr.to_bytes().to_vec()
                                        } else {
                                            continue; // EAGAIN
                                        }
                                    } else {
                                        let data = &buf[..n as usize];
                                        let mut hdr = VsockHeader::new(
                                            VsockAddr::host(conn_id.host_port),
                                            VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                            VsockOp::Rw,
                                        );
                                        hdr.len = data.len() as u32;
                                        hdr.buf_alloc = TX_BUFFER_SIZE;
                                        hdr.fwd_cnt = conn.fwd_cnt.0;

                                        conn.record_rx(data.len() as u32);
                                        // After sending, our view of the
                                        // peer's free buffer has shrunk.
                                        // Ask for a refresh if we've crossed
                                        // the half-window mark.
                                        conn.maybe_request_credit();

                                        let hdr_bytes = hdr.to_bytes();
                                        let mut pkt =
                                            Vec::with_capacity(VsockHeader::SIZE + data.len());
                                        pkt.extend_from_slice(&hdr_bytes[..VsockHeader::SIZE]);
                                        pkt.extend_from_slice(data);

                                        tracing::debug!(
                                            "Vsock RX: OP_RW {} bytes guest_port={} host_port={} fwd_cnt={}",
                                            data.len(),
                                            conn_id.guest_port,
                                            conn_id.host_port,
                                            conn.fwd_cnt.0,
                                        );
                                        pkt
                                    }
                                }
                            }
                        }
                        RxOps::CREDIT_UPDATE => {
                            let mut hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::CreditUpdate,
                            );
                            hdr.buf_alloc = TX_BUFFER_SIZE;
                            hdr.fwd_cnt = conn.fwd_cnt.0;
                            conn.mark_credit_sent();
                            hdr.to_bytes().to_vec()
                        }
                        RxOps::CREDIT_REQUEST => {
                            // Ask the peer for their current fwd_cnt. The
                            // pending flag is already set — it stays set
                            // until the peer answers with CREDIT_UPDATE,
                            // which clears it via update_peer_credit.
                            let mut hdr = VsockHeader::new(
                                VsockAddr::host(conn_id.host_port),
                                VsockAddr::new(conn.guest_cid, conn_id.guest_port),
                                VsockOp::CreditRequest,
                            );
                            hdr.buf_alloc = TX_BUFFER_SIZE;
                            hdr.fwd_cnt = conn.fwd_cnt.0;
                            tracing::debug!(
                                "Vsock RX: OP_CREDIT_REQUEST guest_port={} host_port={}",
                                conn_id.guest_port,
                                conn_id.host_port,
                            );
                            hdr.to_bytes().to_vec()
                        }
                        _ => continue,
                    }
                }
            };

            // Write the packet into an available RX descriptor.
            let written = Self::write_to_rx_descriptor(
                guest_mem,
                rx_desc,
                rx_avail,
                rx_used,
                q_size,
                gpa_base_usize,
                &packet,
            );

            if written > 0 {
                injected = true;

                // Fire injected_notify for REQUEST ops — unblocks any
                // daemon-side connect waiting in `connect_vsock_hv`.
                if let Ok(mut mgr) = conns.lock() {
                    if let Some(conn) = mgr.get_mut(&conn_id) {
                        if let Some(tx) = conn.injected_notify.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }

            // If the connection still has pending ops, re-push it.
            if let Ok(mut mgr) = conns.lock() {
                if let Some(conn) = mgr.get(&conn_id) {
                    if conn.rx_queue.pending() {
                        mgr.backend_rxq.push_back(conn_id);
                    }
                }
            }
        }

        if rxq_starved {
            injected = true;
        }

        // Drop the phase-2 slice borrow before phase 3 re-derives one
        // (and before we hand a fresh `&mut [u8]` to `process_queue`,
        // which takes `&mut self`). `let _ = ...` for clippy.
        let _ = guest_mem;

        // ------------------------------------------------------------------
        // Phase 3: TX poll — drain TX queue for guest→host responses
        // ------------------------------------------------------------------
        if let Some(tx_qcfg) = tx_qcfg {
            // SAFETY: same as above — short-lived slice, descriptor-scoped
            // access discipline holds.
            let Some(tx_mem) = (unsafe { mem_arc.slice_mut(gpa_base_usize, mem_len) }) else {
                return injected;
            };
            // Use `VirtioDevice::process_queue` directly on `&mut self`.
            // `tx_mem` borrows `mem_arc` (a clone), not `self`, so the
            // borrows are disjoint.
            match <Self as VirtioDevice>::process_queue(self, 1, tx_mem, tx_qcfg) {
                Ok(completions) if !completions.is_empty() => {
                    tracing::trace!("Vsock TX poll: {} completions", completions.len());
                    injected = true;

                    // After TX processing, re-queue any connections whose
                    // RX state advanced (e.g. CreditUpdate after OP_RW).
                    if let Ok(mut mgr) = conns.lock() {
                        let ids: Vec<_> = mgr.connections_with_pending_rx();
                        for id in ids {
                            mgr.backend_rxq.push_back(id);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Vsock TX poll error: {e}");
                }
                _ => {}
            }
        }

        injected
    }

    /// Writes `packet` into the next available RX descriptor chain.
    ///
    /// `desc_addr`, `avail_addr`, `used_addr` are slice offsets (already
    /// translated from GPA by subtracting `gpa_base`). Returns the number
    /// of bytes written, or 0 if no RX descriptor was available or the
    /// descriptor chain ran out of writable buffer space.
    #[allow(clippy::too_many_arguments)]
    fn write_to_rx_descriptor(
        guest_mem: &mut [u8],
        desc_addr: usize,
        avail_addr: usize,
        used_addr: usize,
        q_size: usize,
        gpa_base: usize,
        packet: &[u8],
    ) -> usize {
        let avail_idx =
            u16::from_le_bytes([guest_mem[avail_addr + 2], guest_mem[avail_addr + 3]]) as usize;
        let used_idx_off = used_addr + 2;
        let used_idx =
            u16::from_le_bytes([guest_mem[used_idx_off], guest_mem[used_idx_off + 1]]) as usize;

        if avail_idx == used_idx {
            return 0; // No available descriptors.
        }

        let ring_off = avail_addr + 4 + 2 * (used_idx % q_size);
        if ring_off + 2 > guest_mem.len() {
            return 0;
        }
        let head_idx = u16::from_le_bytes([guest_mem[ring_off], guest_mem[ring_off + 1]]) as usize;

        // Walk descriptor chain, writing packet data to WRITE-flagged
        // descriptors.
        let mut written = 0;
        let mut idx = head_idx;
        for _ in 0..q_size {
            let d_off = desc_addr + idx * 16;
            if d_off + 16 > guest_mem.len() {
                break;
            }
            let addr_gpa =
                u64::from_le_bytes(guest_mem[d_off..d_off + 8].try_into().unwrap()) as usize;
            let len =
                u32::from_le_bytes(guest_mem[d_off + 8..d_off + 12].try_into().unwrap()) as usize;
            let flags = u16::from_le_bytes(guest_mem[d_off + 12..d_off + 14].try_into().unwrap());
            let next = u16::from_le_bytes(guest_mem[d_off + 14..d_off + 16].try_into().unwrap());
            let Some(addr) = addr_gpa.checked_sub(gpa_base) else {
                continue;
            };

            if flags & 2 != 0 && addr + len <= guest_mem.len() {
                let remaining = packet.len().saturating_sub(written);
                let to_write = remaining.min(len);
                if to_write > 0 {
                    guest_mem[addr..addr + to_write]
                        .copy_from_slice(&packet[written..written + to_write]);
                    written += to_write;
                }
            }

            if flags & 1 == 0 || written >= packet.len() {
                break;
            }
            idx = next as usize;
        }

        if written == 0 {
            return 0;
        }

        // Update used ring entry.
        let used_entry = used_addr + 4 + (used_idx % q_size) * 8;
        if used_entry + 8 <= guest_mem.len() {
            guest_mem[used_entry..used_entry + 4].copy_from_slice(&(head_idx as u32).to_le_bytes());
            guest_mem[used_entry + 4..used_entry + 8]
                .copy_from_slice(&(written as u32).to_le_bytes());
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            let new_used = (used_idx + 1) as u16;
            guest_mem[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used.to_le_bytes());
        }

        written
    }
}

impl VirtioDevice for VirtioVsock {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Vsock
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout:
        // offset 0: guest_cid (u64)
        let config_data = self.config.guest_cid.to_le_bytes();

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Vsock config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // Create virtqueues: RX (0), TX (1), Event (2).
        self.rx_queue = Some(VirtQueue::new(256)?);
        self.tx_queue = Some(VirtQueue::new(256)?);
        self.event_queue = Some(VirtQueue::new(64)?);

        // If no backend is set, use loopback for testing.
        if self.backend.is_none() {
            tracing::info!("Vsock: using loopback backend (no backend configured)");
            self.backend = Some(Arc::new(Mutex::new(LoopbackBackend::new())));
        }
        tracing::info!(
            "Vsock device activated, guest CID: {}",
            self.config.guest_cid
        );
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.connections.write().unwrap().clear();
        self.backend = None;
        self.rx_queue = None;
        self.tx_queue = None;
        self.event_queue = None;
        self.last_avail_idx_tx = 0;
        self.last_avail_idx_rx = 0;
    }

    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<Vec<(u16, u32)>> {
        // Queue 0 = RX (host→guest), Queue 1 = TX (guest→host), Queue 2 = Event.
        // We handle TX here: extract vsock packets, forward data to host fds.
        // We also try to inject pending RX data from host fds.
        if queue_idx != 1 || !queue_config.ready || queue_config.size == 0 {
            return Ok(Vec::new());
        }

        // Translate GPAs to slice offsets by subtracting gpa_base (checked to
        // guard against a malicious guest providing a GPA below the RAM base).
        let gpa_base = queue_config.gpa_base as usize;
        let desc_addr = (queue_config.desc_addr as usize)
            .checked_sub(gpa_base)
            .ok_or_else(|| {
                tracing::warn!(
                    "invalid desc GPA {:#x} below ram base {:#x}",
                    queue_config.desc_addr,
                    gpa_base
                );
                VirtioError::InvalidQueue("desc GPA below ram base".into())
            })?;
        let avail_addr = (queue_config.avail_addr as usize)
            .checked_sub(gpa_base)
            .ok_or_else(|| {
                tracing::warn!(
                    "invalid avail GPA {:#x} below ram base {:#x}",
                    queue_config.avail_addr,
                    gpa_base
                );
                VirtioError::InvalidQueue("avail GPA below ram base".into())
            })?;
        let used_addr = (queue_config.used_addr as usize)
            .checked_sub(gpa_base)
            .ok_or_else(|| {
                tracing::warn!(
                    "invalid used GPA {:#x} below ram base {:#x}",
                    queue_config.used_addr,
                    gpa_base
                );
                VirtioError::InvalidQueue("used GPA below ram base".into())
            })?;
        let q_size = queue_config.size as usize;

        if avail_addr + 4 > memory.len() {
            return Ok(Vec::new());
        }
        let avail_idx =
            u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]) as usize;

        let mut current_avail = self.last_avail_idx_tx;
        let mut completions = Vec::new();

        while current_avail != avail_idx {
            let ring_off = avail_addr + 4 + 2 * (current_avail % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]) as usize;

            // Walk descriptor chain to extract vsock packet.
            let mut packet_data = Vec::new();
            let mut idx = head_idx;
            for _ in 0..q_size {
                let d_off = desc_addr + idx * 16;
                if d_off + 16 > memory.len() {
                    break;
                }
                let addr = match (u64::from_le_bytes(memory[d_off..d_off + 8].try_into().unwrap())
                    as usize)
                    .checked_sub(gpa_base)
                {
                    Some(a) => a,
                    None => continue,
                };
                let len =
                    u32::from_le_bytes(memory[d_off + 8..d_off + 12].try_into().unwrap()) as usize;
                let flags = u16::from_le_bytes(memory[d_off + 12..d_off + 14].try_into().unwrap());
                let next = u16::from_le_bytes(memory[d_off + 14..d_off + 16].try_into().unwrap());

                // TX descriptors are read-only (guest→host data).
                if flags & arcbox_virtio_core::queue::flags::WRITE == 0
                    && addr + len <= memory.len()
                {
                    packet_data.extend_from_slice(&memory[addr..addr + len]);
                }

                if flags & arcbox_virtio_core::queue::flags::NEXT == 0 {
                    break;
                }
                idx = next as usize;
            }

            // Parse vsock header (44 bytes) and forward via host fds.
            if packet_data.len() >= VsockHeader::SIZE {
                if let Some(hdr) = VsockHeader::from_bytes(&packet_data[..VsockHeader::SIZE]) {
                    let op_val = { hdr.op };
                    let src_cid = { hdr.src_cid };
                    let dst_cid = { hdr.dst_cid };
                    let src_port = { hdr.src_port };
                    let dst_port = { hdr.dst_port };
                    tracing::info!(
                        "Vsock TX: op={} src={}:{} dst={}:{} len={} (packet_data={} bytes)",
                        op_val,
                        src_cid,
                        src_port,
                        dst_cid,
                        dst_port,
                        { hdr.len },
                        packet_data.len(),
                    );

                    let payload = &packet_data[VsockHeader::SIZE..];
                    if let Some(conns_arc) = self.conns.clone() {
                        if let Ok(mut conns) = conns_arc.lock() {
                            self.handle_tx_packet_with_fds(&hdr, payload, Some(&mut *conns));
                        }
                    } else {
                        self.handle_tx_packet_with_fds(&hdr, payload, None);
                    }
                }
            } else {
                tracing::warn!(
                    "Vsock TX: packet too short ({} bytes < {} header), skipping",
                    packet_data.len(),
                    VsockHeader::SIZE,
                );
            }

            // Update used ring.
            let used_idx_off = used_addr + 2;
            let used_idx = u16::from_le_bytes([memory[used_idx_off], memory[used_idx_off + 1]]);
            let used_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_entry + 8 <= memory.len() {
                memory[used_entry..used_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                memory[used_entry + 4..used_entry + 8]
                    .copy_from_slice(&(packet_data.len() as u32).to_le_bytes());
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                let new_used = used_idx.wrapping_add(1);
                memory[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used.to_le_bytes());
            }

            // Update avail_event.
            let avail_event_off = used_addr + 4 + 8 * q_size;
            if avail_event_off + 2 <= memory.len() {
                let ae = ((current_avail + 1) as u16).to_le_bytes();
                memory[avail_event_off] = ae[0];
                memory[avail_event_off + 1] = ae[1];
            }

            completions.push((head_idx as u16, packet_data.len() as u32));
            current_avail += 1;
        }

        self.last_avail_idx_tx = current_avail;
        Ok(completions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_config_default() {
        let config = VsockConfig::default();
        assert_eq!(config.guest_cid, 3);
    }

    #[test]
    fn test_vsock_config_custom() {
        let config = VsockConfig { guest_cid: 100 };
        assert_eq!(config.guest_cid, 100);
    }

    #[test]
    fn test_vsock_config_clone() {
        let config = VsockConfig { guest_cid: 42 };
        let cloned = config.clone();
        assert_eq!(cloned.guest_cid, 42);
    }

    #[test]
    fn test_vsock_new() {
        let vsock = VirtioVsock::new(VsockConfig::default());
        assert_eq!(vsock.guest_cid(), 3);
    }

    #[test]
    fn test_vsock_device_id() {
        let vsock = VirtioVsock::new(VsockConfig::default());
        assert_eq!(vsock.device_id(), VirtioDeviceId::Vsock);
    }

    #[test]
    fn test_vsock_features() {
        let vsock = VirtioVsock::new(VsockConfig::default());
        let features = vsock.features();
        assert!(features & VirtioVsock::FEATURE_STREAM != 0);
    }

    #[test]
    fn test_vsock_ack_features() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());

        vsock.ack_features(VirtioVsock::FEATURE_STREAM);
        assert_eq!(vsock.acked_features, VirtioVsock::FEATURE_STREAM);
    }

    #[test]
    fn test_vsock_ack_unsupported_feature() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());

        // SEQPACKET is not supported by default
        vsock.ack_features(VirtioVsock::FEATURE_SEQPACKET);
        assert_eq!(vsock.acked_features, 0);
    }

    #[test]
    fn test_vsock_read_config() {
        let config = VsockConfig {
            guest_cid: 0x12345678,
        };
        let vsock = VirtioVsock::new(config);

        let mut data = [0u8; 8];
        vsock.read_config(0, &mut data);

        let cid = u64::from_le_bytes(data);
        assert_eq!(cid, 0x12345678);
    }

    #[test]
    fn test_vsock_read_config_partial() {
        let config = VsockConfig {
            guest_cid: 0xDEADBEEF,
        };
        let vsock = VirtioVsock::new(config);

        let mut data = [0u8; 4];
        vsock.read_config(0, &mut data);

        let low_bytes = u32::from_le_bytes(data);
        assert_eq!(low_bytes, 0xDEADBEEF);
    }

    #[test]
    fn test_vsock_read_config_offset() {
        let config = VsockConfig {
            guest_cid: 0xAABBCCDD_11223344,
        };
        let vsock = VirtioVsock::new(config);

        let mut data = [0u8; 4];
        vsock.read_config(4, &mut data);

        let high_bytes = u32::from_le_bytes(data);
        assert_eq!(high_bytes, 0xAABBCCDD);
    }

    #[test]
    fn test_vsock_read_config_beyond() {
        let vsock = VirtioVsock::new(VsockConfig::default());

        let mut data = [0xFFu8; 4];
        vsock.read_config(100, &mut data);
    }

    #[test]
    fn test_vsock_write_config_noop() {
        let mut vsock = VirtioVsock::new(VsockConfig { guest_cid: 42 });

        vsock.write_config(0, &[0xFF; 8]);

        assert_eq!(vsock.guest_cid(), 42);
    }

    #[test]
    fn test_vsock_activate() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        assert!(vsock.activate().is_ok());
    }

    #[test]
    fn test_vsock_reset() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.ack_features(VirtioVsock::FEATURE_STREAM);
        assert_ne!(vsock.acked_features, 0);

        vsock.reset();
        assert_eq!(vsock.acked_features, 0);
    }

    #[test]
    fn test_vsock_constants() {
        assert_eq!(VirtioVsock::HOST_CID, 2);
        assert_eq!(VirtioVsock::RESERVED_CID, 1);
        assert_eq!(VirtioVsock::FEATURE_STREAM, 1 << 0);
        assert_eq!(VirtioVsock::FEATURE_SEQPACKET, 1 << 1);
    }

    #[test]
    fn test_vsock_with_loopback_backend() {
        let vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        assert_eq!(vsock.guest_cid(), 3);
        assert_eq!(vsock.connection_count(), 0);
    }

    #[test]
    fn test_vsock_connect_send_recv() {
        let vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());

        vsock.handle_connect(1000, 80).unwrap();
        assert_eq!(vsock.connection_count(), 1);

        let data = b"GET / HTTP/1.1";
        let sent = vsock.handle_send(1000, 80, data).unwrap();
        assert_eq!(sent, data.len());

        let mut buf = [0u8; 64];
        let received = vsock.handle_recv(1000, 80, &mut buf).unwrap();
        assert_eq!(received, data.len());
        assert_eq!(&buf[..received], data);

        vsock.handle_close(1000, 80).unwrap();
        assert_eq!(vsock.connection_count(), 0);
    }

    #[test]
    fn test_vsock_activate_creates_queues() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        assert!(vsock.rx_queue.is_none());
        assert!(vsock.tx_queue.is_none());
        assert!(vsock.event_queue.is_none());

        vsock.activate().unwrap();

        assert!(vsock.rx_queue.is_some());
        assert!(vsock.tx_queue.is_some());
        assert!(vsock.event_queue.is_some());
    }

    #[test]
    fn test_vsock_reset_clears_queues() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();
        assert!(vsock.rx_queue.is_some());

        vsock.reset();
        assert!(vsock.rx_queue.is_none());
        assert!(vsock.tx_queue.is_none());
        assert!(vsock.event_queue.is_none());
    }

    /// Helper: Build a simulated guest memory region with a vsock packet
    /// placed at a given address, and configure the TX queue with matching
    /// descriptors.
    fn setup_tx_packet(
        vsock: &mut VirtioVsock,
        guest_addr: usize,
        header: &VsockHeader,
        payload: &[u8],
        memory: &mut Vec<u8>,
    ) {
        let header_bytes = header.to_bytes();
        let total = header_bytes.len() + payload.len();

        if memory.len() < guest_addr + total {
            memory.resize(guest_addr + total, 0);
        }

        memory[guest_addr..guest_addr + header_bytes.len()].copy_from_slice(&header_bytes);
        if !payload.is_empty() {
            memory[guest_addr + header_bytes.len()..guest_addr + total].copy_from_slice(payload);
        }

        let queue = vsock.tx_queue.as_mut().unwrap();
        let desc = arcbox_virtio_core::queue::Descriptor {
            addr: guest_addr as u64,
            len: total as u32,
            flags: 0, // Read-only for device
            next: 0,
        };
        queue.set_descriptor(0, desc).unwrap();
        queue.add_avail(0).unwrap();
    }

    #[test]
    fn test_process_tx_queue_not_ready() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        let mut memory = vec![0u8; 1024];
        let result = vsock.process_tx_queue(&mut memory);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_tx_queue_empty() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();

        let mut memory = vec![0u8; 4096];
        let completions = vsock.process_tx_queue(&mut memory).unwrap();
        assert!(completions.is_empty());
    }

    #[test]
    fn test_process_tx_queue_connect_request() {
        let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        vsock.activate().unwrap();

        let mut memory = vec![0u8; 4096];

        // Guest sends OP_REQUEST from port 1000 to host port 80.
        let header = VsockHeader::new(
            VsockAddr::new(3, 1000),
            VsockAddr::new(VirtioVsock::HOST_CID, 80),
            VsockOp::Request,
        );
        setup_tx_packet(&mut vsock, 0x100, &header, &[], &mut memory);

        // Also prepare RX queue with a write-only descriptor for the response.
        {
            let rx_queue = vsock.rx_queue.as_mut().unwrap();
            let rx_desc = arcbox_virtio_core::queue::Descriptor {
                addr: 0x800,
                len: 256,
                flags: arcbox_virtio_core::queue::flags::WRITE,
                next: 0,
            };
            rx_queue.set_descriptor(0, rx_desc).unwrap();
            rx_queue.add_avail(0).unwrap();
        }

        let completions = vsock.process_tx_queue(&mut memory).unwrap();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].0, 0); // descriptor head index

        assert_eq!(vsock.connection_count(), 1);

        let resp_header = VsockHeader::from_bytes(&memory[0x800..0x800 + VsockHeader::SIZE]);
        assert!(resp_header.is_some());
        let resp = resp_header.unwrap();
        assert_eq!(resp.operation(), Some(VsockOp::Response));
        let resp_src_cid = resp.src_cid;
        let resp_dst_cid = resp.dst_cid;
        assert_eq!(resp_src_cid, VirtioVsock::HOST_CID);
        assert_eq!(resp_dst_cid, 3);
    }

    #[test]
    fn test_process_tx_queue_data_rw() {
        let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        vsock.activate().unwrap();

        vsock.handle_connect(1000, 80).unwrap();

        let mut memory = vec![0u8; 4096];

        let payload = b"hello world";
        let mut header = VsockHeader::new(
            VsockAddr::new(3, 1000),
            VsockAddr::new(VirtioVsock::HOST_CID, 80),
            VsockOp::Rw,
        );
        header.len = payload.len() as u32;
        setup_tx_packet(&mut vsock, 0x100, &header, payload, &mut memory);

        let completions = vsock.process_tx_queue(&mut memory).unwrap();
        assert_eq!(completions.len(), 1);

        let backend = vsock.backend.as_ref().unwrap();
        let mut backend = backend.lock().unwrap();
        let addr = VsockAddr::new(3, 1000);
        assert!(backend.has_pending_data(addr));

        let mut buf = [0u8; 64];
        let n = backend.on_recv(addr, &mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn test_process_tx_queue_shutdown() {
        let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        vsock.activate().unwrap();

        vsock.handle_connect(2000, 443).unwrap();
        assert_eq!(vsock.connection_count(), 1);

        let mut memory = vec![0u8; 4096];

        let header = VsockHeader::new(
            VsockAddr::new(3, 2000),
            VsockAddr::new(VirtioVsock::HOST_CID, 443),
            VsockOp::Shutdown,
        );
        setup_tx_packet(&mut vsock, 0x100, &header, &[], &mut memory);

        // Provide an RX descriptor for the RST response.
        {
            let rx_queue = vsock.rx_queue.as_mut().unwrap();
            let rx_desc = arcbox_virtio_core::queue::Descriptor {
                addr: 0x800,
                len: 256,
                flags: arcbox_virtio_core::queue::flags::WRITE,
                next: 0,
            };
            rx_queue.set_descriptor(0, rx_desc).unwrap();
            rx_queue.add_avail(0).unwrap();
        }

        let completions = vsock.process_tx_queue(&mut memory).unwrap();
        assert_eq!(completions.len(), 1);

        assert_eq!(vsock.connection_count(), 0);

        let rst_header = VsockHeader::from_bytes(&memory[0x800..0x800 + VsockHeader::SIZE]);
        assert!(rst_header.is_some());
        assert_eq!(rst_header.unwrap().operation(), Some(VsockOp::Rst));
    }

    #[test]
    fn test_process_tx_queue_credit_update() {
        let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        vsock.activate().unwrap();

        vsock.handle_connect(3000, 22).unwrap();

        let mut memory = vec![0u8; 4096];

        let mut header = VsockHeader::new(
            VsockAddr::new(3, 3000),
            VsockAddr::new(VirtioVsock::HOST_CID, 22),
            VsockOp::CreditUpdate,
        );
        header.buf_alloc = 131_072;
        header.fwd_cnt = 500;
        setup_tx_packet(&mut vsock, 0x100, &header, &[], &mut memory);

        let completions = vsock.process_tx_queue(&mut memory).unwrap();
        assert_eq!(completions.len(), 1);

        let conns = vsock.connections.read().unwrap();
        let conn = conns.get(&(3000, 22)).unwrap();
        assert_eq!(conn.peer_buf_alloc, 131_072);
        assert_eq!(conn.peer_fwd_cnt, 500);
    }

    #[test]
    fn test_process_queue_dispatches_tx() {
        let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
        vsock.activate().unwrap();

        let mut memory = vec![0u8; 4096];

        let completions = vsock.process_queue(1, &mut memory).unwrap();
        assert!(completions.is_empty());
    }

    #[test]
    fn test_process_queue_unknown_index() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();

        let mut memory = vec![0u8; 1024];
        let completions = vsock.process_queue(0, &mut memory).unwrap();
        assert!(completions.is_empty());
        let completions = vsock.process_queue(2, &mut memory).unwrap();
        assert!(completions.is_empty());
        let completions = vsock.process_queue(99, &mut memory).unwrap();
        assert!(completions.is_empty());
    }

    #[test]
    fn test_inject_rx_packet_not_ready() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        let header = VsockHeader::new(
            VsockAddr::host(80),
            VsockAddr::new(3, 1000),
            VsockOp::Response,
        );
        let mut memory = vec![0u8; 1024];
        let result = vsock.inject_rx_packet(&header, &[], &mut memory);
        assert!(result.is_err());
    }

    #[test]
    fn test_inject_rx_packet_no_descriptors() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();

        let header = VsockHeader::new(
            VsockAddr::host(80),
            VsockAddr::new(3, 1000),
            VsockOp::Response,
        );
        let mut memory = vec![0u8; 1024];
        let result = vsock.inject_rx_packet(&header, &[], &mut memory);
        assert!(result.is_err());
    }

    #[test]
    fn test_inject_rx_packet_with_data() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();

        let mut memory = vec![0u8; 4096];

        {
            let rx_queue = vsock.rx_queue.as_mut().unwrap();
            let desc = arcbox_virtio_core::queue::Descriptor {
                addr: 0x200,
                len: 512,
                flags: arcbox_virtio_core::queue::flags::WRITE,
                next: 0,
            };
            rx_queue.set_descriptor(0, desc).unwrap();
            rx_queue.add_avail(0).unwrap();
        }

        let payload = b"response data";
        let mut header =
            VsockHeader::new(VsockAddr::host(80), VsockAddr::new(3, 1000), VsockOp::Rw);
        header.len = payload.len() as u32;

        vsock
            .inject_rx_packet(&header, payload, &mut memory)
            .unwrap();

        let written_hdr =
            VsockHeader::from_bytes(&memory[0x200..0x200 + VsockHeader::SIZE]).unwrap();
        assert_eq!(written_hdr.operation(), Some(VsockOp::Rw));
        let wh_src_cid = written_hdr.src_cid;
        assert_eq!(wh_src_cid, VirtioVsock::HOST_CID);

        let payload_start = 0x200 + VsockHeader::SIZE;
        assert_eq!(
            &memory[payload_start..payload_start + payload.len()],
            payload
        );
    }

    /// Builds a simulated split virtqueue layout in a flat memory buffer.
    /// Returns (`desc_addr`, `avail_addr`, `used_addr`).
    fn setup_virtqueue_layout(
        memory: &mut Vec<u8>,
        base: usize,
        q_size: usize,
    ) -> (usize, usize, usize) {
        let desc_addr = base;
        let avail_addr = desc_addr + q_size * 16;
        let avail_addr = (avail_addr + 15) & !15;
        let avail_size = 4 + 2 * q_size + 2;
        let used_addr = avail_addr + avail_size;
        let used_addr = (used_addr + 15) & !15;
        let used_size = 4 + 8 * q_size + 2;
        let total = used_addr + used_size;
        if memory.len() < total {
            memory.resize(total, 0);
        }
        (desc_addr, avail_addr, used_addr)
    }

    fn write_descriptor(
        memory: &mut [u8],
        desc_addr: usize,
        idx: usize,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let off = desc_addr + idx * 16;
        memory[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        memory[off + 8..off + 12].copy_from_slice(&len.to_le_bytes());
        memory[off + 12..off + 14].copy_from_slice(&flags.to_le_bytes());
        memory[off + 14..off + 16].copy_from_slice(&next.to_le_bytes());
    }

    fn avail_ring_push(memory: &mut [u8], avail_addr: usize, q_size: usize, head_idx: u16) {
        let avail_idx =
            u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]) as usize;
        let ring_off = avail_addr + 4 + 2 * (avail_idx % q_size);
        memory[ring_off..ring_off + 2].copy_from_slice(&head_idx.to_le_bytes());
        let new_idx = (avail_idx + 1) as u16;
        memory[avail_addr + 2..avail_addr + 4].copy_from_slice(&new_idx.to_le_bytes());
    }

    /// Verifies that the guest-memory-based `process_queue` correctly parses
    /// a 44-byte OP_RESPONSE packet from the TX virtqueue.
    #[test]
    fn test_process_queue_guest_memory_op_response() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();

        let q_size = 16usize;
        let mut memory = vec![0u8; 0x10000];

        let (desc_addr, avail_addr, used_addr) =
            setup_virtqueue_layout(&mut memory, 0x4000, q_size);

        let pkt_addr = 0x8000usize;
        let hdr = VsockHeader::new(
            VsockAddr::new(3, 1024),
            VsockAddr::host(50000),
            VsockOp::Response,
        );
        let hdr_bytes = hdr.to_bytes();
        assert_eq!(
            hdr_bytes.len(),
            44,
            "VsockHeader must serialize to 44 bytes"
        );
        memory[pkt_addr..pkt_addr + 44].copy_from_slice(&hdr_bytes[..44]);

        write_descriptor(&mut memory, desc_addr, 0, pkt_addr as u64, 44, 0, 0);
        avail_ring_push(&mut memory, avail_addr, q_size, 0);

        struct MockConns {
            connected: Vec<(u32, u32)>,
            credit_updates: Vec<(u32, u32, u32, u32)>,
        }
        impl VsockHostConnections for MockConns {
            fn fd_for(&self, _gp: u32, _hp: u32) -> Option<std::os::unix::io::RawFd> {
                None
            }
            fn mark_connected(&mut self, gp: u32, hp: u32) {
                self.connected.push((gp, hp));
            }
            fn remove_connection(&mut self, _gp: u32, _hp: u32) {}
            fn update_peer_credit(&mut self, gp: u32, hp: u32, ba: u32, fc: u32) {
                self.credit_updates.push((gp, hp, ba, fc));
            }
        }

        let mock = Arc::new(Mutex::new(MockConns {
            connected: Vec::new(),
            credit_updates: Vec::new(),
        }));

        let qcfg = QueueConfig {
            desc_addr: desc_addr as u64,
            avail_addr: avail_addr as u64,
            used_addr: used_addr as u64,
            size: q_size as u16,
            ready: true,
            gpa_base: 0,
        };
        vsock.bind_connections(mock.clone());

        let completions =
            <VirtioVsock as VirtioDevice>::process_queue(&mut vsock, 1, &mut memory, &qcfg)
                .unwrap();

        assert_eq!(
            completions.len(),
            1,
            "Expected 1 completion for OP_RESPONSE"
        );
        assert_eq!(completions[0].0, 0, "head_idx should be 0");
        assert_eq!(completions[0].1, 44, "written bytes should be 44");

        let mock_guard = mock.lock().unwrap();
        assert_eq!(
            mock_guard.connected.len(),
            1,
            "mark_connected should be called once for OP_RESPONSE"
        );
        assert_eq!(mock_guard.connected[0], (1024, 50000));

        assert_eq!(mock_guard.credit_updates.len(), 1);
        assert_eq!(
            mock_guard.credit_updates[0],
            (1024, 50000, 64 * 1024, 0),
            "peer credit should be synced from OP_RESPONSE header"
        );
    }

    /// Verifies that a 44-byte OP_RST from guest is correctly parsed via
    /// the guest-memory `process_queue` path.
    #[test]
    fn test_process_queue_guest_memory_op_rst() {
        let mut vsock = VirtioVsock::new(VsockConfig::default());
        vsock.activate().unwrap();

        let q_size = 16usize;
        let mut memory = vec![0u8; 0x10000];

        let (desc_addr, avail_addr, used_addr) =
            setup_virtqueue_layout(&mut memory, 0x4000, q_size);

        let pkt_addr = 0x8000usize;
        let hdr = VsockHeader::new(
            VsockAddr::new(3, 1024),
            VsockAddr::host(50000),
            VsockOp::Rst,
        );
        memory[pkt_addr..pkt_addr + 44].copy_from_slice(&hdr.to_bytes()[..44]);

        write_descriptor(&mut memory, desc_addr, 0, pkt_addr as u64, 44, 0, 0);
        avail_ring_push(&mut memory, avail_addr, q_size, 0);

        struct MockConns {
            removed: Vec<(u32, u32)>,
        }
        impl VsockHostConnections for MockConns {
            fn fd_for(&self, _: u32, _: u32) -> Option<std::os::unix::io::RawFd> {
                None
            }
            fn mark_connected(&mut self, _: u32, _: u32) {}
            fn remove_connection(&mut self, gp: u32, hp: u32) {
                self.removed.push((gp, hp));
            }
        }
        let mock = Arc::new(Mutex::new(MockConns {
            removed: Vec::new(),
        }));

        let qcfg = QueueConfig {
            desc_addr: desc_addr as u64,
            avail_addr: avail_addr as u64,
            used_addr: used_addr as u64,
            size: q_size as u16,
            ready: true,
            gpa_base: 0,
        };
        vsock.bind_connections(mock.clone());

        let completions =
            <VirtioVsock as VirtioDevice>::process_queue(&mut vsock, 1, &mut memory, &qcfg)
                .unwrap();
        assert_eq!(completions.len(), 1);

        let mock_guard = mock.lock().unwrap();
        assert_eq!(mock_guard.removed.len(), 1);
        assert_eq!(mock_guard.removed[0], (1024, 50000));
    }
}
