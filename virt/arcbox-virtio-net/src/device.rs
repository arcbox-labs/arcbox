//! `VirtioNet` device — TX/RX queue handling, hot-path drains, `VirtioDevice` impl.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::{Descriptor, VirtQueue};
use arcbox_virtio_core::{DeviceCtx, QueueConfig, VirtioDevice, VirtioDeviceId, virtio_bindings};

use crate::backend::{LoopbackBackend, NetBackend, NetOffloadFlags};
use crate::config::{NetConfig, NetPort, NetStatus};
use crate::header::{NetPacket, VirtioNetHeader};

/// `VirtIO` network device.
pub struct VirtioNet {
    config: NetConfig,
    features: u64,
    acked_features: u64,
    /// Link status.
    status: u16,
    /// Receive queue.
    rx_queue: Option<VirtQueue>,
    /// Transmit queue.
    tx_queue: Option<VirtQueue>,
    /// Network backend.
    backend: Option<Arc<Mutex<dyn NetBackend>>>,
    /// RX buffer.
    rx_buffer: VecDeque<NetPacket>,
    /// Persistent scratch buffer for draining backend reads into before
    /// copying to `rx_buffer`. Sized at construction and reused across every
    /// `poll_backend_batch` iteration so we don't heap-allocate 64 KB per
    /// received packet. `Box<[u8]>` rather than `Box<[u8; N]>` so the
    /// initialisation lands straight on the heap (an array literal would
    /// materialise on the stack first).
    rx_scratch: Box<[u8]>,
    /// TX statistics.
    tx_packets: u64,
    tx_bytes: u64,
    /// RX statistics.
    rx_packets: u64,
    rx_bytes: u64,
    /// Guest memory + interrupt context, shared with the VMM. Optional
    /// because VZ-backed `VirtioNet` instances do not use the custom-VMM
    /// MMIO hot path and never bind one.
    ctx: Option<DeviceCtx>,
    /// Host fd + TX cursor. Bound once after the socketpair is created.
    /// `OnceLock` rather than `Mutex<Option<_>>` so the TX hot path reads
    /// both fields without acquiring a lock.
    port: OnceLock<NetPort>,
}

impl VirtioNet {
    // Feature bits sourced from `virtio_bindings::virtio_net`.
    // The crate exports bit *positions* (e.g. VIRTIO_NET_F_CSUM = 0), so
    // we shift 1 left by that position to get the feature mask.

    /// Feature: Checksum offload.
    pub const FEATURE_CSUM: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_CSUM;
    /// Feature: Guest checksum offload.
    pub const FEATURE_GUEST_CSUM: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_GUEST_CSUM;
    /// Feature: Control virtqueue.
    pub const FEATURE_CTRL_VQ: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_CTRL_VQ;
    /// Feature: MTU.
    pub const FEATURE_MTU: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_MTU;
    /// Feature: MAC address.
    pub const FEATURE_MAC: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
    /// Feature: GSO.
    pub const FEATURE_GSO: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_GSO;
    /// Feature: Guest TSO4.
    pub const FEATURE_GUEST_TSO4: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_GUEST_TSO4;
    /// Feature: Guest TSO6.
    pub const FEATURE_GUEST_TSO6: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_GUEST_TSO6;
    /// Feature: Guest ECN.
    pub const FEATURE_GUEST_ECN: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_GUEST_ECN;
    /// Feature: Guest UFO.
    pub const FEATURE_GUEST_UFO: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_GUEST_UFO;
    /// Feature: Host TSO4.
    pub const FEATURE_HOST_TSO4: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_HOST_TSO4;
    /// Feature: Host TSO6.
    pub const FEATURE_HOST_TSO6: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_HOST_TSO6;
    /// Feature: Host ECN.
    pub const FEATURE_HOST_ECN: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_HOST_ECN;
    /// Feature: Host UFO.
    pub const FEATURE_HOST_UFO: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_HOST_UFO;
    /// Feature: Merge RX buffers.
    pub const FEATURE_MRG_RXBUF: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_MRG_RXBUF;
    /// Feature: Status.
    pub const FEATURE_STATUS: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_STATUS;
    /// Feature: Multiple queues.
    pub const FEATURE_MQ: u64 = 1 << virtio_bindings::virtio_net::VIRTIO_NET_F_MQ;
    /// `VirtIO` 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// Default maximum number of packets per `poll_backend_batch` call.
    pub const DEFAULT_RX_BATCH_SIZE: usize = 64;

    /// Size of the persistent RX scratch buffer. 64 KiB covers any
    /// plausible single-frame read — jumbo frames, GSO-merged bursts
    /// from vmnet, and standard MTU frames all fit comfortably.
    pub const RX_SCRATCH_SIZE: usize = 65536;

    /// Ethernet (14) + IPv4 (20) + TCP (20) header length.
    const ETH_IP_TCP_HDR_LEN: u16 = 54;

    /// Default MSS for TSO segments (standard Ethernet MTU minus headers).
    const DEFAULT_TSO_MSS: u16 = 1460;

    /// Creates a new network device.
    #[must_use]
    pub fn new(config: NetConfig) -> Self {
        let features = Self::FEATURE_MAC
            | Self::FEATURE_MTU
            | Self::FEATURE_STATUS
            | Self::FEATURE_CSUM
            | Self::FEATURE_GUEST_CSUM
            | Self::FEATURE_VERSION_1
            | arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX;

        Self {
            config,
            features,
            acked_features: 0,
            status: NetStatus::LinkUp as u16,
            rx_queue: None,
            tx_queue: None,
            backend: None,
            rx_buffer: VecDeque::new(),
            rx_scratch: vec![0u8; Self::RX_SCRATCH_SIZE].into_boxed_slice(),
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            ctx: None,
            port: OnceLock::new(),
        }
    }

    /// Binds the device's `DeviceCtx` (guest memory + IRQ trigger).
    ///
    /// Must be called once after registration, before the VM starts
    /// running the guest. For VZ-backed deployments that do not use the
    /// custom-VMM hot path this stays `None` and no harm is done.
    pub fn bind_ctx(&mut self, ctx: DeviceCtx) {
        self.ctx = Some(ctx);
    }

    /// Binds the `NetPort` (host fd + TX cursor) for this device.
    ///
    /// May be called once. Returns the rejected `NetPort` if a port was
    /// already bound, so the caller can decide whether to log or error.
    pub fn bind_port(&self, port: NetPort) -> std::result::Result<(), NetPort> {
        self.port.set(port)
    }

    /// Returns the bound `NetPort` if one has been set.
    pub fn port(&self) -> Option<&NetPort> {
        self.port.get()
    }

    /// Enables TSO/GSO feature advertisement.
    ///
    /// Call this after construction when the backend supports TSO offload.
    /// The guest driver will then negotiate TSO and emit large segments
    /// instead of MTU-sized packets, reducing per-packet overhead by ~45x.
    pub fn enable_tso_features(&mut self) {
        self.features |= Self::FEATURE_GUEST_TSO4
            | Self::FEATURE_GUEST_TSO6
            | Self::FEATURE_HOST_TSO4
            | Self::FEATURE_HOST_TSO6
            | Self::FEATURE_GUEST_ECN
            | Self::FEATURE_HOST_ECN
            | Self::FEATURE_MRG_RXBUF;
    }

    /// Returns whether TSO was negotiated with the guest.
    #[must_use]
    pub fn tso_negotiated(&self) -> bool {
        self.acked_features & Self::FEATURE_GUEST_TSO4 != 0
            || self.acked_features & Self::FEATURE_GUEST_TSO6 != 0
    }

    /// Creates a new network device with loopback backend.
    #[must_use]
    pub fn with_loopback() -> Self {
        let mut net = Self::new(NetConfig::default());
        net.backend = Some(Arc::new(Mutex::new(LoopbackBackend::new())));
        net
    }

    /// Sets the network backend.
    pub fn set_backend(&mut self, backend: Arc<Mutex<dyn NetBackend>>) {
        self.backend = Some(backend);
    }

    /// Returns the MAC address.
    #[must_use]
    pub const fn mac(&self) -> &[u8; 6] {
        &self.config.mac
    }

    /// Returns TX statistics.
    #[must_use]
    pub const fn tx_stats(&self) -> (u64, u64) {
        (self.tx_packets, self.tx_bytes)
    }

    /// Returns RX statistics.
    #[must_use]
    pub const fn rx_stats(&self) -> (u64, u64) {
        (self.rx_packets, self.rx_bytes)
    }

    /// Sets the link status.
    pub const fn set_link_up(&mut self, up: bool) {
        if up {
            self.status |= NetStatus::LinkUp as u16;
        } else {
            self.status &= !(NetStatus::LinkUp as u16);
        }
    }

    /// Returns whether the link is up.
    #[must_use]
    pub const fn is_link_up(&self) -> bool {
        self.status & (NetStatus::LinkUp as u16) != 0
    }

    /// Queues a packet for reception by the guest.
    pub fn queue_rx(&mut self, packet: NetPacket) {
        self.rx_buffer.push_back(packet);
    }

    /// Handles TX from guest.
    fn handle_tx(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < VirtioNetHeader::SIZE {
            return Err(VirtioError::InvalidOperation("Packet too small".into()));
        }

        let header = VirtioNetHeader::from_bytes(data)
            .ok_or_else(|| VirtioError::InvalidOperation("Invalid header".into()))?;

        let packet = NetPacket {
            header,
            data: data[VirtioNetHeader::SIZE..].to_vec(),
        };

        self.tx_packets += 1;
        self.tx_bytes += packet.data.len() as u64;

        if let Some(backend) = &self.backend {
            let mut backend = backend
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock backend: {e}")))?;

            let is_tso = header.gso_type != VirtioNetHeader::GSO_NONE && header.gso_size > 0;
            if is_tso {
                tracing::trace!(
                    "Net TX TSO: {} bytes, gso_type={}, gso_size={}",
                    packet.data.len(),
                    header.gso_type,
                    header.gso_size
                );
                backend
                    .send_tso(&packet)
                    .map_err(|e| VirtioError::Io(format!("TSO send failed: {e}")))?;
            } else {
                backend
                    .send(&packet)
                    .map_err(|e| VirtioError::Io(format!("Send failed: {e}")))?;
            }
        }

        tracing::trace!("Net TX: {} bytes", packet.data.len());
        Ok(())
    }

    /// Processes the TX queue.
    ///
    /// Collects all pending TX descriptors and sends them. Returns completions
    /// for batch notification via `push_used_batch()`.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_tx_queue(&mut self, memory: &[u8]) -> Result<Vec<(u16, u32)>> {
        let mut tx_data: Vec<(u16, Vec<u8>)> = Vec::new();

        {
            let queue = self
                .tx_queue
                .as_mut()
                .ok_or_else(|| VirtioError::NotReady("TX queue not ready".into()))?;

            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut data = Vec::new();

                for desc in chain {
                    if !desc.is_write_only() {
                        let start = desc.addr as usize;
                        let end = start + desc.len as usize;
                        if end <= memory.len() {
                            data.extend_from_slice(&memory[start..end]);
                        }
                    }
                }

                tx_data.push((head_idx, data));
            }
        }

        let mut completed = Vec::new();
        for (head_idx, data) in tx_data {
            let len = data.len() as u32;
            self.handle_tx(&data)?;
            completed.push((head_idx, len));
        }

        Ok(completed)
    }

    /// Returns the number of packets in the RX buffer.
    #[must_use]
    pub fn rx_pending(&self) -> usize {
        self.rx_buffer.len()
    }

    /// Polls the backend for incoming packets.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails.
    pub fn poll_backend(&mut self) -> Result<()> {
        self.poll_backend_batch(usize::MAX).map(|_| ())
    }

    /// Polls the backend for up to `max_batch` incoming packets.
    ///
    /// Returns the number of packets received. Use this instead of
    /// `poll_backend()` to limit per-iteration work and ensure fairness
    /// with other select! arms.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails.
    pub fn poll_backend_batch(&mut self, max_batch: usize) -> Result<usize> {
        let mut received = 0;

        let Some(backend) = self.backend.clone() else {
            return Ok(0);
        };
        let mut backend = backend
            .lock()
            .map_err(|e| VirtioError::Io(format!("Failed to lock backend: {e}")))?;

        while received < max_batch && backend.has_data() {
            // Reuse the per-device scratch buffer instead of allocating a
            // fresh 64 KiB `Vec` per packet — that alloc+dealloc pair was
            // the dominant CPU cost at sustained RX rates. The Vec we push
            // into `rx_buffer` still holds an owned copy (sized to the
            // actual frame length), which is unavoidable while we stage
            // through `rx_buffer`; true readv-to-guest zero-copy is the
            // job of the dedicated net-io worker, not this path.
            let n = backend
                .recv(&mut self.rx_scratch[..])
                .map_err(|e| VirtioError::Io(format!("Recv failed: {e}")))?;

            if n == 0 {
                break;
            }
            let packet = NetPacket::new(self.rx_scratch[..n].to_vec());
            self.rx_packets += 1;
            self.rx_bytes += n as u64;
            self.rx_buffer.push_back(packet);
            received += 1;
        }

        Ok(received)
    }

    /// Inject packets from `rx_buffer` into the guest RX virtqueue.
    ///
    /// Drains as many packets as possible from the buffer into guest-provided
    /// descriptors. Returns completions for batch notification.
    /// TODO(ABX-208): Caller should use `push_used_batch()` for single interrupt.
    ///
    /// When `HOST_TSO4/6` was negotiated and a packet exceeds the MTU, the
    /// header is stamped with GSO metadata so the guest kernel can handle
    /// segmentation — a single virtqueue push replaces ~45 small pushes.
    ///
    /// # Errors
    ///
    /// Returns an error if the RX queue is not ready.
    pub fn inject_rx_batch(&mut self, memory: &mut [u8]) -> Result<Vec<(u16, u32)>> {
        let host_tso4 = self.acked_features & Self::FEATURE_HOST_TSO4 != 0;
        let host_tso6 = self.acked_features & Self::FEATURE_HOST_TSO6 != 0;
        let mrg_rxbuf = self.acked_features & Self::FEATURE_MRG_RXBUF != 0;
        let mtu = self.config.mtu as usize;

        let queue = self
            .rx_queue
            .as_mut()
            .ok_or_else(|| VirtioError::NotReady("RX queue not ready".into()))?;

        let mut completions = Vec::new();

        while let Some(mut packet) = self.rx_buffer.pop_front() {
            // If the packet is larger than MTU and TSO was negotiated, stamp
            // the virtio-net header so the guest kernel segments it.
            if packet.data.len() > mtu && packet.header.gso_type == VirtioNetHeader::GSO_NONE {
                if host_tso4 {
                    packet.header.gso_type = VirtioNetHeader::GSO_TCPV4;
                    packet.header.gso_size = Self::DEFAULT_TSO_MSS;
                    packet.header.hdr_len = Self::ETH_IP_TCP_HDR_LEN;
                } else if host_tso6 {
                    packet.header.gso_type = VirtioNetHeader::GSO_TCPV6;
                    packet.header.gso_size = Self::DEFAULT_TSO_MSS;
                    packet.header.hdr_len = Self::ETH_IP_TCP_HDR_LEN;
                }
            }

            let header_bytes = packet.header.to_bytes();
            let full_frame_len = header_bytes.len() + packet.data.len();
            let mut frame = Vec::with_capacity(full_frame_len);
            frame.extend_from_slice(&header_bytes);
            frame.extend_from_slice(&packet.data);

            // Collect chains until we either have enough capacity for the
            // whole frame or the guest runs out of posted buffers. When
            // MRG_RXBUF wasn't negotiated we stop at one chain — the guest
            // driver won't accept multi-buffer delivery.
            let mut chains: Vec<(u16, Vec<Descriptor>)> = Vec::new();
            let mut capacity = 0usize;
            while capacity < frame.len() {
                match queue.pop_avail() {
                    Some((head_idx, chain)) => {
                        let descs: Vec<Descriptor> = chain.copied().collect();
                        capacity += descs
                            .iter()
                            .filter(|d| d.is_write_only())
                            .map(|d| d.len as usize)
                            .sum::<usize>();
                        chains.push((head_idx, descs));
                    }
                    None => break,
                }
                if !mrg_rxbuf {
                    break;
                }
            }

            if chains.is_empty() {
                // No posted buffers at all — re-queue the packet and bail.
                self.rx_buffer.push_front(packet);
                break;
            }

            // Stamp num_buffers into the first chain's virtio_net_hdr. The
            // field is bytes 10..12 of the 12-byte header we emit with
            // VERSION_1 / MRG_RXBUF. Non-MRG_RXBUF guests ignore it.
            let num_buffers = chains.len() as u16;
            frame[10..12].copy_from_slice(&num_buffers.to_le_bytes());

            // Write the frame across every chain. Each chain's used-ring
            // entry reports how many bytes landed in that chain's buffers.
            let mut written = 0usize;
            let mut out_of_bounds = false;
            let mut per_chain: Vec<(u16, u32)> = Vec::with_capacity(chains.len());
            for (head_idx, descs) in chains {
                let mut chain_written = 0usize;
                for desc in descs {
                    if !desc.is_write_only() {
                        continue;
                    }
                    let remaining = frame.len().saturating_sub(written);
                    let to_write = remaining.min(desc.len as usize);
                    if to_write == 0 {
                        continue;
                    }
                    let start = desc.addr as usize;
                    let end = start + to_write;
                    if end > memory.len() {
                        out_of_bounds = true;
                        break;
                    }
                    memory[start..end].copy_from_slice(&frame[written..written + to_write]);
                    written += to_write;
                    chain_written += to_write;
                }
                if out_of_bounds {
                    break;
                }
                per_chain.push((head_idx, chain_written as u32));
            }

            if out_of_bounds {
                // Some descriptor pointed outside guest RAM — the packet is
                // lost for correctness, but we still have to publish the
                // consumed chains to the used ring (the guest has already
                // handed them over). Publish with len=0 so the guest
                // re-uses the buffers without surfacing garbage data.
                for (head_idx, _) in per_chain {
                    completions.push((head_idx, 0));
                }
                continue;
            }

            if written < frame.len() {
                tracing::warn!(
                    "virtio-net RX: truncated {}-byte frame to {} bytes ({} chains, mrg_rxbuf={})",
                    frame.len(),
                    written,
                    per_chain.len(),
                    mrg_rxbuf,
                );
            }

            completions.extend(per_chain);
        }

        Ok(completions)
    }

    // =====================================================================
    // Custom-VMM hot path
    // =====================================================================
    //
    // The methods below are the device-side of what used to be
    // `DeviceManager::handle_net_tx` / `handle_bridge_tx` /
    // `poll_bridge_rx` / `write_net_tx_frame` in arcbox-vmm. They depend
    // on a bound `DeviceCtx` (guest memory + IRQ trigger) and, for TX and
    // raw-frame writes, a bound `NetPort` (host fd + TX cursor).
    //
    // Each method is a no-op (returns empty / false) when its prerequisites
    // aren't bound — that keeps the device usable on the VZ backend without
    // gating every call site.

    /// Drains the TX virtqueue: walks descriptor chains starting from the
    /// current TX cursor up to the guest's latest `avail_idx`, concatenates
    /// each chain's read-flagged descriptors into a packet, runs `finalize`
    /// to complete any guest-requested checksum offload, strips the
    /// virtio-net header, and writes the raw Ethernet frame to the bound
    /// host fd. Returns `(head_idx, total_len_including_header)` for each
    /// drained chain so the caller can advance the used ring.
    ///
    /// `finalize` is injected so arcbox-virtio doesn't depend on
    /// arcbox-net's checksum helpers.
    pub fn drain_tx_queue<F>(&self, qcfg: &QueueConfig, finalize: F) -> Vec<(u16, u32)>
    where
        F: Fn(&mut [u8]),
    {
        let Some(port) = self.port.get() else {
            return Vec::new();
        };
        let Some(ctx) = self.ctx.as_ref() else {
            return Vec::new();
        };
        if !qcfg.ready || qcfg.size == 0 {
            return Vec::new();
        }
        let host_fd = port.host_fd;

        // Translate GPAs to slice offsets (checked against ram base).
        let gpa_base = qcfg.gpa_base as usize;
        let Some(desc_addr) = (qcfg.desc_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "VirtioNet::handle_tx: desc GPA {:#x} below ram base {:#x}",
                qcfg.desc_addr,
                gpa_base
            );
            return Vec::new();
        };
        let Some(avail_addr) = (qcfg.avail_addr as usize).checked_sub(gpa_base) else {
            tracing::warn!(
                "VirtioNet::handle_tx: avail GPA {:#x} below ram base {:#x}",
                qcfg.avail_addr,
                gpa_base
            );
            return Vec::new();
        };
        let q_size = qcfg.size as usize;

        // SAFETY: `ctx.mem` was constructed from the VM-lifetime guest RAM
        // mmap. Each slice view is short-lived and never escapes this
        // function; the wider aliasing concern is documented on the
        // `GuestMemWriter` type.
        let Some(memory) = (unsafe { ctx.mem.slice_mut(gpa_base, ctx.mem.len()) }) else {
            return Vec::new();
        };

        if avail_addr + 4 > memory.len() {
            return Vec::new();
        }
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        let mut current_avail = port.last_avail_tx.load(Ordering::Relaxed);
        let mut completions = Vec::new();

        while current_avail != avail_idx {
            let ring_off = avail_addr + 4 + 2 * ((current_avail as usize) % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]) as usize;

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

                // WRITE flag clear = read-only (guest → host). TX descriptors
                // are always read-only.
                if flags & 2 == 0 && addr + len <= memory.len() {
                    packet_data.extend_from_slice(&memory[addr..addr + len]);
                }
                if flags & 1 == 0 {
                    break;
                }
                idx = next as usize;
            }

            let total_len = packet_data.len() as u32;
            finalize(&mut packet_data);

            // Strip the virtio-net header after applying checksum offload.
            if packet_data.len() > VirtioNetHeader::SIZE {
                let frame = &packet_data[VirtioNetHeader::SIZE..];
                // Retry briefly on EAGAIN/ENOBUFS: the host-side socketpair
                // peer (datapath classifier) might be behind by a few frames
                // under bulk bursts (iperf3 -R and similar). Without this
                // retry, guest TCP sees silent packet loss and retransmits,
                // collapsing throughput to under 1 MB/s while the fast-path
                // can do ~1 GB/s.
                let mut retries = 0;
                loop {
                    // SAFETY: `host_fd` is owned by the caller via `NetPort`;
                    // `frame` is a valid slice borrowed from `packet_data`
                    // for the duration of the write.
                    let n = unsafe {
                        libc::write(host_fd, frame.as_ptr().cast::<libc::c_void>(), frame.len())
                    };
                    if n >= 0 {
                        break;
                    }
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EAGAIN | libc::ENOBUFS) if retries < 64 => {
                            // Yield so the peer thread can drain, then retry.
                            std::thread::yield_now();
                            retries += 1;
                        }
                        Some(libc::EAGAIN | libc::ENOBUFS) => {
                            // Peer is persistently slow — drop the frame.
                            // Guest TCP will retransmit.
                            break;
                        }
                        _ => {
                            tracing::warn!("VirtioNet TX write failed: {err}");
                            break;
                        }
                    }
                }
            }

            completions.push((head_idx as u16, total_len));
            current_avail = current_avail.wrapping_add(1);
        }

        port.last_avail_tx.store(current_avail, Ordering::Relaxed);
        completions
    }

    /// Writes a raw Ethernet frame (without virtio-net header) directly to
    /// the bound host fd. Intended for out-of-band injection paths; no-op
    /// if the port is unbound.
    pub fn write_tx_frame(&self, frame: &[u8]) {
        let Some(port) = self.port.get() else {
            return;
        };
        // SAFETY: `port.host_fd` is live for as long as `self.port` holds
        // the `NetPort`; `frame` is a caller-provided valid slice.
        let n = unsafe {
            libc::write(
                port.host_fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN) {
                tracing::warn!("VirtioNet::write_tx_frame failed: {err}");
            }
        }
    }

    /// Polls the bound host fd for inbound Ethernet frames and injects up
    /// to 64 of them into the RX virtqueue described by `rx_qcfg`. Prepends
    /// a zeroed 12-byte virtio-net header to each frame. Returns `true` if
    /// any frame was injected, so the caller can fire the used-ring IRQ.
    ///
    /// The caller is responsible for building `rx_qcfg` from the device's
    /// MMIO state and gating on DRIVER_OK.
    #[allow(clippy::too_many_lines)]
    pub fn poll_rx(&self, rx_qcfg: &QueueConfig) -> bool {
        let Some(port) = self.port.get() else {
            return false;
        };
        let Some(ctx) = self.ctx.as_ref() else {
            return false;
        };
        if !rx_qcfg.ready || rx_qcfg.size == 0 {
            return false;
        }
        let host_fd = port.host_fd;
        let gpa_base = rx_qcfg.gpa_base as usize;

        // SAFETY: `ctx.mem` was constructed from the VM-lifetime guest RAM
        // mmap. Each slice view is short-lived.
        let Some(guest_mem) = (unsafe { ctx.mem.slice_mut(gpa_base, ctx.mem.len()) }) else {
            return false;
        };

        // Translate GPAs to slice offsets (checked against ram base).
        let Some(desc_addr) = (rx_qcfg.desc_addr as usize).checked_sub(gpa_base) else {
            return false;
        };
        let Some(avail_addr) = (rx_qcfg.avail_addr as usize).checked_sub(gpa_base) else {
            return false;
        };
        let Some(used_addr) = (rx_qcfg.used_addr as usize).checked_sub(gpa_base) else {
            return false;
        };
        let q_size = rx_qcfg.size as usize;

        if avail_addr + 4 > guest_mem.len() {
            return false;
        }

        let mut injected = false;
        let used_idx_off = used_addr + 2;
        let mut used_idx =
            u16::from_le_bytes([guest_mem[used_idx_off], guest_mem[used_idx_off + 1]]);

        for _ in 0..64 {
            // Re-read avail_idx each iteration so newly posted buffers are
            // picked up without waiting for the next poll cycle.
            std::sync::atomic::fence(Ordering::Acquire);
            let avail_idx =
                u16::from_le_bytes([guest_mem[avail_addr + 2], guest_mem[avail_addr + 3]]);

            if avail_idx == used_idx {
                break;
            }

            // Non-blocking read from the bound fd.
            let mut buf = [0u8; 9216]; // MAX_FRAME_SIZE
            // SAFETY: `host_fd` is owned by the bound `NetPort`. `buf` is a
            // valid mutable stack slice of `buf.len()` bytes. MSG_DONTWAIT
            // ensures non-blocking.
            let n = unsafe {
                libc::recv(
                    host_fd,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                break;
            }
            let frame = &buf[..n as usize];

            // Prepend 12-byte virtio-net header (all zeros = no offload).
            let virtio_hdr = [0u8; 12];
            let total = virtio_hdr.len() + frame.len();

            // Pop an available RX descriptor and write header + frame.
            let ring_off = avail_addr + 4 + 2 * ((used_idx as usize) % q_size);
            if ring_off + 2 > guest_mem.len() {
                break;
            }
            let head_idx =
                u16::from_le_bytes([guest_mem[ring_off], guest_mem[ring_off + 1]]) as usize;

            let mut written = 0;
            let mut idx = head_idx;
            for _ in 0..q_size {
                let d_off = desc_addr + idx * 16;
                if d_off + 16 > guest_mem.len() {
                    break;
                }
                let addr_gpa =
                    u64::from_le_bytes(guest_mem[d_off..d_off + 8].try_into().unwrap()) as usize;
                let len = u32::from_le_bytes(guest_mem[d_off + 8..d_off + 12].try_into().unwrap())
                    as usize;
                let flags =
                    u16::from_le_bytes(guest_mem[d_off + 12..d_off + 14].try_into().unwrap());
                let next =
                    u16::from_le_bytes(guest_mem[d_off + 14..d_off + 16].try_into().unwrap());
                let Some(addr) = addr_gpa.checked_sub(gpa_base) else {
                    continue;
                };

                if flags & 2 != 0 && addr + len <= guest_mem.len() {
                    // Scatter from [virtio_hdr | frame] combined.
                    let remaining = total.saturating_sub(written);
                    let to_write = remaining.min(len);
                    if to_write > 0 {
                        let hdr_remaining = virtio_hdr.len().saturating_sub(written);
                        if hdr_remaining > 0 {
                            let hdr_write = hdr_remaining.min(to_write);
                            guest_mem[addr..addr + hdr_write]
                                .copy_from_slice(&virtio_hdr[written..written + hdr_write]);
                            if to_write > hdr_write {
                                let frame_write = to_write - hdr_write;
                                guest_mem[addr + hdr_write..addr + hdr_write + frame_write]
                                    .copy_from_slice(&frame[..frame_write]);
                            }
                        } else {
                            let frame_off = written - virtio_hdr.len();
                            guest_mem[addr..addr + to_write]
                                .copy_from_slice(&frame[frame_off..frame_off + to_write]);
                        }
                        written += to_write;
                    }
                }

                if flags & 1 == 0 || written >= total {
                    break;
                }
                idx = next as usize;
            }

            if written == 0 {
                continue;
            }

            // Update used ring.
            let used_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_entry + 8 <= guest_mem.len() {
                guest_mem[used_entry..used_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                guest_mem[used_entry + 4..used_entry + 8]
                    .copy_from_slice(&(written as u32).to_le_bytes());
                std::sync::atomic::fence(Ordering::Release);
                used_idx = used_idx.wrapping_add(1);
                guest_mem[used_idx_off..used_idx_off + 2].copy_from_slice(&used_idx.to_le_bytes());
            }

            injected = true;
        }

        // Write avail_event for EVENT_IDX.
        if injected {
            let avail_idx_now =
                u16::from_le_bytes([guest_mem[avail_addr + 2], guest_mem[avail_addr + 3]]);
            let avail_event_off = used_addr + 4 + q_size * 8;
            if avail_event_off + 2 <= guest_mem.len() {
                guest_mem[avail_event_off..avail_event_off + 2]
                    .copy_from_slice(&avail_idx_now.to_le_bytes());
            }
        }

        injected
    }
}

impl VirtioDevice for VirtioNet {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Net
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout (VirtIO 1.1):
        // offset 0: mac (6 bytes)
        // offset 6: status (u16)
        // offset 8: max_virtqueue_pairs (u16)
        // offset 10: mtu (u16)
        let mut config_data = vec![0u8; 12];
        config_data[0..6].copy_from_slice(&self.config.mac);
        config_data[6..8].copy_from_slice(&self.status.to_le_bytes());
        config_data[8..10].copy_from_slice(&self.config.num_queues.to_le_bytes());
        config_data[10..12].copy_from_slice(&self.config.mtu.to_le_bytes());

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Network config is mostly read-only
    }

    fn activate(&mut self) -> Result<()> {
        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;

        let mut rx = VirtQueue::new(256)?;
        let mut tx = VirtQueue::new(256)?;
        rx.set_event_idx(event_idx);
        tx.set_event_idx(event_idx);
        self.rx_queue = Some(rx);
        self.tx_queue = Some(tx);

        // Wire the negotiated offload features into the backend. Without
        // this, we were advertising CSUM/TSO to the guest but never telling
        // the backend's kernel side to accept partial checksums or segmented
        // frames — guests would emit them expecting completion we weren't
        // asking for. Default no-op keeps in-process backends unaffected.
        if let Some(backend) = &self.backend {
            let flags = NetOffloadFlags {
                csum: (self.acked_features & Self::FEATURE_GUEST_CSUM) != 0,
                tso4: (self.acked_features & Self::FEATURE_GUEST_TSO4) != 0,
                tso6: (self.acked_features & Self::FEATURE_GUEST_TSO6) != 0,
                tso_ecn: (self.acked_features & Self::FEATURE_GUEST_ECN) != 0,
                ufo: (self.acked_features & Self::FEATURE_GUEST_UFO) != 0,
            };
            let mut b = backend
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock backend: {e}")))?;
            b.configure_offload(flags)
                .map_err(|e| VirtioError::Io(format!("Failed to configure offload: {e}")))?;

            // 12 bytes for virtio_net_hdr_v1 (what VERSION_1 / MRG_RXBUF use).
            // Legacy (10 bytes) is not supported by any modern guest driver we
            // care about.
            b.set_vnet_hdr_sz(12)
                .map_err(|e| VirtioError::Io(format!("Failed to set vnet_hdr_sz: {e}")))?;
        }

        tracing::info!(
            "VirtIO net activated: MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, MTU={}",
            self.config.mac[0],
            self.config.mac[1],
            self.config.mac[2],
            self.config.mac[3],
            self.config.mac[4],
            self.config.mac[5],
            self.config.mtu
        );

        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.rx_queue = None;
        self.tx_queue = None;
        self.rx_buffer.clear();
        self.tx_packets = 0;
        self.tx_bytes = 0;
        self.rx_packets = 0;
        self.rx_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn test_net_device_creation() {
        let net = VirtioNet::new(NetConfig::default());
        assert_eq!(net.device_id(), VirtioDeviceId::Net);
        assert!(net.features() & VirtioNet::FEATURE_MAC != 0);
    }

    #[test]
    fn test_net_device_features() {
        let net = VirtioNet::new(NetConfig::default());
        let features = net.features();

        assert!(features & VirtioNet::FEATURE_MAC != 0);
        assert!(features & VirtioNet::FEATURE_MTU != 0);
        assert!(features & VirtioNet::FEATURE_STATUS != 0);
        assert!(features & VirtioNet::FEATURE_CSUM != 0);
        assert!(features & VirtioNet::FEATURE_GUEST_CSUM != 0);
        assert!(features & VirtioNet::FEATURE_VERSION_1 != 0);
    }

    #[test]
    fn test_net_device_ack_features() {
        let mut net = VirtioNet::new(NetConfig::default());

        let requested = VirtioNet::FEATURE_MAC | VirtioNet::FEATURE_MTU;
        net.ack_features(requested);

        assert_eq!(net.acked_features, requested & net.features());
    }

    #[test]
    fn test_net_device_ack_features_unsupported() {
        let mut net = VirtioNet::new(NetConfig::default());

        let unsupported = 1 << 63;
        net.ack_features(unsupported);

        assert_eq!(net.acked_features, 0);
    }

    #[test]
    fn test_mac_address() {
        let config = NetConfig {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ..Default::default()
        };
        let net = VirtioNet::new(config);

        let mut data = [0u8; 6];
        net.read_config(0, &mut data);
        assert_eq!(data, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_read_config_status() {
        let net = VirtioNet::new(NetConfig::default());

        let mut data = [0u8; 2];
        net.read_config(6, &mut data);

        let status = u16::from_le_bytes(data);
        assert_eq!(status, NetStatus::LinkUp as u16);
    }

    #[test]
    fn test_read_config_mtu() {
        let config = NetConfig {
            mtu: 9000,
            ..Default::default()
        };
        let net = VirtioNet::new(config);

        let mut data = [0u8; 2];
        net.read_config(10, &mut data);

        let mtu = u16::from_le_bytes(data);
        assert_eq!(mtu, 9000);
    }

    #[test]
    fn test_read_config_num_queues() {
        let config = NetConfig {
            num_queues: 4,
            ..Default::default()
        };
        let net = VirtioNet::new(config);

        let mut data = [0u8; 2];
        net.read_config(8, &mut data);

        let num_queues = u16::from_le_bytes(data);
        assert_eq!(num_queues, 4);
    }

    #[test]
    fn test_read_config_beyond_end() {
        let net = VirtioNet::new(NetConfig::default());

        let mut data = [0xFFu8; 4];
        net.read_config(100, &mut data);

        // Should not crash.
    }

    #[test]
    fn test_read_config_partial() {
        let net = VirtioNet::new(NetConfig::default());

        let mut data = [0u8; 20];
        net.read_config(0, &mut data);

        assert_eq!(&data[0..6], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_write_config_noop() {
        let mut net = VirtioNet::new(NetConfig::default());

        net.write_config(0, &[0xFF; 6]);

        assert_eq!(net.mac(), &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_net_with_loopback() {
        let mut net = VirtioNet::with_loopback();
        net.activate().unwrap();

        assert!(net.is_link_up());
        assert!(net.backend.is_some());

        assert_eq!(net.tx_stats(), (0, 0));
        assert_eq!(net.rx_stats(), (0, 0));
    }

    #[test]
    fn test_link_status() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert!(net.is_link_up());

        net.set_link_up(false);
        assert!(!net.is_link_up());

        net.set_link_up(true);
        assert!(net.is_link_up());
    }

    #[test]
    fn test_link_status_toggle_multiple() {
        let mut net = VirtioNet::new(NetConfig::default());

        for _ in 0..10 {
            net.set_link_up(false);
            assert!(!net.is_link_up());
            net.set_link_up(true);
            assert!(net.is_link_up());
        }
    }

    #[test]
    fn test_net_activate() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert!(net.rx_queue.is_none());
        assert!(net.tx_queue.is_none());

        net.activate().unwrap();

        assert!(net.rx_queue.is_some());
        assert!(net.tx_queue.is_some());
    }

    #[test]
    fn test_net_reset() {
        let mut net = VirtioNet::with_loopback();
        net.activate().unwrap();

        net.queue_rx(NetPacket::new(vec![1, 2, 3]));
        assert_eq!(net.rx_pending(), 1);

        net.ack_features(VirtioNet::FEATURE_MAC);

        net.reset();

        assert_eq!(net.acked_features, 0);
        assert!(net.rx_queue.is_none());
        assert!(net.tx_queue.is_none());
        assert_eq!(net.rx_pending(), 0);
        assert_eq!(net.tx_stats(), (0, 0));
        assert_eq!(net.rx_stats(), (0, 0));
    }

    #[test]
    fn test_queue_rx() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert_eq!(net.rx_pending(), 0);

        net.queue_rx(NetPacket::new(vec![1, 2, 3]));
        assert_eq!(net.rx_pending(), 1);

        net.queue_rx(NetPacket::new(vec![4, 5, 6]));
        assert_eq!(net.rx_pending(), 2);
    }

    #[test]
    fn test_set_backend() {
        let mut net = VirtioNet::new(NetConfig::default());

        assert!(net.backend.is_none());

        let backend = Arc::new(Mutex::new(LoopbackBackend::new()));
        net.set_backend(backend);

        assert!(net.backend.is_some());
    }

    #[test]
    fn test_poll_backend_no_data() {
        let mut net = VirtioNet::with_loopback();

        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 0);
    }

    #[test]
    fn test_poll_backend_with_data() {
        let mut net = VirtioNet::with_loopback();

        if let Some(backend) = &net.backend {
            let mut backend = backend.lock().unwrap();
            backend.send(&NetPacket::new(vec![1, 2, 3, 4, 5])).unwrap();
        }

        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 1);
        assert_eq!(net.rx_stats(), (1, 5));
    }

    #[test]
    fn test_poll_backend_multiple() {
        let mut net = VirtioNet::with_loopback();

        if let Some(backend) = &net.backend {
            let mut backend = backend.lock().unwrap();
            for i in 0..5 {
                backend.send(&NetPacket::new(vec![i; 100])).unwrap();
            }
        }

        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 5);
        assert_eq!(net.rx_stats(), (5, 500));
    }

    #[test]
    fn test_handle_tx_too_small() {
        let mut net = VirtioNet::with_loopback();

        let data = [0u8; 5];
        let result = net.handle_tx(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_net_no_backend() {
        let mut net = VirtioNet::new(NetConfig::default());

        net.poll_backend().unwrap();
        assert_eq!(net.rx_pending(), 0);
    }

    #[test]
    fn test_process_tx_queue_not_ready() {
        let mut net = VirtioNet::new(NetConfig::default());

        let memory = vec![0u8; 1024];
        let result = net.process_tx_queue(&memory);

        assert!(result.is_err());
    }

    #[test]
    fn test_inject_rx_batch_mrg_rxbuf_spans_chains() {
        use arcbox_virtio_core::queue::{Descriptor, flags};
        // With MRG_RXBUF on, a frame larger than a single chain's write-only
        // capacity should consume multiple chains and stamp num_buffers with
        // the chain count in the first chain's virtio_net_hdr.
        let mut net = VirtioNet::with_loopback();
        net.enable_tso_features(); // adds MRG_RXBUF to the advertised set
        net.ack_features(VirtioNet::FEATURE_MRG_RXBUF);
        net.activate().unwrap();

        // Lay out a scratch "guest memory" big enough for header + payload
        // split across two small buffers (32 bytes each of write space).
        let mut memory = vec![0u8; 512];
        let buf0_addr = 128u64;
        let buf1_addr = 256u64;
        let buf_size: u32 = 32;

        {
            let q = net.rx_queue.as_mut().expect("rx queue");
            // Chain 0 at descriptor 0 — single write-only descriptor.
            q.set_descriptor(
                0,
                Descriptor {
                    addr: buf0_addr,
                    len: buf_size,
                    flags: flags::WRITE,
                    next: 0,
                },
            )
            .unwrap();
            // Chain 1 at descriptor 1 — single write-only descriptor.
            q.set_descriptor(
                1,
                Descriptor {
                    addr: buf1_addr,
                    len: buf_size,
                    flags: flags::WRITE,
                    next: 0,
                },
            )
            .unwrap();
            q.add_avail(0).unwrap();
            q.add_avail(1).unwrap();
            q.set_ready(true);
        }

        // Packet payload of 40 bytes; total frame = 12 (header) + 40 = 52
        // which exceeds a single 32-byte buffer → MRG_RXBUF must span.
        let payload = vec![0xABu8; 40];
        net.queue_rx(NetPacket::new(payload));

        let completions = net.inject_rx_batch(&mut memory).unwrap();
        assert_eq!(completions.len(), 2, "frame should span two chains");

        // num_buffers stamped at offset 10..12 in the first chain's header.
        let num_buffers = u16::from_le_bytes([
            memory[buf0_addr as usize + 10],
            memory[buf0_addr as usize + 11],
        ]);
        assert_eq!(num_buffers, 2);
    }

    #[test]
    fn test_inject_rx_batch_no_mrg_rxbuf_stamps_one() {
        use arcbox_virtio_core::queue::{Descriptor, flags};
        // Without MRG_RXBUF, num_buffers should still be set to 1 for spec
        // compliance on VERSION_1 headers, and we should never consume more
        // than one chain even if the frame overflows.
        let mut net = VirtioNet::with_loopback();
        net.activate().unwrap(); // no MRG_RXBUF ack

        let mut memory = vec![0u8; 512];
        let buf_addr = 64u64;

        {
            let q = net.rx_queue.as_mut().expect("rx queue");
            q.set_descriptor(
                0,
                Descriptor {
                    addr: buf_addr,
                    len: 128,
                    flags: flags::WRITE,
                    next: 0,
                },
            )
            .unwrap();
            q.set_descriptor(
                1,
                Descriptor {
                    addr: 300,
                    len: 128,
                    flags: flags::WRITE,
                    next: 0,
                },
            )
            .unwrap();
            q.add_avail(0).unwrap();
            q.add_avail(1).unwrap();
            q.set_ready(true);
        }

        net.queue_rx(NetPacket::new(vec![0xCDu8; 40]));
        let completions = net.inject_rx_batch(&mut memory).unwrap();
        assert_eq!(completions.len(), 1, "must not span without MRG_RXBUF");

        let num_buffers = u16::from_le_bytes([
            memory[buf_addr as usize + 10],
            memory[buf_addr as usize + 11],
        ]);
        assert_eq!(num_buffers, 1);
    }

    #[test]
    fn test_feature_constants() {
        assert_eq!(VirtioNet::FEATURE_CSUM, 1 << 0);
        assert_eq!(VirtioNet::FEATURE_GUEST_CSUM, 1 << 1);
        assert_eq!(VirtioNet::FEATURE_MTU, 1 << 3);
        assert_eq!(VirtioNet::FEATURE_MAC, 1 << 5);
        assert_eq!(VirtioNet::FEATURE_GSO, 1 << 6);
        assert_eq!(VirtioNet::FEATURE_GUEST_TSO4, 1 << 7);
        assert_eq!(VirtioNet::FEATURE_GUEST_TSO6, 1 << 8);
        assert_eq!(VirtioNet::FEATURE_GUEST_ECN, 1 << 9);
        assert_eq!(VirtioNet::FEATURE_GUEST_UFO, 1 << 10);
        assert_eq!(VirtioNet::FEATURE_HOST_TSO4, 1 << 11);
        assert_eq!(VirtioNet::FEATURE_HOST_TSO6, 1 << 12);
        assert_eq!(VirtioNet::FEATURE_HOST_ECN, 1 << 13);
        assert_eq!(VirtioNet::FEATURE_HOST_UFO, 1 << 14);
        assert_eq!(VirtioNet::FEATURE_MRG_RXBUF, 1 << 15);
        assert_eq!(VirtioNet::FEATURE_STATUS, 1 << 16);
        assert_eq!(VirtioNet::FEATURE_CTRL_VQ, 1 << 17);
        assert_eq!(VirtioNet::FEATURE_MQ, 1 << 22);
        assert_eq!(VirtioNet::FEATURE_VERSION_1, 1 << 32);
    }

    #[test]
    fn test_enable_tso_features() {
        let mut net = VirtioNet::new(NetConfig::default());
        let base = net.features();

        assert_eq!(base & VirtioNet::FEATURE_GUEST_TSO4, 0);
        assert_eq!(base & VirtioNet::FEATURE_HOST_TSO4, 0);

        net.enable_tso_features();
        let tso = net.features();
        assert_ne!(tso & VirtioNet::FEATURE_GUEST_TSO4, 0);
        assert_ne!(tso & VirtioNet::FEATURE_GUEST_TSO6, 0);
        assert_ne!(tso & VirtioNet::FEATURE_HOST_TSO4, 0);
        assert_ne!(tso & VirtioNet::FEATURE_HOST_TSO6, 0);
        assert_ne!(tso & VirtioNet::FEATURE_GUEST_ECN, 0);
        assert_ne!(tso & VirtioNet::FEATURE_HOST_ECN, 0);
    }

    #[test]
    fn test_tso_negotiated() {
        let mut net = VirtioNet::new(NetConfig::default());
        net.enable_tso_features();
        assert!(!net.tso_negotiated());

        net.ack_features(
            VirtioNet::FEATURE_MAC
                | VirtioNet::FEATURE_GUEST_TSO4
                | VirtioNet::FEATURE_VERSION_1
                | arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX,
        );
        assert!(net.tso_negotiated());
    }

    #[test]
    fn test_handle_tx_routes_tso_to_send_tso() {
        // Backend that tracks whether send_tso was called.
        struct TsoTracker {
            tso_called: Arc<AtomicBool>,
        }
        impl NetBackend for TsoTracker {
            fn send(&mut self, _packet: &NetPacket) -> std::io::Result<usize> {
                Ok(0)
            }
            fn send_tso(&mut self, _packet: &NetPacket) -> std::io::Result<usize> {
                self.tso_called.store(true, Ordering::Relaxed);
                Ok(0)
            }
            fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
            fn has_data(&self) -> bool {
                false
            }
            fn supports_tso(&self) -> bool {
                true
            }
        }

        let flag = Arc::new(AtomicBool::new(false));
        let tracker = TsoTracker {
            tso_called: flag.clone(),
        };

        let mut net = VirtioNet::new(NetConfig::default());
        net.enable_tso_features();
        net.set_backend(Arc::new(Mutex::new(tracker)));

        // Build a TSO TX packet: 12-byte header + payload.
        let mut data = vec![0u8; VirtioNetHeader::SIZE + 4000];
        data[1] = VirtioNetHeader::GSO_TCPV4; // gso_type
        data[4..6].copy_from_slice(&1460u16.to_le_bytes()); // gso_size

        net.handle_tx(&data).unwrap();
        assert!(
            flag.load(Ordering::Relaxed),
            "send_tso should be called for TSO packets"
        );
    }

    #[test]
    fn test_handle_tx_normal_packet_uses_send() {
        struct SendTracker {
            send_called: Arc<AtomicBool>,
        }
        impl NetBackend for SendTracker {
            fn send(&mut self, _packet: &NetPacket) -> std::io::Result<usize> {
                self.send_called.store(true, Ordering::Relaxed);
                Ok(0)
            }
            fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
            fn has_data(&self) -> bool {
                false
            }
        }

        let flag = Arc::new(AtomicBool::new(false));
        let tracker = SendTracker {
            send_called: flag.clone(),
        };

        let mut net = VirtioNet::new(NetConfig::default());
        net.set_backend(Arc::new(Mutex::new(tracker)));

        let data = vec![0u8; VirtioNetHeader::SIZE + 100];
        net.handle_tx(&data).unwrap();
        assert!(
            flag.load(Ordering::Relaxed),
            "send should be called for normal packets"
        );
    }
}
