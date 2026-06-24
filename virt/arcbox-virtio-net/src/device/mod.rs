//! `VirtioNet` device — TX/RX queue handling, hot-path drains, `VirtioDevice` impl.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{DeviceCtx, virtio_bindings};

use crate::backend::{LoopbackBackend, NetBackend};
use crate::config::{NetConfig, NetPort, NetStatus};
use crate::header::NetPacket;

/// `VirtIO` network device.
pub struct VirtioNet {
    pub(super) config: NetConfig,
    pub(super) features: u64,
    pub(super) acked_features: u64,
    /// Link status.
    pub(super) status: u16,
    /// Receive queue.
    pub(super) rx_queue: Option<VirtQueue>,
    /// Transmit queue.
    pub(super) tx_queue: Option<VirtQueue>,
    /// Network backend.
    pub(super) backend: Option<Arc<Mutex<dyn NetBackend>>>,
    /// RX buffer.
    pub(super) rx_buffer: VecDeque<NetPacket>,
    /// Persistent scratch buffer for draining backend reads into before
    /// copying to `rx_buffer`. Sized at construction and reused across every
    /// `poll_backend_batch` iteration so we don't heap-allocate 64 KB per
    /// received packet. `Box<[u8]>` rather than `Box<[u8; N]>` so the
    /// initialisation lands straight on the heap (an array literal would
    /// materialise on the stack first).
    pub(super) rx_scratch: Box<[u8]>,
    /// TX statistics.
    pub(super) tx_packets: u64,
    pub(super) tx_bytes: u64,
    /// RX statistics.
    pub(super) rx_packets: u64,
    pub(super) rx_bytes: u64,
    /// Guest memory + interrupt context, shared with the VMM. Optional
    /// because VZ-backed `VirtioNet` instances do not use the custom-VMM
    /// MMIO hot path and never bind one.
    pub(super) ctx: Option<DeviceCtx>,
    /// Host fd + TX cursor. Bound once after the socketpair is created.
    /// `OnceLock` rather than `Mutex<Option<_>>` so the TX hot path reads
    /// both fields without acquiring a lock.
    pub(super) port: OnceLock<NetPort>,
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
}

mod hot_path;
mod tx_rx;
mod virtio_device;

#[cfg(test)]
mod tests;
