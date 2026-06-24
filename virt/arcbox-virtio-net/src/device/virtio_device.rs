use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{VirtioDevice, VirtioDeviceId};

use crate::backend::NetOffloadFlags;

use super::VirtioNet;

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
