use std::sync::{Arc, Mutex};

use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId};

use crate::backend::LoopbackBackend;

use super::*;

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

        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;
        // SAFETY: `memory` is the guest RAM slice; the queue accesses it only
        // through the GuestMemWriter built here, and `memory` is not touched
        // directly while the queue is alive.
        let mem = std::sync::Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(
                memory.as_mut_ptr(),
                memory.len(),
                queue_config.gpa_base as usize,
            )
        });
        let mut queue =
            arcbox_virtio_core::SplitQueue::new(mem, queue_idx, queue_config, event_idx);
        queue.set_last_avail_idx(self.last_avail_idx_tx as u16);

        let mut completions = Vec::new();
        while let Some(chain) = queue.pop_avail() {
            // Walk the descriptor chain to extract the vsock packet (TX
            // descriptors are read-only, guest→host data).
            let mut packet_data = Vec::new();
            for desc in &chain.descriptors {
                if !desc.is_write() {
                    if let Some(data) = queue.mem().slice(desc.addr as usize, desc.len as usize) {
                        packet_data.extend_from_slice(data);
                    }
                }
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

            queue.push_used(chain.head_idx, packet_data.len() as u32);
            // Always publish avail_event so an isolated TX frame cannot sit
            // undrained behind EVENT_IDX kick suppression (ABX-386).
            queue.write_avail_event();
            completions.push((chain.head_idx, packet_data.len() as u32));
        }

        self.last_avail_idx_tx = queue.last_avail_idx() as usize;
        Ok(completions)
    }
}
