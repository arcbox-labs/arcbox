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
