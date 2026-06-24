use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId};

use crate::request::FuseResponse;

use super::VirtioFs;

impl VirtioDevice for VirtioFs {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Fs
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout:
        // offset 0: tag (36 bytes, null-padded)
        // offset 36: num_request_queues (u32)
        let mut config_data = vec![0u8; 40];

        let tag_bytes = self.config.tag.as_bytes();
        let tag_len = tag_bytes.len().min(36);
        config_data[..tag_len].copy_from_slice(&tag_bytes[..tag_len]);

        config_data[36..40].copy_from_slice(&self.config.num_queues.to_le_bytes());

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Filesystem config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        if self.activated {
            return Ok(());
        }

        if self.config.shared_dir.is_empty() {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "shared_dir not configured".to_string(),
            });
        }

        if self.config.num_queues == 0 {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "num_queues must be greater than 0".to_string(),
            });
        }

        self.session.reset();

        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;
        let mut queues = Vec::with_capacity(self.config.num_queues as usize);
        for _ in 0..self.config.num_queues {
            let mut q = VirtQueue::new(self.config.queue_size)?;
            q.set_event_idx(event_idx);
            queues.push(q);
        }
        self.request_queues = queues;

        // The FUSE_INIT handshake will happen when the guest driver sends the
        // first request through the virtqueue.
        self.activated = true;

        tracing::info!(
            "VirtIO-FS device activated: tag='{}', shared_dir='{}', queues={}",
            self.config.tag,
            self.config.shared_dir,
            self.config.num_queues
        );

        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.session.reset();
        self.activated = false;
        self.request_queues.clear();

        if let Some(handler) = &self.handler {
            handler.on_destroy();
        }

        tracing::debug!("VirtIO-FS device reset: tag='{}'", self.config.tag);
    }

    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<Vec<(u16, u32)>> {
        // Queue 0 is the hiprio/notification queue — nothing to do for now.
        if queue_idx == 0 {
            return Ok(Vec::new());
        }

        if !queue_config.ready || queue_config.size == 0 {
            return Ok(Vec::new());
        }

        // Read descriptors directly from guest memory (not the internal VirtQueue).
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
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        // Track last processed index per queue. Use a simple field for queue 1.
        let mut current_avail = self.last_avail_idx_q1;
        let mut completions = Vec::new();

        while current_avail != avail_idx {
            let ring_off = avail_addr + 4 + 2 * (current_avail as usize % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]) as usize;

            // Walk descriptor chain: collect request data (read-only) and
            // response buffer locations (write-only).
            let mut request_data = Vec::new();
            let mut write_bufs: Vec<(usize, usize)> = Vec::new();
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

                if flags & arcbox_virtio_core::queue::flags::WRITE != 0 {
                    write_bufs.push((addr, len));
                } else if addr + len <= memory.len() {
                    request_data.extend_from_slice(&memory[addr..addr + len]);
                }

                if flags & arcbox_virtio_core::queue::flags::NEXT == 0 {
                    break;
                }
                idx = next as usize;
            }

            let response = match self.process_request(&request_data) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("VirtioFS FUSE request error: {e}");
                    let unique = if request_data.len() >= 16 {
                        u64::from_le_bytes(request_data[8..16].try_into().unwrap())
                    } else {
                        0
                    };
                    FuseResponse::error(unique, libc::EIO).into_data()
                }
            };

            // Write response into the write-only descriptors.
            let mut resp_offset = 0;
            for &(buf_addr, buf_len) in &write_bufs {
                let remaining = response.len() - resp_offset;
                if remaining == 0 {
                    break;
                }
                let to_write = remaining.min(buf_len);
                if buf_addr + to_write <= memory.len() {
                    memory[buf_addr..buf_addr + to_write]
                        .copy_from_slice(&response[resp_offset..resp_offset + to_write]);
                }
                resp_offset += to_write;
            }

            // Update used ring.
            let used_idx_off = used_addr + 2;
            let used_idx = u16::from_le_bytes([memory[used_idx_off], memory[used_idx_off + 1]]);
            let used_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_entry + 8 <= memory.len() {
                memory[used_entry..used_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                memory[used_entry + 4..used_entry + 8]
                    .copy_from_slice(&(response.len() as u32).to_le_bytes());
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                let new_used = used_idx.wrapping_add(1);
                memory[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used.to_le_bytes());
            }

            // Update avail_event for EVENT_IDX notification — only when negotiated.
            if (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0 {
                let avail_event_off = used_addr + 4 + 8 * q_size;
                if avail_event_off + 2 <= memory.len() {
                    let ae = current_avail.wrapping_add(1).to_le_bytes();
                    memory[avail_event_off] = ae[0];
                    memory[avail_event_off + 1] = ae[1];
                }
            }

            completions.push((head_idx as u16, response.len() as u32));
            current_avail = current_avail.wrapping_add(1);
        }

        self.last_avail_idx_q1 = current_avail;
        Ok(completions)
    }
}
