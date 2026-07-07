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
        let mut queue = arcbox_virtio_core::SplitQueue::new(mem, queue_idx, queue_config, false);
        queue.set_last_avail_idx(self.last_avail_idx_q1);

        let mut completions = Vec::new();
        while let Some(chain) = queue.pop_avail() {
            // Collect request data (read-only descriptors) and response buffer
            // locations (write-only descriptors, kept as GPA + len).
            let mut request_data = Vec::new();
            let mut write_bufs: Vec<(u64, usize)> = Vec::new();
            for desc in &chain.descriptors {
                if desc.is_write() {
                    write_bufs.push((desc.addr, desc.len as usize));
                } else if let Some(data) = queue.mem().slice(desc.addr as usize, desc.len as usize)
                {
                    request_data.extend_from_slice(data);
                }
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
                // SAFETY: write-only descriptor buffers are device-owned.
                if let Some(buf) = unsafe { queue.mem().slice_mut(buf_addr as usize, to_write) } {
                    buf.copy_from_slice(&response[resp_offset..resp_offset + to_write]);
                }
                resp_offset += to_write;
            }

            // Publish the completion (every chain advances the used ring, even
            // when the FUSE request errored and returned an EIO response, so the
            // used and available rings stay in sync).
            queue.push_used(chain.head_idx, response.len() as u32);
            completions.push((chain.head_idx, response.len() as u32));
        }

        self.last_avail_idx_q1 = queue.last_avail_idx();
        Ok(completions)
    }
}
