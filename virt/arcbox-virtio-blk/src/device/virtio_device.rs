use std::fs::OpenOptions;
use std::sync::{Arc, RwLock};

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::{Descriptor, VirtQueue};
use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId};

use super::VirtioBlock;

impl VirtioDevice for VirtioBlock {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Block
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // VirtIO 1.1 `virtio_blk_config` layout:
        //   0:  capacity (u64)
        //   8:  size_max (u32)
        //  12:  seg_max (u32)
        //  16:  geometry (4 bytes)
        //  20:  blk_size (u32)
        //  24:  topology (10 bytes)
        //  34:  num_queues (u16, only with F_MQ)
        //  36:  max_discard_sectors (u32, only with F_DISCARD)
        //  40:  max_discard_seg (u32)
        //  44:  discard_sector_alignment (u32)
        //  48:  max_write_zeroes_sectors (u32, only with F_WRITE_ZEROES)
        //  52:  max_write_zeroes_seg (u32)
        //  56:  write_zeroes_may_unmap (u8)
        //  57:  unused (3 bytes)
        //
        // Guests inspect these fields at probe time before any request is
        // issued, so they must be populated whenever the matching feature is
        // advertised — a zeroed field signals "not supported" and the guest
        // will never emit the op despite the feature bit being set.
        let config_data = [
            self.config.capacity.to_le_bytes().as_slice(),
            &(1u32 << 12).to_le_bytes(), // size_max: 4 KiB
            &128u32.to_le_bytes(),       // seg_max: 128 segments
            &[0u8; 4],                   // geometry: not used
            &self.config.blk_size.to_le_bytes(),
            &[0u8; 10], // topology: not used
            &self.config.num_queues.to_le_bytes(),
            &Self::MAX_DISCARD_SECTORS.to_le_bytes(),
            &1u32.to_le_bytes(), // max_discard_seg: one range per request
            &1u32.to_le_bytes(), // discard_sector_alignment: any sector
            &Self::MAX_WRITE_ZEROES_SECTORS.to_le_bytes(),
            &1u32.to_le_bytes(), // max_write_zeroes_seg
            &[0u8; 4],           // write_zeroes_may_unmap=0 + 3 pad bytes
        ]
        .concat();

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Block device config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        if self.file.is_none() && !self.config.path.as_os_str().is_empty() {
            let file = OpenOptions::new()
                .read(true)
                .write(!self.config.read_only)
                .open(&self.config.path)
                .map_err(|e| {
                    VirtioError::Io(format!(
                        "Failed to open {}: {}",
                        self.config.path.display(),
                        e
                    ))
                })?;

            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();

            // F_NOCACHE is intentionally NOT set for data disks here:
            // container metadata scanning benefits from page-cache warmup, and
            // the pread/pwrite path (no seek, no RwLock) is the primary
            // performance win over the older seek+lock+read pattern.

            self.raw_fd = Some(fd);
            self.file = Some(Arc::new(RwLock::new(file)));
        }

        let event_idx = (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0;
        let mut queue = VirtQueue::new(256)?;
        queue.set_event_idx(event_idx);
        self.queue = Some(queue);

        tracing::info!("VirtIO block device activated: {:?}", self.config.path);
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.queue = None;
        self.last_avail_idx = 0;
        // Keep file handle open for quick reactivation
    }

    fn process_queue(
        &mut self,
        _queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<Vec<(u16, u32)>> {
        if !queue_config.ready || queue_config.size == 0 {
            return Ok(Vec::new());
        }

        // Translate GPAs to slice offsets by subtracting gpa_base (checked to
        // guard against a malicious guest providing a GPA below the RAM base).
        let gpa_base = queue_config.gpa_base as usize;
        let desc_table_addr = (queue_config.desc_addr as usize)
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

        if avail_addr + 4 + 2 * q_size > memory.len() {
            return Err(VirtioError::InvalidQueue("avail ring out of bounds".into()));
        }
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        let last_avail = self.last_avail_idx;

        let mut completions = Vec::new();

        let mut current_avail = last_avail;
        while current_avail != avail_idx {
            let ring_offset = avail_addr + 4 + 2 * ((current_avail as usize) % q_size);
            let head_idx =
                u16::from_le_bytes([memory[ring_offset], memory[ring_offset + 1]]) as usize;

            // Walk the descriptor chain starting at head_idx. Bounded to
            // `q_size` iterations so a cyclic `next` chain (e.g. 0->1->0) from a
            // malformed or malicious guest cannot spin the vCPU thread forever.
            // Any legitimate chain has at most `q_size` descriptors.
            let mut descriptors = Vec::new();
            let mut idx = head_idx;
            for _ in 0..q_size {
                let desc_offset = desc_table_addr + idx * 16;
                if desc_offset + 16 > memory.len() {
                    return Err(VirtioError::InvalidQueue("descriptor out of bounds".into()));
                }
                let raw_gpa =
                    u64::from_le_bytes(memory[desc_offset..desc_offset + 8].try_into().unwrap());
                let addr = match raw_gpa.checked_sub(gpa_base as u64) {
                    Some(a) => a,
                    None => {
                        tracing::warn!(
                            "invalid descriptor GPA {:#x} below ram base {:#x}",
                            raw_gpa,
                            gpa_base
                        );
                        break;
                    }
                };
                let len = u32::from_le_bytes(
                    memory[desc_offset + 8..desc_offset + 12]
                        .try_into()
                        .unwrap(),
                );
                let flags = u16::from_le_bytes(
                    memory[desc_offset + 12..desc_offset + 14]
                        .try_into()
                        .unwrap(),
                );
                let next = u16::from_le_bytes(
                    memory[desc_offset + 14..desc_offset + 16]
                        .try_into()
                        .unwrap(),
                );

                descriptors.push(Descriptor {
                    addr,
                    len,
                    flags,
                    next,
                });

                if flags & arcbox_virtio_core::queue::flags::NEXT == 0 {
                    break;
                }
                idx = next as usize;
                if idx >= q_size {
                    return Err(VirtioError::InvalidQueue(
                        "descriptor next index out of bounds".into(),
                    ));
                }
            }

            let (bytes, status) = self.process_descriptor_chain(&descriptors, memory)?;

            // Write the status byte into the last writable descriptor.
            if let Some(last_wr) = descriptors.iter().rev().find(|d| d.is_write_only()) {
                let status_offset = last_wr.addr as usize + last_wr.len as usize - 1;
                if status_offset < memory.len() {
                    memory[status_offset] = status as u8;
                }
            }

            // Push completion into the used ring.
            let used_idx_offset = used_addr + 2;
            let used_idx =
                u16::from_le_bytes([memory[used_idx_offset], memory[used_idx_offset + 1]]);
            let used_ring_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_ring_entry + 8 <= memory.len() {
                memory[used_ring_entry..used_ring_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                memory[used_ring_entry + 4..used_ring_entry + 8]
                    .copy_from_slice(&(bytes as u32).to_le_bytes());
                // Write barrier: ensure ring entry is visible before idx update.
                // ARM64 weak memory ordering requires this for correct guest observation.
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                let new_used_idx = used_idx.wrapping_add(1);
                memory[used_idx_offset..used_idx_offset + 2]
                    .copy_from_slice(&new_used_idx.to_le_bytes());
            }

            completions.push((head_idx as u16, bytes as u32));
            current_avail = current_avail.wrapping_add(1);
        }

        self.last_avail_idx = current_avail;

        // When VIRTIO_F_EVENT_IDX is negotiated, set avail_event = current
        // avail_idx so the driver notifies on the very next request.
        // avail_event lives at used_ring + 4 + 8 * queue_size.
        if !completions.is_empty()
            && (self.acked_features & arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX) != 0
        {
            let avail_event_offset = used_addr + 4 + 8 * q_size;
            if avail_event_offset + 2 <= memory.len() {
                memory[avail_event_offset..avail_event_offset + 2]
                    .copy_from_slice(&current_avail.to_le_bytes());
            }
        }

        Ok(completions)
    }
}
