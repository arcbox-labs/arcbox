//! VirtIO entropy device (virtio-rng).
//!
//! Provides random bytes to the guest via /dev/hwrng.
//! This is one of the simplest VirtIO devices — it has a single
//! request queue and no configuration space.

use arcbox_virtio_core::error::VirtioError;
use arcbox_virtio_core::{VirtioDevice, VirtioDeviceId, virtio_bindings};

/// VirtIO entropy (RNG) device.
pub struct VirtioRng {
    /// Device features.
    features: u64,
    /// Whether the device has been activated.
    active: bool,
    /// Last processed avail index for the request queue.
    last_avail: u16,
}

impl VirtioRng {
    /// VirtIO 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// Creates a new VirtIO entropy device.
    pub fn new() -> Self {
        Self {
            features: Self::FEATURE_VERSION_1,
            active: false,
            last_avail: 0,
        }
    }
}

impl Default for VirtioRng {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for VirtioRng {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Rng
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.features &= features;
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        // RNG has no config space.
        for b in data.iter_mut() {
            *b = 0;
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn activate(&mut self) -> arcbox_virtio_core::Result<()> {
        self.active = true;
        tracing::info!("VirtIO RNG activated");
        Ok(())
    }

    fn reset(&mut self) {
        self.active = false;
    }

    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &arcbox_virtio_core::QueueConfig,
    ) -> arcbox_virtio_core::Result<Vec<(u16, u32)>> {
        // Queue 0 is the only queue: guest provides empty write-only
        // buffers, we fill them with random bytes.
        if queue_idx != 0 || !queue_config.ready || queue_config.size == 0 {
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
        let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]);

        let mut current = self.last_avail;
        let mut completions = Vec::new();

        while current != avail_idx {
            let ring_off = avail_addr + 4 + 2 * (current as usize % q_size);
            if ring_off + 2 > memory.len() {
                break;
            }
            let head_idx = u16::from_le_bytes([memory[ring_off], memory[ring_off + 1]]) as usize;

            let mut filled = 0u32;
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

                // RNG buffers are write-only (device fills them).
                if flags & 2 != 0 && addr + len <= memory.len() {
                    // Fill with random bytes from host entropy source. A
                    // zero-fill fallback would hand the guest all-zero bytes
                    // while reporting them as valid entropy — so on failure
                    // we stop filling this chain and let the guest retry via
                    // a short read.
                    if let Err(e) = getrandom::getrandom(&mut memory[addr..addr + len]) {
                        tracing::warn!(
                            "virtio-rng: getrandom failed: {e}; returning short read ({filled} bytes)",
                        );
                        break;
                    }
                    filled += len as u32;
                }

                if flags & 1 == 0 {
                    break;
                }
                idx = next as usize;
            }

            // Update used ring.
            let used_idx_off = used_addr + 2;
            let used_idx = u16::from_le_bytes([memory[used_idx_off], memory[used_idx_off + 1]]);
            let used_entry = used_addr + 4 + ((used_idx as usize) % q_size) * 8;
            if used_entry + 8 <= memory.len() {
                memory[used_entry..used_entry + 4]
                    .copy_from_slice(&(head_idx as u32).to_le_bytes());
                memory[used_entry + 4..used_entry + 8].copy_from_slice(&filled.to_le_bytes());
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                let new_used = used_idx.wrapping_add(1);
                memory[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used.to_le_bytes());
            }

            completions.push((head_idx as u16, filled));
            current = current.wrapping_add(1);
        }

        self.last_avail = current;
        Ok(completions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_device_id() {
        let rng = VirtioRng::new();
        assert_eq!(rng.device_id(), VirtioDeviceId::Rng);
    }

    #[test]
    fn test_rng_default() {
        let rng = VirtioRng::default();
        assert_eq!(rng.device_id(), VirtioDeviceId::Rng);
        assert!(!rng.active);
    }

    #[test]
    fn test_rng_features() {
        let rng = VirtioRng::new();
        assert!(rng.features() & VirtioRng::FEATURE_VERSION_1 != 0);
    }

    #[test]
    fn test_rng_ack_features() {
        let mut rng = VirtioRng::new();
        let original = rng.features();
        rng.ack_features(VirtioRng::FEATURE_VERSION_1);
        assert_eq!(rng.features(), original & VirtioRng::FEATURE_VERSION_1);
    }

    #[test]
    fn test_rng_config_read() {
        let rng = VirtioRng::new();
        let mut data = [0xFFu8; 4];
        rng.read_config(0, &mut data);
        assert_eq!(data, [0, 0, 0, 0]);
    }

    #[test]
    fn test_rng_activate_and_reset() {
        let mut rng = VirtioRng::new();

        assert!(!rng.active);
        rng.activate().unwrap();
        assert!(rng.active);

        rng.reset();
        assert!(!rng.active);
    }
}
