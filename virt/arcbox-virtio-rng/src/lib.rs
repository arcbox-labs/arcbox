//! VirtIO entropy device (virtio-rng).
//!
//! Provides random bytes to the guest via /dev/hwrng.
//! This is one of the simplest VirtIO devices — it has a single
//! request queue and no configuration space.

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
        queue.set_last_avail_idx(self.last_avail);

        let mut completions = Vec::new();
        while let Some(chain) = queue.pop_avail() {
            let mut filled = 0u32;
            for desc in &chain.descriptors {
                // RNG buffers are write-only (the device fills them).
                if !desc.is_write() || desc.len == 0 {
                    continue;
                }
                // SAFETY: descriptor buffers are device-owned during processing.
                let Some(buf) =
                    (unsafe { queue.mem().slice_mut(desc.addr as usize, desc.len as usize) })
                else {
                    continue;
                };
                // A zero-fill fallback would hand the guest all-zero bytes while
                // reporting them as valid entropy — so on failure we stop filling
                // this chain and let the guest retry via a short read.
                if let Err(e) = getrandom::getrandom(buf) {
                    tracing::warn!(
                        "virtio-rng: getrandom failed: {e}; returning short read ({filled} bytes)",
                    );
                    break;
                }
                filled += desc.len;
            }
            queue.push_used(chain.head_idx, filled);
            completions.push((chain.head_idx, filled));
        }

        self.last_avail = queue.last_avail_idx();
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
    fn test_rng_process_queue_fills_write_buffer() {
        use arcbox_virtio_core::QueueConfig;
        use arcbox_virtio_core::queue::flags;

        const DESC: usize = 0x1000;
        const AVAIL: usize = 0x2000;
        const USED: usize = 0x3000;
        const DATA: usize = 0x4000;

        let mut mem = vec![0u8; 0x8000];
        // desc 0: a single write-only buffer at DATA, length 64.
        mem[DESC..DESC + 8].copy_from_slice(&(DATA as u64).to_le_bytes());
        mem[DESC + 8..DESC + 12].copy_from_slice(&64u32.to_le_bytes());
        mem[DESC + 12..DESC + 14].copy_from_slice(&flags::WRITE.to_le_bytes());
        // avail ring: idx = 1, ring[0] = head descriptor 0.
        mem[AVAIL + 2..AVAIL + 4].copy_from_slice(&1u16.to_le_bytes());
        mem[AVAIL + 4..AVAIL + 6].copy_from_slice(&0u16.to_le_bytes());

        let cfg = QueueConfig {
            desc_addr: DESC as u64,
            avail_addr: AVAIL as u64,
            used_addr: USED as u64,
            size: 4,
            ready: true,
            gpa_base: 0,
        };

        let mut rng = VirtioRng::new();
        let completions = rng.process_queue(0, &mut mem, &cfg).unwrap();
        assert_eq!(completions, vec![(0, 64)]);
        // Used ring advanced by one.
        assert_eq!(u16::from_le_bytes([mem[USED + 2], mem[USED + 3]]), 1);
        // The buffer was filled with entropy (overwhelmingly non-zero).
        assert!(mem[DATA..DATA + 64].iter().any(|&b| b != 0));
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
