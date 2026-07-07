//! On-demand debug snapshot of virtio MMIO devices and their queues.
//!
//! Race-class bugs (a wedged RX ring, a suppressed completion interrupt)
//! are invisible in logs; the diagnosis needs the ring pointers and the
//! kick/interrupt history at the moment of failure. [`DeviceManager::
//! virtio_debug`] captures exactly that as one structured record per
//! device: MMIO register mirror, cumulative counters, and the live
//! avail/used indices (plus the EVENT_IDX slots) read straight from
//! guest memory.
//!
//! HV backend only — under VZ the devices belong to
//! Virtualization.framework and there is nothing to snapshot.

use serde::Serialize;

use super::DeviceManager;

/// Snapshot of one virtqueue: configuration, counters, and live ring
/// indices read from guest memory (`None` when the ring address is
/// unset or out of guest RAM bounds).
#[derive(Debug, Clone, Serialize)]
pub struct QueueDebug {
    /// Queue index within the device.
    pub index: u16,
    /// Ring size negotiated by the driver.
    pub size: u16,
    /// QUEUE_READY state.
    pub ready: bool,
    /// Cumulative guest kicks (QUEUE_NOTIFY writes) for this queue.
    pub kicks: u64,
    /// `avail.idx` — where the guest has published up to.
    pub avail_idx: Option<u16>,
    /// `used.idx` — where the device has completed up to. A persistent
    /// gap behind `avail_idx` means the queue is wedged.
    pub used_idx: Option<u16>,
    /// `avail.flags` (bit 0 = `VRING_AVAIL_F_NO_INTERRUPT`).
    pub avail_flags: Option<u16>,
    /// `used.flags` (bit 0 = `VRING_USED_F_NO_NOTIFY`).
    pub used_flags: Option<u16>,
    /// `used_event` slot (guest → device kick threshold; EVENT_IDX only).
    pub used_event: Option<u16>,
    /// `avail_event` slot (device → guest interrupt threshold; EVENT_IDX
    /// only).
    pub avail_event: Option<u16>,
}

/// Snapshot of one virtio MMIO device.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceDebug {
    /// Device ID within the `DeviceManager`.
    pub id: u32,
    /// Device type (e.g. `VirtioNet`).
    pub device_type: String,
    /// Device name.
    pub name: String,
    /// MMIO device status register (`DeviceStatus` bits).
    pub status: u8,
    /// Pending interrupt reasons (`INT_VRING` / `INT_CONFIG`) not yet
    /// acknowledged by the guest.
    pub interrupt_status: u32,
    /// Whether `VIRTIO_F_EVENT_IDX` was negotiated.
    pub event_idx: bool,
    /// Cumulative interrupts raised by the device.
    pub interrupts: u64,
    /// Configured queues (unconfigured, never-kicked queues are omitted).
    pub queues: Vec<QueueDebug>,
}

impl DeviceManager {
    /// Captures a debug snapshot of every registered virtio MMIO device.
    ///
    /// Purely observational: reads the MMIO mirrors and guest ring
    /// memory, mutates nothing, and reads through poisoned state locks.
    #[must_use]
    pub fn virtio_debug(&self) -> Vec<DeviceDebug> {
        let mut devices: Vec<&super::RegisteredDevice> = self.devices.values().collect();
        devices.sort_by_key(|device| device.info.id.raw());

        devices
            .into_iter()
            .filter_map(|device| {
                let state = device.mmio_state.as_ref()?;
                let state = match state.read() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };

                let event_idx =
                    (state.driver_features & arcbox_virtio::queue::VIRTIO_F_EVENT_IDX) != 0;

                let queues = (0..super::MAX_VIRTQUEUES)
                    .filter(|&qi| {
                        state.queue_num[qi] != 0 || state.queue_ready[qi] || state.kicks[qi] != 0
                    })
                    .map(|qi| {
                        let size = u64::from(state.queue_num[qi]);
                        let avail = state.queue_driver[qi];
                        let used = state.queue_device[qi];
                        QueueDebug {
                            index: qi as u16,
                            size: state.queue_num[qi],
                            ready: state.queue_ready[qi],
                            kicks: state.kicks[qi],
                            avail_flags: self.read_guest_u16(avail),
                            avail_idx: self.read_guest_u16(avail + 2),
                            used_flags: self.read_guest_u16(used),
                            used_idx: self.read_guest_u16(used + 2),
                            // Split-ring trailers (virtio 1.1 §2.6):
                            // used_event lives after the avail ring,
                            // avail_event after the used ring.
                            used_event: event_idx
                                .then(|| self.read_guest_u16(avail + 4 + 2 * size))
                                .flatten(),
                            avail_event: event_idx
                                .then(|| self.read_guest_u16(used + 4 + 8 * size))
                                .flatten(),
                        }
                    })
                    .collect();

                Some(DeviceDebug {
                    id: device.info.id.raw(),
                    device_type: format!("{:?}", device.info.device_type),
                    name: device.info.name.clone(),
                    status: state.status,
                    interrupt_status: state.interrupt_status,
                    event_idx,
                    interrupts: state.interrupts,
                    queues,
                })
            })
            .collect()
    }

    /// Reads a `u16` from guest memory by GPA. Returns `None` when guest
    /// RAM is not set, the address is out of bounds, misaligned, or zero
    /// (ring address never configured).
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "pointer alignment is checked at runtime just above the cast"
    )]
    fn read_guest_u16(&self, gpa: u64) -> Option<u16> {
        let base = self.guest_ram_base?;
        if gpa == 0 {
            return None;
        }
        let offset = gpa.checked_sub(self.guest_ram_gpa)?;
        if offset + 2 > self.guest_ram_size as u64 {
            return None;
        }
        // SAFETY: `base` is the host mapping of guest RAM, valid for
        // `guest_ram_size` bytes for the VM's lifetime; the offset is
        // bounds-checked above.
        let ptr = unsafe { base.add(offset as usize) };
        if ptr as usize % 2 != 0 {
            return None;
        }
        // SAFETY: in-bounds and 2-aligned per the checks above. Volatile
        // because the guest writes these words concurrently.
        Some(unsafe { ptr.cast::<u16>().read_volatile() })
    }
}
