//! Shared VirtIO queue helper functions used by both the block I/O
//! worker and the net-io RX worker.

use std::sync::atomic::Ordering;

use crate::blk_worker::GuestMemWriter;

/// Reads the `used.idx` field from the used ring in guest memory.
pub fn read_used_idx(guest_mem: &GuestMemWriter, used_gpa: u64) -> u16 {
    guest_mem.read_u16(used_gpa as usize + 2)
}

/// Writes a single used ring entry (id + len) and bumps `used.idx`.
///
/// The `Release` fence ensures the entry data is visible to the guest
/// before it sees the index advance.
pub fn write_used_entry(
    guest_mem: &GuestMemWriter,
    used_gpa: u64,
    queue_size: u16,
    head_idx: u16,
    total_bytes: u32,
) {
    let used_idx = read_used_idx(guest_mem, used_gpa);
    let entry_off = used_gpa as usize + 4 + ((used_idx as usize) % (queue_size as usize)) * 8;
    guest_mem.write_u32(entry_off, head_idx as u32);
    guest_mem.write_u32(entry_off + 4, total_bytes);
    std::sync::atomic::fence(Ordering::Release);
    guest_mem.write_u16(used_gpa as usize + 2, used_idx.wrapping_add(1));
}

/// Checks whether the guest wants an interrupt (EVENT_IDX suppression).
///
/// Implements VirtIO spec section 2.7.7.2: the device should only
/// notify when `new_used - used_event - 1 < new_used - old_used`.
///
/// `used_event` is read from the avail ring at offset
/// `avail_gpa + 4 + 2 * queue_size` (the EVENT_IDX field).
pub fn should_notify(
    guest_mem: &GuestMemWriter,
    avail_gpa: u64,
    queue_size: u16,
    old_used: u16,
    new_used: u16,
) -> bool {
    if old_used == new_used {
        return false;
    }
    let used_event_off = avail_gpa as usize + 4 + 2 * (queue_size as usize);
    let used_event = guest_mem.read_u16(used_event_off);
    new_used.wrapping_sub(used_event).wrapping_sub(1) < new_used.wrapping_sub(old_used)
}
