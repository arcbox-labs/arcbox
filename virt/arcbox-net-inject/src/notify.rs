//! VirtIO EVENT_IDX notification suppression.

use crate::guest_mem::GuestMemWriter;

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
