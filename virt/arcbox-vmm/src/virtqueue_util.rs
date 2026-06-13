//! Shared VirtIO queue helper functions used by both the block I/O
//! worker and the net-io RX worker.

use std::sync::atomic::Ordering;

use crate::blk_worker::GuestMemWriter;

/// Core EVENT_IDX notification check (VirtIO spec 2.7.7.2).
///
/// Returns `true` if `used_event` falls in the half-open interval
/// `(old_used, new_used]`.
const fn needs_notification(old_used: u16, new_used: u16, used_event: u16) -> bool {
    new_used.wrapping_sub(used_event).wrapping_sub(1) < new_used.wrapping_sub(old_used)
}

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
    needs_notification(old_used, new_used, used_event)
}

/// Checks whether the guest wants an interrupt, reading `used_event`
/// directly from a guest memory slice.
///
/// This is the slice-based counterpart of [`should_notify`] for callers
/// that already hold a `&mut [u8]` view of guest RAM. If `used_event` is
/// outside the slice bounds, returns `true` (notify rather than miss an
/// event).
pub fn should_notify_slice(
    guest_mem: &[u8],
    avail_gpa: usize,
    queue_size: u16,
    old_used: u16,
    new_used: u16,
) -> bool {
    if old_used == new_used {
        return false;
    }
    let used_event_off = avail_gpa + 4 + 2 * (queue_size as usize);
    if used_event_off.saturating_add(2) > guest_mem.len() {
        return true;
    }
    let used_event = u16::from_le_bytes([guest_mem[used_event_off], guest_mem[used_event_off + 1]]);
    needs_notification(old_used, new_used, used_event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_notify_slice_no_progress() {
        let mem = vec![0u8; 64];
        // old == new => no notification regardless of used_event.
        assert!(!should_notify_slice(&mem, 0, 4, 7, 7));
    }

    #[test]
    fn should_notify_slice_when_used_event_in_range() {
        // Avail ring at GPA 0, size 4: used_event at offset 4 + 2*4 = 12.
        let mut mem = vec![0u8; 64];
        mem[12..14].copy_from_slice(&7u16.to_le_bytes());
        // used_event=7 lies in (5, 10] => notify.
        assert!(should_notify_slice(&mem, 0, 4, 5, 10));
    }

    #[test]
    fn should_notify_slice_when_used_event_already_seen() {
        let mut mem = vec![0u8; 64];
        // used_event=10 is not in (5, 10] => no notify.
        mem[12..14].copy_from_slice(&10u16.to_le_bytes());
        assert!(!should_notify_slice(&mem, 0, 4, 5, 10));
    }

    #[test]
    fn should_notify_slice_out_of_bounds_falls_back_to_notify() {
        let mem = vec![0u8; 8];
        // used_event offset would be past slice end; prefer notifying to
        // avoiding missing an event.
        assert!(should_notify_slice(&mem, 0, 4, 5, 10));
    }
}
