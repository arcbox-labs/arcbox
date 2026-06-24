use arcbox_virtio_core::error::{Result, VirtioError};

/// One entry in a DISCARD / WRITE_ZEROES request's range list. The on-wire
/// struct is `virtio_blk_discard_write_zeroes`: sector (le64), num_sectors
/// (le32), flags (le32) — 16 bytes total.
#[derive(Debug, Clone, Copy)]
pub(super) struct DiscardWriteZeroesRange {
    pub(super) sector: u64,
    pub(super) num_sectors: u32,
    pub(super) flags: u32,
}

const RANGE_ENTRY_SIZE: usize = 16;

pub(super) fn parse_range_list(bytes: &[u8]) -> Result<Vec<DiscardWriteZeroesRange>> {
    if bytes.is_empty() || bytes.len() % RANGE_ENTRY_SIZE != 0 {
        return Err(VirtioError::InvalidOperation(format!(
            "range list size {} not a multiple of 16",
            bytes.len()
        )));
    }
    let mut ranges = Vec::with_capacity(bytes.len() / RANGE_ENTRY_SIZE);
    for chunk in bytes.chunks_exact(RANGE_ENTRY_SIZE) {
        ranges.push(DiscardWriteZeroesRange {
            sector: u64::from_le_bytes(chunk[0..8].try_into().unwrap()),
            num_sectors: u32::from_le_bytes(chunk[8..12].try_into().unwrap()),
            flags: u32::from_le_bytes(chunk[12..16].try_into().unwrap()),
        });
    }
    Ok(ranges)
}
