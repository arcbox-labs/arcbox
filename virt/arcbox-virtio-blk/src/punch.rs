//! Cross-platform sparse-file hole punching.
//!
//! Shared by the block device's DISCARD handling on both I/O paths: the generic
//! `VirtioBlock::process_descriptor_chain` and the macOS HV `blk_worker`. A
//! DISCARD that lands here deallocates the named range from the backing image,
//! so guest `fstrim` / `discard=async` actually shrinks the sparse file.

use std::os::unix::io::RawFd;

/// Host filesystem allocation unit used to align hole-punch ranges.
///
/// APFS and modern ext4/btrfs all use 4 KiB blocks; macOS `F_PUNCHHOLE`
/// requires the punch offset and length to be multiples of this, and Linux
/// only frees fully-covered blocks regardless.
pub const PUNCH_HOLE_ALIGNMENT: u64 = 4096;

/// Aligns the byte range `[start, end)` inward to [`PUNCH_HOLE_ALIGNMENT`] and
/// returns the `(offset, len)` that may be safely punched, or `None` if nothing
/// remains after alignment.
///
/// Punching only the aligned interior is always correct: the guest already
/// considers the whole range free, and we give up at most one block of reclaim
/// at each edge. It also keeps macOS `F_PUNCHHOLE` (which rejects unaligned
/// ranges) and Linux (which only frees fully-covered blocks) happy.
#[must_use]
pub fn aligned_punch_range(start: u64, end: u64) -> Option<(u64, u64)> {
    let aligned_start =
        start.saturating_add(PUNCH_HOLE_ALIGNMENT - 1) & !(PUNCH_HOLE_ALIGNMENT - 1);
    let aligned_end = end & !(PUNCH_HOLE_ALIGNMENT - 1);
    // `.then(||…)` is lazy: the subtraction only runs when end > start, so it
    // never underflows (e.g. a sub-block range where aligned_end < aligned_start).
    (aligned_end > aligned_start).then(|| (aligned_start, aligned_end - aligned_start))
}

/// Deallocates `[offset, offset + len)` in the file behind `fd`, leaving a
/// sparse hole without changing the file's logical size. `offset` and `len`
/// should be [`PUNCH_HOLE_ALIGNMENT`]-aligned (see [`aligned_punch_range`]).
#[cfg(target_os = "linux")]
pub fn punch_hole(fd: RawFd, offset: u64, len: u64) -> std::io::Result<()> {
    // PUNCH_HOLE must be combined with KEEP_SIZE: free the range but keep EOF.
    let mode = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
    #[allow(clippy::cast_possible_wrap)]
    let (off, length) = (offset as libc::off_t, len as libc::off_t);
    // SAFETY: `fd` is a valid writable descriptor; `off`/`length` are aligned,
    // non-negative, and fit `off_t` (the backing file is at most 8 TiB).
    let ret = unsafe { libc::fallocate(fd, mode, off, length) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn punch_hole(fd: RawFd, offset: u64, len: u64) -> std::io::Result<()> {
    #[allow(clippy::cast_possible_wrap)]
    let mut ph = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: offset as libc::off_t,
        fp_length: len as libc::off_t,
    };
    // SAFETY: `fd` is a valid writable descriptor and `ph` is a fully
    // initialized `fpunchhole_t` that outlives the `fcntl` call.
    let ret = unsafe { libc::fcntl(fd, libc::F_PUNCHHOLE, &mut ph) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn punch_hole(_fd: RawFd, _offset: u64, _len: u64) -> std::io::Result<()> {
    // No portable hole-punch; leave the range allocated (DISCARD is advisory).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_punch_range_skips_sub_block() {
        // A 2 KiB range inside a single 4 KiB block punches nothing.
        assert_eq!(aligned_punch_range(0, 2048), None);
        assert_eq!(aligned_punch_range(1024, 3072), None);
    }

    #[test]
    fn aligned_punch_range_trims_edges_inward() {
        // [2 KiB, 10 KiB) -> aligned interior [4 KiB, 8 KiB) = (4096, 4096).
        assert_eq!(aligned_punch_range(2048, 10 * 1024), Some((4096, 4096)));
        // Already aligned: kept as-is.
        assert_eq!(aligned_punch_range(4096, 12288), Some((4096, 8192)));
    }

    #[cfg(unix)]
    #[test]
    fn punch_hole_reclaims_physical_blocks() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;

        let mut temp = tempfile::NamedTempFile::new().unwrap();
        // Allocate 1 MiB of real (non-zero) data so the host backs it with
        // physical blocks rather than a hole.
        temp.write_all(&vec![0xABu8; 1024 * 1024]).unwrap();
        temp.as_file().sync_all().unwrap();

        let before = std::fs::metadata(temp.path()).unwrap().blocks() * 512;
        assert!(
            before >= 1024 * 1024,
            "expected ~1 MiB allocated before punch, got {before}"
        );

        punch_hole(temp.as_file().as_raw_fd(), 0, 1024 * 1024).unwrap();
        temp.as_file().sync_all().unwrap();

        let after = std::fs::metadata(temp.path()).unwrap().blocks() * 512;
        assert!(
            after < 64 * 1024,
            "expected the hole-punch to free the blocks, still {after} allocated"
        );
    }
}
