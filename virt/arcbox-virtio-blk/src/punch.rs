//! Cross-platform sparse-file zeroing primitives, shared across both block I/O
//! paths (the generic `VirtioBlock::process_descriptor_chain` and the macOS HV
//! `blk_worker`).
//!
//! - [`punch_hole`] deallocates a range so guest `fstrim` / `discard=async`
//!   shrinks the sparse image (DISCARD).
//! - [`zero_range`] makes a range read back as zeros while staying as sparse as
//!   possible — hole-punch the aligned interior, write zeros only on the
//!   unaligned edges (WRITE_ZEROES).

use std::os::unix::io::RawFd;

/// Host filesystem allocation unit used to align hole-punch ranges.
///
/// APFS and modern ext4/btrfs all use 4 KiB blocks; macOS `F_PUNCHHOLE`
/// requires the punch offset and length to be multiples of this, and Linux
/// only frees fully-covered blocks regardless.
pub const PUNCH_HOLE_ALIGNMENT: u64 = 4096;

/// The [`PUNCH_HOLE_ALIGNMENT`]-aligned interior `[aligned_start, aligned_end)`
/// of `[start, end)`, or `None` if the range spans no whole block.
///
/// This is the portion that may be hole-punched; the unaligned head/tail are
/// handled by the caller (DISCARD ignores them as advisory; WRITE_ZEROES zeros
/// them). macOS `F_PUNCHHOLE` rejects unaligned ranges and Linux only frees
/// fully-covered blocks, so punching just the interior is the safe maximum.
fn block_aligned_interior(start: u64, end: u64) -> Option<(u64, u64)> {
    let aligned_start =
        start.saturating_add(PUNCH_HOLE_ALIGNMENT - 1) & !(PUNCH_HOLE_ALIGNMENT - 1);
    let aligned_end = end & !(PUNCH_HOLE_ALIGNMENT - 1);
    (aligned_end > aligned_start).then_some((aligned_start, aligned_end))
}

/// Aligns `[start, end)` inward and returns the `(offset, len)` that may be
/// safely hole-punched (for DISCARD), or `None` if nothing remains.
#[must_use]
pub fn aligned_punch_range(start: u64, end: u64) -> Option<(u64, u64)> {
    block_aligned_interior(start, end).map(|(s, e)| (s, e - s))
}

/// Makes `[start, end)` read back as zeros, kept as sparse as possible.
///
/// The block-aligned interior is hole-punched (zeroed *and* reclaimed), and
/// only the unaligned head/tail are physically written with zeros. This is the
/// WRITE_ZEROES primitive.
///
/// # Errors
/// Propagates I/O errors from the underlying `punch`/`pwrite` syscalls.
pub fn zero_range(fd: RawFd, start: u64, end: u64) -> std::io::Result<()> {
    if end <= start {
        return Ok(());
    }
    match block_aligned_interior(start, end) {
        Some((aligned_start, aligned_end)) => {
            // Hole-punch the aligned interior for sparseness. If the host fs
            // rejects punching (e.g. EOPNOTSUPP), fall back to writing zeros:
            // WRITE_ZEROES requires the range to read back as zero, and the
            // sparse punch is only an optimization, not a requirement.
            if punch_hole(fd, aligned_start, aligned_end - aligned_start).is_err() {
                zero_pwrite(fd, aligned_start, aligned_end)?;
            }
            zero_pwrite(fd, start, aligned_start)?; // head (may be empty)
            zero_pwrite(fd, aligned_end, end)?; // tail (may be empty)
        }
        // No whole block inside the range (< 2 blocks): just write the zeros.
        None => zero_pwrite(fd, start, end)?,
    }
    Ok(())
}

/// Writes zeros over `[start, end)` with a single `pwrite`. Only used for the
/// unaligned edges of [`zero_range`] (each strictly smaller than one block) or
/// ranges with no aligned interior, so the temporary buffer stays small.
fn zero_pwrite(fd: RawFd, start: u64, end: u64) -> std::io::Result<()> {
    if end <= start {
        return Ok(());
    }
    let zeros = vec![0u8; (end - start) as usize];
    #[allow(clippy::cast_possible_wrap)]
    let mut off = start as libc::off_t;
    let mut written = 0usize;
    while written < zeros.len() {
        // SAFETY: `zeros[written..]` is a valid buffer; `fd` is writable.
        let n = unsafe {
            libc::pwrite(
                fd,
                zeros[written..].as_ptr().cast::<libc::c_void>(),
                zeros.len() - written,
                off,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "pwrite made no progress while zeroing range",
            ));
        }
        written += n as usize;
        off += n as libc::off_t;
    }
    Ok(())
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

    #[cfg(unix)]
    #[test]
    #[allow(clippy::cast_possible_wrap)] // off_t / pread-return casts on small test sizes
    fn zero_range_zeros_edges_and_reclaims_interior() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;

        // 2 MiB of real data so the ~1 MiB punched interior is well above any
        // host allocation-clumping noise.
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(&vec![0xCDu8; 2 * 1024 * 1024]).unwrap();
        temp.as_file().sync_all().unwrap();
        let fd = temp.as_file().as_raw_fd();
        let before = std::fs::metadata(temp.path()).unwrap().blocks() * 512;

        // Unaligned range [512, 1 MiB + 512): a head edge, a ~1 MiB aligned
        // interior to punch, and a tail edge.
        let (start, end) = (512u64, 1024 * 1024 + 512);
        zero_range(fd, start, end).unwrap();
        temp.as_file().sync_all().unwrap();

        // The whole requested range reads back as zeros (edges + interior)...
        let mut buf = vec![0xFFu8; (end - start) as usize];
        // SAFETY: reading our own file into a sized buffer.
        let n =
            unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), start as libc::off_t) };
        assert_eq!(n, buf.len() as isize);
        assert!(
            buf.iter().all(|&b| b == 0),
            "zeroed range must read back as zeros"
        );

        // ...while data past the range is untouched.
        let mut tail = [0xFFu8; 512];
        // SAFETY: reading our own file into a sized buffer.
        let n =
            unsafe { libc::pread(fd, tail.as_mut_ptr().cast(), tail.len(), end as libc::off_t) };
        assert_eq!(n, 512);
        assert!(
            tail.iter().all(|&b| b == 0xCD),
            "data past the range is intact"
        );

        // The aligned interior was punched (not written), so usage drops by
        // roughly the interior size.
        let after = std::fs::metadata(temp.path()).unwrap().blocks() * 512;
        assert!(
            after < before,
            "interior should be reclaimed: before={before} after={after}"
        );
    }
}
