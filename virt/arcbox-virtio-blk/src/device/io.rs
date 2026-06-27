use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::Descriptor;

use crate::request::{
    BlockRequestHeader, BlockRequestType, BlockStatus, WRITE_ZEROES_FLAG_UNMAP,
    checked_io_byte_range, parse_range_list,
};

use super::VirtioBlock;

impl VirtioBlock {
    /// Handles a block request.
    ///
    /// For DISCARD/WRITE_ZEROES, `data` is the range list (N × 16-byte
    /// `virtio_blk_discard_write_zeroes` entries); the caller passes it as
    /// `&mut` for API uniformity with IN/GET_ID but it is only read.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be processed.
    pub fn handle_request(&self, header: &BlockRequestHeader, data: &mut [u8]) -> Result<usize> {
        let request_type = BlockRequestType::try_from(header.request_type)?;

        match request_type {
            BlockRequestType::In => self.handle_read(header.sector, data),
            BlockRequestType::Out => self.handle_write(header.sector, data),
            BlockRequestType::Flush => self.handle_flush(),
            BlockRequestType::GetId => self.handle_get_id(data),
            BlockRequestType::Discard => self.handle_discard_list(data),
            BlockRequestType::WriteZeroes => self.handle_write_zeroes_list(data),
        }
    }

    /// Reads from disk using pread — no seek, no lock, position-independent.
    pub(super) fn handle_read(&self, sector: u64, data: &mut [u8]) -> Result<usize> {
        let fd = self
            .raw_fd
            .ok_or_else(|| VirtioError::NotReady("Block device not activated".into()))?;

        let (offset, _) = checked_io_byte_range(
            sector,
            data.len(),
            self.config.blk_size,
            self.config.capacity,
        )?;
        #[allow(clippy::cast_possible_wrap)]
        let mut off = offset as libc::off_t;
        let mut read = 0usize;
        while read < data.len() {
            // SAFETY: fd is valid, and `data[read..]` is a valid mutable buffer.
            let n = unsafe {
                libc::pread(
                    fd,
                    data[read..].as_mut_ptr().cast::<libc::c_void>(),
                    data.len() - read,
                    off,
                )
            };
            if n < 0 {
                return Err(VirtioError::Io(format!(
                    "pread failed at sector {}: {}",
                    sector,
                    std::io::Error::last_os_error()
                )));
            }
            if n == 0 {
                return Err(VirtioError::Io(format!(
                    "pread reached EOF before completing sector {sector}"
                )));
            }
            read += n as usize;
            off += n as libc::off_t;
        }
        Ok(data.len())
    }

    /// Writes to disk using pwrite — no seek, no lock, position-independent.
    pub(super) fn handle_write(&self, sector: u64, data: &[u8]) -> Result<usize> {
        if self.config.read_only {
            return Err(VirtioError::InvalidOperation("Device is read-only".into()));
        }

        let fd = self
            .raw_fd
            .ok_or_else(|| VirtioError::NotReady("Block device not activated".into()))?;

        let (offset, _) = checked_io_byte_range(
            sector,
            data.len(),
            self.config.blk_size,
            self.config.capacity,
        )?;
        #[allow(clippy::cast_possible_wrap)]
        let mut off = offset as libc::off_t;
        let mut written = 0usize;
        while written < data.len() {
            // SAFETY: fd is valid, and `data[written..]` is a valid buffer.
            let n = unsafe {
                libc::pwrite(
                    fd,
                    data[written..].as_ptr().cast::<libc::c_void>(),
                    data.len() - written,
                    off,
                )
            };
            if n < 0 {
                return Err(VirtioError::Io(format!(
                    "pwrite failed at sector {}: {}",
                    sector,
                    std::io::Error::last_os_error()
                )));
            }
            if n == 0 {
                return Err(VirtioError::Io(format!(
                    "pwrite made no progress at sector {sector}"
                )));
            }
            written += n as usize;
            off += n as libc::off_t;
        }
        Ok(data.len())
    }

    pub(super) fn handle_flush(&self) -> Result<usize> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| VirtioError::NotReady("Block device not activated".into()))?;

        let file = file
            .write()
            .map_err(|e| VirtioError::Io(format!("Failed to lock file: {e}")))?;

        file.sync_all()
            .map_err(|e| VirtioError::Io(format!("Flush failed: {e}")))?;

        tracing::trace!("Flushed block device");
        Ok(0)
    }

    pub(super) fn handle_get_id(&self, data: &mut [u8]) -> Result<usize> {
        let id_bytes = self.device_id.as_bytes();
        let len = id_bytes.len().min(data.len());
        data[..len].copy_from_slice(&id_bytes[..len]);
        Ok(len)
    }

    /// DISCARD reclaims host disk for the named sector ranges by punching holes
    /// in the backing file (`fallocate` PUNCH_HOLE on Linux, `F_PUNCHHOLE` on
    /// macOS). This is what makes guest `fstrim` / `discard=async` actually
    /// shrink the sparse data image instead of growing forever.
    ///
    /// Under the virtio-blk spec DISCARD is advisory — the device "MAY" reclaim
    /// storage but the guest must not rely on it. So a punch *failure* is logged
    /// and swallowed rather than failing the request: the blocks are already
    /// logically free in the guest either way, and failing would only break the
    /// guest's `fstrim`. Malformed requests still error.
    pub(super) fn handle_discard_list(&self, data: &[u8]) -> Result<usize> {
        if self.config.read_only {
            // Read-only devices don't advertise FEATURE_DISCARD, so this is only
            // reached by a misbehaving guest. DISCARD is advisory — answer OK
            // (no-op) rather than failing the request.
            return Ok(0);
        }

        let fd = self
            .raw_fd
            .ok_or_else(|| VirtioError::NotReady("Block device not activated".into()))?;
        let block_size = self.config.blk_size;

        for range in parse_range_list(data)? {
            if u64::from(range.num_sectors) > u64::from(Self::MAX_DISCARD_SECTORS) {
                return Err(VirtioError::InvalidOperation(format!(
                    "discard range too large: {} > {}",
                    range.num_sectors,
                    Self::MAX_DISCARD_SECTORS
                )));
            }
            if range.flags != 0 {
                return Err(VirtioError::InvalidOperation(format!(
                    "discard range has reserved flags set: 0x{:x}",
                    range.flags
                )));
            }

            let (start, end) = range.checked_byte_range(block_size, self.config.capacity)?;
            if let Some((offset, len)) = crate::punch::aligned_punch_range(start, end) {
                if let Err(e) = crate::punch::punch_hole(fd, offset, len) {
                    tracing::warn!(
                        sector = range.sector,
                        num_sectors = range.num_sectors,
                        error = %e,
                        "discard hole-punch failed; range left allocated on host"
                    );
                }
            }
        }
        Ok(0)
    }

    /// WRITE_ZEROES must actually zero the indicated sectors — the guest relies
    /// on subsequent reads returning zero.
    /// `MAX_WRITE_ZEROES_SECTORS` caps each range at 1 MiB so the allocation +
    /// syscall count stay predictable; the guest splits larger requests.
    pub(super) fn handle_write_zeroes_list(&self, data: &[u8]) -> Result<usize> {
        if self.config.read_only {
            return Err(VirtioError::InvalidOperation("Device is read-only".into()));
        }

        let fd = self
            .raw_fd
            .ok_or_else(|| VirtioError::NotReady("Block device not activated".into()))?;
        let block_size = self.config.blk_size;

        for range in parse_range_list(data)? {
            if u64::from(range.num_sectors) > u64::from(Self::MAX_WRITE_ZEROES_SECTORS) {
                return Err(VirtioError::InvalidOperation(format!(
                    "write_zeroes range too large: {} > {}",
                    range.num_sectors,
                    Self::MAX_WRITE_ZEROES_SECTORS
                )));
            }
            if range.flags & !WRITE_ZEROES_FLAG_UNMAP != 0 {
                return Err(VirtioError::InvalidOperation(format!(
                    "write_zeroes range has reserved flags set: 0x{:x}",
                    range.flags
                )));
            }
            // Ignore the UNMAP flag: we advertise write_zeroes_may_unmap=0, so
            // the guest must treat the range as zeroed regardless of whether the
            // host implementation chooses to keep it sparse.
            let (start, end) = range.checked_byte_range(block_size, self.config.capacity)?;
            if start == end {
                continue;
            }
            if let Err(e) = crate::punch::zero_range(fd, start, end) {
                return Err(VirtioError::Io(format!(
                    "write_zeroes failed at sector {}: {}",
                    range.sector, e
                )));
            }
        }
        Ok(0)
    }

    /// Processes a descriptor chain from the virtqueue.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_descriptor_chain(
        &self,
        descriptors: &[Descriptor],
        memory: &mut [u8],
    ) -> Result<(usize, BlockStatus)> {
        if descriptors.is_empty() {
            return Err(VirtioError::InvalidQueue("Empty descriptor chain".into()));
        }

        let header_desc = &descriptors[0];
        let header_start = header_desc.addr as usize;
        let header_end = header_start + BlockRequestHeader::SIZE;

        if header_end > memory.len() {
            return Err(VirtioError::InvalidQueue("Header out of bounds".into()));
        }

        let header = BlockRequestHeader::from_bytes(&memory[header_start..header_end])
            .ok_or_else(|| VirtioError::InvalidQueue("Failed to parse header".into()))?;

        let request_type = BlockRequestType::try_from(header.request_type)?;

        match request_type {
            BlockRequestType::In => {
                let mut total_bytes = 0;
                let mut current_sector = header.sector;
                for desc in descriptors.iter().skip(1) {
                    if !desc.is_write_only() {
                        continue;
                    }
                    if desc.len == 1 {
                        continue; // Status byte
                    }

                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue("Data out of bounds".into()));
                    }

                    let data = &mut memory[start..end];
                    match self.handle_read(current_sector, data) {
                        Ok(n) => {
                            total_bytes += n;
                            current_sector += (n as u64) / 512;
                        }
                        Err(_) => return Ok((0, BlockStatus::IoErr)),
                    }
                }
                Ok((total_bytes, BlockStatus::Ok))
            }
            BlockRequestType::Out => {
                let mut total_bytes = 0;
                for desc in descriptors.iter().skip(1) {
                    if desc.is_write_only() {
                        continue;
                    }

                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue("Data out of bounds".into()));
                    }

                    let data = &memory[start..end];
                    match self.handle_write(header.sector + (total_bytes as u64 / 512), data) {
                        Ok(n) => total_bytes += n,
                        Err(_) => return Ok((0, BlockStatus::IoErr)),
                    }
                }
                Ok((total_bytes, BlockStatus::Ok))
            }
            BlockRequestType::Flush => match self.handle_flush() {
                Ok(_) => Ok((0, BlockStatus::Ok)),
                Err(_) => Ok((0, BlockStatus::IoErr)),
            },
            BlockRequestType::Discard | BlockRequestType::WriteZeroes => {
                // Concatenate every read-only payload descriptor — guests are
                // free to split the range list across chained descriptors.
                let mut list: Vec<u8> = Vec::new();
                for desc in descriptors.iter().skip(1) {
                    if desc.is_write_only() {
                        continue;
                    }
                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue("Data out of bounds".into()));
                    }
                    list.extend_from_slice(&memory[start..end]);
                }
                let result = if matches!(request_type, BlockRequestType::Discard) {
                    self.handle_discard_list(&list)
                } else {
                    self.handle_write_zeroes_list(&list)
                };
                match result {
                    Ok(_) => Ok((0, BlockStatus::Ok)),
                    Err(_) => Ok((0, BlockStatus::IoErr)),
                }
            }
            BlockRequestType::GetId => {
                // Write the device ID into the first write-only payload desc.
                for desc in descriptors.iter().skip(1) {
                    if !desc.is_write_only() || desc.len == 1 {
                        continue;
                    }
                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue("Data out of bounds".into()));
                    }
                    match self.handle_get_id(&mut memory[start..end]) {
                        Ok(n) => return Ok((n, BlockStatus::Ok)),
                        Err(_) => return Ok((0, BlockStatus::IoErr)),
                    }
                }
                Ok((0, BlockStatus::IoErr))
            }
        }
    }
}
