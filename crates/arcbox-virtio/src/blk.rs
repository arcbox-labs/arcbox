//! VirtIO block device (virtio-blk).
//!
//! Implements the VirtIO block device specification for disk I/O.
//!
//! Supports:
//! - Synchronous I/O with standard file operations
//! - Asynchronous I/O with tokio
//! - Direct I/O (O_DIRECT) for bypassing OS cache
//! - Memory-mapped I/O for zero-copy operations

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::error::{Result, VirtioError};
use crate::queue::{Descriptor, VirtQueue};
use crate::{VirtioDevice, VirtioDeviceId};

// ============================================================================
// Async Block Backend Trait
// ============================================================================

/// Async block I/O backend trait.
#[async_trait::async_trait]
pub trait AsyncBlockBackend: Send + Sync {
    /// Reads data from the given sector.
    async fn read(&self, sector: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Writes data to the given sector.
    async fn write(&self, sector: u64, buf: &[u8]) -> std::io::Result<usize>;

    /// Flushes pending writes.
    async fn flush(&self) -> std::io::Result<()>;

    /// Returns the capacity in sectors.
    fn capacity(&self) -> u64;

    /// Returns whether the device is read-only.
    fn is_read_only(&self) -> bool;
}

// ============================================================================
// Direct I/O Backend (Linux)
// ============================================================================

/// Direct I/O block backend using O_DIRECT.
#[cfg(target_os = "linux")]
pub struct DirectIoBackend {
    /// File descriptor.
    fd: std::os::unix::io::RawFd,
    /// Capacity in sectors.
    capacity: u64,
    /// Block size.
    block_size: u32,
    /// Read-only mode.
    read_only: bool,
}

#[cfg(target_os = "linux")]
impl DirectIoBackend {
    /// Creates a new direct I/O backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened with O_DIRECT.
    pub fn new(path: &std::path::Path, read_only: bool) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;

        let flags = if read_only {
            libc::O_RDONLY | libc::O_DIRECT | libc::O_CLOEXEC
        } else {
            libc::O_RDWR | libc::O_DIRECT | libc::O_CLOEXEC
        };

        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let fd = unsafe { libc::open(path_cstr.as_ptr(), flags, 0o644) };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Get file size
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd, &mut stat) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        let capacity = stat.st_size as u64 / 512;

        tracing::info!("Opened {} with O_DIRECT, capacity={} sectors", path.display(), capacity);

        Ok(Self {
            fd,
            capacity,
            block_size: 512,
            read_only,
        })
    }

    /// Reads data at the given offset using pread.
    pub fn pread(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe {
            libc::pread(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                offset as libc::off_t,
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Writes data at the given offset using pwrite.
    pub fn pwrite(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
        if self.read_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Device is read-only",
            ));
        }

        let ret = unsafe {
            libc::pwrite(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                offset as libc::off_t,
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Syncs the file to disk.
    pub fn sync(&self) -> std::io::Result<()> {
        let ret = unsafe { libc::fdatasync(self.fd) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for DirectIoBackend {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

// ============================================================================
// Async File Backend (Cross-platform)
// ============================================================================

/// Async file-based block backend using tokio.
pub struct AsyncFileBackend {
    /// Path to the backing file.
    path: PathBuf,
    /// Capacity in sectors.
    capacity: u64,
    /// Block size.
    block_size: u32,
    /// Read-only mode.
    read_only: bool,
}

impl AsyncFileBackend {
    /// Creates a new async file backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn new(path: impl Into<PathBuf>, read_only: bool) -> std::io::Result<Self> {
        let path = path.into();

        let file = std::fs::File::open(&path)?;
        let metadata = file.metadata()?;
        let capacity = metadata.len() / 512;

        tracing::info!("Created async file backend: {}, capacity={} sectors", path.display(), capacity);

        Ok(Self {
            path,
            capacity,
            block_size: 512,
            read_only,
        })
    }

    /// Performs async read.
    pub async fn async_read(&self, sector: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let mut file = tokio::fs::File::open(&self.path).await?;
        let offset = sector * u64::from(self.block_size);
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.read(buf).await
    }

    /// Performs async write.
    pub async fn async_write(&self, sector: u64, buf: &[u8]) -> std::io::Result<usize> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};

        if self.read_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Device is read-only",
            ));
        }

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .await?;

        let offset = sector * u64::from(self.block_size);
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.write(buf).await
    }

    /// Performs async flush.
    pub async fn async_flush(&self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .await?;
        file.flush().await?;
        file.sync_all().await
    }
}

// ============================================================================
// Memory-Mapped I/O Backend
// ============================================================================

/// Memory-mapped I/O backend for zero-copy operations.
pub struct MmapBackend {
    /// Mapped memory pointer.
    ptr: *mut u8,
    /// Size of the mapping.
    size: usize,
    /// Read-only mode.
    read_only: bool,
}

unsafe impl Send for MmapBackend {}
unsafe impl Sync for MmapBackend {}

impl MmapBackend {
    /// Creates a new memory-mapped backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be mapped.
    pub fn new(path: &std::path::Path, read_only: bool) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)?;

        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        if size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot mmap empty file",
            ));
        }

        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();

        let prot = if read_only {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                prot,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        tracing::info!("Memory-mapped {} at {:p}, size={}", path.display(), ptr, size);

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            read_only,
        })
    }

    /// Returns the capacity in sectors (512 bytes each).
    #[must_use]
    pub fn capacity(&self) -> u64 {
        (self.size / 512) as u64
    }

    /// Reads data at the given offset.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let len = buf.len().min(self.size - offset);
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), len);
        }
        Ok(len)
    }

    /// Writes data at the given offset.
    pub fn write(&self, offset: usize, buf: &[u8]) -> std::io::Result<usize> {
        if self.read_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Mapping is read-only",
            ));
        }

        if offset >= self.size {
            return Ok(0);
        }

        let len = buf.len().min(self.size - offset);
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.ptr.add(offset), len);
        }
        Ok(len)
    }

    /// Syncs the mapping to disk.
    pub fn sync(&self) -> std::io::Result<()> {
        let ret = unsafe { libc::msync(self.ptr as *mut libc::c_void, self.size, libc::MS_SYNC) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Returns a pointer to the mapped memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is used within the valid range.
    #[must_use]
    pub unsafe fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns a mutable pointer to the mapped memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is used within the valid range and
    /// the backend is not read-only.
    #[must_use]
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for MmapBackend {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
        }
    }
}

/// Block device configuration.
#[derive(Debug, Clone)]
pub struct BlockConfig {
    /// Disk capacity in 512-byte sectors.
    pub capacity: u64,
    /// Block size (usually 512).
    pub blk_size: u32,
    /// Path to the backing file/device.
    pub path: PathBuf,
    /// Read-only mode.
    pub read_only: bool,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            capacity: 0,
            blk_size: 512,
            path: PathBuf::new(),
            read_only: false,
        }
    }
}

/// VirtIO block request types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRequestType {
    /// Read request.
    In = 0,
    /// Write request.
    Out = 1,
    /// Flush request.
    Flush = 4,
    /// Get device ID.
    GetId = 8,
    /// Discard request.
    Discard = 11,
    /// Write zeroes request.
    WriteZeroes = 13,
}

impl TryFrom<u32> for BlockRequestType {
    type Error = VirtioError;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::In),
            1 => Ok(Self::Out),
            4 => Ok(Self::Flush),
            8 => Ok(Self::GetId),
            11 => Ok(Self::Discard),
            13 => Ok(Self::WriteZeroes),
            _ => Err(VirtioError::InvalidOperation(format!(
                "Unknown block request type: {}",
                value
            ))),
        }
    }
}

/// VirtIO block request status.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BlockStatus {
    /// Success.
    Ok = 0,
    /// I/O error.
    IoErr = 1,
    /// Unsupported operation.
    Unsupp = 2,
}

/// VirtIO block request header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockRequestHeader {
    /// Request type.
    pub request_type: u32,
    /// Reserved.
    pub reserved: u32,
    /// Sector offset.
    pub sector: u64,
}

impl BlockRequestHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = 16;

    /// Parses header from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            request_type: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            reserved: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            sector: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
        })
    }
}

/// VirtIO block device.
pub struct VirtioBlock {
    config: BlockConfig,
    features: u64,
    acked_features: u64,
    /// Backing file handle.
    file: Option<Arc<RwLock<File>>>,
    /// Request queue.
    queue: Option<VirtQueue>,
    /// Device ID string.
    device_id: String,
}

impl VirtioBlock {
    /// Feature: Maximum segment size.
    pub const FEATURE_SIZE_MAX: u64 = 1 << 1;
    /// Feature: Maximum number of segments.
    pub const FEATURE_SEG_MAX: u64 = 1 << 2;
    /// Feature: Disk geometry.
    pub const FEATURE_GEOMETRY: u64 = 1 << 4;
    /// Feature: Read-only.
    pub const FEATURE_RO: u64 = 1 << 5;
    /// Feature: Block size.
    pub const FEATURE_BLK_SIZE: u64 = 1 << 6;
    /// Feature: Flush command.
    pub const FEATURE_FLUSH: u64 = 1 << 9;
    /// Feature: Topology.
    pub const FEATURE_TOPOLOGY: u64 = 1 << 10;
    /// Feature: Configuration writeback.
    pub const FEATURE_CONFIG_WCE: u64 = 1 << 11;
    /// Feature: Discard command.
    pub const FEATURE_DISCARD: u64 = 1 << 13;
    /// Feature: Write zeroes command.
    pub const FEATURE_WRITE_ZEROES: u64 = 1 << 14;
    /// VirtIO 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << 32;

    /// Creates a new block device.
    #[must_use]
    pub fn new(config: BlockConfig) -> Self {
        let mut features = Self::FEATURE_SIZE_MAX
            | Self::FEATURE_SEG_MAX
            | Self::FEATURE_BLK_SIZE
            | Self::FEATURE_FLUSH
            | Self::FEATURE_VERSION_1;

        if config.read_only {
            features |= Self::FEATURE_RO;
        }

        let device_id = format!(
            "arcbox-blk-{}",
            config
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
        );

        Self {
            config,
            features,
            acked_features: 0,
            file: None,
            queue: None,
            device_id,
        }
    }

    /// Creates a new block device from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or its size cannot be determined.
    pub fn from_path(path: impl Into<PathBuf>, read_only: bool) -> Result<Self> {
        let path = path.into();

        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&path)
            .map_err(|e| VirtioError::Io(format!("Failed to open {}: {}", path.display(), e)))?;

        let metadata = file
            .metadata()
            .map_err(|e| VirtioError::Io(format!("Failed to get metadata: {}", e)))?;

        let capacity = metadata.len() / 512;

        let config = BlockConfig {
            capacity,
            blk_size: 512,
            path: path.clone(),
            read_only,
        };

        let mut device = Self::new(config);
        device.file = Some(Arc::new(RwLock::new(file)));

        tracing::info!(
            "Created block device from {}: capacity={} sectors ({} bytes)",
            path.display(),
            capacity,
            capacity * 512
        );

        Ok(device)
    }

    /// Returns the disk capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.config.capacity * u64::from(self.config.blk_size)
    }

    /// Handles a block request.
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
            BlockRequestType::Discard | BlockRequestType::WriteZeroes => {
                Err(VirtioError::NotSupported("Operation not supported".into()))
            }
        }
    }

    fn handle_read(&self, sector: u64, data: &mut [u8]) -> Result<usize> {
        let file = self.file.as_ref().ok_or_else(|| {
            VirtioError::NotReady("Block device not activated".into())
        })?;

        let mut file = file.write().map_err(|e| {
            VirtioError::Io(format!("Failed to lock file: {}", e))
        })?;

        let offset = sector * u64::from(self.config.blk_size);
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| VirtioError::Io(format!("Seek failed: {}", e)))?;

        let bytes_read = file
            .read(data)
            .map_err(|e| VirtioError::Io(format!("Read failed: {}", e)))?;

        tracing::trace!("Read {} bytes from sector {}", bytes_read, sector);
        Ok(bytes_read)
    }

    fn handle_write(&self, sector: u64, data: &[u8]) -> Result<usize> {
        if self.config.read_only {
            return Err(VirtioError::InvalidOperation("Device is read-only".into()));
        }

        let file = self.file.as_ref().ok_or_else(|| {
            VirtioError::NotReady("Block device not activated".into())
        })?;

        let mut file = file.write().map_err(|e| {
            VirtioError::Io(format!("Failed to lock file: {}", e))
        })?;

        let offset = sector * u64::from(self.config.blk_size);
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| VirtioError::Io(format!("Seek failed: {}", e)))?;

        let bytes_written = file
            .write(data)
            .map_err(|e| VirtioError::Io(format!("Write failed: {}", e)))?;

        tracing::trace!("Wrote {} bytes to sector {}", bytes_written, sector);
        Ok(bytes_written)
    }

    fn handle_flush(&self) -> Result<usize> {
        let file = self.file.as_ref().ok_or_else(|| {
            VirtioError::NotReady("Block device not activated".into())
        })?;

        let file = file.write().map_err(|e| {
            VirtioError::Io(format!("Failed to lock file: {}", e))
        })?;

        file.sync_all()
            .map_err(|e| VirtioError::Io(format!("Flush failed: {}", e)))?;

        tracing::trace!("Flushed block device");
        Ok(0)
    }

    fn handle_get_id(&self, data: &mut [u8]) -> Result<usize> {
        let id_bytes = self.device_id.as_bytes();
        let len = id_bytes.len().min(data.len());
        data[..len].copy_from_slice(&id_bytes[..len]);
        Ok(len)
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

        // First descriptor should contain the header
        let header_desc = &descriptors[0];
        let header_start = header_desc.addr as usize;
        let header_end = header_start + BlockRequestHeader::SIZE;

        if header_end > memory.len() {
            return Err(VirtioError::InvalidQueue("Header out of bounds".into()));
        }

        let header = BlockRequestHeader::from_bytes(&memory[header_start..header_end])
            .ok_or_else(|| VirtioError::InvalidQueue("Failed to parse header".into()))?;

        let request_type = BlockRequestType::try_from(header.request_type)?;

        // Handle based on request type
        match request_type {
            BlockRequestType::In => {
                // Read: write data to guest memory
                // Data descriptors should be writable
                let mut total_bytes = 0;
                let mut current_sector = header.sector;
                for desc in descriptors.iter().skip(1) {
                    if !desc.is_write_only() {
                        continue; // Skip read-only descriptors
                    }
                    if desc.len == 1 {
                        continue; // Status byte
                    }

                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue("Data out of bounds".into()));
                    }

                    // Actually read from disk into guest memory
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
                // Write: read data from guest memory
                let mut total_bytes = 0;
                for desc in descriptors.iter().skip(1) {
                    if desc.is_write_only() {
                        continue; // Skip writable descriptors
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
            BlockRequestType::Flush => {
                match self.handle_flush() {
                    Ok(_) => Ok((0, BlockStatus::Ok)),
                    Err(_) => Ok((0, BlockStatus::IoErr)),
                }
            }
            _ => Ok((0, BlockStatus::Unsupp)),
        }
    }
}

impl VirtioDevice for VirtioBlock {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Block
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout (VirtIO 1.1):
        // offset 0: capacity (u64)
        // offset 8: size_max (u32)
        // offset 12: seg_max (u32)
        // offset 16: geometry (cylinders u16, heads u8, sectors u8)
        // offset 20: blk_size (u32)
        // offset 24: topology...
        let config_data = [
            self.config.capacity.to_le_bytes().as_slice(),
            &(1u32 << 12).to_le_bytes(),  // size_max: 4KB
            &128u32.to_le_bytes(),         // seg_max: 128 segments
            &[0u8; 4],                     // geometry: not used
            &self.config.blk_size.to_le_bytes(),
        ]
        .concat();

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Block device config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // Open backing file if not already open
        if self.file.is_none() && !self.config.path.as_os_str().is_empty() {
            let file = OpenOptions::new()
                .read(true)
                .write(!self.config.read_only)
                .open(&self.config.path)
                .map_err(|e| {
                    VirtioError::Io(format!(
                        "Failed to open {}: {}",
                        self.config.path.display(),
                        e
                    ))
                })?;

            self.file = Some(Arc::new(RwLock::new(file)));
        }

        // Create request queue
        self.queue = Some(VirtQueue::new(256)?);

        tracing::info!("VirtIO block device activated: {:?}", self.config.path);
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.queue = None;
        // Keep file handle open for quick reactivation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ========================================================================
    // Basic VirtioBlock Tests
    // ========================================================================

    #[test]
    fn test_block_device_creation() {
        let config = BlockConfig {
            capacity: 2048,
            blk_size: 512,
            path: PathBuf::from("/tmp/test.img"),
            read_only: false,
        };

        let device = VirtioBlock::new(config);
        assert_eq!(device.capacity_bytes(), 2048 * 512);
    }

    #[test]
    fn test_block_device_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();
        assert_eq!(device.config.capacity, 8); // 4096 / 512
    }

    #[test]
    fn test_block_config_features() {
        let ro_config = BlockConfig {
            capacity: 1024,
            blk_size: 512,
            path: PathBuf::new(),
            read_only: true,
        };

        let device = VirtioBlock::new(ro_config);
        assert!(device.features() & VirtioBlock::FEATURE_RO != 0);
    }

    #[test]
    fn test_request_header_parsing() {
        let bytes = [
            0x00, 0x00, 0x00, 0x00, // type: IN
            0x00, 0x00, 0x00, 0x00, // reserved
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sector: 16
        ];

        let header = BlockRequestHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.request_type, 0);
        assert_eq!(header.sector, 16);
    }

    #[test]
    fn test_read_write() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

        // Write data
        let write_data = b"Hello, VirtIO!";
        device.handle_write(0, write_data).unwrap();

        // Read it back
        let mut read_data = vec![0u8; write_data.len()];
        device.handle_read(0, &mut read_data).unwrap();

        assert_eq!(&read_data, write_data);
    }

    // ========================================================================
    // MmapBackend Tests
    // ========================================================================

    #[test]
    fn test_mmap_backend_creation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 8192]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), false).unwrap();
        assert_eq!(backend.capacity(), 16); // 8192 / 512
    }

    #[test]
    fn test_mmap_backend_read_write() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), false).unwrap();

        // Write data
        let write_data = b"MmapBackend test data!";
        let written = backend.write(0, write_data).unwrap();
        assert_eq!(written, write_data.len());

        // Read it back
        let mut read_data = vec![0u8; write_data.len()];
        let read = backend.read(0, &mut read_data).unwrap();
        assert_eq!(read, write_data.len());
        assert_eq!(&read_data, write_data);
    }

    #[test]
    fn test_mmap_backend_read_at_offset() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 4096];
        data[1024..1034].copy_from_slice(b"TestOffset");
        temp_file.write_all(&data).unwrap();

        let backend = MmapBackend::new(temp_file.path(), true).unwrap();

        let mut buf = vec![0u8; 10];
        backend.read(1024, &mut buf).unwrap();
        assert_eq!(&buf, b"TestOffset");
    }

    #[test]
    fn test_mmap_backend_read_only() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), true).unwrap();

        // Attempt to write should fail
        let result = backend.write(0, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_mmap_backend_read_beyond_bounds() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 1024]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), true).unwrap();

        // Read beyond file size should return 0
        let mut buf = vec![0u8; 100];
        let read = backend.read(2000, &mut buf).unwrap();
        assert_eq!(read, 0);
    }

    #[test]
    fn test_mmap_backend_partial_read() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0xAA; 1024]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), true).unwrap();

        // Read starting near the end
        let mut buf = vec![0u8; 100];
        let read = backend.read(1000, &mut buf).unwrap();
        assert_eq!(read, 24); // Only 24 bytes available
    }

    #[test]
    fn test_mmap_backend_sync() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), false).unwrap();
        backend.write(0, b"sync test").unwrap();

        // Sync should succeed
        assert!(backend.sync().is_ok());
    }

    #[test]
    fn test_mmap_backend_empty_file_fails() {
        let temp_file = NamedTempFile::new().unwrap();
        // Don't write anything - empty file

        let result = MmapBackend::new(temp_file.path(), true);
        assert!(result.is_err());
    }

    // ========================================================================
    // AsyncFileBackend Tests
    // ========================================================================

    #[test]
    fn test_async_file_backend_creation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 8192]).unwrap();

        let backend = AsyncFileBackend::new(temp_file.path(), false).unwrap();
        assert_eq!(backend.capacity, 16); // 8192 / 512
    }

    #[tokio::test]
    async fn test_async_file_backend_read() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 4096];
        data[0..5].copy_from_slice(b"Hello");
        temp_file.write_all(&data).unwrap();

        let backend = AsyncFileBackend::new(temp_file.path(), true).unwrap();

        let mut buf = vec![0u8; 5];
        let read = backend.async_read(0, &mut buf).await.unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf, b"Hello");
    }

    #[tokio::test]
    async fn test_async_file_backend_write() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let backend = AsyncFileBackend::new(temp_file.path(), false).unwrap();

        // Write data
        let written = backend.async_write(0, b"AsyncTest").await.unwrap();
        assert_eq!(written, 9);

        // Read it back
        let mut buf = vec![0u8; 9];
        backend.async_read(0, &mut buf).await.unwrap();
        assert_eq!(&buf, b"AsyncTest");
    }

    #[tokio::test]
    async fn test_async_file_backend_read_only() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let backend = AsyncFileBackend::new(temp_file.path(), true).unwrap();

        // Attempt to write should fail
        let result = backend.async_write(0, b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_file_backend_flush() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let backend = AsyncFileBackend::new(temp_file.path(), false).unwrap();
        backend.async_write(0, b"flush test").await.unwrap();

        // Flush should succeed
        assert!(backend.async_flush().await.is_ok());
    }

    // ========================================================================
    // Edge Cases and Error Handling
    // ========================================================================

    #[test]
    fn test_request_header_too_short() {
        let bytes = [0x00, 0x00, 0x00]; // Too short
        let header = BlockRequestHeader::from_bytes(&bytes);
        assert!(header.is_none());
    }

    #[test]
    fn test_invalid_request_type() {
        let result = BlockRequestType::try_from(999u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_request_types() {
        assert_eq!(BlockRequestType::try_from(0).unwrap(), BlockRequestType::In);
        assert_eq!(BlockRequestType::try_from(1).unwrap(), BlockRequestType::Out);
        assert_eq!(BlockRequestType::try_from(4).unwrap(), BlockRequestType::Flush);
        assert_eq!(BlockRequestType::try_from(8).unwrap(), BlockRequestType::GetId);
        assert_eq!(BlockRequestType::try_from(11).unwrap(), BlockRequestType::Discard);
        assert_eq!(BlockRequestType::try_from(13).unwrap(), BlockRequestType::WriteZeroes);
    }

    #[test]
    fn test_block_device_not_activated() {
        let config = BlockConfig {
            capacity: 1024,
            blk_size: 512,
            path: PathBuf::new(),
            read_only: false,
        };

        let device = VirtioBlock::new(config);

        // Device not activated, no file handle
        let mut buf = vec![0u8; 512];
        let result = device.handle_read(0, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_device_read_only_write() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), true).unwrap();

        // Write should fail for read-only device
        let result = device.handle_write(0, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_block_device_flush() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

        // Flush should succeed
        assert!(device.handle_flush().is_ok());
    }

    #[test]
    fn test_block_device_get_id() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

        let mut buf = vec![0u8; 64];
        let len = device.handle_get_id(&mut buf).unwrap();
        assert!(len > 0);

        let id = String::from_utf8_lossy(&buf[..len]);
        assert!(id.starts_with("arcbox-blk-"));
    }

    #[test]
    fn test_block_device_activate_and_reset() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 4096]).unwrap();

        let mut device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

        // Activate
        device.activate().unwrap();
        assert!(device.queue.is_some());

        // Reset
        device.reset();
        assert!(device.queue.is_none());
        assert_eq!(device.acked_features, 0);
    }

    #[test]
    fn test_block_config_space() {
        let config = BlockConfig {
            capacity: 2048,
            blk_size: 512,
            path: PathBuf::new(),
            read_only: false,
        };

        let device = VirtioBlock::new(config);

        // Read capacity (first 8 bytes)
        let mut buf = [0u8; 8];
        device.read_config(0, &mut buf);
        let capacity = u64::from_le_bytes(buf);
        assert_eq!(capacity, 2048);

        // Read block size (offset 20)
        let mut buf = [0u8; 4];
        device.read_config(20, &mut buf);
        let blk_size = u32::from_le_bytes(buf);
        assert_eq!(blk_size, 512);
    }

    #[test]
    fn test_block_device_large_io() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let size = 1024 * 1024; // 1MB
        temp_file.write_all(&vec![0u8; size]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

        // Write 64KB
        let write_data = vec![0xAB; 65536];
        device.handle_write(0, &write_data).unwrap();

        // Read it back
        let mut read_data = vec![0u8; 65536];
        device.handle_read(0, &mut read_data).unwrap();
        assert_eq!(read_data, write_data);
    }

    #[test]
    fn test_block_device_sector_alignment() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 8192]).unwrap();

        let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

        // Write at sector 2 (offset 1024)
        let write_data = b"Sector2Data";
        device.handle_write(2, write_data).unwrap();

        // Read from sector 2
        let mut read_data = vec![0u8; write_data.len()];
        device.handle_read(2, &mut read_data).unwrap();
        assert_eq!(&read_data, write_data);

        // Verify sector 0 is still zeros
        let mut sector0 = vec![0u8; 512];
        device.handle_read(0, &mut sector0).unwrap();
        assert!(sector0.iter().all(|&b| b == 0));
    }
}
