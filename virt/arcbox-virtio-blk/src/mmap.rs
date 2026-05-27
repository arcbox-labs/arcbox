//! Memory-mapped block backend (zero-copy reads/writes).

/// Memory-mapped I/O backend for zero-copy operations.
pub struct MmapBackend {
    /// Mapped memory pointer.
    ptr: *mut u8,
    /// Size of the mapping.
    size: usize,
    /// Read-only mode.
    read_only: bool,
}

// SAFETY: the underlying mmap region is shared and we only hand out raw
// pointers behind unsafe accessors; the safe `read`/`write` methods perform
// bounded copies that are safe to invoke from multiple threads.
unsafe impl Send for MmapBackend {}
// SAFETY: see above.
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

        // SAFETY: mmap with NULL hint, valid size, valid fd from `file`. The
        // returned mapping is owned by `Self` and only released in `Drop`.
        let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, libc::MAP_SHARED, fd, 0) };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        tracing::info!(
            "Memory-mapped {} at {:p}, size={}",
            path.display(),
            ptr,
            size
        );

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            read_only,
        })
    }

    /// Returns the capacity in sectors (512 bytes each).
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        (self.size / 512) as u64
    }

    /// Reads data at the given offset.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let len = buf.len().min(self.size - offset);
        // SAFETY: bounds check above guarantees the source range
        // `[offset, offset+len)` is inside the mapping.
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
        // SAFETY: bounds check above guarantees the destination range
        // `[offset, offset+len)` is inside the mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.ptr.add(offset), len);
        }
        Ok(len)
    }

    /// Syncs the mapping to disk.
    pub fn sync(&self) -> std::io::Result<()> {
        // SAFETY: msync over the full mapping we own.
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
    pub const unsafe fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns a mutable pointer to the mapped memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is used within the valid range and
    /// the backend is not read-only.
    #[must_use]
    pub const unsafe fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for MmapBackend {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: unmap the mapping we created in `new`.
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

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

        let write_data = b"MmapBackend test data!";
        let written = backend.write(0, write_data).unwrap();
        assert_eq!(written, write_data.len());

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

        let result = backend.write(0, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_mmap_backend_read_beyond_bounds() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 1024]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), true).unwrap();

        let mut buf = vec![0u8; 100];
        let read = backend.read(2000, &mut buf).unwrap();
        assert_eq!(read, 0);
    }

    #[test]
    fn test_mmap_backend_partial_read() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0xAA; 1024]).unwrap();

        let backend = MmapBackend::new(temp_file.path(), true).unwrap();

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

        assert!(backend.sync().is_ok());
    }

    #[test]
    fn test_mmap_backend_empty_file_fails() {
        let temp_file = NamedTempFile::new().unwrap();

        let result = MmapBackend::new(temp_file.path(), true);
        assert!(result.is_err());
    }
}
