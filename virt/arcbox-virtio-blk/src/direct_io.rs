//! Direct I/O block backend (Linux, `O_DIRECT`).

#![cfg(target_os = "linux")]

use std::os::unix::io::RawFd;

/// Direct I/O block backend using `O_DIRECT`.
pub struct DirectIoBackend {
    /// File descriptor.
    fd: RawFd,
    /// Capacity in sectors.
    capacity: u64,
    /// Block size.
    block_size: u32,
    /// Read-only mode.
    read_only: bool,
}

impl DirectIoBackend {
    /// Creates a new direct I/O backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened with `O_DIRECT`.
    pub fn new(path: &std::path::Path, read_only: bool) -> std::io::Result<Self> {
        let flags = if read_only {
            libc::O_RDONLY | libc::O_DIRECT | libc::O_CLOEXEC
        } else {
            libc::O_RDWR | libc::O_DIRECT | libc::O_CLOEXEC
        };

        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        // SAFETY: open() reads the C-string we just constructed; on success it
        // returns a fresh fd we own.
        let fd = unsafe { libc::open(path_cstr.as_ptr(), flags, 0o644) };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: `stat` is zero-initialised plain-old-data; fstat fills it
        // in over the borrow we hand it. On error we close the fd we opened.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd, &mut stat) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        let capacity = stat.st_size as u64 / 512;

        tracing::info!(
            "Opened {} with O_DIRECT, capacity={} sectors",
            path.display(),
            capacity
        );

        Ok(Self {
            fd,
            capacity,
            block_size: 512,
            read_only,
        })
    }

    /// Reads data at the given offset using pread.
    pub fn pread(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: pread writes at most buf.len() bytes into our borrowed buffer.
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

        // SAFETY: pwrite reads buf.len() bytes from our borrowed buffer.
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
        // SAFETY: fdatasync on an fd we own.
        let ret = unsafe { libc::fdatasync(self.fd) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for DirectIoBackend {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: closing an fd we exclusively own.
            unsafe { libc::close(self.fd) };
        }
    }
}
