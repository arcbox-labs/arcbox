use super::*;

impl PassthroughFs {
    /// Opens a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the file cannot be opened
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    pub fn open(&self, inode: u64, flags: u32) -> Result<u64> {
        let path = self.inode_path(inode)?;

        let mut opts = OpenOptions::new();
        Self::apply_flags(&mut opts, flags);

        let file = opts.open(&path).map_err(FsError::io)?;
        let handle = self.alloc_handle();

        {
            let mut handles = self
                .handles
                .write()
                .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;
            handles.insert(handle, HandleData { file, inode, flags });
        }

        Ok(handle)
    }

    /// Reads from a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if read fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn read(&self, handle: u64, offset: u64, size: u32) -> Result<Vec<u8>> {
        let mut handles = self
            .handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let data = handles
            .get_mut(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;

        data.file
            .seek(SeekFrom::Start(offset))
            .map_err(FsError::io)?;

        let mut buf = vec![0u8; size as usize];
        let n = data.file.read(&mut buf).map_err(FsError::io)?;
        buf.truncate(n);

        Ok(buf)
    }

    /// Writes to a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if write fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn write(&self, handle: u64, offset: u64, data: &[u8], _flags: u32) -> Result<u32> {
        let mut handles = self
            .handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let handle_data = handles
            .get_mut(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;

        handle_data
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(FsError::io)?;
        let n = handle_data.file.write(data).map_err(FsError::io)?;

        #[allow(clippy::cast_possible_truncation)]
        Ok(n as u32)
    }

    /// Flushes a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if flush fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn flush(&self, handle: u64) -> Result<()> {
        let mut handles = self
            .handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let data = handles
            .get_mut(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;
        data.file.flush().map_err(FsError::io)
    }

    /// Syncs a file to disk.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if sync fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn fsync(&self, handle: u64, datasync: bool) -> Result<()> {
        let handles = self
            .handles
            .read()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let data = handles.get(&handle).ok_or(FsError::InvalidHandle(handle))?;

        if datasync {
            data.file.sync_data().map_err(FsError::io)
        } else {
            data.file.sync_all().map_err(FsError::io)
        }
    }

    /// Releases (closes) a file handle.
    pub fn release(&self, handle: u64) -> Result<()> {
        let mut handles = self
            .handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        handles.remove(&handle);
        Ok(())
    }

    /// Returns the raw fd for an open file handle (for DAX mapping).
    pub fn get_file_raw_fd(&self, handle: u64) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        let handles = self.handles.read().ok()?;
        handles.get(&handle).map(|h| h.file.as_raw_fd())
    }

    /// Seeks in a file (lseek).
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if seek fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn lseek(&self, handle: u64, offset: i64, whence: u32) -> Result<u64> {
        let mut handles = self
            .handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let data = handles
            .get_mut(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;

        let seek_from = match whence {
            0 => SeekFrom::Start(offset as u64), // SEEK_SET
            1 => SeekFrom::Current(offset),      // SEEK_CUR
            2 => SeekFrom::End(offset),          // SEEK_END
            _ => return Err(FsError::InvalidPath("invalid whence".to_string())),
        };

        data.file.seek(seek_from).map_err(FsError::io)
    }

    /// Allocates space for a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if allocation fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    #[cfg(target_os = "linux")]
    pub fn fallocate(&self, handle: u64, mode: u32, offset: u64, length: u64) -> Result<()> {
        use std::os::unix::io::AsRawFd;

        let handles = self
            .handles
            .read()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let data = handles.get(&handle).ok_or(FsError::InvalidHandle(handle))?;
        let fd = data.file.as_raw_fd();

        #[allow(clippy::cast_possible_wrap)]
        let ret = unsafe { libc::fallocate(fd, mode as i32, offset as i64, length as i64) };

        if ret != 0 {
            Err(FsError::io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    pub fn fallocate(&self, handle: u64, _mode: u32, offset: u64, length: u64) -> Result<()> {
        // macOS doesn't have fallocate, use ftruncate as fallback for simple cases
        let mut handles = self
            .handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;

        let data = handles
            .get_mut(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;
        let new_size = offset + length;
        data.file.set_len(new_size).map_err(FsError::io)
    }
}
