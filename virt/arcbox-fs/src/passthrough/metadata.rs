use super::*;

impl PassthroughFs {
    /// Gets an extended attribute.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the operation fails
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    #[cfg(target_os = "linux")]
    pub fn getxattr(&self, inode: u64, name: &OsStr, size: u32) -> Result<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;

        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
        let name_cstr = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid name".to_string()))?;

        if size == 0 {
            // Query size
            let ret = unsafe {
                libc::getxattr(
                    path_cstr.as_ptr(),
                    name_cstr.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                )
            };
            if ret < 0 {
                return Err(FsError::io(std::io::Error::last_os_error()));
            }
            Ok(vec![0u8; ret as usize])
        } else {
            let mut buf = vec![0u8; size as usize];
            let ret = unsafe {
                libc::getxattr(
                    path_cstr.as_ptr(),
                    name_cstr.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    size as usize,
                )
            };
            if ret < 0 {
                return Err(FsError::io(std::io::Error::last_os_error()));
            }
            buf.truncate(ret as usize);
            Ok(buf)
        }
    }

    #[cfg(target_os = "macos")]
    pub fn getxattr(&self, inode: u64, name: &OsStr, size: u32) -> Result<Vec<u8>> {
        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
        let name_cstr = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid name".to_string()))?;

        if size == 0 {
            let ret = unsafe {
                libc::getxattr(
                    path_cstr.as_ptr(),
                    name_cstr.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                )
            };
            if ret < 0 {
                return Err(FsError::io(std::io::Error::last_os_error()));
            }
            Ok(vec![0u8; ret as usize])
        } else {
            let mut buf = vec![0u8; size as usize];
            let ret = unsafe {
                libc::getxattr(
                    path_cstr.as_ptr(),
                    name_cstr.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    size as usize,
                    0,
                    0,
                )
            };
            if ret < 0 {
                return Err(FsError::io(std::io::Error::last_os_error()));
            }
            buf.truncate(ret as usize);
            Ok(buf)
        }
    }

    /// Sets an extended attribute.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the operation fails
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    #[cfg(target_os = "linux")]
    pub fn setxattr(&self, inode: u64, name: &OsStr, value: &[u8], flags: u32) -> Result<()> {
        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
        let name_cstr = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid name".to_string()))?;

        let ret = unsafe {
            libc::setxattr(
                path_cstr.as_ptr(),
                name_cstr.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                flags as i32,
            )
        };
        if ret != 0 {
            Err(FsError::io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    pub fn setxattr(&self, inode: u64, name: &OsStr, value: &[u8], flags: u32) -> Result<()> {
        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
        let name_cstr = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid name".to_string()))?;

        let ret = unsafe {
            libc::setxattr(
                path_cstr.as_ptr(),
                name_cstr.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                flags as i32,
            )
        };
        if ret != 0 {
            Err(FsError::io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Removes an extended attribute.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the operation fails
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    #[cfg(target_os = "linux")]
    pub fn removexattr(&self, inode: u64, name: &OsStr) -> Result<()> {
        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
        let name_cstr = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid name".to_string()))?;

        let ret = unsafe { libc::removexattr(path_cstr.as_ptr(), name_cstr.as_ptr()) };
        if ret != 0 {
            Err(FsError::io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    pub fn removexattr(&self, inode: u64, name: &OsStr) -> Result<()> {
        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
        let name_cstr = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid name".to_string()))?;

        let ret = unsafe { libc::removexattr(path_cstr.as_ptr(), name_cstr.as_ptr(), 0) };
        if ret != 0 {
            Err(FsError::io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Gets filesystem statistics.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if statfs fails
    pub fn statfs(&self) -> Result<crate::fuse::StatFs> {
        let path_cstr = std::ffi::CString::new(self.root.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;

        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statfs(path_cstr.as_ptr(), &raw mut stat) };
        if ret != 0 {
            return Err(FsError::io(std::io::Error::last_os_error()));
        }

        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            clippy::unnecessary_cast // Field types differ between macOS (u32) and Linux (u64).
        )]
        Ok(crate::fuse::StatFs {
            blocks: stat.f_blocks as u64,
            bfree: stat.f_bfree as u64,
            bavail: stat.f_bavail as u64,
            files: stat.f_files as u64,
            ffree: stat.f_ffree as u64,
            bsize: stat.f_bsize as u32,
            namelen: 255, // Common limit
            frsize: stat.f_bsize as u32,
        })
    }

    /// Checks file access permissions.
    ///
    /// # Errors
    ///
    /// - [`FsError::PermissionDenied`] if access is denied
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    pub fn access(&self, inode: u64, mask: u32) -> Result<()> {
        let path = self.inode_path(inode)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;

        #[allow(clippy::cast_possible_wrap)]
        let ret = unsafe { libc::access(path_cstr.as_ptr(), mask as i32) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EACCES) {
                Err(FsError::permission_denied(path.display().to_string()))
            } else {
                Err(FsError::io(err))
            }
        } else {
            Ok(())
        }
    }
}
