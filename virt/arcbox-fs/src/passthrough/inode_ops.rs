use super::*;

impl PassthroughFs {
    /// Looks up a name in a directory.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotFound`] if the file doesn't exist
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    /// - [`FsError::Io`] for other I/O errors
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        // Fast path: check negative cache first
        if let Some(ref cache) = self.negative_cache {
            if cache.contains(&path) {
                tracing::trace!(path = %path.display(), "negative cache hit");
                return Err(FsError::not_found(path.display().to_string()));
            }
        }

        // Perform actual lookup
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Add to negative cache
                if let Some(ref cache) = self.negative_cache {
                    tracing::trace!(path = %path.display(), "adding to negative cache");
                    cache.insert(path.clone());
                }
                return Err(FsError::not_found(path.display().to_string()));
            }
            Err(e) => return Err(FsError::io(e)),
        };

        let file_type = FileType::from_mode(metadata.mode());
        let relative = self.relative_path(&path);

        // Check if we already have this inode
        {
            let inodes = self
                .inodes
                .read()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            for (&ino, data) in inodes.iter() {
                if data.path == relative {
                    data.inc_ref();
                    return Ok((ino, Self::metadata_to_attr(ino, &metadata)));
                }
            }
        }

        // Create new inode
        let kernel_ino = metadata.ino();
        let inode = self.alloc_inode();
        {
            let mut inodes = self
                .inodes
                .write()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            inodes.insert(inode, InodeData::new(relative, file_type, kernel_ino));
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    /// Decrements the reference count of an inode.
    ///
    /// When the count reaches zero, the inode is removed from the table.
    pub fn forget(&self, inode: u64, nlookup: u64) {
        if inode == Self::ROOT_INODE {
            return;
        }

        let should_remove = {
            let inodes = match self.inodes.read() {
                Ok(i) => i,
                Err(_) => return,
            };
            if let Some(data) = inodes.get(&inode) {
                for _ in 0..nlookup {
                    if data.dec_ref() == 1 {
                        return;
                    }
                }
                data.refcount.load(Ordering::Relaxed) == 0
            } else {
                false
            }
        };

        if should_remove {
            if let Ok(mut inodes) = self.inodes.write() {
                inodes.remove(&inode);
            }
        }
    }

    /// Gets file attributes.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the attributes cannot be retrieved
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    pub fn getattr(&self, inode: u64) -> Result<crate::fuse::FuseAttr> {
        let path = self.inode_path(inode)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::io)?;
        Ok(Self::metadata_to_attr(inode, &metadata))
    }

    /// Sets file attributes.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the attributes cannot be set
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    #[allow(clippy::too_many_arguments)]
    pub fn setattr(
        &self,
        inode: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<(i64, u32)>,
        mtime: Option<(i64, u32)>,
    ) -> Result<crate::fuse::FuseAttr> {
        let path = self.inode_path(inode)?;

        // Set mode
        if let Some(mode) = mode {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .map_err(FsError::io)?;
        }

        // Set owner
        if uid.is_some() || gid.is_some() {
            let uid = uid.unwrap_or(-1_i32 as libc::uid_t);
            let gid = gid.unwrap_or(-1_i32 as libc::gid_t);
            let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
            let ret = unsafe { libc::chown(path_cstr.as_ptr(), uid, gid) };
            if ret != 0 {
                return Err(FsError::io(std::io::Error::last_os_error()));
            }
        }

        // Set size (truncate)
        if let Some(size) = size {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(FsError::io)?;
            file.set_len(size).map_err(FsError::io)?;
        }

        // Set times
        if atime.is_some() || mtime.is_some() {
            let atime_spec = atime.map_or(
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                |(sec, nsec)| libc::timespec {
                    tv_sec: sec,
                    tv_nsec: i64::from(nsec),
                },
            );
            let mtime_spec = mtime.map_or(
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                |(sec, nsec)| libc::timespec {
                    tv_sec: sec,
                    tv_nsec: i64::from(nsec),
                },
            );
            let times = [atime_spec, mtime_spec];
            let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
            let ret =
                unsafe { libc::utimensat(libc::AT_FDCWD, path_cstr.as_ptr(), times.as_ptr(), 0) };
            if ret != 0 {
                return Err(FsError::io(std::io::Error::last_os_error()));
            }
        }

        self.getattr(inode)
    }

    /// Reads a symbolic link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the link cannot be read
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    pub fn readlink(&self, inode: u64) -> Result<PathBuf> {
        let path = self.inode_path(inode)?;
        std::fs::read_link(&path).map_err(FsError::io)
    }
}
