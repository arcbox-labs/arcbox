use super::*;

impl PassthroughFs {
    /// Creates a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the file cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn create(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<(u64, crate::fuse::FuseAttr, u64)> {
        let path = self.get_path(parent, name)?;

        // Build open options from flags
        let mut opts = OpenOptions::new();
        Self::apply_flags(&mut opts, flags);
        opts.create(true);
        opts.mode(mode & 0o7777);

        let file = opts.open(&path).map_err(FsError::io)?;
        let metadata = file.metadata().map_err(FsError::io)?;

        // Invalidate negative cache
        self.invalidate_negative_cache(&path);

        // Create inode
        let relative = self.relative_path(&path);
        let kernel_ino = metadata.ino();
        let inode = self.alloc_inode();
        {
            let mut inodes = self
                .inodes
                .write()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            inodes.insert(
                inode,
                InodeData::new(relative, FileType::Regular, kernel_ino),
            );
        }

        // Create file handle
        let handle = self.alloc_handle();
        {
            let mut handles = self
                .handles
                .write()
                .map_err(|_| FsError::Cache("failed to acquire handle lock".to_string()))?;
            handles.insert(handle, HandleData { file, inode, flags });
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata), handle))
    }

    /// Creates a directory.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the directory cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn mkdir(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
    ) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        std::fs::create_dir(&path).map_err(FsError::io)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(FsError::io)?;

        self.invalidate_negative_cache(&path);

        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::io)?;
        let relative = self.relative_path(&path);
        let kernel_ino = metadata.ino();
        let inode = self.alloc_inode();

        {
            let mut inodes = self
                .inodes
                .write()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            inodes.insert(
                inode,
                InodeData::new(relative, FileType::Directory, kernel_ino),
            );
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    /// Creates a symbolic link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the symlink cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn symlink(
        &self,
        parent: u64,
        name: &OsStr,
        target: &Path,
    ) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        std::os::unix::fs::symlink(target, &path).map_err(FsError::io)?;

        self.invalidate_negative_cache(&path);

        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::io)?;
        let relative = self.relative_path(&path);
        let kernel_ino = metadata.ino();
        let inode = self.alloc_inode();

        {
            let mut inodes = self
                .inodes
                .write()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            inodes.insert(
                inode,
                InodeData::new(relative, FileType::Symlink, kernel_ino),
            );
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    /// Creates a hard link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the link cannot be created
    /// - [`FsError::InvalidHandle`] if the source or parent inode is invalid
    pub fn link(
        &self,
        inode: u64,
        new_parent: u64,
        new_name: &OsStr,
    ) -> Result<(u64, crate::fuse::FuseAttr)> {
        let source_path = self.inode_path(inode)?;
        let new_path = self.get_path(new_parent, new_name)?;

        std::fs::hard_link(&source_path, &new_path).map_err(FsError::io)?;

        self.invalidate_negative_cache(&new_path);

        // Hard link shares the same inode
        let metadata = std::fs::symlink_metadata(&new_path).map_err(FsError::io)?;

        // Increment reference count
        {
            let inodes = self
                .inodes
                .read()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            if let Some(data) = inodes.get(&inode) {
                data.inc_ref();
            }
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    /// Creates a special file node.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the node cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    #[allow(clippy::cast_possible_truncation)]
    pub fn mknod(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        rdev: u64,
    ) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;

        let ret = unsafe {
            libc::mknod(
                path_cstr.as_ptr(),
                mode as libc::mode_t,
                rdev as libc::dev_t,
            )
        };
        if ret != 0 {
            return Err(FsError::io(std::io::Error::last_os_error()));
        }

        self.invalidate_negative_cache(&path);

        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::io)?;
        let file_type = FileType::from_mode(metadata.mode());
        let relative = self.relative_path(&path);
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

    /// Removes a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the file cannot be removed
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn unlink(&self, parent: u64, name: &OsStr) -> Result<()> {
        let path = self.get_path(parent, name)?;
        std::fs::remove_file(&path).map_err(FsError::io)?;

        // The old path should now return ENOENT, so we could add it to
        // negative cache, but since the file is gone, it's cleaner to
        // just let it be discovered naturally.
        Ok(())
    }

    /// Removes a directory.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the directory cannot be removed
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn rmdir(&self, parent: u64, name: &OsStr) -> Result<()> {
        let path = self.get_path(parent, name)?;
        std::fs::remove_dir(&path).map_err(FsError::io)
    }

    /// Renames a file or directory.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the rename fails
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
    ) -> Result<()> {
        let old_path = self.get_path(parent, name)?;
        let new_path = self.get_path(new_parent, new_name)?;

        std::fs::rename(&old_path, &new_path).map_err(FsError::io)?;

        // Invalidate both paths
        self.invalidate_negative_cache(&old_path);
        self.invalidate_negative_cache(&new_path);

        // Update inode path if we have it cached
        let old_relative = self.relative_path(&old_path);
        let new_relative = self.relative_path(&new_path);

        {
            let mut inodes = self
                .inodes
                .write()
                .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
            for data in inodes.values_mut() {
                if data.path == old_relative {
                    data.path = new_relative;
                    break;
                }
            }
        }

        Ok(())
    }
}
