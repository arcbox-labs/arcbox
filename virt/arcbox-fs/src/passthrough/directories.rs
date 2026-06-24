use super::*;

impl PassthroughFs {
    /// Opens a directory for reading.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the directory cannot be opened
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    pub fn opendir(&self, inode: u64) -> Result<u64> {
        let path = self.inode_path(inode)?;

        // Read directory entries
        let mut entries = Vec::new();

        // Add . and ..
        entries.push(DirEntry {
            name: OsString::from("."),
            ino: inode,
            file_type: FileType::Directory,
        });

        // For .., use root inode (parent tracking not yet implemented).
        entries.push(DirEntry {
            name: OsString::from(".."),
            ino: Self::ROOT_INODE,
            file_type: FileType::Directory,
        });

        // Read actual entries
        for entry in std::fs::read_dir(&path).map_err(FsError::io)? {
            let entry = entry.map_err(FsError::io)?;
            let metadata = entry.metadata().map_err(FsError::io)?;
            let file_type = FileType::from_mode(metadata.mode());

            // Look up or create inode for this entry
            let entry_path = entry.path();
            let relative = self.relative_path(&entry_path);
            let entry_ino = {
                let inodes = self
                    .inodes
                    .read()
                    .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
                let mut found_ino = None;
                for (&ino, data) in inodes.iter() {
                    if data.path == relative {
                        found_ino = Some(ino);
                        break;
                    }
                }
                found_ino
            };

            let ino = if let Some(ino) = entry_ino {
                ino
            } else {
                // Create new inode
                let kernel_ino = metadata.ino();
                let new_ino = self.alloc_inode();
                let mut inodes = self
                    .inodes
                    .write()
                    .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;
                inodes.insert(new_ino, InodeData::new(relative, file_type, kernel_ino));
                new_ino
            };

            entries.push(DirEntry {
                name: entry.file_name(),
                ino,
                file_type,
            });
        }

        let handle = self.alloc_handle();
        {
            let mut dir_handles = self
                .dir_handles
                .write()
                .map_err(|_| FsError::Cache("failed to acquire dir handle lock".to_string()))?;
            dir_handles.insert(handle, DirHandleData { inode, entries });
        }

        Ok(handle)
    }

    /// Reads directory entries.
    ///
    /// Returns entries starting from `offset`.
    ///
    /// # Errors
    ///
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn readdir(&self, handle: u64, offset: u64) -> Result<Vec<DirEntry>> {
        let dir_handles = self
            .dir_handles
            .read()
            .map_err(|_| FsError::Cache("failed to acquire dir handle lock".to_string()))?;

        let data = dir_handles
            .get(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;

        let entries: Vec<DirEntry> = data.entries.iter().skip(offset as usize).cloned().collect();

        Ok(entries)
    }

    /// Releases (closes) a directory handle.
    pub fn releasedir(&self, handle: u64) -> Result<()> {
        let mut dir_handles = self
            .dir_handles
            .write()
            .map_err(|_| FsError::Cache("failed to acquire dir handle lock".to_string()))?;

        dir_handles.remove(&handle);
        Ok(())
    }

    /// Syncs a directory.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if sync fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn fsyncdir(&self, handle: u64, _datasync: bool) -> Result<()> {
        let dir_handles = self
            .dir_handles
            .read()
            .map_err(|_| FsError::Cache("failed to acquire dir handle lock".to_string()))?;

        let data = dir_handles
            .get(&handle)
            .ok_or(FsError::InvalidHandle(handle))?;
        let path = self.inode_path(data.inode)?;

        // Open directory and sync
        let dir = File::open(&path).map_err(FsError::io)?;
        dir.sync_all().map_err(FsError::io)
    }
}
