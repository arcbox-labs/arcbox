//! Passthrough filesystem implementation.
//!
//! Maps guest filesystem operations directly to host filesystem.

use crate::cache::{NegativeCache, NegativeCacheConfig};
use crate::error::{FsError, Result};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

/// Inode data.
#[derive(Debug)]
#[allow(dead_code)] // Fields used for future file handle management
struct InodeData {
    /// Host file descriptor.
    fd: RawFd,
    /// Reference count.
    refcount: u64,
    /// File type and mode.
    mode: u32,
    /// Path relative to root.
    path: PathBuf,
}

/// Configuration for the passthrough filesystem.
#[derive(Debug, Clone)]
pub struct PassthroughConfig {
    /// Enable negative cache for non-existent file lookups.
    pub negative_cache_enabled: bool,
    /// Maximum entries in the negative cache.
    pub negative_cache_max_entries: usize,
    /// Timeout for negative cache entries.
    pub negative_cache_timeout: Duration,
}

impl Default for PassthroughConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PassthroughConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            negative_cache_enabled: true,
            negative_cache_max_entries: 10_000,
            negative_cache_timeout: Duration::from_secs(1),
        }
    }
}

/// Passthrough filesystem.
///
/// Implements a passthrough filesystem that maps all operations
/// to the underlying host filesystem. Includes negative caching
/// to optimize lookups for non-existent files.
pub struct PassthroughFs {
    /// Root directory path on host.
    root: PathBuf,
    /// Inode to data mapping.
    inodes: RwLock<HashMap<u64, InodeData>>,
    /// Next inode number.
    next_inode: AtomicU64,
    /// Negative cache for non-existent paths.
    negative_cache: Option<NegativeCache>,
    /// Configuration.
    #[allow(dead_code)] // Reserved for future configuration access
    config: PassthroughConfig,
}

impl PassthroughFs {
    /// Root inode number.
    pub const ROOT_INODE: u64 = 1;

    /// Creates a new passthrough filesystem with default configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::InvalidPath`] if the root path is not a directory.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        Self::with_config(root, PassthroughConfig::default())
    }

    /// Creates a new passthrough filesystem with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::InvalidPath`] if the root path is not a directory.
    pub fn with_config(root: impl Into<PathBuf>, config: PassthroughConfig) -> Result<Self> {
        let root = root.into();
        if !root.is_dir() {
            return Err(FsError::InvalidPath(format!(
                "root path is not a directory: {}",
                root.display()
            )));
        }

        let negative_cache = if config.negative_cache_enabled {
            Some(NegativeCache::new(NegativeCacheConfig {
                max_entries: config.negative_cache_max_entries,
                timeout: config.negative_cache_timeout,
            }))
        } else {
            None
        };

        Ok(Self {
            root,
            inodes: RwLock::new(HashMap::new()),
            next_inode: AtomicU64::new(Self::ROOT_INODE + 1),
            negative_cache,
            config,
        })
    }

    /// Returns the root directory path.
    #[must_use]
    pub const fn root(&self) -> &PathBuf {
        &self.root
    }

    /// Returns a reference to the negative cache, if enabled.
    #[must_use]
    pub const fn negative_cache(&self) -> Option<&NegativeCache> {
        self.negative_cache.as_ref()
    }

    /// Allocates a new inode number.
    fn alloc_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::Relaxed)
    }

    /// Constructs the full host path for a given parent inode and name.
    #[allow(clippy::significant_drop_tightening)]
    fn get_path(&self, parent: u64, name: &OsStr) -> Result<PathBuf> {
        if parent == Self::ROOT_INODE {
            return Ok(self.root.join(name));
        }

        let inodes = self.inodes.read().map_err(|_| {
            FsError::Cache("failed to acquire inode lock".to_string())
        })?;

        let parent_data = inodes.get(&parent).ok_or(FsError::InvalidHandle(parent))?;

        Ok(self.root.join(&parent_data.path).join(name))
    }

    /// Performs the actual filesystem lookup.
    #[allow(clippy::cast_possible_truncation)]
    fn do_lookup(&self, path: &Path) -> Result<(u64, crate::fuse::FuseAttr)> {
        // Check if path exists on the host filesystem
        let metadata = std::fs::metadata(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FsError::NotFound(path.display().to_string())
            } else {
                FsError::Io(e)
            }
        })?;

        let inode = self.alloc_inode();
        let relative_path = path
            .strip_prefix(&self.root)
            .map_or_else(|_| path.to_path_buf(), Path::to_path_buf);

        // Store inode data
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.insert(inode, InodeData {
                fd: -1, // TODO: Open file descriptor
                refcount: 1,
                mode: metadata.permissions().mode(),
                path: relative_path,
            });
        }

        // Build attributes (nlink is u64 on macOS but u32 in FUSE)
        let attr = crate::fuse::FuseAttr {
            ino: inode,
            size: metadata.len(),
            mode: metadata.permissions().mode(),
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            ..Default::default()
        };

        Ok((inode, attr))
    }

    /// Looks up a name in a directory.
    ///
    /// This method integrates with the negative cache to avoid repeated
    /// system calls for non-existent files.
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
                return Err(FsError::NotFound(path.display().to_string()));
            }
        }

        // Perform actual lookup
        match self.do_lookup(&path) {
            Ok(result) => Ok(result),
            Err(e) if matches!(e, FsError::NotFound(_)) => {
                // Add to negative cache on not found
                if let Some(ref cache) = self.negative_cache {
                    tracing::trace!(path = %path.display(), "adding to negative cache");
                    cache.insert(path);
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Creates a file in the filesystem.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the file cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn create(&self, parent: u64, name: &OsStr, mode: u32) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        // Create the file
        std::fs::File::create(&path).map_err(FsError::Io)?;

        // Set permissions
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(FsError::Io)?;

        // Invalidate negative cache since file now exists
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(path = %path.display(), "invalidating negative cache on create");
            cache.invalidate(&path);
        }

        // Lookup the newly created file
        self.do_lookup(&path)
    }

    /// Creates a directory in the filesystem.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the directory cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn mkdir(&self, parent: u64, name: &OsStr, mode: u32) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        // Create the directory
        std::fs::create_dir(&path).map_err(FsError::Io)?;

        // Set permissions
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(FsError::Io)?;

        // Invalidate negative cache
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(path = %path.display(), "invalidating negative cache on mkdir");
            cache.invalidate(&path);
        }

        self.do_lookup(&path)
    }

    /// Creates a symbolic link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the symlink cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn symlink(&self, parent: u64, name: &OsStr, target: &Path) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        // Create the symlink
        std::os::unix::fs::symlink(target, &path).map_err(FsError::Io)?;

        // Invalidate negative cache
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(path = %path.display(), "invalidating negative cache on symlink");
            cache.invalidate(&path);
        }

        self.do_lookup(&path)
    }

    /// Creates a hard link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the link cannot be created
    /// - [`FsError::InvalidHandle`] if the source or parent inode is invalid
    #[allow(clippy::significant_drop_tightening)]
    pub fn link(&self, source: u64, parent: u64, name: &OsStr) -> Result<(u64, crate::fuse::FuseAttr)> {
        let new_path = self.get_path(parent, name)?;

        // Get source path
        let source_path = {
            let inodes = self.inodes.read().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            let source_data = inodes.get(&source).ok_or(FsError::InvalidHandle(source))?;
            self.root.join(&source_data.path)
        };

        // Create the hard link
        std::fs::hard_link(&source_path, &new_path).map_err(FsError::Io)?;

        // Invalidate negative cache
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(path = %new_path.display(), "invalidating negative cache on link");
            cache.invalidate(&new_path);
        }

        self.do_lookup(&new_path)
    }

    /// Creates a special file (device node, FIFO, etc.).
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the node cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn mknod(&self, parent: u64, name: &OsStr, mode: u32, _rdev: u64) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        // For regular files, use create
        // TODO: Support device nodes and FIFOs using libc::mknod
        std::fs::File::create(&path).map_err(FsError::Io)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(FsError::Io)?;

        // Invalidate negative cache
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(path = %path.display(), "invalidating negative cache on mknod");
            cache.invalidate(&path);
        }

        self.do_lookup(&path)
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
    ) -> Result<()> {
        let old_path = self.get_path(parent, name)?;
        let new_path = self.get_path(new_parent, new_name)?;

        // Perform the rename
        std::fs::rename(&old_path, &new_path).map_err(FsError::Io)?;

        // Invalidate both old and new paths in negative cache
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(
                old = %old_path.display(),
                new = %new_path.display(),
                "invalidating negative cache on rename"
            );
            cache.invalidate(&old_path);
            cache.invalidate(&new_path);
        }

        Ok(())
    }

    /// Gets file attributes.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the attributes cannot be retrieved
    /// - [`FsError::InvalidHandle`] if the inode is invalid
    #[allow(clippy::significant_drop_tightening, clippy::cast_possible_truncation)]
    pub fn getattr(&self, inode: u64) -> Result<crate::fuse::FuseAttr> {
        if inode == Self::ROOT_INODE {
            let metadata = std::fs::metadata(&self.root).map_err(FsError::Io)?;
            return Ok(crate::fuse::FuseAttr {
                ino: Self::ROOT_INODE,
                size: metadata.len(),
                mode: metadata.permissions().mode(),
                nlink: metadata.nlink() as u32,
                uid: metadata.uid(),
                gid: metadata.gid(),
                ..Default::default()
            });
        }

        let inodes = self.inodes.read().map_err(|_| {
            FsError::Cache("failed to acquire inode lock".to_string())
        })?;

        let inode_data = inodes.get(&inode).ok_or(FsError::InvalidHandle(inode))?;
        let path = self.root.join(&inode_data.path);
        let metadata = std::fs::metadata(&path).map_err(FsError::Io)?;

        Ok(crate::fuse::FuseAttr {
            ino: inode,
            size: metadata.len(),
            mode: metadata.permissions().mode(),
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            ..Default::default()
        })
    }
}

// Required for metadata access on Unix
use std::os::unix::fs::{MetadataExt, PermissionsExt};
