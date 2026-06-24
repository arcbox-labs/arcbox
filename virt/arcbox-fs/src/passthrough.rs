//! Passthrough filesystem implementation.
//!
//! Maps guest filesystem operations directly to host filesystem.
//! This is the core filesystem backend that provides actual file I/O.

// Allow casts that are necessary for system calls (libc interop)
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]

mod directories;
mod file_handles;
mod inode_ops;
mod metadata;
mod node_ops;
#[cfg(test)]
mod tests;
mod types;

use crate::cache::{NegativeCache, NegativeCacheConfig};
use crate::error::{FsError, Result};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

pub use types::{DirEntry, FileType, PassthroughConfig};
use types::{DirHandleData, HandleData, InodeData};

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
    /// File handle to data mapping.
    handles: RwLock<HashMap<u64, HandleData>>,
    /// Directory handle to data mapping.
    dir_handles: RwLock<HashMap<u64, DirHandleData>>,
    /// Next handle number.
    next_handle: AtomicU64,
    /// Negative cache for non-existent paths.
    negative_cache: Option<NegativeCache>,
    /// Configuration.
    #[allow(dead_code)]
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
                adaptive_ttl: Some(crate::cache::AdaptiveTtlConfig::default()),
            }))
        } else {
            None
        };

        // Initialize root inode — stat the root directory to capture its
        // kernel st_ino at registration time for TOCTOU detection.
        // Propagating the error here rather than silently falling back to 0:
        // a kernel_ino of 0 would cause every subsequent DAX TOCTOU check on
        // the root inode to silently pass (any real st_ino is non-zero), turning
        // the guard into a no-op and masking rename-based attacks on the root.
        let root_kernel_ino = {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(&root)
                .map(|m| m.ino())
                .map_err(|e| {
                    FsError::io(std::io::Error::new(
                        e.kind(),
                        format!("failed to stat root path '{}': {e}", root.display()),
                    ))
                })?
        };
        let mut inodes = HashMap::new();
        inodes.insert(
            Self::ROOT_INODE,
            InodeData::new(PathBuf::new(), FileType::Directory, root_kernel_ino),
        );

        Ok(Self {
            root,
            inodes: RwLock::new(inodes),
            next_inode: AtomicU64::new(Self::ROOT_INODE + 1),
            handles: RwLock::new(HashMap::new()),
            dir_handles: RwLock::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            negative_cache,
            config,
        })
    }

    /// Returns the root directory path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns a reference to the negative cache, if enabled.
    #[must_use]
    pub fn negative_cache(&self) -> Option<&NegativeCache> {
        self.negative_cache.as_ref()
    }

    /// Allocates a new inode number.
    fn alloc_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocates a new handle number.
    fn alloc_handle(&self) -> u64 {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    /// Gets the full host path for an inode.
    pub(crate) fn inode_path(&self, inode: u64) -> Result<PathBuf> {
        if inode == Self::ROOT_INODE {
            return Ok(self.root.clone());
        }

        let inodes = self
            .inodes
            .read()
            .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;

        let data = inodes.get(&inode).ok_or(FsError::InvalidHandle(inode))?;
        Ok(self.root.join(&data.path))
    }

    /// Returns the host kernel `st_ino` that was recorded when this inode was
    /// first registered (at `lookup` / `create` / `mkdir` / `mknod` time).
    ///
    /// Used by `DaxFsExt::open_inode_for_dax` to detect TOCTOU swaps: if the
    /// opened fd's `st_ino` differs from this value the directory entry was
    /// renamed between resolution and open.
    pub(crate) fn kernel_ino_for(&self, inode: u64) -> Option<u64> {
        let inodes = self
            .inodes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inodes.get(&inode).map(|d| d.kernel_ino)
    }

    /// Constructs the full host path for a given parent inode and name.
    #[allow(clippy::significant_drop_tightening)]
    fn get_path(&self, parent: u64, name: &OsStr) -> Result<PathBuf> {
        if parent == Self::ROOT_INODE {
            return Ok(self.root.join(name));
        }

        let inodes = self
            .inodes
            .read()
            .map_err(|_| FsError::Cache("failed to acquire inode lock".to_string()))?;

        let parent_data = inodes.get(&parent).ok_or(FsError::InvalidHandle(parent))?;
        Ok(self.root.join(&parent_data.path).join(name))
    }

    /// Gets the relative path from full path.
    fn relative_path(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.root)
            .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
    }

    /// Creates `FuseAttr` from metadata.
    #[allow(clippy::cast_possible_truncation)]
    fn metadata_to_attr(ino: u64, metadata: &std::fs::Metadata) -> crate::fuse::FuseAttr {
        crate::fuse::FuseAttr {
            ino,
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime: metadata.atime() as u64,
            mtime: metadata.mtime() as u64,
            ctime: metadata.ctime() as u64,
            atimensec: metadata.atime_nsec() as u32,
            mtimensec: metadata.mtime_nsec() as u32,
            ctimensec: metadata.ctime_nsec() as u32,
            mode: metadata.mode(),
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            blksize: metadata.blksize() as u32,
            padding: 0,
        }
    }

    /// Invalidates negative cache for a path.
    fn invalidate_negative_cache(&self, path: &Path) {
        if let Some(ref cache) = self.negative_cache {
            tracing::trace!(path = %path.display(), "invalidating negative cache");
            cache.invalidate(path);
        }
    }

    /// Applies POSIX open flags to `OpenOptions`.
    fn apply_flags(opts: &mut OpenOptions, flags: u32) {
        let access_mode = flags & libc::O_ACCMODE as u32;
        match access_mode {
            x if x == libc::O_RDONLY as u32 => {
                opts.read(true);
            }
            x if x == libc::O_WRONLY as u32 => {
                opts.write(true);
            }
            x if x == libc::O_RDWR as u32 => {
                opts.read(true).write(true);
            }
            _ => {
                opts.read(true);
            }
        }

        if flags & libc::O_APPEND as u32 != 0 {
            opts.append(true);
        }
        if flags & libc::O_TRUNC as u32 != 0 {
            opts.truncate(true);
        }
    }
}

// Internal counters and atomics (next_inode, next_handle, negative_cache, config)
// are intentionally omitted from Debug — they are implementation details that
// add noise without aiding diagnostics.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for PassthroughFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassthroughFs")
            .field("root", &self.root)
            .field("inodes", &self.inodes.read().map_or(0, |i| i.len()))
            .field("handles", &self.handles.read().map_or(0, |h| h.len()))
            .field(
                "dir_handles",
                &self.dir_handles.read().map_or(0, |h| h.len()),
            )
            .finish()
    }
}
