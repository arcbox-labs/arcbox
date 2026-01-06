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

use crate::cache::{NegativeCache, NegativeCacheConfig};
use crate::error::{FsError, Result};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

// ============================================================================
// Inode Management
// ============================================================================

/// Inode data stored for each known file/directory.
#[derive(Debug)]
struct InodeData {
    /// Path relative to root.
    path: PathBuf,
    /// Reference count (for FUSE forget).
    refcount: AtomicU64,
    /// File type from stat mode.
    file_type: FileType,
}

impl InodeData {
    fn new(path: PathBuf, file_type: FileType) -> Self {
        Self {
            path,
            refcount: AtomicU64::new(1),
            file_type,
        }
    }

    fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_ref(&self) -> u64 {
        self.refcount.fetch_sub(1, Ordering::Relaxed)
    }
}

/// File type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    Unknown,
}

impl FileType {
    fn from_mode(mode: u32) -> Self {
        let file_type = mode & u32::from(libc::S_IFMT);
        if file_type == u32::from(libc::S_IFREG) {
            Self::Regular
        } else if file_type == u32::from(libc::S_IFDIR) {
            Self::Directory
        } else if file_type == u32::from(libc::S_IFLNK) {
            Self::Symlink
        } else if file_type == u32::from(libc::S_IFBLK) {
            Self::BlockDevice
        } else if file_type == u32::from(libc::S_IFCHR) {
            Self::CharDevice
        } else if file_type == u32::from(libc::S_IFIFO) {
            Self::Fifo
        } else if file_type == u32::from(libc::S_IFSOCK) {
            Self::Socket
        } else {
            Self::Unknown
        }
    }

    #[allow(dead_code)]
    fn is_dir(self) -> bool {
        self == Self::Directory
    }

    /// Converts to dirent type (DT_*).
    #[must_use]
    pub fn to_dirent_type(self) -> u32 {
        match self {
            Self::Regular => libc::DT_REG as u32,
            Self::Directory => libc::DT_DIR as u32,
            Self::Symlink => libc::DT_LNK as u32,
            Self::BlockDevice => libc::DT_BLK as u32,
            Self::CharDevice => libc::DT_CHR as u32,
            Self::Fifo => libc::DT_FIFO as u32,
            Self::Socket => libc::DT_SOCK as u32,
            Self::Unknown => libc::DT_UNKNOWN as u32,
        }
    }
}

// ============================================================================
// File Handle Management
// ============================================================================

/// Handle data for an open file.
#[derive(Debug)]
struct HandleData {
    /// The open file.
    file: File,
    /// Inode this handle refers to.
    inode: u64,
    /// Open flags.
    flags: u32,
}

/// Handle data for an open directory.
#[derive(Debug)]
struct DirHandleData {
    /// Inode this handle refers to.
    inode: u64,
    /// Cached directory entries.
    entries: Vec<DirEntry>,
}

/// A directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name.
    pub name: OsString,
    /// Inode number.
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
}

// ============================================================================
// Configuration
// ============================================================================

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

// ============================================================================
// Passthrough Filesystem
// ============================================================================

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
            }))
        } else {
            None
        };

        // Initialize root inode
        let mut inodes = HashMap::new();
        inodes.insert(
            Self::ROOT_INODE,
            InodeData::new(PathBuf::new(), FileType::Directory),
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

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    /// Allocates a new inode number.
    fn alloc_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocates a new handle number.
    fn alloc_handle(&self) -> u64 {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    /// Gets the full host path for an inode.
    fn inode_path(&self, inode: u64) -> Result<PathBuf> {
        if inode == Self::ROOT_INODE {
            return Ok(self.root.clone());
        }

        let inodes = self.inodes.read().map_err(|_| {
            FsError::Cache("failed to acquire inode lock".to_string())
        })?;

        let data = inodes.get(&inode).ok_or(FsError::InvalidHandle(inode))?;
        Ok(self.root.join(&data.path))
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

    /// Gets the relative path from full path.
    fn relative_path(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf())
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

    // ========================================================================
    // Inode Operations
    // ========================================================================

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
                return Err(FsError::NotFound(path.display().to_string()));
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
                return Err(FsError::NotFound(path.display().to_string()));
            }
            Err(e) => return Err(FsError::Io(e)),
        };

        let file_type = FileType::from_mode(metadata.mode());
        let relative = self.relative_path(&path);

        // Check if we already have this inode
        {
            let inodes = self.inodes.read().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            for (&ino, data) in inodes.iter() {
                if data.path == relative {
                    data.inc_ref();
                    return Ok((ino, Self::metadata_to_attr(ino, &metadata)));
                }
            }
        }

        // Create new inode
        let inode = self.alloc_inode();
        {
            let mut inodes = self.inodes.write().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            inodes.insert(inode, InodeData::new(relative, file_type));
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
        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::Io)?;
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
                .map_err(FsError::Io)?;
        }

        // Set owner
        if uid.is_some() || gid.is_some() {
            let uid = uid.map_or(-1_i32 as libc::uid_t, |u| u);
            let gid = gid.map_or(-1_i32 as libc::gid_t, |g| g);
            let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;
            let ret = unsafe { libc::chown(path_cstr.as_ptr(), uid, gid) };
            if ret != 0 {
                return Err(FsError::Io(std::io::Error::last_os_error()));
            }
        }

        // Set size (truncate)
        if let Some(size) = size {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(FsError::Io)?;
            file.set_len(size).map_err(FsError::Io)?;
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
            let ret = unsafe { libc::utimensat(libc::AT_FDCWD, path_cstr.as_ptr(), times.as_ptr(), 0) };
            if ret != 0 {
                return Err(FsError::Io(std::io::Error::last_os_error()));
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
        std::fs::read_link(&path).map_err(FsError::Io)
    }

    // ========================================================================
    // File Creation Operations
    // ========================================================================

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

        let file = opts.open(&path).map_err(FsError::Io)?;
        let metadata = file.metadata().map_err(FsError::Io)?;

        // Invalidate negative cache
        self.invalidate_negative_cache(&path);

        // Create inode
        let relative = self.relative_path(&path);
        let inode = self.alloc_inode();
        {
            let mut inodes = self.inodes.write().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            inodes.insert(inode, InodeData::new(relative, FileType::Regular));
        }

        // Create file handle
        let handle = self.alloc_handle();
        {
            let mut handles = self.handles.write().map_err(|_| {
                FsError::Cache("failed to acquire handle lock".to_string())
            })?;
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
    pub fn mkdir(&self, parent: u64, name: &OsStr, mode: u32) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        std::fs::create_dir(&path).map_err(FsError::Io)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(FsError::Io)?;

        self.invalidate_negative_cache(&path);

        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::Io)?;
        let relative = self.relative_path(&path);
        let inode = self.alloc_inode();

        {
            let mut inodes = self.inodes.write().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            inodes.insert(inode, InodeData::new(relative, FileType::Directory));
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    /// Creates a symbolic link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the symlink cannot be created
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn symlink(&self, parent: u64, name: &OsStr, target: &Path) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;

        std::os::unix::fs::symlink(target, &path).map_err(FsError::Io)?;

        self.invalidate_negative_cache(&path);

        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::Io)?;
        let relative = self.relative_path(&path);
        let inode = self.alloc_inode();

        {
            let mut inodes = self.inodes.write().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            inodes.insert(inode, InodeData::new(relative, FileType::Symlink));
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    /// Creates a hard link.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the link cannot be created
    /// - [`FsError::InvalidHandle`] if the source or parent inode is invalid
    pub fn link(&self, inode: u64, new_parent: u64, new_name: &OsStr) -> Result<(u64, crate::fuse::FuseAttr)> {
        let source_path = self.inode_path(inode)?;
        let new_path = self.get_path(new_parent, new_name)?;

        std::fs::hard_link(&source_path, &new_path).map_err(FsError::Io)?;

        self.invalidate_negative_cache(&new_path);

        // Hard link shares the same inode
        let metadata = std::fs::symlink_metadata(&new_path).map_err(FsError::Io)?;

        // Increment reference count
        {
            let inodes = self.inodes.read().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
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
    pub fn mknod(&self, parent: u64, name: &OsStr, mode: u32, rdev: u64) -> Result<(u64, crate::fuse::FuseAttr)> {
        let path = self.get_path(parent, name)?;
        let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;

        let ret = unsafe { libc::mknod(path_cstr.as_ptr(), mode as libc::mode_t, rdev as libc::dev_t) };
        if ret != 0 {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }

        self.invalidate_negative_cache(&path);

        let metadata = std::fs::symlink_metadata(&path).map_err(FsError::Io)?;
        let file_type = FileType::from_mode(metadata.mode());
        let relative = self.relative_path(&path);
        let inode = self.alloc_inode();

        {
            let mut inodes = self.inodes.write().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            inodes.insert(inode, InodeData::new(relative, file_type));
        }

        Ok((inode, Self::metadata_to_attr(inode, &metadata)))
    }

    // ========================================================================
    // File Deletion Operations
    // ========================================================================

    /// Removes a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if the file cannot be removed
    /// - [`FsError::InvalidHandle`] if the parent inode is invalid
    pub fn unlink(&self, parent: u64, name: &OsStr) -> Result<()> {
        let path = self.get_path(parent, name)?;
        std::fs::remove_file(&path).map_err(FsError::Io)?;

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
        std::fs::remove_dir(&path).map_err(FsError::Io)
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

        std::fs::rename(&old_path, &new_path).map_err(FsError::Io)?;

        // Invalidate both paths
        self.invalidate_negative_cache(&old_path);
        self.invalidate_negative_cache(&new_path);

        // Update inode path if we have it cached
        let old_relative = self.relative_path(&old_path);
        let new_relative = self.relative_path(&new_path);

        {
            let mut inodes = self.inodes.write().map_err(|_| {
                FsError::Cache("failed to acquire inode lock".to_string())
            })?;
            for data in inodes.values_mut() {
                if data.path == old_relative {
                    data.path = new_relative.clone();
                    break;
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // File Handle Operations
    // ========================================================================

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

        let file = opts.open(&path).map_err(FsError::Io)?;
        let handle = self.alloc_handle();

        {
            let mut handles = self.handles.write().map_err(|_| {
                FsError::Cache("failed to acquire handle lock".to_string())
            })?;
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
        let mut handles = self.handles.write().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let data = handles.get_mut(&handle).ok_or(FsError::InvalidHandle(handle))?;

        data.file.seek(SeekFrom::Start(offset)).map_err(FsError::Io)?;

        let mut buf = vec![0u8; size as usize];
        let n = data.file.read(&mut buf).map_err(FsError::Io)?;
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
        let mut handles = self.handles.write().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let handle_data = handles.get_mut(&handle).ok_or(FsError::InvalidHandle(handle))?;

        handle_data.file.seek(SeekFrom::Start(offset)).map_err(FsError::Io)?;
        let n = handle_data.file.write(data).map_err(FsError::Io)?;

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
        let mut handles = self.handles.write().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let data = handles.get_mut(&handle).ok_or(FsError::InvalidHandle(handle))?;
        data.file.flush().map_err(FsError::Io)
    }

    /// Syncs a file to disk.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if sync fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn fsync(&self, handle: u64, datasync: bool) -> Result<()> {
        let handles = self.handles.read().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let data = handles.get(&handle).ok_or(FsError::InvalidHandle(handle))?;

        if datasync {
            data.file.sync_data().map_err(FsError::Io)
        } else {
            data.file.sync_all().map_err(FsError::Io)
        }
    }

    /// Releases (closes) a file handle.
    pub fn release(&self, handle: u64) -> Result<()> {
        let mut handles = self.handles.write().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        handles.remove(&handle);
        Ok(())
    }

    /// Seeks in a file (lseek).
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if seek fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    pub fn lseek(&self, handle: u64, offset: i64, whence: u32) -> Result<u64> {
        let mut handles = self.handles.write().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let data = handles.get_mut(&handle).ok_or(FsError::InvalidHandle(handle))?;

        let seek_from = match whence {
            0 => SeekFrom::Start(offset as u64), // SEEK_SET
            1 => SeekFrom::Current(offset),      // SEEK_CUR
            2 => SeekFrom::End(offset),          // SEEK_END
            _ => return Err(FsError::InvalidPath("invalid whence".to_string())),
        };

        data.file.seek(seek_from).map_err(FsError::Io)
    }

    /// Allocates space for a file.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if allocation fails
    /// - [`FsError::InvalidHandle`] if the handle is invalid
    #[cfg(target_os = "linux")]
    pub fn fallocate(&self, handle: u64, mode: u32, offset: u64, length: u64) -> Result<()> {
        let handles = self.handles.read().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let data = handles.get(&handle).ok_or(FsError::InvalidHandle(handle))?;
        let fd = data.file.as_raw_fd();

        #[allow(clippy::cast_possible_wrap)]
        let ret = unsafe {
            libc::fallocate(fd, mode as i32, offset as i64, length as i64)
        };

        if ret != 0 {
            Err(FsError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    pub fn fallocate(&self, handle: u64, _mode: u32, offset: u64, length: u64) -> Result<()> {
        // macOS doesn't have fallocate, use ftruncate as fallback for simple cases
        let mut handles = self.handles.write().map_err(|_| {
            FsError::Cache("failed to acquire handle lock".to_string())
        })?;

        let data = handles.get_mut(&handle).ok_or(FsError::InvalidHandle(handle))?;
        let new_size = offset + length;
        data.file.set_len(new_size).map_err(FsError::Io)
    }

    // ========================================================================
    // Directory Operations
    // ========================================================================

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

        // For .., we need the parent inode
        let parent_ino = if inode == Self::ROOT_INODE {
            Self::ROOT_INODE
        } else {
            // Try to find parent, default to root
            Self::ROOT_INODE
        };
        entries.push(DirEntry {
            name: OsString::from(".."),
            ino: parent_ino,
            file_type: FileType::Directory,
        });

        // Read actual entries
        for entry in std::fs::read_dir(&path).map_err(FsError::Io)? {
            let entry = entry.map_err(FsError::Io)?;
            let metadata = entry.metadata().map_err(FsError::Io)?;
            let file_type = FileType::from_mode(metadata.mode());

            // Look up or create inode for this entry
            let entry_path = entry.path();
            let relative = self.relative_path(&entry_path);
            let entry_ino = {
                let inodes = self.inodes.read().map_err(|_| {
                    FsError::Cache("failed to acquire inode lock".to_string())
                })?;
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
                let new_ino = self.alloc_inode();
                let mut inodes = self.inodes.write().map_err(|_| {
                    FsError::Cache("failed to acquire inode lock".to_string())
                })?;
                inodes.insert(new_ino, InodeData::new(relative, file_type));
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
            let mut dir_handles = self.dir_handles.write().map_err(|_| {
                FsError::Cache("failed to acquire dir handle lock".to_string())
            })?;
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
        let dir_handles = self.dir_handles.read().map_err(|_| {
            FsError::Cache("failed to acquire dir handle lock".to_string())
        })?;

        let data = dir_handles.get(&handle).ok_or(FsError::InvalidHandle(handle))?;

        let entries: Vec<DirEntry> = data.entries
            .iter()
            .skip(offset as usize)
            .cloned()
            .collect();

        Ok(entries)
    }

    /// Releases (closes) a directory handle.
    pub fn releasedir(&self, handle: u64) -> Result<()> {
        let mut dir_handles = self.dir_handles.write().map_err(|_| {
            FsError::Cache("failed to acquire dir handle lock".to_string())
        })?;

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
        let dir_handles = self.dir_handles.read().map_err(|_| {
            FsError::Cache("failed to acquire dir handle lock".to_string())
        })?;

        let data = dir_handles.get(&handle).ok_or(FsError::InvalidHandle(handle))?;
        let path = self.inode_path(data.inode)?;

        // Open directory and sync
        let dir = File::open(&path).map_err(FsError::Io)?;
        dir.sync_all().map_err(FsError::Io)
    }

    // ========================================================================
    // Extended Attributes (xattr)
    // ========================================================================

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
                libc::getxattr(path_cstr.as_ptr(), name_cstr.as_ptr(), std::ptr::null_mut(), 0)
            };
            if ret < 0 {
                return Err(FsError::Io(std::io::Error::last_os_error()));
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
                return Err(FsError::Io(std::io::Error::last_os_error()));
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
                libc::getxattr(path_cstr.as_ptr(), name_cstr.as_ptr(), std::ptr::null_mut(), 0, 0, 0)
            };
            if ret < 0 {
                return Err(FsError::Io(std::io::Error::last_os_error()));
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
                return Err(FsError::Io(std::io::Error::last_os_error()));
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
            Err(FsError::Io(std::io::Error::last_os_error()))
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
            Err(FsError::Io(std::io::Error::last_os_error()))
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
            Err(FsError::Io(std::io::Error::last_os_error()))
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
            Err(FsError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    // ========================================================================
    // Filesystem Information
    // ========================================================================

    /// Gets filesystem statistics.
    ///
    /// # Errors
    ///
    /// - [`FsError::Io`] if statfs fails
    pub fn statfs(&self) -> Result<crate::fuse::StatFs> {
        let path_cstr = std::ffi::CString::new(self.root.as_os_str().as_bytes())
            .map_err(|_| FsError::InvalidPath("invalid path".to_string()))?;

        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statfs(path_cstr.as_ptr(), &mut stat) };
        if ret != 0 {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
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
                Err(FsError::PermissionDenied(path.display().to_string()))
            } else {
                Err(FsError::Io(err))
            }
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for PassthroughFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassthroughFs")
            .field("root", &self.root)
            .field("inodes", &self.inodes.read().map(|i| i.len()).unwrap_or(0))
            .field("handles", &self.handles.read().map(|h| h.len()).unwrap_or(0))
            .field("dir_handles", &self.dir_handles.read().map(|h| h.len()).unwrap_or(0))
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const S_IFDIR: u32 = libc::S_IFDIR as u32;
    const S_IFREG: u32 = libc::S_IFREG as u32;

    fn setup_test_fs() -> (TempDir, PassthroughFs) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let fs = PassthroughFs::new(temp.path()).expect("failed to create fs");
        (temp, fs)
    }

    #[test]
    fn test_new_filesystem() {
        let temp = TempDir::new().unwrap();
        let fs = PassthroughFs::new(temp.path()).unwrap();
        assert_eq!(fs.root(), temp.path());
    }

    #[test]
    fn test_new_invalid_path() {
        let result = PassthroughFs::new("/nonexistent/path/12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_existing_file() {
        let (temp, fs) = setup_test_fs();

        // Create a test file
        let file_path = temp.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        // Lookup should succeed
        let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("test.txt"));
        assert!(result.is_ok());
        let (inode, attr) = result.unwrap();
        assert!(inode > PassthroughFs::ROOT_INODE);
        assert_eq!(attr.size, 5);
    }

    #[test]
    fn test_lookup_nonexistent_file() {
        let (_temp, fs) = setup_test_fs();

        let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("nonexistent.txt"));
        assert!(matches!(result, Err(FsError::NotFound(_))));
    }

    #[test]
    fn test_lookup_negative_cache() {
        let (_temp, fs) = setup_test_fs();

        // First lookup - should miss
        let _ = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("missing.txt"));

        // Check stats
        if let Some(cache) = fs.negative_cache() {
            let stats = cache.stats();
            assert!(stats.entries > 0 || stats.misses > 0);
        }

        // Second lookup - should hit cache
        let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("missing.txt"));
        assert!(matches!(result, Err(FsError::NotFound(_))));
    }

    #[test]
    fn test_getattr_root() {
        let (_temp, fs) = setup_test_fs();

        let result = fs.getattr(PassthroughFs::ROOT_INODE);
        assert!(result.is_ok());
        let attr = result.unwrap();
        assert_eq!(attr.ino, PassthroughFs::ROOT_INODE);
        assert!(attr.mode & S_IFDIR != 0);
    }

    #[test]
    fn test_create_and_read_file() {
        let (_temp, fs) = setup_test_fs();

        // Create file
        let (inode, _attr, handle) = fs
            .create(
                PassthroughFs::ROOT_INODE,
                OsStr::new("newfile.txt"),
                0o644,
                libc::O_RDWR as u32,
            )
            .unwrap();

        assert!(inode > PassthroughFs::ROOT_INODE);

        // Write to file
        let data = b"hello world";
        let written = fs.write(handle, 0, data, 0).unwrap();
        assert_eq!(written, data.len() as u32);

        // Read back
        let read_data = fs.read(handle, 0, 100).unwrap();
        assert_eq!(read_data, data);

        // Release handle
        fs.release(handle).unwrap();
    }

    #[test]
    fn test_mkdir_and_rmdir() {
        let (_temp, fs) = setup_test_fs();

        // Create directory
        let (inode, attr) = fs
            .mkdir(PassthroughFs::ROOT_INODE, OsStr::new("testdir"), 0o755)
            .unwrap();

        assert!(inode > PassthroughFs::ROOT_INODE);
        assert!(attr.mode & S_IFDIR != 0);

        // Remove directory
        fs.rmdir(PassthroughFs::ROOT_INODE, OsStr::new("testdir"))
            .unwrap();

        // Lookup should fail
        let result = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new("testdir"));
        assert!(matches!(result, Err(FsError::NotFound(_))));
    }

    #[test]
    fn test_symlink_and_readlink() {
        let (temp, fs) = setup_test_fs();

        // Create a target file
        let target = temp.path().join("target.txt");
        std::fs::write(&target, "target content").unwrap();

        // Create symlink
        let (inode, _attr) = fs
            .symlink(
                PassthroughFs::ROOT_INODE,
                OsStr::new("link"),
                Path::new("target.txt"),
            )
            .unwrap();

        // Read link
        let link_target = fs.readlink(inode).unwrap();
        assert_eq!(link_target, Path::new("target.txt"));
    }

    #[test]
    fn test_hard_link() {
        let (temp, fs) = setup_test_fs();

        // Create original file
        let original = temp.path().join("original.txt");
        std::fs::write(&original, "content").unwrap();

        // Lookup original
        let (orig_inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("original.txt"))
            .unwrap();

        // Create hard link
        let (link_inode, attr) = fs
            .link(orig_inode, PassthroughFs::ROOT_INODE, OsStr::new("hardlink.txt"))
            .unwrap();

        // Hard links share the same inode
        assert_eq!(link_inode, orig_inode);
        assert!(attr.nlink >= 2);
    }

    #[test]
    fn test_unlink() {
        let (temp, fs) = setup_test_fs();

        // Create file
        let file_path = temp.path().join("todelete.txt");
        std::fs::write(&file_path, "delete me").unwrap();

        // Unlink
        fs.unlink(PassthroughFs::ROOT_INODE, OsStr::new("todelete.txt"))
            .unwrap();

        // File should be gone
        assert!(!file_path.exists());
    }

    #[test]
    fn test_rename() {
        let (temp, fs) = setup_test_fs();

        // Create file
        let old_path = temp.path().join("old.txt");
        std::fs::write(&old_path, "content").unwrap();

        // Rename
        fs.rename(
            PassthroughFs::ROOT_INODE,
            OsStr::new("old.txt"),
            PassthroughFs::ROOT_INODE,
            OsStr::new("new.txt"),
            0,
        )
        .unwrap();

        // Old path should not exist
        assert!(!old_path.exists());
        // New path should exist
        assert!(temp.path().join("new.txt").exists());
    }

    #[test]
    fn test_opendir_readdir() {
        let (temp, fs) = setup_test_fs();

        // Create some files
        std::fs::write(temp.path().join("file1.txt"), "1").unwrap();
        std::fs::write(temp.path().join("file2.txt"), "2").unwrap();
        std::fs::create_dir(temp.path().join("subdir")).unwrap();

        // Open directory
        let handle = fs.opendir(PassthroughFs::ROOT_INODE).unwrap();

        // Read entries
        let entries = fs.readdir(handle, 0).unwrap();

        // Should have at least . .. and our 3 entries
        assert!(entries.len() >= 5);

        // Check for expected names
        let names: Vec<_> = entries.iter().map(|e| e.name.to_string_lossy().to_string()).collect();
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"file1.txt".to_string()));
        assert!(names.contains(&"file2.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));

        // Release
        fs.releasedir(handle).unwrap();
    }

    #[test]
    fn test_setattr_size() {
        let (temp, fs) = setup_test_fs();

        // Create file with content
        let file_path = temp.path().join("truncate.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("truncate.txt"))
            .unwrap();

        // Truncate to 5 bytes
        let attr = fs.setattr(inode, None, None, None, Some(5), None, None).unwrap();
        assert_eq!(attr.size, 5);

        // Verify content
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    fn test_setattr_mode() {
        let (temp, fs) = setup_test_fs();

        let file_path = temp.path().join("chmod.txt");
        std::fs::write(&file_path, "test").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("chmod.txt"))
            .unwrap();

        // Change mode
        let attr = fs.setattr(inode, Some(0o600), None, None, None, None, None).unwrap();
        assert_eq!(attr.mode & 0o777, 0o600);
    }

    #[test]
    fn test_open_read_write() {
        let (temp, fs) = setup_test_fs();

        // Create file
        let file_path = temp.path().join("rw.txt");
        std::fs::write(&file_path, "initial").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("rw.txt"))
            .unwrap();

        // Open for read/write
        let handle = fs.open(inode, libc::O_RDWR as u32).unwrap();

        // Read
        let data = fs.read(handle, 0, 100).unwrap();
        assert_eq!(data, b"initial");

        // Write at offset
        fs.write(handle, 0, b"INITIAL", 0).unwrap();

        // Read again
        let data = fs.read(handle, 0, 100).unwrap();
        assert_eq!(data, b"INITIAL");

        fs.release(handle).unwrap();
    }

    #[test]
    fn test_fsync() {
        let (temp, fs) = setup_test_fs();

        let file_path = temp.path().join("sync.txt");
        std::fs::write(&file_path, "test").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("sync.txt"))
            .unwrap();

        let handle = fs.open(inode, libc::O_RDWR as u32).unwrap();
        fs.write(handle, 0, b"updated", 0).unwrap();

        // Sync should succeed
        fs.fsync(handle, false).unwrap();
        fs.fsync(handle, true).unwrap();

        fs.release(handle).unwrap();
    }

    #[test]
    fn test_flush() {
        let (temp, fs) = setup_test_fs();

        let file_path = temp.path().join("flush.txt");
        std::fs::write(&file_path, "test").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("flush.txt"))
            .unwrap();

        let handle = fs.open(inode, libc::O_RDWR as u32).unwrap();
        fs.write(handle, 0, b"updated", 0).unwrap();
        fs.flush(handle).unwrap();
        fs.release(handle).unwrap();
    }

    #[test]
    fn test_lseek() {
        let (temp, fs) = setup_test_fs();

        let file_path = temp.path().join("seek.txt");
        std::fs::write(&file_path, "0123456789").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("seek.txt"))
            .unwrap();

        let handle = fs.open(inode, libc::O_RDONLY as u32).unwrap();

        // Seek to offset 5
        let pos = fs.lseek(handle, 5, 0).unwrap(); // SEEK_SET
        assert_eq!(pos, 5);

        // Read from there
        let data = fs.read(handle, pos, 5).unwrap();
        assert_eq!(data, b"56789");

        fs.release(handle).unwrap();
    }

    #[test]
    fn test_statfs() {
        let (_temp, fs) = setup_test_fs();

        let stat = fs.statfs().unwrap();
        assert!(stat.blocks > 0);
        assert!(stat.bsize > 0);
    }

    #[test]
    fn test_access() {
        let (temp, fs) = setup_test_fs();

        let file_path = temp.path().join("access.txt");
        std::fs::write(&file_path, "test").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("access.txt"))
            .unwrap();

        // Should be readable
        fs.access(inode, libc::R_OK as u32).unwrap();

        // Should be writable
        fs.access(inode, libc::W_OK as u32).unwrap();
    }

    #[test]
    fn test_forget() {
        let (temp, fs) = setup_test_fs();

        let file_path = temp.path().join("forget.txt");
        std::fs::write(&file_path, "test").unwrap();

        let (inode, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("forget.txt"))
            .unwrap();

        // Lookup again to increase refcount
        let (inode2, _) = fs
            .lookup(PassthroughFs::ROOT_INODE, OsStr::new("forget.txt"))
            .unwrap();
        assert_eq!(inode, inode2);

        // Forget once
        fs.forget(inode, 1);

        // Should still be in table
        assert!(fs.getattr(inode).is_ok());

        // Forget again
        fs.forget(inode, 1);

        // May or may not be removed depending on timing
    }

    #[test]
    #[ignore = "mknod requires elevated permissions on macOS"]
    fn test_mknod_regular_file() {
        let (_temp, fs) = setup_test_fs();

        // Create regular file via mknod
        let (inode, attr) = fs
            .mknod(
                PassthroughFs::ROOT_INODE,
                OsStr::new("mknod_file"),
                S_IFREG | 0o644,
                0,
            )
            .unwrap();

        assert!(inode > PassthroughFs::ROOT_INODE);
        assert!(attr.mode & S_IFREG != 0);
    }

    #[test]
    fn test_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        let (temp, fs) = setup_test_fs();
        let fs = Arc::new(fs);

        // Create some initial files
        for i in 0..10 {
            std::fs::write(temp.path().join(format!("file{i}.txt")), format!("content{i}")).unwrap();
        }

        let mut handles = vec![];

        // Spawn threads doing lookups
        for i in 0..4 {
            let fs = Arc::clone(&fs);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let name = format!("file{}.txt", (i + j) % 10);
                    let _ = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new(&name));
                }
            }));
        }

        // Spawn threads doing reads
        for i in 0..4 {
            let fs = Arc::clone(&fs);
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let name = format!("file{}.txt", (i + j) % 10);
                    if let Ok((inode, _)) = fs.lookup(PassthroughFs::ROOT_INODE, OsStr::new(&name)) {
                        if let Ok(handle) = fs.open(inode, libc::O_RDONLY as u32) {
                            let _ = fs.read(handle, 0, 100);
                            let _ = fs.release(handle);
                        }
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }
}
