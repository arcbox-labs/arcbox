use std::ffi::OsString;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Inode data stored for each known file/directory.
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct InodeData {
    /// Path relative to root.
    pub(super) path: PathBuf,
    /// Reference count (for FUSE forget).
    pub(super) refcount: AtomicU64,
    /// File type from stat mode.
    pub(super) file_type: FileType,
    /// Host kernel inode number (`st_ino`) at registration time.
    ///
    /// Used by `DaxFsExt::open_inode_for_dax` for TOCTOU detection: after
    /// opening the file by path we compare the opened fd's `st_ino` against
    /// this value. A mismatch means the directory entry was swapped (renamed)
    /// between our path-to-inode resolution and the open call.
    pub(super) kernel_ino: u64,
}

impl InodeData {
    pub(super) fn new(path: PathBuf, file_type: FileType, kernel_ino: u64) -> Self {
        Self {
            path,
            refcount: AtomicU64::new(1),
            file_type,
            kernel_ino,
        }
    }

    pub(super) fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dec_ref(&self) -> u64 {
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
    pub(super) fn from_mode(mode: u32) -> Self {
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

/// Handle data for an open file.
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct HandleData {
    /// The open file.
    pub(super) file: File,
    /// Inode this handle refers to.
    pub(super) inode: u64,
    /// Open flags.
    pub(super) flags: u32,
}

/// Handle data for an open directory.
#[derive(Debug)]
pub(super) struct DirHandleData {
    /// Inode this handle refers to.
    pub(super) inode: u64,
    /// Cached directory entries.
    pub(super) entries: Vec<DirEntry>,
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
            negative_cache_timeout: Duration::from_secs(5),
        }
    }
}
