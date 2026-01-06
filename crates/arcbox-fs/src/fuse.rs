//! FUSE protocol implementation.
//!
//! This module implements the FUSE (Filesystem in Userspace) protocol structures
//! for communication between the kernel and userspace filesystem implementation.
//!
//! Reference: <https://github.com/libfuse/libfuse/blob/master/include/fuse_kernel.h>

// Allow casts for FUSE protocol binary compatibility
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]

use std::mem::size_of;

// ============================================================================
// Constants
// ============================================================================

/// FUSE kernel protocol major version.
pub const FUSE_KERNEL_VERSION: u32 = 7;

/// FUSE kernel protocol minor version.
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 38;

/// Root inode number.
pub const FUSE_ROOT_ID: u64 = 1;

// FUSE init flags
pub const FUSE_ASYNC_READ: u32 = 1 << 0;
pub const FUSE_POSIX_LOCKS: u32 = 1 << 1;
pub const FUSE_FILE_OPS: u32 = 1 << 2;
pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4;
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
pub const FUSE_DONT_MASK: u32 = 1 << 6;
pub const FUSE_SPLICE_WRITE: u32 = 1 << 7;
pub const FUSE_SPLICE_MOVE: u32 = 1 << 8;
pub const FUSE_SPLICE_READ: u32 = 1 << 9;
pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10;
pub const FUSE_HAS_IOCTL_DIR: u32 = 1 << 11;
pub const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
pub const FUSE_ASYNC_DIO: u32 = 1 << 15;
pub const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;
pub const FUSE_NO_OPEN_SUPPORT: u32 = 1 << 17;
pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
pub const FUSE_HANDLE_KILLPRIV: u32 = 1 << 19;
pub const FUSE_POSIX_ACL: u32 = 1 << 20;
pub const FUSE_ABORT_ERROR: u32 = 1 << 21;
pub const FUSE_MAX_PAGES: u32 = 1 << 22;
pub const FUSE_CACHE_SYMLINKS: u32 = 1 << 23;
pub const FUSE_NO_OPENDIR_SUPPORT: u32 = 1 << 24;
pub const FUSE_EXPLICIT_INVAL_DATA: u32 = 1 << 25;

// Setattr valid flags
pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
pub const FATTR_CTIME: u32 = 1 << 10;

// Open flags
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
pub const FOPEN_NONSEEKABLE: u32 = 1 << 2;
pub const FOPEN_CACHE_DIR: u32 = 1 << 3;
pub const FOPEN_STREAM: u32 = 1 << 4;

// ============================================================================
// Opcodes
// ============================================================================

/// FUSE operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseOpcode {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Setxattr = 21,
    Getxattr = 22,
    Listxattr = 23,
    Removexattr = 24,
    Flush = 25,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Fsyncdir = 30,
    Getlk = 31,
    Setlk = 32,
    Setlkw = 33,
    Access = 34,
    Create = 35,
    Interrupt = 36,
    Bmap = 37,
    Destroy = 38,
    Ioctl = 39,
    Poll = 40,
    NotifyReply = 41,
    BatchForget = 42,
    Fallocate = 43,
    Readdirplus = 44,
    Rename2 = 45,
    Lseek = 46,
    CopyFileRange = 47,
    SetupMapping = 48,
    RemoveMapping = 49,
}

/// FUSE request header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseInHeader {
    /// Total message length.
    pub len: u32,
    /// Operation code.
    pub opcode: u32,
    /// Unique request ID.
    pub unique: u64,
    /// Node ID.
    pub nodeid: u64,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Process ID.
    pub pid: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE response header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseOutHeader {
    /// Total message length.
    pub len: u32,
    /// Error code (0 on success, negative errno on error).
    pub error: i32,
    /// Unique request ID (must match request).
    pub unique: u64,
}

/// File attributes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub padding: u32,
}

/// Filesystem statistics.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct StatFs {
    /// Total data blocks in filesystem.
    pub blocks: u64,
    /// Free blocks in filesystem.
    pub bfree: u64,
    /// Free blocks available to unprivileged user.
    pub bavail: u64,
    /// Total file nodes in filesystem.
    pub files: u64,
    /// Free file nodes in filesystem.
    pub ffree: u64,
    /// Optimal transfer block size.
    pub bsize: u32,
    /// Maximum length of filenames.
    pub namelen: u32,
    /// Fragment size.
    pub frsize: u32,
}

// ============================================================================
// Request Structures
// ============================================================================

/// FUSE_INIT request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseInitIn {
    /// Major version supported by kernel.
    pub major: u32,
    /// Minor version supported by kernel.
    pub minor: u32,
    /// Maximum readahead size.
    pub max_readahead: u32,
    /// Flags.
    pub flags: u32,
}

/// FUSE_GETATTR request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseGetattrIn {
    /// Getattr flags.
    pub getattr_flags: u32,
    /// Padding.
    pub dummy: u32,
    /// File handle (if FUSE_GETATTR_FH is set).
    pub fh: u64,
}

/// FUSE_SETATTR request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseSetattrIn {
    /// Valid attribute mask.
    pub valid: u32,
    /// Padding.
    pub padding: u32,
    /// File handle.
    pub fh: u64,
    /// New size.
    pub size: u64,
    /// Lock owner.
    pub lock_owner: u64,
    /// New access time (seconds).
    pub atime: u64,
    /// New modification time (seconds).
    pub mtime: u64,
    /// New ctime (seconds).
    pub ctime: u64,
    /// Access time nanoseconds.
    pub atimensec: u32,
    /// Modification time nanoseconds.
    pub mtimensec: u32,
    /// Ctime nanoseconds.
    pub ctimensec: u32,
    /// New mode.
    pub mode: u32,
    /// Unused.
    pub unused4: u32,
    /// New UID.
    pub uid: u32,
    /// New GID.
    pub gid: u32,
    /// Unused.
    pub unused5: u32,
}

/// FUSE_MKNOD request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseMknodIn {
    /// File mode.
    pub mode: u32,
    /// Device number.
    pub rdev: u32,
    /// Umask.
    pub umask: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_MKDIR request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseMkdirIn {
    /// Directory mode.
    pub mode: u32,
    /// Umask.
    pub umask: u32,
}

/// FUSE_RENAME request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseRenameIn {
    /// New parent directory inode.
    pub newdir: u64,
}

/// FUSE_RENAME2 request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseRename2In {
    /// New parent directory inode.
    pub newdir: u64,
    /// Rename flags.
    pub flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_LINK request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseLinkIn {
    /// Old inode number.
    pub oldnodeid: u64,
}

/// FUSE_OPEN request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseOpenIn {
    /// Open flags.
    pub flags: u32,
    /// Unused.
    pub unused: u32,
}

/// FUSE_CREATE request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseCreateIn {
    /// Open flags.
    pub flags: u32,
    /// File mode.
    pub mode: u32,
    /// Umask.
    pub umask: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_READ request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseReadIn {
    /// File handle.
    pub fh: u64,
    /// Read offset.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: u32,
    /// Read flags.
    pub read_flags: u32,
    /// Lock owner.
    pub lock_owner: u64,
    /// Open flags.
    pub flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_WRITE request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseWriteIn {
    /// File handle.
    pub fh: u64,
    /// Write offset.
    pub offset: u64,
    /// Number of bytes to write.
    pub size: u32,
    /// Write flags.
    pub write_flags: u32,
    /// Lock owner.
    pub lock_owner: u64,
    /// Open flags.
    pub flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_RELEASE request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseReleaseIn {
    /// File handle.
    pub fh: u64,
    /// Open flags.
    pub flags: u32,
    /// Release flags.
    pub release_flags: u32,
    /// Lock owner.
    pub lock_owner: u64,
}

/// FUSE_FLUSH request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseFlushIn {
    /// File handle.
    pub fh: u64,
    /// Unused.
    pub unused: u32,
    /// Padding.
    pub padding: u32,
    /// Lock owner.
    pub lock_owner: u64,
}

/// FUSE_FSYNC request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseFsyncIn {
    /// File handle.
    pub fh: u64,
    /// Fsync flags (1 = datasync).
    pub fsync_flags: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_SETXATTR request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseSetxattrIn {
    /// Attribute value size.
    pub size: u32,
    /// Setxattr flags.
    pub flags: u32,
}

/// FUSE_GETXATTR request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseGetxattrIn {
    /// Maximum size of attribute value.
    pub size: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_ACCESS request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseAccessIn {
    /// Access mode mask.
    pub mask: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_LSEEK request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseLseekIn {
    /// File handle.
    pub fh: u64,
    /// Seek offset.
    pub offset: u64,
    /// Seek whence (SEEK_SET, SEEK_CUR, SEEK_END, etc.).
    pub whence: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_FALLOCATE request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseFallocateIn {
    /// File handle.
    pub fh: u64,
    /// Offset.
    pub offset: u64,
    /// Length.
    pub length: u64,
    /// Fallocate mode.
    pub mode: u32,
    /// Padding.
    pub padding: u32,
}

/// FUSE_FORGET request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseForgetIn {
    /// Number of lookups to forget.
    pub nlookup: u64,
}

/// Single forget entry for batch forget.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseForgetOne {
    /// Inode number.
    pub nodeid: u64,
    /// Number of lookups to forget.
    pub nlookup: u64,
}

/// FUSE_BATCH_FORGET request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseBatchForgetIn {
    /// Number of entries.
    pub count: u32,
    /// Padding.
    pub dummy: u32,
}

// ============================================================================
// Response Structures
// ============================================================================

/// FUSE_INIT response.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseInitOut {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Maximum readahead size.
    pub max_readahead: u32,
    /// Flags.
    pub flags: u32,
    /// Maximum background requests.
    pub max_background: u16,
    /// Congestion threshold.
    pub congestion_threshold: u16,
    /// Maximum write size.
    pub max_write: u32,
    /// Time granularity (nanoseconds).
    pub time_gran: u32,
    /// Maximum pages for a single request.
    pub max_pages: u16,
    /// Padding.
    pub padding: u16,
    /// Unused.
    pub unused: [u32; 8],
}

impl Default for FuseInitOut {
    fn default() -> Self {
        Self {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 128 * 1024,
            flags: FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_WRITEBACK_CACHE,
            max_background: 16,
            congestion_threshold: 12,
            max_write: 128 * 1024,
            time_gran: 1,
            max_pages: 32,
            padding: 0,
            unused: [0; 8],
        }
    }
}

/// Entry response (for lookup, mkdir, mknod, symlink, link, create).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseEntryOut {
    /// Inode number.
    pub nodeid: u64,
    /// Inode generation.
    pub generation: u64,
    /// Cache timeout for entry (seconds).
    pub entry_valid: u64,
    /// Cache timeout for attributes (seconds).
    pub attr_valid: u64,
    /// Entry timeout nanoseconds.
    pub entry_valid_nsec: u32,
    /// Attribute timeout nanoseconds.
    pub attr_valid_nsec: u32,
    /// File attributes.
    pub attr: FuseAttr,
}

/// Attribute response.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseAttrOut {
    /// Cache timeout for attributes (seconds).
    pub attr_valid: u64,
    /// Attribute timeout nanoseconds.
    pub attr_valid_nsec: u32,
    /// Padding.
    pub dummy: u32,
    /// File attributes.
    pub attr: FuseAttr,
}

/// Open response.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseOpenOut {
    /// File handle.
    pub fh: u64,
    /// Open flags.
    pub open_flags: u32,
    /// Padding.
    pub padding: u32,
}

/// Write response.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseWriteOut {
    /// Number of bytes written.
    pub size: u32,
    /// Padding.
    pub padding: u32,
}

/// Getxattr response.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseGetxattrOut {
    /// Attribute value size.
    pub size: u32,
    /// Padding.
    pub padding: u32,
}

/// Statfs response.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseStatfsOut {
    /// Filesystem statistics.
    pub st: StatFs,
}

/// Lseek response.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FuseLseekOut {
    /// New offset.
    pub offset: u64,
}

/// Directory entry for readdir.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FuseDirent {
    /// Inode number.
    pub ino: u64,
    /// Offset to next entry.
    pub off: u64,
    /// Name length.
    pub namelen: u32,
    /// File type (DT_*).
    pub typ: u32,
    // Followed by name[namelen] (not null-terminated, but padded to 8-byte boundary)
}

impl FuseDirent {
    /// Returns the total size of this entry including the name.
    #[must_use]
    pub const fn size(namelen: usize) -> usize {
        // Header size + name length, rounded up to 8-byte boundary
        let base = size_of::<Self>() + namelen;
        (base + 7) & !7
    }
}

// ============================================================================
// Opcode Conversion
// ============================================================================

impl FuseOpcode {
    /// Tries to convert a u32 to a `FuseOpcode`.
    #[must_use]
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Lookup),
            2 => Some(Self::Forget),
            3 => Some(Self::Getattr),
            4 => Some(Self::Setattr),
            5 => Some(Self::Readlink),
            6 => Some(Self::Symlink),
            8 => Some(Self::Mknod),
            9 => Some(Self::Mkdir),
            10 => Some(Self::Unlink),
            11 => Some(Self::Rmdir),
            12 => Some(Self::Rename),
            13 => Some(Self::Link),
            14 => Some(Self::Open),
            15 => Some(Self::Read),
            16 => Some(Self::Write),
            17 => Some(Self::Statfs),
            18 => Some(Self::Release),
            20 => Some(Self::Fsync),
            21 => Some(Self::Setxattr),
            22 => Some(Self::Getxattr),
            23 => Some(Self::Listxattr),
            24 => Some(Self::Removexattr),
            25 => Some(Self::Flush),
            26 => Some(Self::Init),
            27 => Some(Self::Opendir),
            28 => Some(Self::Readdir),
            29 => Some(Self::Releasedir),
            30 => Some(Self::Fsyncdir),
            31 => Some(Self::Getlk),
            32 => Some(Self::Setlk),
            33 => Some(Self::Setlkw),
            34 => Some(Self::Access),
            35 => Some(Self::Create),
            36 => Some(Self::Interrupt),
            37 => Some(Self::Bmap),
            38 => Some(Self::Destroy),
            39 => Some(Self::Ioctl),
            40 => Some(Self::Poll),
            41 => Some(Self::NotifyReply),
            42 => Some(Self::BatchForget),
            43 => Some(Self::Fallocate),
            44 => Some(Self::Readdirplus),
            45 => Some(Self::Rename2),
            46 => Some(Self::Lseek),
            47 => Some(Self::CopyFileRange),
            48 => Some(Self::SetupMapping),
            49 => Some(Self::RemoveMapping),
            _ => None,
        }
    }
}

// ============================================================================
// Header Size Constants
// ============================================================================

impl FuseInHeader {
    /// Size of the input header.
    pub const SIZE: usize = size_of::<Self>();
}

impl FuseOutHeader {
    /// Size of the output header.
    pub const SIZE: usize = size_of::<Self>();

    /// Creates a success response header.
    #[must_use]
    pub const fn success(unique: u64, len: u32) -> Self {
        Self {
            len,
            error: 0,
            unique,
        }
    }

    /// Creates an error response header.
    #[must_use]
    pub const fn error(unique: u64, errno: i32) -> Self {
        Self {
            len: Self::SIZE as u32,
            error: -errno,
            unique,
        }
    }
}
