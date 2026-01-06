//! FUSE request dispatcher.
//!
//! This module handles parsing FUSE requests and dispatching them to the
//! appropriate filesystem operations. It acts as the bridge between the
//! raw FUSE protocol and the [`PassthroughFs`] implementation.

// Allow casts and pointer operations for FUSE protocol binary compatibility
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::ptr_as_ptr,
    clippy::borrow_as_ptr,
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_ref_mut
)]

use crate::error::{FsError, Result};
use crate::fuse::{
    FuseAccessIn, FuseAttr, FuseAttrOut, FuseCreateIn, FuseDirent, FuseEntryOut, FuseFallocateIn,
    FuseFlushIn, FuseForgetIn, FuseFsyncIn, FuseGetxattrIn, FuseGetxattrOut, FuseInHeader,
    FuseInitIn, FuseInitOut, FuseLinkIn, FuseLseekIn, FuseLseekOut, FuseMkdirIn, FuseMknodIn,
    FuseOpenIn, FuseOpenOut, FuseOpcode, FuseOutHeader, FuseReadIn, FuseReleaseIn, FuseRenameIn,
    FuseSetattrIn, FuseSetxattrIn, FuseStatfsOut, FuseWriteIn, FuseWriteOut,
    FATTR_ATIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID,
    FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
};
use crate::passthrough::PassthroughFs;

use std::ffi::OsStr;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

// ============================================================================
// Dispatcher Configuration
// ============================================================================

/// Configuration for the FUSE dispatcher.
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Entry cache timeout in seconds.
    pub entry_timeout: u64,
    /// Attribute cache timeout in seconds.
    pub attr_timeout: u64,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            entry_timeout: 1,
            attr_timeout: 1,
        }
    }
}

// ============================================================================
// Request Context
// ============================================================================

/// Context for a FUSE request.
#[derive(Debug, Clone, Copy)]
pub struct RequestContext {
    /// Unique request ID.
    pub unique: u64,
    /// Node ID (inode).
    pub nodeid: u64,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Process ID.
    pub pid: u32,
}

impl From<&FuseInHeader> for RequestContext {
    fn from(header: &FuseInHeader) -> Self {
        Self {
            unique: header.unique,
            nodeid: header.nodeid,
            uid: header.uid,
            gid: header.gid,
            pid: header.pid,
        }
    }
}

// ============================================================================
// Response Builder
// ============================================================================

/// Helper for building FUSE responses.
pub struct ResponseBuilder {
    buffer: Vec<u8>,
}

impl ResponseBuilder {
    /// Creates a new response builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
        }
    }

    /// Writes an error response.
    pub fn write_error(&mut self, unique: u64, errno: i32) {
        self.buffer.clear();
        let header = FuseOutHeader::error(unique, errno);
        self.write_struct(&header);
    }

    /// Writes a success response with only a header.
    pub fn write_empty(&mut self, unique: u64) {
        self.buffer.clear();
        let header = FuseOutHeader::success(unique, FuseOutHeader::SIZE as u32);
        self.write_struct(&header);
    }

    /// Writes a success response with data.
    pub fn write_data<T: Copy>(&mut self, unique: u64, data: &T) {
        self.buffer.clear();
        let len = (FuseOutHeader::SIZE + size_of::<T>()) as u32;
        let header = FuseOutHeader::success(unique, len);
        self.write_struct(&header);
        self.write_struct(data);
    }

    /// Writes a success response with raw bytes.
    pub fn write_bytes(&mut self, unique: u64, data: &[u8]) {
        self.buffer.clear();
        let len = (FuseOutHeader::SIZE + data.len()) as u32;
        let header = FuseOutHeader::success(unique, len);
        self.write_struct(&header);
        self.buffer.extend_from_slice(data);
    }

    /// Returns the built response.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Returns a reference to the buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    fn write_struct<T: Copy>(&mut self, value: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>())
        };
        self.buffer.extend_from_slice(bytes);
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FUSE Dispatcher
// ============================================================================

/// FUSE request dispatcher.
///
/// Parses incoming FUSE requests and routes them to the appropriate
/// filesystem operations on [`PassthroughFs`].
///
/// # Example
///
/// ```no_run
/// use arcbox_fs::dispatcher::{FuseDispatcher, DispatcherConfig};
/// use arcbox_fs::passthrough::PassthroughFs;
/// use std::sync::Arc;
///
/// let fs = Arc::new(PassthroughFs::new("/tmp").unwrap());
/// let dispatcher = FuseDispatcher::new(fs, DispatcherConfig::default());
///
/// // Process a FUSE request
/// let request = vec![0u8; 64]; // Example request bytes
/// let response = dispatcher.dispatch(&request);
/// ```
pub struct FuseDispatcher {
    /// The underlying filesystem.
    fs: Arc<PassthroughFs>,
    /// Dispatcher configuration.
    config: DispatcherConfig,
    /// Whether FUSE_INIT has been received.
    initialized: std::sync::atomic::AtomicBool,
}

impl FuseDispatcher {
    /// Creates a new dispatcher.
    #[must_use]
    pub fn new(fs: Arc<PassthroughFs>, config: DispatcherConfig) -> Self {
        Self {
            fs,
            config,
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Dispatches a FUSE request and returns the response.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be parsed.
    pub fn dispatch(&self, request: &[u8]) -> Result<Vec<u8>> {
        // Parse header
        if request.len() < FuseInHeader::SIZE {
            return Err(FsError::Fuse("request too small".to_string()));
        }

        let header = unsafe { &*(request.as_ptr() as *const FuseInHeader) };
        let body = &request[FuseInHeader::SIZE..];

        // Parse opcode
        let opcode = FuseOpcode::from_u32(header.opcode)
            .ok_or_else(|| FsError::Fuse(format!("unknown opcode: {}", header.opcode)))?;

        let ctx = RequestContext::from(header);
        let mut response = ResponseBuilder::new();

        // Dispatch to handler
        match opcode {
            FuseOpcode::Init => self.handle_init(&ctx, body, &mut response),
            FuseOpcode::Destroy => self.handle_destroy(&ctx, &mut response),
            FuseOpcode::Lookup => self.handle_lookup(&ctx, body, &mut response),
            FuseOpcode::Forget => self.handle_forget(&ctx, body, &mut response),
            FuseOpcode::Getattr => self.handle_getattr(&ctx, body, &mut response),
            FuseOpcode::Setattr => self.handle_setattr(&ctx, body, &mut response),
            FuseOpcode::Readlink => self.handle_readlink(&ctx, &mut response),
            FuseOpcode::Mknod => self.handle_mknod(&ctx, body, &mut response),
            FuseOpcode::Mkdir => self.handle_mkdir(&ctx, body, &mut response),
            FuseOpcode::Unlink => self.handle_unlink(&ctx, body, &mut response),
            FuseOpcode::Rmdir => self.handle_rmdir(&ctx, body, &mut response),
            FuseOpcode::Symlink => self.handle_symlink(&ctx, body, &mut response),
            FuseOpcode::Rename => self.handle_rename(&ctx, body, &mut response),
            FuseOpcode::Link => self.handle_link(&ctx, body, &mut response),
            FuseOpcode::Open => self.handle_open(&ctx, body, &mut response),
            FuseOpcode::Read => self.handle_read(&ctx, body, &mut response),
            FuseOpcode::Write => self.handle_write(&ctx, body, &mut response),
            FuseOpcode::Statfs => self.handle_statfs(&ctx, &mut response),
            FuseOpcode::Release => self.handle_release(&ctx, body, &mut response),
            FuseOpcode::Fsync => self.handle_fsync(&ctx, body, &mut response),
            FuseOpcode::Flush => self.handle_flush(&ctx, body, &mut response),
            FuseOpcode::Opendir => self.handle_opendir(&ctx, body, &mut response),
            FuseOpcode::Readdir => self.handle_readdir(&ctx, body, &mut response),
            FuseOpcode::Releasedir => self.handle_releasedir(&ctx, body, &mut response),
            FuseOpcode::Fsyncdir => self.handle_fsyncdir(&ctx, body, &mut response),
            FuseOpcode::Access => self.handle_access(&ctx, body, &mut response),
            FuseOpcode::Create => self.handle_create(&ctx, body, &mut response),
            FuseOpcode::Getxattr => self.handle_getxattr(&ctx, body, &mut response),
            FuseOpcode::Setxattr => self.handle_setxattr(&ctx, body, &mut response),
            FuseOpcode::Removexattr => self.handle_removexattr(&ctx, body, &mut response),
            FuseOpcode::Lseek => self.handle_lseek(&ctx, body, &mut response),
            FuseOpcode::Fallocate => self.handle_fallocate(&ctx, body, &mut response),
            _ => {
                // Unsupported operation
                response.write_error(ctx.unique, libc::ENOSYS);
            }
        }

        Ok(response.finish())
    }

    // ========================================================================
    // Init / Destroy
    // ========================================================================

    fn handle_init(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseInitIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let init_in = unsafe { &*(body.as_ptr() as *const FuseInitIn) };

        // Check version compatibility
        if init_in.major < FUSE_KERNEL_VERSION {
            response.write_error(ctx.unique, libc::EPROTO);
            return;
        }

        let init_out = FuseInitOut {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: init_in.max_readahead,
            ..FuseInitOut::default()
        };

        self.initialized
            .store(true, std::sync::atomic::Ordering::SeqCst);
        response.write_data(ctx.unique, &init_out);
    }

    fn handle_destroy(&self, ctx: &RequestContext, response: &mut ResponseBuilder) {
        self.initialized
            .store(false, std::sync::atomic::Ordering::SeqCst);
        response.write_empty(ctx.unique);
    }

    // ========================================================================
    // Lookup / Forget
    // ========================================================================

    fn handle_lookup(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        // Body is null-terminated name
        let name = self.parse_name(body);

        match self.fs.lookup(ctx.nodeid, name) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_forget(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() >= size_of::<FuseForgetIn>() {
            let forget_in = unsafe { &*(body.as_ptr() as *const FuseForgetIn) };
            self.fs.forget(ctx.nodeid, forget_in.nlookup);
        }
        // FORGET has no response
        let _ = response;
    }

    // ========================================================================
    // Attributes
    // ========================================================================

    fn handle_getattr(&self, ctx: &RequestContext, _body: &[u8], response: &mut ResponseBuilder) {
        match self.fs.getattr(ctx.nodeid) {
            Ok(attr) => {
                let attr_out = FuseAttrOut {
                    attr_valid: self.config.attr_timeout,
                    attr_valid_nsec: 0,
                    dummy: 0,
                    attr,
                };
                response.write_data(ctx.unique, &attr_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_setattr(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseSetattrIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let setattr_in = unsafe { &*(body.as_ptr() as *const FuseSetattrIn) };

        let mode = if setattr_in.valid & FATTR_MODE != 0 {
            Some(setattr_in.mode)
        } else {
            None
        };

        let uid = if setattr_in.valid & FATTR_UID != 0 {
            Some(setattr_in.uid)
        } else {
            None
        };

        let gid = if setattr_in.valid & FATTR_GID != 0 {
            Some(setattr_in.gid)
        } else {
            None
        };

        let size = if setattr_in.valid & FATTR_SIZE != 0 {
            Some(setattr_in.size)
        } else {
            None
        };

        let atime = if setattr_in.valid & FATTR_ATIME != 0 {
            Some((setattr_in.atime as i64, setattr_in.atimensec))
        } else {
            None
        };

        let mtime = if setattr_in.valid & FATTR_MTIME != 0 {
            Some((setattr_in.mtime as i64, setattr_in.mtimensec))
        } else {
            None
        };

        match self.fs.setattr(ctx.nodeid, mode, uid, gid, size, atime, mtime) {
            Ok(attr) => {
                let attr_out = FuseAttrOut {
                    attr_valid: self.config.attr_timeout,
                    attr_valid_nsec: 0,
                    dummy: 0,
                    attr,
                };
                response.write_data(ctx.unique, &attr_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_readlink(&self, ctx: &RequestContext, response: &mut ResponseBuilder) {
        match self.fs.readlink(ctx.nodeid) {
            Ok(target) => {
                response.write_bytes(ctx.unique, target.as_os_str().as_bytes());
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // File Creation
    // ========================================================================

    fn handle_mknod(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseMknodIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let mknod_in = unsafe { &*(body.as_ptr() as *const FuseMknodIn) };
        let name = self.parse_name(&body[size_of::<FuseMknodIn>()..]);

        match self.fs.mknod(ctx.nodeid, name, mknod_in.mode, u64::from(mknod_in.rdev)) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_mkdir(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseMkdirIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let mkdir_in = unsafe { &*(body.as_ptr() as *const FuseMkdirIn) };
        let name = self.parse_name(&body[size_of::<FuseMkdirIn>()..]);

        match self.fs.mkdir(ctx.nodeid, name, mkdir_in.mode) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_symlink(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        // Body: name\0linkname\0
        let parts: Vec<&[u8]> = body.splitn(2, |&b| b == 0).collect();
        if parts.len() < 2 {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let name = OsStr::from_bytes(parts[0]);
        let link_target = Path::new(OsStr::from_bytes(
            parts[1].split(|&b| b == 0).next().unwrap_or(&[]),
        ));

        match self.fs.symlink(ctx.nodeid, name, link_target) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_link(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseLinkIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let link_in = unsafe { &*(body.as_ptr() as *const FuseLinkIn) };
        let name = self.parse_name(&body[size_of::<FuseLinkIn>()..]);

        match self.fs.link(link_in.oldnodeid, ctx.nodeid, name) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_create(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseCreateIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let create_in = unsafe { &*(body.as_ptr() as *const FuseCreateIn) };
        let name = self.parse_name(&body[size_of::<FuseCreateIn>()..]);

        match self.fs.create(ctx.nodeid, name, create_in.mode, create_in.flags) {
            Ok((inode, attr, handle)) => {
                let entry = self.make_entry_out(inode, &attr);
                let open_out = FuseOpenOut {
                    fh: handle,
                    open_flags: 0,
                    padding: 0,
                };

                // Write entry followed by open response
                response.buffer.clear();
                let len = (FuseOutHeader::SIZE + size_of::<FuseEntryOut>() + size_of::<FuseOpenOut>()) as u32;
                let header = FuseOutHeader::success(ctx.unique, len);
                response.write_struct(&header);
                response.write_struct(&entry);
                response.write_struct(&open_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // File Deletion
    // ========================================================================

    fn handle_unlink(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        let name = self.parse_name(body);

        match self.fs.unlink(ctx.nodeid, name) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_rmdir(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        let name = self.parse_name(body);

        match self.fs.rmdir(ctx.nodeid, name) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_rename(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseRenameIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let rename_in = unsafe { &*(body.as_ptr() as *const FuseRenameIn) };
        let names = &body[size_of::<FuseRenameIn>()..];

        // Parse old_name\0new_name\0
        let parts: Vec<&[u8]> = names.splitn(2, |&b| b == 0).collect();
        if parts.len() < 2 {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let old_name = OsStr::from_bytes(parts[0]);
        let new_name = OsStr::from_bytes(parts[1].split(|&b| b == 0).next().unwrap_or(&[]));

        match self.fs.rename(ctx.nodeid, old_name, rename_in.newdir, new_name, 0) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // File Operations
    // ========================================================================

    fn handle_open(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseOpenIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let open_in = unsafe { &*(body.as_ptr() as *const FuseOpenIn) };

        match self.fs.open(ctx.nodeid, open_in.flags) {
            Ok(handle) => {
                let open_out = FuseOpenOut {
                    fh: handle,
                    open_flags: 0,
                    padding: 0,
                };
                response.write_data(ctx.unique, &open_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_read(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseReadIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let read_in = unsafe { &*(body.as_ptr() as *const FuseReadIn) };

        match self.fs.read(read_in.fh, read_in.offset, read_in.size) {
            Ok(data) => response.write_bytes(ctx.unique, &data),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_write(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseWriteIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let write_in = unsafe { &*(body.as_ptr() as *const FuseWriteIn) };
        let data = &body[size_of::<FuseWriteIn>()..];

        match self.fs.write(write_in.fh, write_in.offset, data, write_in.write_flags) {
            Ok(written) => {
                let write_out = FuseWriteOut {
                    size: written,
                    padding: 0,
                };
                response.write_data(ctx.unique, &write_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_release(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseReleaseIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let release_in = unsafe { &*(body.as_ptr() as *const FuseReleaseIn) };

        match self.fs.release(release_in.fh) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_flush(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseFlushIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let flush_in = unsafe { &*(body.as_ptr() as *const FuseFlushIn) };

        match self.fs.flush(flush_in.fh) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_fsync(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseFsyncIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let fsync_in = unsafe { &*(body.as_ptr() as *const FuseFsyncIn) };
        let datasync = fsync_in.fsync_flags & 1 != 0;

        match self.fs.fsync(fsync_in.fh, datasync) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_lseek(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseLseekIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let lseek_in = unsafe { &*(body.as_ptr() as *const FuseLseekIn) };

        match self.fs.lseek(lseek_in.fh, lseek_in.offset as i64, lseek_in.whence) {
            Ok(offset) => {
                let lseek_out = FuseLseekOut { offset };
                response.write_data(ctx.unique, &lseek_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_fallocate(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseFallocateIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let fallocate_in = unsafe { &*(body.as_ptr() as *const FuseFallocateIn) };

        match self.fs.fallocate(
            fallocate_in.fh,
            fallocate_in.mode,
            fallocate_in.offset,
            fallocate_in.length,
        ) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // Directory Operations
    // ========================================================================

    fn handle_opendir(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseOpenIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        match self.fs.opendir(ctx.nodeid) {
            Ok(handle) => {
                let open_out = FuseOpenOut {
                    fh: handle,
                    open_flags: 0,
                    padding: 0,
                };
                response.write_data(ctx.unique, &open_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_readdir(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseReadIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let read_in = unsafe { &*(body.as_ptr() as *const FuseReadIn) };

        match self.fs.readdir(read_in.fh, read_in.offset) {
            Ok(entries) => {
                let mut dirent_buf = Vec::new();
                let mut offset = read_in.offset + 1;

                for entry in entries {
                    let name_bytes = entry.name.as_bytes();
                    let entry_size = FuseDirent::size(name_bytes.len());

                    // Check if we have room in the buffer
                    if dirent_buf.len() + entry_size > read_in.size as usize {
                        break;
                    }

                    let dirent = FuseDirent {
                        ino: entry.ino,
                        off: offset,
                        namelen: name_bytes.len() as u32,
                        typ: entry.file_type.to_dirent_type(),
                    };

                    // Write dirent header
                    let dirent_bytes = unsafe {
                        std::slice::from_raw_parts(
                            &dirent as *const FuseDirent as *const u8,
                            size_of::<FuseDirent>(),
                        )
                    };
                    dirent_buf.extend_from_slice(dirent_bytes);

                    // Write name
                    dirent_buf.extend_from_slice(name_bytes);

                    // Pad to 8-byte boundary
                    let padding = entry_size - size_of::<FuseDirent>() - name_bytes.len();
                    dirent_buf.extend(std::iter::repeat(0u8).take(padding));

                    offset += 1;
                }

                response.write_bytes(ctx.unique, &dirent_buf);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_releasedir(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseReleaseIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let release_in = unsafe { &*(body.as_ptr() as *const FuseReleaseIn) };

        match self.fs.releasedir(release_in.fh) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_fsyncdir(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseFsyncIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let fsync_in = unsafe { &*(body.as_ptr() as *const FuseFsyncIn) };
        let datasync = fsync_in.fsync_flags & 1 != 0;

        match self.fs.fsyncdir(fsync_in.fh, datasync) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // Extended Attributes
    // ========================================================================

    fn handle_getxattr(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseGetxattrIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let getxattr_in = unsafe { &*(body.as_ptr() as *const FuseGetxattrIn) };
        let name = self.parse_name(&body[size_of::<FuseGetxattrIn>()..]);

        match self.fs.getxattr(ctx.nodeid, name, getxattr_in.size) {
            Ok(value) => {
                if getxattr_in.size == 0 {
                    // Return size only
                    let out = FuseGetxattrOut {
                        size: value.len() as u32,
                        padding: 0,
                    };
                    response.write_data(ctx.unique, &out);
                } else {
                    response.write_bytes(ctx.unique, &value);
                }
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_setxattr(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseSetxattrIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let setxattr_in = unsafe { &*(body.as_ptr() as *const FuseSetxattrIn) };
        let rest = &body[size_of::<FuseSetxattrIn>()..];

        // Parse name\0value
        if let Some(null_pos) = rest.iter().position(|&b| b == 0) {
            let name = OsStr::from_bytes(&rest[..null_pos]);
            let value = &rest[null_pos + 1..][..setxattr_in.size as usize];

            match self.fs.setxattr(ctx.nodeid, name, value, setxattr_in.flags) {
                Ok(()) => response.write_empty(ctx.unique),
                Err(e) => response.write_error(ctx.unique, e.to_errno()),
            }
        } else {
            response.write_error(ctx.unique, libc::EINVAL);
        }
    }

    fn handle_removexattr(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        let name = self.parse_name(body);

        match self.fs.removexattr(ctx.nodeid, name) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // Other Operations
    // ========================================================================

    fn handle_statfs(&self, ctx: &RequestContext, response: &mut ResponseBuilder) {
        match self.fs.statfs() {
            Ok(st) => {
                let statfs_out = FuseStatfsOut { st };
                response.write_data(ctx.unique, &statfs_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    fn handle_access(&self, ctx: &RequestContext, body: &[u8], response: &mut ResponseBuilder) {
        if body.len() < size_of::<FuseAccessIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let access_in = unsafe { &*(body.as_ptr() as *const FuseAccessIn) };

        match self.fs.access(ctx.nodeid, access_in.mask) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    fn parse_name<'a>(&self, body: &'a [u8]) -> &'a OsStr {
        let name_end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        OsStr::from_bytes(&body[..name_end])
    }

    fn make_entry_out(&self, inode: u64, attr: &FuseAttr) -> FuseEntryOut {
        FuseEntryOut {
            nodeid: inode,
            generation: 0,
            entry_valid: self.config.entry_timeout,
            attr_valid: self.config.attr_timeout,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: *attr,
        }
    }
}

impl std::fmt::Debug for FuseDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseDispatcher")
            .field("config", &self.config)
            .field(
                "initialized",
                &self.initialized.load(std::sync::atomic::Ordering::Relaxed),
            )
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

    fn setup_dispatcher() -> (TempDir, FuseDispatcher) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let fs = Arc::new(PassthroughFs::new(temp.path()).expect("failed to create fs"));
        let dispatcher = FuseDispatcher::new(fs, DispatcherConfig::default());
        (temp, dispatcher)
    }

    fn make_header(opcode: FuseOpcode, nodeid: u64, body_len: usize) -> Vec<u8> {
        let header = FuseInHeader {
            len: (FuseInHeader::SIZE + body_len) as u32,
            opcode: opcode as u32,
            unique: 1,
            nodeid,
            uid: 0,
            gid: 0,
            pid: 0,
            padding: 0,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(&header as *const FuseInHeader as *const u8, FuseInHeader::SIZE)
        };
        header_bytes.to_vec()
    }

    fn parse_response_header(response: &[u8]) -> FuseOutHeader {
        assert!(response.len() >= FuseOutHeader::SIZE);
        unsafe { *(response.as_ptr() as *const FuseOutHeader) }
    }

    #[test]
    fn test_init() {
        let (_temp, dispatcher) = setup_dispatcher();

        let init_in = FuseInitIn {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 128 * 1024,
            flags: 0,
        };

        let mut request = make_header(FuseOpcode::Init, 0, size_of::<FuseInitIn>());
        let init_bytes = unsafe {
            std::slice::from_raw_parts(&init_in as *const FuseInitIn as *const u8, size_of::<FuseInitIn>())
        };
        request.extend_from_slice(init_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);

        assert_eq!(header.error, 0);
        assert!(dispatcher.initialized.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_getattr_root() {
        let (_temp, dispatcher) = setup_dispatcher();

        let request = make_header(FuseOpcode::Getattr, 1, 0);
        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);

        assert_eq!(header.error, 0);
        assert!(response.len() > FuseOutHeader::SIZE);
    }

    #[test]
    fn test_lookup_nonexistent() {
        let (_temp, dispatcher) = setup_dispatcher();

        let name = b"nonexistent\0";
        let mut request = make_header(FuseOpcode::Lookup, 1, name.len());
        request.extend_from_slice(name);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);

        assert_eq!(header.error, -libc::ENOENT);
    }

    #[test]
    fn test_lookup_existing() {
        let (temp, dispatcher) = setup_dispatcher();

        // Create a file
        std::fs::write(temp.path().join("test.txt"), "hello").unwrap();

        let name = b"test.txt\0";
        let mut request = make_header(FuseOpcode::Lookup, 1, name.len());
        request.extend_from_slice(name);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);

        assert_eq!(header.error, 0);
    }

    #[test]
    fn test_mkdir_and_rmdir() {
        let (_temp, dispatcher) = setup_dispatcher();

        // Mkdir
        let mkdir_in = FuseMkdirIn { mode: 0o755, umask: 0 };
        let name = b"testdir\0";

        let mut request = make_header(FuseOpcode::Mkdir, 1, size_of::<FuseMkdirIn>() + name.len());
        let mkdir_bytes = unsafe {
            std::slice::from_raw_parts(&mkdir_in as *const FuseMkdirIn as *const u8, size_of::<FuseMkdirIn>())
        };
        request.extend_from_slice(mkdir_bytes);
        request.extend_from_slice(name);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);

        // Rmdir
        let mut request = make_header(FuseOpcode::Rmdir, 1, name.len());
        request.extend_from_slice(name);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);
    }

    #[test]
    fn test_open_read_write_release() {
        let (temp, dispatcher) = setup_dispatcher();

        // Create file
        std::fs::write(temp.path().join("test.txt"), "initial").unwrap();

        // Lookup to get inode
        let name = b"test.txt\0";
        let mut request = make_header(FuseOpcode::Lookup, 1, name.len());
        request.extend_from_slice(name);
        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);

        // Extract inode from entry response
        let entry = unsafe {
            &*((response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseEntryOut)
        };
        let inode = entry.nodeid;

        // Open
        let open_in = FuseOpenIn {
            flags: libc::O_RDWR as u32,
            unused: 0,
        };
        let mut request = make_header(FuseOpcode::Open, inode, size_of::<FuseOpenIn>());
        let open_bytes = unsafe {
            std::slice::from_raw_parts(&open_in as *const FuseOpenIn as *const u8, size_of::<FuseOpenIn>())
        };
        request.extend_from_slice(open_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);

        // Extract file handle
        let open_out = unsafe {
            &*((response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseOpenOut)
        };
        let fh = open_out.fh;

        // Read
        let read_in = FuseReadIn {
            fh,
            offset: 0,
            size: 100,
            read_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        let mut request = make_header(FuseOpcode::Read, inode, size_of::<FuseReadIn>());
        let read_bytes = unsafe {
            std::slice::from_raw_parts(&read_in as *const FuseReadIn as *const u8, size_of::<FuseReadIn>())
        };
        request.extend_from_slice(read_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);

        let data = &response[FuseOutHeader::SIZE..];
        assert_eq!(data, b"initial");

        // Release
        let release_in = FuseReleaseIn {
            fh,
            flags: 0,
            release_flags: 0,
            lock_owner: 0,
        };
        let mut request = make_header(FuseOpcode::Release, inode, size_of::<FuseReleaseIn>());
        let release_bytes = unsafe {
            std::slice::from_raw_parts(&release_in as *const FuseReleaseIn as *const u8, size_of::<FuseReleaseIn>())
        };
        request.extend_from_slice(release_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);
    }

    #[test]
    fn test_statfs() {
        let (_temp, dispatcher) = setup_dispatcher();

        let request = make_header(FuseOpcode::Statfs, 1, 0);
        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);

        assert_eq!(header.error, 0);
        assert!(response.len() >= FuseOutHeader::SIZE + size_of::<FuseStatfsOut>());
    }

    #[test]
    fn test_unknown_opcode() {
        let (_temp, dispatcher) = setup_dispatcher();

        let header = FuseInHeader {
            len: FuseInHeader::SIZE as u32,
            opcode: 9999, // Unknown opcode
            unique: 1,
            nodeid: 1,
            uid: 0,
            gid: 0,
            pid: 0,
            padding: 0,
        };

        let request = unsafe {
            std::slice::from_raw_parts(&header as *const FuseInHeader as *const u8, FuseInHeader::SIZE)
        };

        let result = dispatcher.dispatch(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_opcode() {
        let (_temp, dispatcher) = setup_dispatcher();

        // IOCTL is unsupported
        let request = make_header(FuseOpcode::Ioctl, 1, 0);
        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);

        assert_eq!(header.error, -libc::ENOSYS);
    }

    #[test]
    fn test_opendir_readdir_releasedir() {
        let (temp, dispatcher) = setup_dispatcher();

        // Create some files
        std::fs::write(temp.path().join("file1.txt"), "").unwrap();
        std::fs::write(temp.path().join("file2.txt"), "").unwrap();

        // Opendir
        let open_in = FuseOpenIn { flags: 0, unused: 0 };
        let mut request = make_header(FuseOpcode::Opendir, 1, size_of::<FuseOpenIn>());
        let open_bytes = unsafe {
            std::slice::from_raw_parts(&open_in as *const FuseOpenIn as *const u8, size_of::<FuseOpenIn>())
        };
        request.extend_from_slice(open_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);

        let open_out = unsafe {
            &*((response.as_ptr() as *const u8).add(FuseOutHeader::SIZE) as *const FuseOpenOut)
        };
        let fh = open_out.fh;

        // Readdir
        let read_in = FuseReadIn {
            fh,
            offset: 0,
            size: 4096,
            read_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        let mut request = make_header(FuseOpcode::Readdir, 1, size_of::<FuseReadIn>());
        let read_bytes = unsafe {
            std::slice::from_raw_parts(&read_in as *const FuseReadIn as *const u8, size_of::<FuseReadIn>())
        };
        request.extend_from_slice(read_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);

        // Releasedir
        let release_in = FuseReleaseIn {
            fh,
            flags: 0,
            release_flags: 0,
            lock_owner: 0,
        };
        let mut request = make_header(FuseOpcode::Releasedir, 1, size_of::<FuseReleaseIn>());
        let release_bytes = unsafe {
            std::slice::from_raw_parts(&release_in as *const FuseReleaseIn as *const u8, size_of::<FuseReleaseIn>())
        };
        request.extend_from_slice(release_bytes);

        let response = dispatcher.dispatch(&request).unwrap();
        let header = parse_response_header(&response);
        assert_eq!(header.error, 0);
    }

    #[test]
    fn test_response_builder() {
        let mut builder = ResponseBuilder::new();

        // Test error response
        builder.write_error(123, libc::ENOENT);
        let response = builder.as_bytes();
        let header = parse_response_header(response);
        assert_eq!(header.unique, 123);
        assert_eq!(header.error, -libc::ENOENT);
        assert_eq!(header.len as usize, FuseOutHeader::SIZE);

        // Test empty response
        builder.write_empty(456);
        let response = builder.as_bytes();
        let header = parse_response_header(response);
        assert_eq!(header.unique, 456);
        assert_eq!(header.error, 0);
        assert_eq!(header.len as usize, FuseOutHeader::SIZE);

        // Test bytes response
        builder.write_bytes(789, b"hello");
        let response = builder.as_bytes();
        let header = parse_response_header(response);
        assert_eq!(header.unique, 789);
        assert_eq!(header.error, 0);
        assert_eq!(header.len as usize, FuseOutHeader::SIZE + 5);
        assert_eq!(&response[FuseOutHeader::SIZE..], b"hello");
    }
}
