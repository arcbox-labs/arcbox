//! FUSE request dispatcher.
//!
//! This module handles parsing FUSE requests and dispatching them to the
//! appropriate filesystem operations. It acts as the bridge between the
//! raw FUSE protocol and the [`PassthroughFs`] implementation.

// Allow casts and pointer operations for FUSE protocol binary compatibility.
// FUSE structs arriving from VirtIO queue memory may be unaligned, so all
// deserialization uses `std::ptr::read_unaligned` instead of reference casts.
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::ptr_as_ptr,
    clippy::borrow_as_ptr,
    // Test helpers serialize FUSE structs to byte slices using the same
    // `&x as *const T as *const u8` and `.add(N) as *const T` patterns as
    // the production code. The suppression is intentional for binary compat.
    clippy::ref_as_ptr,
    clippy::unnecessary_cast,
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_ref_mut
)]

mod dax;
mod directories;
mod file_ops;
mod lookup_attrs;
mod mapping_xattr;
mod nodes;
#[cfg(test)]
mod tests;
mod types;

use crate::error::{FsError, Result};
use crate::fuse::{
    FATTR_ATIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID, FUSE_NO_FH,
    FuseAccessIn, FuseAttr, FuseAttrOut, FuseCreateIn, FuseDirent, FuseEntryOut, FuseFallocateIn,
    FuseFlushIn, FuseForgetIn, FuseFsyncIn, FuseGetxattrIn, FuseGetxattrOut, FuseInHeader,
    FuseLinkIn, FuseLseekIn, FuseLseekOut, FuseMkdirIn, FuseMknodIn, FuseOpcode, FuseOpenIn,
    FuseOpenOut, FuseOutHeader, FuseReadIn, FuseReleaseIn, FuseRenameIn, FuseSetattrIn,
    FuseSetxattrIn, FuseStatfsOut, FuseWriteIn, FuseWriteOut,
};
use crate::passthrough::PassthroughFs;

use std::ffi::OsStr;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

pub use dax::DaxFsExt;
pub use types::{DispatcherConfig, RequestContext, ResponseBuilder};
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
    /// Optional DAX mapper for direct host page mapping.
    dax_mapper: Option<Arc<dyn crate::DaxMapper>>,
}

impl FuseDispatcher {
    /// Creates a new dispatcher.
    #[must_use]
    pub fn new(fs: Arc<PassthroughFs>, config: DispatcherConfig) -> Self {
        Self {
            fs,
            config,
            dax_mapper: None,
        }
    }

    /// Sets the DAX mapper for direct host page mapping.
    pub fn set_dax_mapper(&mut self, mapper: Arc<dyn crate::DaxMapper>) {
        self.dax_mapper = Some(mapper);
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

        // SAFETY: FuseInHeader is a packed FUSE protocol struct that may arrive at
        // an unaligned offset from VirtIO queue memory; read_unaligned avoids UB.
        let header = unsafe { std::ptr::read_unaligned(request.as_ptr() as *const FuseInHeader) };
        let body = &request[FuseInHeader::SIZE..];

        // Parse opcode
        let opcode = FuseOpcode::from_u32(header.opcode)
            .ok_or_else(|| FsError::Fuse(format!("unknown opcode: {}", header.opcode)))?;

        let ctx = RequestContext::from(&header);
        let mut response = ResponseBuilder::new();

        tracing::debug!(
            "FUSE: {:?} nodeid={} unique={}",
            opcode,
            ctx.nodeid,
            ctx.unique
        );

        // Dispatch to handler
        match opcode {
            // FUSE_INIT is intercepted by FuseSession::handle_init in arcbox-virtio-fs
            // before any FuseRequestHandler is called.  If we somehow receive it here
            // the session has already sent the handshake; responding ENOSYS is safe.
            FuseOpcode::Init => response.write_error(ctx.unique, libc::ENOSYS),
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
            FuseOpcode::Readdirplus => self.handle_readdirplus(&ctx, body, &mut response),
            FuseOpcode::Releasedir => self.handle_releasedir(&ctx, body, &mut response),
            FuseOpcode::Fsyncdir => self.handle_fsyncdir(&ctx, body, &mut response),
            FuseOpcode::Access => self.handle_access(&ctx, body, &mut response),
            FuseOpcode::Create => self.handle_create(&ctx, body, &mut response),
            FuseOpcode::Getxattr => self.handle_getxattr(&ctx, body, &mut response),
            FuseOpcode::Setxattr => self.handle_setxattr(&ctx, body, &mut response),
            FuseOpcode::Removexattr => self.handle_removexattr(&ctx, body, &mut response),
            FuseOpcode::Lseek => self.handle_lseek(&ctx, body, &mut response),
            FuseOpcode::Fallocate => self.handle_fallocate(&ctx, body, &mut response),
            FuseOpcode::SetupMapping => self.handle_setup_mapping(&ctx, body, &mut response),
            FuseOpcode::RemoveMapping => self.handle_remove_mapping(&ctx, body, &mut response),
            _ => {
                tracing::warn!(
                    "FUSE: unsupported opcode {:?} ({}), returning ENOSYS",
                    opcode,
                    header.opcode
                );
                response.write_error(ctx.unique, libc::ENOSYS);
            }
        }

        Ok(response.finish())
    }

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

// The `fs` field is intentionally excluded from Debug output — it contains
// internal locks and file descriptors that are not meaningful to log.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for FuseDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseDispatcher")
            .field("config", &self.config)
            .finish()
    }
}
